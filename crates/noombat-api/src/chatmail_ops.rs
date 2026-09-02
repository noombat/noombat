// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chatmail work this instance owes the sidecar, and the record of it.
//!
//! One operation matters in v1: deleting the maildir when an account is
//! erased. `delete_account` existed on the client and nothing called it,
//! so an erasure removed the rows and left the mail.
//!
//! **The intent is written down before it is attempted.** The sidecar is
//! a separate process that can be down while this one is up, and an
//! erasure is not repeatable: by the time the delete would be retried,
//! the actor row is gone and nothing remembers which address it held.
//! Recording the address at erasure and draining it afterwards is what
//! makes the failure survivable.
//!
//! **This is also the outage record.** The same table answers "is
//! Chatmail deletion working", which is why a failure keeps its error
//! text and its attempt count rather than only a state, and why the
//! administration page reads it rather than a log.

use std::time::Duration;

use chrono::{DateTime, Utc};
use noombat_chat::admin_client::ChatmailAdminClient;
use noombat_core::error::Result;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

/// How many attempts before an operation is given up on.
///
/// Given up on, not forgotten: the row stays as `failed`, with its last
/// error, because an administrator has to be able to see what was never
/// completed. A silent give-up is the erasure failing silently again,
/// one layer up.
const MAX_ATTEMPTS: i32 = 8;

/// Backoff for attempt `n`, capped.
///
/// A sidecar that is down is usually down for minutes, not seconds, and
/// hammering it while it restarts is how a partial outage becomes a
/// full one.
fn backoff(attempts: i32) -> Duration {
    let seconds = 30_u64.saturating_mul(1 << attempts.clamp(0, 6) as u32);
    Duration::from_secs(seconds.min(3600))
}

/// Record that a maildir is owed deletion.
///
/// Called from the erasure path *before* the actor row is tombstoned,
/// because tombstoning clears `chatmail_addr` and afterwards nothing
/// knows which mailbox to remove.
///
/// `ON CONFLICT DO NOTHING` against the address: a second erasure of the
/// same address is the same work, not more of it.
pub async fn enqueue_delete(pool: &PgPool, actor_id: Uuid, address: &str) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO chatmail_operations (actor_id, address, operation)
           VALUES ($1, $2, 'delete_account')
           ON CONFLICT (address, operation) DO NOTHING"#,
    )
    .bind(actor_id)
    .bind(address)
    .execute(pool)
    .await?;

    Ok(())
}

/// Whether every Chatmail operation for an actor has been settled.
///
/// "Settled" is drained *or* exhausted, not drained: an operation that
/// has failed its last attempt will never succeed, and holding the row
/// open for it forever means the retention window never ends.
pub async fn settled_for(pool: &PgPool, actor_id: Uuid) -> Result<bool> {
    let outstanding: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chatmail_operations WHERE actor_id = $1 AND state = 'pending'",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    Ok(outstanding == 0)
}

/// One operation awaiting the sidecar.
#[derive(Debug, sqlx::FromRow)]
pub struct PendingOperation {
    pub id: Uuid,
    pub address: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// One operation that will not be retried again.
#[derive(Debug, sqlx::FromRow)]
pub struct FailedOperation {
    pub id: Uuid,
    pub address: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What the administration page shows.
pub async fn pending(pool: &PgPool) -> Result<Vec<PendingOperation>> {
    let rows = sqlx::query_as::<_, PendingOperation>(
        "SELECT id, address, attempts, last_error, next_attempt_at, created_at \
         FROM chatmail_operations WHERE state = 'pending' \
         ORDER BY next_attempt_at ASC LIMIT 200",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Operations that exhausted their attempts, newest first.
pub async fn failures(pool: &PgPool) -> Result<Vec<FailedOperation>> {
    let rows = sqlx::query_as::<_, FailedOperation>(
        "SELECT id, address, attempts, last_error, created_at \
         FROM chatmail_operations WHERE state = 'failed' \
         ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Drain every operation that is due, once.
///
/// Returns how many succeeded. A sidecar that is not configured is not
/// an error and not a failure to record: there is nothing to talk to, so
/// the work stays pending and the administration page says so.
pub async fn drain(pool: &PgPool, client: &Option<ChatmailAdminClient>) -> u64 {
    let Some(client) = client.as_ref() else {
        return 0;
    };

    let due = match sqlx::query_as::<_, (Uuid, String, i32)>(
        "SELECT id, address, attempts FROM chatmail_operations \
         WHERE state = 'pending' AND next_attempt_at <= now() \
         ORDER BY next_attempt_at ASC LIMIT 50",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!(error = %e, "chatmail operations could not be read");
            return 0;
        }
    };

    let mut succeeded = 0;
    for (id, address, attempts) in due {
        match client.delete_account(&address).await {
            Ok(()) => {
                // The liveness probe, and the reason it is worth having:
                // a sidecar can answer 200 to a delete and still hold
                // the mailbox, and only asking afterwards catches that.
                match client.account_exists(&address).await {
                    Ok(false) => {
                        mark_succeeded(pool, id).await;
                        succeeded += 1;
                    }
                    Ok(true) => {
                        mark_failed(
                            pool,
                            id,
                            attempts,
                            "the sidecar accepted the deletion and the account still exists",
                        )
                        .await;
                    }
                    // The delete was accepted and the probe itself
                    // failed, which says nothing about the mailbox. Kept
                    // pending rather than called either way.
                    Err(e) => {
                        mark_failed(pool, id, attempts, &format!("liveness probe failed: {e}"))
                            .await;
                    }
                }
            }
            Err(e) => mark_failed(pool, id, attempts, &e.to_string()).await,
        }
    }

    succeeded
}

async fn mark_succeeded(pool: &PgPool, id: Uuid) {
    if let Err(e) = sqlx::query(
        "UPDATE chatmail_operations \
         SET state = 'succeeded', completed_at = now(), attempts = attempts + 1, last_error = NULL \
         WHERE id = $1",
    )
    .bind(id)
    .execute(pool)
    .await
    {
        error!(%id, error = %e, "chatmail operation completed and could not be recorded");
    } else {
        // No address in the log line: this is the record of an erasure
        // and must not reintroduce what was erased.
        info!(%id, "chatmail maildir deleted");
    }
}

async fn mark_failed(pool: &PgPool, id: Uuid, attempts: i32, reason: &str) {
    let next = attempts + 1;
    let exhausted = next >= MAX_ATTEMPTS;
    let delay = backoff(next);

    let result = sqlx::query(
        "UPDATE chatmail_operations \
         SET attempts = $2, last_error = $3, \
             state = CASE WHEN $4 THEN 'failed' ELSE 'pending' END, \
             next_attempt_at = now() + ($5 || ' seconds')::interval \
         WHERE id = $1",
    )
    .bind(id)
    .bind(next)
    .bind(reason)
    .bind(exhausted)
    .bind(delay.as_secs().to_string())
    .execute(pool)
    .await;

    if let Err(e) = result {
        error!(%id, error = %e, "chatmail failure could not be recorded");
        return;
    }

    if exhausted {
        // Loud, because this is a maildir that will now outlive the
        // account it belonged to unless somebody acts.
        error!(%id, attempts = next, reason, "chatmail operation gave up");
    } else {
        warn!(%id, attempts = next, reason, "chatmail operation failed; will retry");
    }
}

/// Drain due operations on a fixed interval.
pub async fn run_worker(pool: PgPool, client: Option<ChatmailAdminClient>, interval: Duration) {
    loop {
        let settled = drain(&pool, &client).await;
        if settled > 0 {
            info!(settled, "chatmail operations completed");
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_grows_and_is_capped() {
        assert_eq!(backoff(0), Duration::from_secs(30));
        assert_eq!(backoff(1), Duration::from_secs(60));
        assert_eq!(backoff(4), Duration::from_secs(480));
        // Capped, so a long outage does not push the next attempt past
        // the retention window that is waiting on it.
        assert_eq!(
            backoff(6),
            Duration::from_secs(1920).min(Duration::from_secs(3600))
        );
        assert!(backoff(60) <= Duration::from_secs(3600));
    }

    #[test]
    fn the_backoff_never_overflows() {
        // The shift is clamped, so a row whose attempts column has been
        // edited by hand cannot panic the worker.
        assert!(backoff(i32::MAX) <= Duration::from_secs(3600));
        assert!(backoff(-1) >= Duration::from_secs(30));
    }
}
