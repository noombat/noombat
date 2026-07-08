// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Delivery queue worker for outbound ActivityPub activities.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{TimeDelta, Utc};
use http_signature_normalization_reqwest::prelude::*;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use sha2::Digest as _;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Maximum number of concurrent outbound HTTP deliveries per poll cycle.
const MAX_CONCURRENT_DELIVERIES: usize = 10;

/// A row from the `delivery_queue` table.
#[derive(FromRow)]
struct DeliveryRow {
    id: i64,
    actor_id: Uuid,
    payload: Value,
    target_inbox: String,
    attempts: i16,
}

/// Signing credentials for the sending actor, fetched once per delivery.
struct SigningCredentials {
    /// Key ID URI, e.g. `https://noombat.social/users/alice#main-key`.
    key_id: String,
    /// RSA private key in PKCS#8 PEM format.
    private_key_pem: String,
}

/// Enqueue an activity for delivery to a remote inbox.
///
/// # Arguments
/// * `pool`: the database connection pool.
/// * `actor_id`: the UUID of the local actor sending the activity
///   (used by the delivery worker to look up the signing key).
/// * `payload`: the full ActivityPub activity as JSON.
/// * `target_inbox`: the remote actor's inbox URI.
pub async fn enqueue(
    pool: &PgPool,
    actor_id: Uuid,
    payload: &Value,
    target_inbox: &str,
) -> noombat_core::error::Result<()> {
    sqlx::query(
        r#"INSERT INTO delivery_queue (actor_id, payload, target_inbox)
           VALUES ($1, $2, $3)"#,
    )
    .bind(actor_id)
    .bind(payload)
    .bind(target_inbox)
    .execute(pool)
    .await?;

    info!(target_inbox, "enqueued activity for delivery");
    Ok(())
}

/// Process pending deliveries (called by a background Tokio task).
///
/// Up to 50 rows are fetched per cycle. Deliveries are dispatched
/// concurrently (bounded to [`MAX_CONCURRENT_DELIVERIES`]) so that a
/// slow or unreachable remote server does not block the entire batch.
///
/// On transient failure, applies exponential backoff up to a maximum of
/// 10 attempts.
pub async fn process_queue(pool: &PgPool, http_client: &reqwest::Client) {
    // Atomically claim rows by advancing `next_retry` one hour into
    // the future. The CTE selects and locks candidate rows; the
    // surrounding UPDATE marks them as in-progress before the
    // implicit transaction commits. Concurrent workers calling the
    // same query will skip these rows (SKIP LOCKED) or see the
    // advanced `next_retry` and ignore them.
    //
    // If the process crashes before delivery completes, the rows
    // become eligible again once the one-hour claim window expires.
    let rows = sqlx::query_as::<_, DeliveryRow>(
        r#"WITH claimed AS (
               SELECT id FROM delivery_queue
               WHERE next_retry <= now() AND attempts < 10
               ORDER BY next_retry ASC
               LIMIT 50
               FOR UPDATE SKIP LOCKED
           )
           UPDATE delivery_queue dq
           SET next_retry = now() + interval '1 hour'
           FROM claimed
           WHERE dq.id = claimed.id
           RETURNING dq.id, dq.actor_id, dq.payload,
                     dq.target_inbox, dq.attempts"#,
    )
    .fetch_all(pool)
    .await;

    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            error!("failed to fetch delivery queue: {e}");
            return;
        }
    };

    if rows.is_empty() {
        return;
    }

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES));
    let mut set = JoinSet::new();

    for row in rows {
        let pool = pool.clone();
        let client = http_client.clone();
        let permit = semaphore.clone();

        set.spawn(async move {
            // Acquire a permit before performing the HTTP request,
            // bounding the number of simultaneous outbound connections.
            let _permit = permit.acquire().await.expect("semaphore closed");
            deliver_one(&pool, &client, row).await;
        });
    }

    // Await all spawned tasks.
    while let Some(result) = set.join_next().await {
        if let Err(e) = result {
            error!("delivery task panicked: {e}");
        }
    }
}

/// Fetch the signing credentials for the sending actor.
async fn fetch_signing_credentials(
    pool: &PgPool,
    actor_id: Uuid,
) -> noombat_core::error::Result<SigningCredentials> {
    let row = sqlx::query_as::<_, (String, Option<String>)>(
        r#"SELECT ap_id, private_key_pem FROM actors WHERE id = $1"#,
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .map_err(noombat_core::error::NoombatError::from)?;

    let private_key_pem = row.1.ok_or_else(|| {
        noombat_core::error::NoombatError::Internal(
            "delivery actor has no private key (remote actor in delivery queue?)".into(),
        )
    })?;

    Ok(SigningCredentials {
        key_id: format!("{}#main-key", row.0),
        private_key_pem,
    })
}

/// Build the signing [`Config`] for outbound deliveries.
///
/// [`mastodon_compat()`][Config::mastodon_compat] produces `rsa-sha256`
/// signatures with `(request-target)`, `host`, and `date` headers, i.e. the
/// format accepted by all deployed Fediverse software.
/// [`require_digest()`][Config::require_digest] additionally signs the
/// `Digest` header, as required by Mastodon for POST requests.
fn signing_config() -> Config {
    Config::default()
        .mastodon_compat()
        .require_digest()
        .set_expiration(Duration::from_secs(30))
}

/// Attempt delivery of a single activity to a remote inbox.
///
/// The `http-signature-normalization-reqwest` crate's [`Sign`] trait
/// handles signing-string construction, `Date`/`Digest`/`Signature`
/// header attachment, and `spawn_blocking` offload (via the default
/// [`DefaultSpawner`]).
async fn deliver_one(pool: &PgPool, http_client: &reqwest::Client, row: DeliveryRow) {
    // Fetch signing credentials for the sending actor.
    let creds = match fetch_signing_credentials(pool, row.actor_id).await {
        Ok(c) => c,
        Err(e) => {
            error!(actor_id = %row.actor_id, "failed to fetch signing credentials: {e}");
            schedule_retry(pool, row.id, row.attempts).await;
            return;
        }
    };

    let body = serde_json::to_string(&row.payload).unwrap_or_default();

    // Build the request with an HTTP Signature via the Sign trait.
    //
    // `signature_with_digest` computes the SHA-256 body digest,
    // attaches the `Digest`, `Date`, and `Signature` headers, and
    // returns a ready-to-send `reqwest::Request`.
    let private_key_pem = creds.private_key_pem.clone();
    let signed_request = http_client
        .post(&row.target_inbox)
        .header("Content-Type", "application/activity+json")
        .signature_with_digest(
            signing_config(),
            creds.key_id.clone(),
            sha2::Sha256::new(),
            body,
            move |signing_string| -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
                let private_key =
                    rsa::RsaPrivateKey::from_pkcs8_pem(&private_key_pem)
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                            Box::new(e)
                        })?;
                let signing_key =
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
                let signature = signing_key.sign(signing_string.as_bytes());
                Ok(BASE64.encode(signature.to_bytes()))
            },
        )
        .await;

    let signed_request = match signed_request {
        Ok(r) => r,
        Err(e) => {
            error!(target_inbox = %row.target_inbox, "failed to sign request: {e}");
            schedule_retry(pool, row.id, row.attempts).await;
            return;
        }
    };

    let result = http_client.execute(signed_request).await;

    match result {
        Ok(resp) if resp.status().is_success() => {
            let _ = sqlx::query("DELETE FROM delivery_queue WHERE id = $1")
                .bind(row.id)
                .execute(pool)
                .await;
            info!(target_inbox = %row.target_inbox, "delivered successfully");
        }
        Ok(resp) if resp.status().as_u16() == 410 => {
            // 410 Gone: remote actor deleted; remove from queue.
            let _ = sqlx::query("DELETE FROM delivery_queue WHERE id = $1")
                .bind(row.id)
                .execute(pool)
                .await;
            info!(target_inbox = %row.target_inbox, "remote actor gone (410); dropping");
        }
        Ok(resp) => {
            warn!(
                target_inbox = %row.target_inbox,
                status = resp.status().as_u16(),
                attempts = row.attempts,
                "delivery failed; scheduling retry"
            );
            schedule_retry(pool, row.id, row.attempts).await;
        }
        Err(e) => {
            error!(
                target_inbox = %row.target_inbox,
                attempts = row.attempts,
                "delivery HTTP error: {e}; scheduling retry"
            );
            schedule_retry(pool, row.id, row.attempts).await;
        }
    }
}

/// Apply exponential backoff to a failed delivery.
async fn schedule_retry(pool: &PgPool, queue_id: i64, current_attempts: i16) {
    let backoff_secs = 60i64 * 2i64.pow(current_attempts as u32);
    let max_backoff = TimeDelta::days(7).num_seconds();
    let delay = backoff_secs.min(max_backoff);
    let next_retry = Utc::now() + TimeDelta::seconds(delay);

    let _ = sqlx::query(
        r#"UPDATE delivery_queue
           SET attempts = attempts + 1, next_retry = $1
           WHERE id = $2"#,
    )
    .bind(next_retry)
    .bind(queue_id)
    .execute(pool)
    .await;
}


