// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Re-derive stored remote HTML when the sanitiser policy moves on.
//!
//! Sanitising at ingestion only protects rows written *after* the guard
//! exists. Rows already in the table were written by whatever policy was
//! current at the time (including no policy at all, which the schema
//! records as version `0`). This module is the other half of that design:
//! stored HTML is a derived projection, and a projection that cannot be
//! rebuilt is just a cache nobody can invalidate.
//!
//! It runs on every boot, sweeps whatever is behind
//! [`noombat_markup::sanitise::STRICT_VERSION`], and stops. Raising that
//! constant is therefore the entire operator procedure for tightening the
//! allowlist: change the number, deploy, and the next boot re-derives the
//! affected rows. There is no script to find, no runbook step to forget.
//!
//! # Scope: remote rows only
//!
//! The version column tracks the *federated ingestion* sanitiser, and the
//! backfill joins `actors` to touch only rows authored remotely. Locally
//! authored content is deliberately left at version `0` forever, because
//! re-deriving it here would be wrong twice over:
//!
//! - Local HTML is produced by `noombat_markup::render`, which applies
//!   the `clean` profile (or `clean_strict` when the author opted in),
//!   not the strict ingestion profile. Re-cleaning it strictly would
//!   strip the `style` attributes the maths renderer legitimately emits,
//!   silently breaking every local post containing maths.
//! - Re-deriving local content means re-running `render` over every local
//!   post, which does not belong in a boot-time sweep.
//!
//! So `sanitiser_version = 0` reads as "not produced by the ingestion
//! sanitiser": true both for un-backfilled remote rows and for every
//! local row, with the `is_local` join telling the two apart.

use noombat_markup::sanitise::STRICT_VERSION;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// Rows fetched and rewritten per statement.
///
/// The sweep runs at boot alongside request serving, so it takes the
/// table in small bites rather than holding one long transaction over
/// every stale row. Each batch is independent: interrupt the process
/// halfway and the next boot resumes from whatever is still behind,
/// because the work list is defined by the data, not by a cursor.
const BATCH: i64 = 500;

/// What one sweep changed, for logging and for tests to assert on.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BackfillReport {
    pub posts_updated: u64,
    pub actors_updated: u64,
}

impl BackfillReport {
    fn is_empty(&self) -> bool {
        self.posts_updated == 0 && self.actors_updated == 0
    }
}

/// Re-derive every remote row whose `sanitiser_version` is behind
/// [`STRICT_VERSION`].
///
/// Idempotent and resumable: running it twice over the same table leaves
/// the second run with nothing to do, and killing it mid-sweep loses only
/// the batch in flight.
pub async fn run(pool: &PgPool) -> BackfillReport {
    let mut report = BackfillReport::default();

    loop {
        match backfill_posts_batch(pool).await {
            Ok(0) => break,
            Ok(n) => report.posts_updated += n,
            Err(e) => {
                // A failed sweep must not take the server down with it:
                // the rows stay behind, stay in the work list, and are
                // retried on the next boot. Loud, because until it
                // succeeds those rows are still rendering unsanitised
                // HTML with `|safe`.
                warn!(error = %e, "sanitiser backfill: post batch failed; rows left for next boot");
                break;
            }
        }
    }

    loop {
        match backfill_actors_batch(pool).await {
            Ok(0) => break,
            Ok(n) => report.actors_updated += n,
            Err(e) => {
                warn!(error = %e, "sanitiser backfill: actor batch failed; rows left for next boot");
                break;
            }
        }
    }

    if report.is_empty() {
        info!(
            version = STRICT_VERSION,
            "sanitiser backfill: nothing stale"
        );
    } else {
        info!(
            version = STRICT_VERSION,
            posts = report.posts_updated,
            actors = report.actors_updated,
            "sanitiser backfill: re-derived stored HTML"
        );
    }

    report
}

/// Re-derive one batch of remote posts from their stored wire records.
///
/// Posts are the good case: `ap_object` holds the peer's document
/// verbatim, so this is a genuine re-derivation rather than a re-clean.
/// That matters for `content_md`, which a version-`0` row may be holding a
/// copy of the *HTML* in (the fallback an older ingestion path used when a
/// peer sent no `source`). Inspecting such a row cannot tell that copy
/// apart from real Markdown, so no schema-only fix can reach it;
/// re-deriving from `ap_object` settles it, because the absence of a
/// `text/markdown` `source` in the document is proof the column should be
/// `NULL`.
async fn backfill_posts_batch(pool: &PgPool) -> sqlx::Result<u64> {
    let stale: Vec<(Uuid, serde_json::Value, String)> = sqlx::query_as(
        r#"SELECT p.id, p.ap_object, p.content_html
           FROM posts p
           JOIN actors a ON a.id = p.actor_id
           WHERE p.sanitiser_version < $1
             AND a.is_local = FALSE
           ORDER BY p.id
           LIMIT $2"#,
    )
    .bind(STRICT_VERSION)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;

    if stale.is_empty() {
        return Ok(0);
    }

    let mut updated = 0;

    for (id, ap_object, stored_html) in stale {
        // A usable wire record is one that actually carries `content`.
        // Rows predating a schema change, or written with `'{}'::jsonb`,
        // have nothing to re-derive from, so fall back to cleaning the
        // stored projection in place. Lossier (a prior policy may
        // already have removed markup a looser future policy would
        // allow), but it still closes the hole, which is the point.
        let derived = if ap_object.get("content").is_some() {
            let content = crate::inbox::extract_remote_content(&ap_object);
            (content.content_html, Some(content.content_md), true)
        } else {
            (
                crate::inbox::sanitise_remote_html(&stored_html),
                None,
                false,
            )
        };

        let (html, content_md, rederived) = derived;

        // `content_md` is only rewritten when it was genuinely
        // re-derived. In the fallback branch the column is left exactly
        // as found: with no wire record there is no evidence about what
        // it should be, and guessing would destroy real Markdown.
        let affected = if rederived {
            sqlx::query(
                r#"UPDATE posts
                   SET content_html = $2,
                       content_md = $3,
                       sanitiser_version = $4
                   WHERE id = $1"#,
            )
            .bind(id)
            .bind(&html)
            .bind(content_md.flatten())
            .bind(STRICT_VERSION)
            .execute(pool)
            .await?
        } else {
            sqlx::query(
                r#"UPDATE posts
                   SET content_html = $2,
                       sanitiser_version = $3
                   WHERE id = $1"#,
            )
            .bind(id)
            .bind(&html)
            .bind(STRICT_VERSION)
            .execute(pool)
            .await?
        };

        updated += affected.rows_affected();
    }

    Ok(updated)
}

/// Re-clean one batch of remote actor summaries.
///
/// Actors are the lossy case. There is no `ap_object` on `actors`: the
/// stored `summary_html` is the only copy of what the peer sent, so this
/// re-cleans in place rather than re-deriving. That is sound while the
/// allowlist only ever tightens (the direction [`STRICT_VERSION`]'s
/// documentation commits to), because cleaning an already-cleaned value
/// is a no-op, and cleaning a raw one produces exactly what ingestion
/// would have. It could not recover content a *loosened* policy wanted
/// back; that would need a re-fetch.
async fn backfill_actors_batch(pool: &PgPool) -> sqlx::Result<u64> {
    let stale: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        r#"SELECT id, summary_html
           FROM actors
           WHERE sanitiser_version < $1
             AND is_local = FALSE
           ORDER BY id
           LIMIT $2"#,
    )
    .bind(STRICT_VERSION)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;

    if stale.is_empty() {
        return Ok(0);
    }

    let mut updated = 0;

    for (id, summary) in stale {
        let cleaned = summary.as_deref().map(crate::inbox::sanitise_remote_html);

        let affected = sqlx::query(
            r#"UPDATE actors
               SET summary_html = $2,
                   sanitiser_version = $3
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(&cleaned)
        .bind(STRICT_VERSION)
        .execute(pool)
        .await?;

        updated += affected.rows_affected();
    }

    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn insert_actor(
        pool: &PgPool,
        ap_id: &str,
        is_local: bool,
        summary: Option<&str>,
    ) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO actors
                   (actor_type, ap_id, username, domain, public_key_pem,
                    is_local, summary_html, sanitiser_version)
               VALUES ('individual', $1, 'alice', 'remote.example', 'KEY', $2, $3, 0)
               RETURNING id"#,
        )
        .bind(ap_id)
        .bind(is_local)
        .bind(summary)
        .fetch_one(pool)
        .await
        .expect("actor fixture inserted")
    }

    async fn insert_post(
        pool: &PgPool,
        actor_id: Uuid,
        ap_id: &str,
        content_md: Option<&str>,
        content_html: &str,
        ap_object: serde_json::Value,
    ) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO posts
                   (actor_id, ap_id, post_type, content_md, content_html,
                    visibility, ap_object, sanitiser_version)
               VALUES ($1, $2, 'note', $3, $4, 'public', $5, 0)
               RETURNING id"#,
        )
        .bind(actor_id)
        .bind(ap_id)
        .bind(content_md)
        .bind(content_html)
        .bind(ap_object)
        .fetch_one(pool)
        .await
        .expect("post fixture inserted")
    }

    async fn post_row(pool: &PgPool, id: Uuid) -> (String, Option<String>, i16) {
        sqlx::query_as(
            "SELECT content_html, content_md, sanitiser_version FROM posts WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("post readable")
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn rederives_a_remote_post_from_its_wire_record(pool: PgPool) {
        let actor = insert_actor(&pool, "https://remote.example/users/alice", false, None).await;
        let id = insert_post(
            &pool,
            actor,
            "https://remote.example/posts/1",
            None,
            "<p>hi</p><script>alert(1)</script>",
            serde_json::json!({ "content": "<p>hi</p><script>alert(1)</script>" }),
        )
        .await;

        let report = run(&pool).await;
        assert_eq!(report.posts_updated, 1);

        let (html, _, ver) = post_row(&pool, id).await;
        assert!(!html.contains("<script"), "got {html}");
        assert!(html.contains("<p>hi</p>"), "got {html}");
        assert_eq!(ver, STRICT_VERSION);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn clears_content_md_that_was_a_copy_of_the_html(pool: PgPool) {
        // An older ingestion path stored `content_html` in `content_md`
        // when the peer sent no `source`. The wire record proves there
        // was none, so the column belongs at NULL.
        let actor = insert_actor(&pool, "https://remote.example/users/alice", false, None).await;
        let id = insert_post(
            &pool,
            actor,
            "https://remote.example/posts/1",
            Some("<p>hi</p>"),
            "<p>hi</p>",
            serde_json::json!({ "content": "<p>hi</p>" }),
        )
        .await;

        run(&pool).await;

        let (_, md, _) = post_row(&pool, id).await;
        assert_eq!(md, None, "an HTML copy is not a Markdown source");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn keeps_a_genuine_markdown_source(pool: PgPool) {
        let actor = insert_actor(&pool, "https://remote.example/users/alice", false, None).await;
        let id = insert_post(
            &pool,
            actor,
            "https://remote.example/posts/1",
            Some("*hi*"),
            "<p><em>hi</em></p>",
            serde_json::json!({
                "content": "<p><em>hi</em></p>",
                "source": { "mediaType": "text/markdown", "content": "*hi*" }
            }),
        )
        .await;

        run(&pool).await;

        let (_, md, _) = post_row(&pool, id).await;
        assert_eq!(md.as_deref(), Some("*hi*"));
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn cleans_in_place_when_there_is_no_wire_record(pool: PgPool) {
        let actor = insert_actor(&pool, "https://remote.example/users/alice", false, None).await;
        let id = insert_post(
            &pool,
            actor,
            "https://remote.example/posts/1",
            Some("*real markdown*"),
            "<p>hi</p><script>alert(1)</script>",
            serde_json::json!({}),
        )
        .await;

        run(&pool).await;

        let (html, md, ver) = post_row(&pool, id).await;
        assert!(!html.contains("<script"), "got {html}");
        assert_eq!(
            md.as_deref(),
            Some("*real markdown*"),
            "with no wire record the Markdown column must be left alone"
        );
        assert_eq!(ver, STRICT_VERSION);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn leaves_local_posts_untouched(pool: PgPool) {
        // Local HTML comes from `render`, whose `clean` profile keeps the
        // `style` attributes the maths renderer emits. Re-cleaning it
        // strictly would silently break every local post with maths.
        let actor = insert_actor(&pool, "https://noombat.test/users/bob", true, None).await;
        let styled = r#"<p><span style="height:0.5em">x</span></p>"#;
        let id = insert_post(
            &pool,
            actor,
            "https://noombat.test/posts/1",
            Some("$x$"),
            styled,
            serde_json::json!({ "content": styled }),
        )
        .await;

        let report = run(&pool).await;
        assert_eq!(report.posts_updated, 0, "local rows are out of scope");

        let (html, md, ver) = post_row(&pool, id).await;
        assert_eq!(html, styled, "local styling must survive");
        assert_eq!(md.as_deref(), Some("$x$"));
        assert_eq!(ver, 0, "local rows stay at 0: not ingestion-sanitised");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn cleans_remote_actor_summaries_and_skips_local_ones(pool: PgPool) {
        let remote = insert_actor(
            &pool,
            "https://remote.example/users/alice",
            false,
            Some("<p>hi</p><script>alert(1)</script>"),
        )
        .await;
        let local = insert_actor(
            &pool,
            "https://noombat.test/users/bob",
            true,
            Some("<p>local</p>"),
        )
        .await;

        let report = run(&pool).await;
        assert_eq!(report.actors_updated, 1);

        let (remote_summary, remote_ver): (Option<String>, i16) =
            sqlx::query_as("SELECT summary_html, sanitiser_version FROM actors WHERE id = $1")
                .bind(remote)
                .fetch_one(&pool)
                .await
                .expect("actor readable");
        assert!(
            !remote_summary
                .as_deref()
                .unwrap_or_default()
                .contains("<script"),
            "got {remote_summary:?}"
        );
        assert_eq!(remote_ver, STRICT_VERSION);

        let local_ver: i16 =
            sqlx::query_scalar("SELECT sanitiser_version FROM actors WHERE id = $1")
                .bind(local)
                .fetch_one(&pool)
                .await
                .expect("actor readable");
        assert_eq!(local_ver, 0, "local actors are out of scope");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn is_idempotent(pool: PgPool) {
        let actor = insert_actor(
            &pool,
            "https://remote.example/users/alice",
            false,
            Some("<p>hi</p><script>x</script>"),
        )
        .await;
        insert_post(
            &pool,
            actor,
            "https://remote.example/posts/1",
            None,
            "<p>hi</p><script>x</script>",
            serde_json::json!({ "content": "<p>hi</p><script>x</script>" }),
        )
        .await;

        let first = run(&pool).await;
        assert_eq!(first.posts_updated, 1);
        assert_eq!(first.actors_updated, 1);

        // The second sweep must find an empty work list. If it does not,
        // the boot-time sweep would rewrite the whole table on every
        // restart forever.
        let second = run(&pool).await;
        assert_eq!(second, BackfillReport::default());
    }
}
