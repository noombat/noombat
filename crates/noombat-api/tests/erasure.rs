// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The account erasure grace period, end to end against the database.
//!
//! The bug these exist for is not a wrong answer, it is a missing
//! actor: `deletion_requested_at` was written by the API, read only to
//! decide what to display, and consumed by nothing. Every unit test of
//! `tombstone_actor` passed throughout, because `tombstone_actor` was
//! never the broken part. So these drive the sweep, and the assertions
//! are about the boundary (who is picked up) and the effect (what is
//! actually gone), not about the pieces.
//!
//! The effect assertion matters most. Erasure that flags the actor row
//! and leaves the career history behind would satisfy any test that
//! only checked `actor_status`, and would be a data-protection failure
//! dressed as a pass.

use std::sync::{Arc, Mutex};

use noombat_core::error::Result;
use noombat_core::extension::SearchBackend;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const GRACE_DAYS: i32 = 30;

/// No search backend, for the tests about the database effect.
fn no_search() -> Option<Arc<dyn SearchBackend>> {
    None
}

/// Records every index call, so the withdrawal of search documents can
/// be asserted. With `search: None` those calls are silent no-ops and
/// any assertion about them would pass against a handler that made
/// none.
#[derive(Default)]
struct RecordingSearch {
    calls: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl SearchBackend for RecordingSearch {
    async fn upsert(&self, index: &str, id: &str, _document: Value) -> Result<()> {
        self.calls
            .lock()
            .expect("not poisoned")
            .push(format!("upsert {index} {id}"));
        Ok(())
    }

    async fn delete(&self, index: &str, id: &str) -> Result<()> {
        self.calls
            .lock()
            .expect("not poisoned")
            .push(format!("delete {index} {id}"));
        Ok(())
    }

    async fn search(
        &self,
        _index: &str,
        _query: &str,
        _filters: Option<&str>,
        _limit: usize,
        _offset: usize,
    ) -> Result<Vec<Value>> {
        Ok(Vec::new())
    }
}

/// Give the actor a public post and return its primary key, which is
/// the key `index_post` uses as the search document id.
async fn insert_post(pool: &PgPool, actor_id: Uuid, username: &str) -> Uuid {
    let ap_id = format!("https://{DOMAIN}/users/{username}/posts/{}", Uuid::new_v4());
    sqlx::query_scalar(
        "INSERT INTO posts (actor_id, ap_id, content_html, visibility, ap_object) \
         VALUES ($1, $2, '<p>something they wrote</p>', 'public', '{}'::jsonb) \
         RETURNING id",
    )
    .bind(actor_id)
    .bind(&ap_id)
    .fetch_one(pool)
    .await
    .expect("post fixture inserted")
}

/// Insert a local actor, optionally with a deletion requested `days`
/// ago, plus one row of career history to prove erasure reaches past
/// the actors table.
async fn insert_actor(pool: &PgPool, username: &str, requested_days_ago: Option<i32>) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local,
                display_name, summary_md, deletion_requested_at)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE, 'Real Name', 'a summary',
                   CASE WHEN $5::int IS NULL THEN NULL
                        ELSE now() - ($5::text || ' days')::interval END)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(requested_days_ago)
    .execute(pool)
    .await
    .expect("actor fixture inserted");

    sqlx::query(
        "INSERT INTO experiences \
             (actor_id, title, company, start_date, visibility, ap_object) \
         VALUES ($1, 'Engineer', 'Acme', '2020-01-01', 'public', '{}'::jsonb)",
    )
    .bind(id)
    .execute(pool)
    .await
    .expect("experience fixture inserted");

    id
}

async fn experience_count(pool: &PgPool, actor_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM experiences WHERE actor_id = $1")
        .bind(actor_id)
        .fetch_one(pool)
        .await
        .expect("countable")
}

async fn display_name(pool: &PgPool, actor_id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT display_name FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_one(pool)
        .await
        .expect("actor row present")
}

/// The boundary: past the grace period is erased, inside it is not.
///
/// Both directions in one test on purpose. A sweep that erased
/// everything would pass a "the expired one is gone" assertion, and a
/// sweep that erased nothing would pass "the recent one survives".
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_sweep_erases_only_expired_requests(pool: PgPool) {
    let expired = insert_actor(&pool, "expired", Some(GRACE_DAYS + 1)).await;
    let recent = insert_actor(&pool, "recent", Some(1)).await;
    let never = insert_actor(&pool, "never", None).await;

    let erased = noombat_api::erasure::sweep(&pool, &no_search(), GRACE_DAYS).await;

    assert_eq!(erased, 1, "exactly the one past its grace period");
    assert_eq!(display_name(&pool, expired).await, None, "expired erased");
    assert_eq!(
        display_name(&pool, recent).await.as_deref(),
        Some("Real Name"),
        "a request one day old is still inside the grace period"
    );
    assert_eq!(
        display_name(&pool, never).await.as_deref(),
        Some("Real Name"),
        "an account that never asked must never be touched"
    );
}

/// Erasure reaches past the actors row.
///
/// Career history is the thing this instance exists to hold, and it is
/// the thing a "mark the account deleted" implementation would leave
/// sitting in the database.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_removes_career_history_not_just_the_actor_row(pool: PgPool) {
    let actor_id = insert_actor(&pool, "leaver", Some(GRACE_DAYS + 1)).await;
    assert_eq!(
        experience_count(&pool, actor_id).await,
        1,
        "fixture should start with career history"
    );

    noombat_api::erasure::sweep(&pool, &no_search(), GRACE_DAYS).await;

    assert_eq!(
        experience_count(&pool, actor_id).await,
        0,
        "the experience row survived erasure"
    );
}

/// A second sweep is a no-op.
///
/// `tombstone_actor` does not clear `deletion_requested_at`, so without
/// care the same account is selected forever, re-erased on every pass
/// and re-broadcast to every follower's inbox each hour.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_sweep_does_not_erase_again(pool: PgPool) {
    insert_actor(&pool, "leaver", Some(GRACE_DAYS + 1)).await;

    let first = noombat_api::erasure::sweep(&pool, &no_search(), GRACE_DAYS).await;
    let second = noombat_api::erasure::sweep(&pool, &no_search(), GRACE_DAYS).await;

    assert_eq!(first, 1, "the first sweep erases");
    assert_eq!(second, 0, "the second must find nothing left to do");
}

/// A grace period of zero erases immediately, which is what an operator
/// setting it to zero is asking for.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_zero_grace_period_erases_on_the_next_sweep(pool: PgPool) {
    let actor_id = insert_actor(&pool, "immediate", Some(0)).await;

    let erased = noombat_api::erasure::sweep(&pool, &no_search(), 0).await;

    assert_eq!(erased, 1);
    assert_eq!(display_name(&pool, actor_id).await, None);
}

/// Erasure withdraws the posts from the search index, not just the rows.
///
/// `tombstone_actor` deletes the post rows, so nothing afterwards knows
/// which documents to remove; the identifiers have to be taken first.
/// Skip that and the database is clean while the full text of
/// everything the user wrote stays searchable by its contents, which is
/// the failure this is here to prevent.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasure_withdraws_the_posts_from_the_search_index(pool: PgPool) {
    let actor_id = insert_actor(&pool, "author", Some(GRACE_DAYS + 1)).await;
    let first = insert_post(&pool, actor_id, "author").await;
    let second = insert_post(&pool, actor_id, "author").await;

    let search = Arc::new(RecordingSearch::default());
    let backend: Option<Arc<dyn SearchBackend>> = Some(search.clone());

    noombat_api::erasure::sweep(&pool, &backend, GRACE_DAYS).await;

    // The removals are spawned, so let the tasks run.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let calls = search.calls.lock().expect("not poisoned").clone();
    for post_id in [&first, &second] {
        assert!(
            calls.contains(&format!("delete posts {post_id}")),
            "post {post_id} was left in the index; calls were {calls:?}"
        );
    }
    assert!(
        calls.contains(&format!("delete profiles {actor_id}")),
        "the profile document should go too; calls were {calls:?}"
    );
}

/// A recruiter's erasure takes their listings and spares the applicants.
///
/// The whole decision in one assertion. `applications.job_listing_id`
/// used to be `NOT NULL ... ON DELETE CASCADE`, so deleting a listing
/// deleted every application to it: erasing one person destroyed
/// another person's records. The listing is the recruiter's content and
/// goes; the application is the applicant's and stays, legible because
/// of the snapshot taken when it was created.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn erasing_a_recruiter_spares_the_applicants(pool: PgPool) {
    let recruiter = insert_actor(&pool, "recruiter", Some(GRACE_DAYS + 1)).await;
    let applicant = insert_actor(&pool, "applicant", None).await;

    let listing: Uuid = sqlx::query_scalar(
        "INSERT INTO job_listings \
             (actor_id, ap_id, title, description_md, description_html) \
         VALUES ($1, 'https://noombat.example/jobs/1', 'Engineer', 'Build things', \
                 '<p>Build things</p>') \
         RETURNING id",
    )
    .bind(recruiter)
    .fetch_one(&pool)
    .await
    .expect("listing fixture inserted");

    sqlx::query(
        "INSERT INTO applications \
             (applicant_id, job_listing_id, listing_title, listing_company, ap_id, \
              cover_letter_md) \
         VALUES ($1, $2, 'Engineer', 'Acme', 'https://noombat.example/applications/1', \
                 'please hire me')",
    )
    .bind(applicant)
    .bind(listing)
    .execute(&pool)
    .await
    .expect("application fixture inserted");

    let search = Arc::new(RecordingSearch::default());
    let backend: Option<Arc<dyn SearchBackend>> = Some(search.clone());
    noombat_api::erasure::sweep(&pool, &backend, GRACE_DAYS).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The recruiter's content is gone.
    let listings: i64 = sqlx::query_scalar("SELECT count(*) FROM job_listings")
        .fetch_one(&pool)
        .await
        .expect("countable");
    assert_eq!(
        listings, 0,
        "the listing should have been erased with its author"
    );

    // The applicant's record is not.
    let (title, company, orphaned): (String, String, Option<Uuid>) = sqlx::query_as(
        "SELECT listing_title, listing_company, job_listing_id FROM applications \
         WHERE applicant_id = $1",
    )
    .bind(applicant)
    .fetch_one(&pool)
    .await
    .expect("the application must survive the recruiter's erasure");

    assert_eq!(orphaned, None, "the reference is cleared, not cascaded");
    assert_eq!(title, "Engineer", "and the snapshot keeps it legible");
    assert_eq!(company, "Acme");

    assert!(
        search
            .calls
            .lock()
            .expect("not poisoned")
            .contains(&format!("delete jobs {listing}")),
        "the listing must leave the search index too"
    );
}
