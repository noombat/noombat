// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! What `usage.users.activeMonth` and `activeHalfyear` actually count.
//!
//! NodeInfo defines both as the number of users who **signed in** during
//! the window. They were computed from `actors.updated_at`, and
//! `trg_actors_updated_at` is a `BEFORE UPDATE ... FOR EACH ROW` trigger,
//! so that column moves on every write to the row whether or not the
//! statement mentions it. The published figures were therefore "actors
//! whose row was touched recently", and wrong in both directions:
//!
//! - Setting `moved_to`, i.e. the user migrating away to another
//!   instance, marked them active for the next thirty days. So did
//!   requesting deletion, and so did a moderator setting
//!   `chat_requires_reprovisioning`.
//! - A user who signed in every day and posted was never counted,
//!   because posting does not write to `actors` at all.
//!
//! These numbers are published to every peer that polls the endpoint, so
//! the test drives the assembled router rather than the query: what
//! matters is the JSON that leaves the instance.
//!
//! Each case below is chosen to fail against the old implementation. The
//! moderation case is the sharp one: it touches the actor row without
//! anyone signing in, which is exactly what `updated_at` could not tell
//! apart, and it is asserted to count zero.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

// ..... Harness .....

fn test_state(pool: PgPool) -> AppState {
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        http_client: reqwest::Client::new(),
        open_registrations: true,
        admin_token: None,
        // NodeInfo reads counts out of Postgres and never touches the
        // search backend, so there is nothing here to fake.
        search: None,
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: None,
        orcid_config: None,
        chatmail_domain: None,
        chatmail_admin_url: None,
        chatmail_admin_secret: None,
        chatmail_admin_client: None,
        contact_email: format!("admin@{DOMAIN}"),
        trending_cache: None,
        analytics: None,
        relay_verification_policy: None,
        envelope_key: None,
        fallback_rate_limiter: FallbackRateLimiter::new(),
        rate_limit: 100_000,
        rate_limit_window_secs: 60,
        fed_rate_limit: 100_000,
        fed_rate_limit_window_secs: 60,
        cv_download_limit: 100_000,
        cv_download_window_secs: 60,
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
    }
}

/// Insert an actor. `signed_in_days_ago` of `None` means the actor has
/// never signed in, which is what every row looks like immediately after
/// the migration.
async fn insert_actor(
    pool: &PgPool,
    username: &str,
    is_local: bool,
    signed_in_days_ago: Option<i32>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local,
                last_sign_in_at)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', $5,
                   CASE WHEN $6::int IS NULL THEN NULL
                        ELSE now() - ($6::int * interval '1 day') END)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(is_local)
    .bind(signed_in_days_ago)
    .execute(pool)
    .await
    .expect("actor fixture inserted");
    id
}

async fn usage(state: AppState) -> (u64, u64, u64) {
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/nodeinfo/2.1")
                .body(Body::empty())
                .expect("request built"),
        )
        .await
        .expect("router responded");

    assert_eq!(response.status(), StatusCode::OK, "nodeinfo must serve");

    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body read");
    let json: Value = serde_json::from_slice(&bytes).expect("nodeinfo is JSON");
    let users = &json["usage"]["users"];

    (
        users["total"].as_u64().expect("total present"),
        users["activeMonth"].as_u64().expect("activeMonth present"),
        users["activeHalfyear"]
            .as_u64()
            .expect("activeHalfyear present"),
    )
}

// ..... Tests .....

/// The two windows count sign-ins, and only sign-ins.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn active_windows_count_sign_ins(pool: PgPool) {
    // Signed in five days ago: inside both windows.
    insert_actor(&pool, "recent", true, Some(5)).await;
    // Signed in a hundred days ago: inside the half-year window only.
    insert_actor(&pool, "lapsed", true, Some(100)).await;
    // Signed in two years ago: inside neither.
    insert_actor(&pool, "ancient", true, Some(730)).await;
    // Never signed in: inside neither, and not counted as active by the
    // absence of a value.
    insert_actor(&pool, "newcomer", true, None).await;
    // Remote actors are not this instance's users at all.
    insert_actor(&pool, "stranger", false, Some(1)).await;

    let (total, month, half_year) = usage(test_state(pool)).await;

    assert_eq!(total, 4, "total counts local actors only");
    assert_eq!(month, 1, "only the actor who signed in five days ago");
    assert_eq!(
        half_year, 2,
        "the five-day and hundred-day actors, not the two-year one"
    );
}

/// Touching an actor's row is not a sign-in.
///
/// This is the case the old implementation could not express. Each write
/// below fires `trg_actors_updated_at`, so under `updated_at` all three
/// actors counted as active this month; two of them are leaving the
/// instance and the third was acted on by a moderator.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_touched_row_is_not_an_active_user(pool: PgPool) {
    let migrating = insert_actor(&pool, "migrating", true, None).await;
    let leaving = insert_actor(&pool, "leaving", true, None).await;
    let flagged = insert_actor(&pool, "flagged", true, None).await;

    // The user has migrated away to another instance.
    sqlx::query("UPDATE actors SET moved_to = $1 WHERE id = $2")
        .bind("https://elsewhere.example/users/migrating")
        .bind(migrating)
        .execute(&pool)
        .await
        .expect("move recorded");

    // The user has asked for their account to be deleted.
    sqlx::query("UPDATE actors SET deletion_requested_at = now() WHERE id = $1")
        .bind(leaving)
        .execute(&pool)
        .await
        .expect("deletion requested");

    // A moderator flagged the account for chat reprovisioning.
    sqlx::query("UPDATE actors SET chat_requires_reprovisioning = TRUE WHERE id = $1")
        .bind(flagged)
        .execute(&pool)
        .await
        .expect("flag set");

    // The trigger must have fired, or this test proves nothing: it would
    // pass on the old code too, simply because nothing moved.
    let touched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM actors WHERE updated_at > now() - interval '1 minute'",
    )
    .fetch_one(&pool)
    .await
    .expect("updated_at readable");
    assert_eq!(
        touched, 3,
        "all three rows must have a fresh updated_at, otherwise this test is vacuous"
    );

    let (total, month, half_year) = usage(test_state(pool)).await;

    assert_eq!(total, 3);
    assert_eq!(
        month, 0,
        "migrating away, requesting deletion and being flagged by a moderator \
         are not sign-ins"
    );
    assert_eq!(
        half_year, 0,
        "and they are not sign-ins over six months either"
    );
}

/// Insert an actor whose row has not been written for `updated_days_ago`
/// but who signed in `signed_in_days_ago`.
///
/// Both timestamps are set in the INSERT, and that is the whole point.
/// `trg_actors_updated_at` is a `BEFORE UPDATE` trigger, so it overwrites
/// any `updated_at` an UPDATE supplies with `now()`, and a row cannot be
/// backdated after the fact. The first version of the test below tried,
/// which left `updated_at` at `now()` and made the test pass against the
/// defect it exists to catch. An INSERT does not fire the trigger.
async fn insert_quiet_actor(
    pool: &PgPool,
    username: &str,
    updated_days_ago: i32,
    signed_in_days_ago: i32,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local,
                created_at, updated_at, last_sign_in_at)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE,
                   now() - ($5::int * interval '1 day'),
                   now() - ($5::int * interval '1 day'),
                   now() - ($6::int * interval '1 day'))"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(updated_days_ago)
    .bind(signed_in_days_ago)
    .execute(pool)
    .await
    .expect("quiet actor fixture inserted");
    id
}

/// A signed-in user stays counted when their row is never written again.
///
/// The mirror of the case above: posting, following and reading do not
/// touch `actors`, so under `updated_at` a user who signed in throughout
/// fell out of the window after thirty quiet days.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_sign_in_counts_without_any_other_row_change(pool: PgPool) {
    let actor = insert_quiet_actor(&pool, "quiet", 400, 2).await;

    // Guard the premise: if the row's own bookkeeping is not actually
    // stale, both implementations agree and this proves nothing.
    let stale: bool = sqlx::query_scalar(
        "SELECT updated_at < now() - interval '365 days' FROM actors WHERE id = $1",
    )
    .bind(actor)
    .fetch_one(&pool)
    .await
    .expect("updated_at readable");
    assert!(
        stale,
        "updated_at was not backdated, so this test cannot tell the two \
         implementations apart"
    );

    let (_, month, half_year) = usage(test_state(pool)).await;

    assert_eq!(month, 1, "a sign-in two days ago is active this month");
    assert_eq!(half_year, 1, "and active this half-year");
}

/// Creating a session records the sign-in; refreshing one does not.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn only_a_sign_in_records_a_sign_in(pool: PgPool) {
    use noombat_identity::session::{SessionConfig, SessionContext, create_session};

    let config = SessionConfig {
        jwt_secret: "test-secret-that-is-at-least-32-bytes-long".to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    };

    let actor = insert_actor(&pool, "returning", true, None).await;

    let before: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_sign_in_at FROM actors WHERE id = $1")
            .bind(actor)
            .fetch_one(&pool)
            .await
            .expect("column readable");
    assert!(before.is_none(), "the fixture has never signed in");

    let tokens = create_session(
        &pool,
        &config,
        actor,
        "returning",
        noombat_core::actor::InstanceRole::User,
        SessionContext::sign_in(),
    )
    .await
    .expect("session created");

    let after_sign_in: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_sign_in_at FROM actors WHERE id = $1")
            .bind(actor)
            .fetch_one(&pool)
            .await
            .expect("column readable");
    let recorded = after_sign_in.expect("signing in records the time");

    // Rotating the refresh token must not move it. A background tab can
    // do this for the whole refresh lifetime with nobody present.
    tokio::time::sleep(Duration::from_millis(20)).await;
    noombat_identity::session::refresh_session(&pool, &config, &tokens.refresh_token)
        .await
        .expect("session refreshed");

    let after_refresh: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_sign_in_at FROM actors WHERE id = $1")
            .bind(actor)
            .fetch_one(&pool)
            .await
            .expect("column readable");

    assert_eq!(
        after_refresh,
        Some(recorded),
        "refreshing a token is not signing in and must leave last_sign_in_at alone"
    );
}
