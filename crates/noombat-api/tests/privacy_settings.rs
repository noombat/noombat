// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The privacy settings write path, through the assembled router.
//!
//! Before this existed, every part of the chain was present and none of
//! it connected: a settings page with a real form, a domain model that
//! reads seven flags, a repository function to persist them, and no
//! route in between. The form posted at the admin JSON API, which would
//! have rejected it three separate ways. So these drive the whole stack
//! rather than the handler, because "the pieces exist" was already true.
//!
//! Two properties are asserted that a simpler test would miss.
//!
//! An unchecked HTML checkbox submits *nothing*. A form body carrying
//! only the boxes that are ticked must therefore clear the rest, and a
//! naive `Form<T>` would instead fail to deserialise. Turning a setting
//! off is the case that matters here, so it is the case that is tested.
//!
//! Turning `discoverable` off has to *remove* an already-indexed
//! profile. `index_profile` honours the flag by declining to index,
//! which does nothing about a document already there, so the control
//! would look right and leave the user searchable. The search backend
//! is a recording fake for exactly this reason: with `search: None`
//! both branches are silent no-ops and the assertion would be vacuous.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::error::Result;
use noombat_core::extension::SearchBackend;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::session::SessionConfig;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const USERNAME: &str = "alice";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

// ..... Recording search backend .....

#[derive(Default)]
struct RecordingSearch {
    calls: Mutex<Vec<String>>,
}

impl RecordingSearch {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("not poisoned").clone()
    }
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

// ..... Fixtures .....

fn session_config() -> SessionConfig {
    SessionConfig {
        jwt_secret: JWT_SECRET.to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    }
}

fn test_state(pool: PgPool, search: Arc<dyn SearchBackend>) -> AppState {
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        http_client: reqwest::Client::new(),
        open_registrations: true,
        search: Some(search),
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: Some(session_config()),
        orcid_config: None,
        mailer: None,
        chatmail_domain: None,
        chatmail_admin_url: None,
        chatmail_admin_client: None,
        contact_email: format!("admin@{DOMAIN}"),
        trending_cache: None,
        analytics: None,
        fallback_rate_limiter: FallbackRateLimiter::new(),
        rate_limit: 100_000,
        rate_limit_window_secs: 60,
        fed_rate_limit: 100_000,
        fed_rate_limit_window_secs: 60,
        cv_download_limit: 100_000,
        cv_download_window_secs: 60,
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
        // A per-test directory: these tests never serve media, and a
        // shared path would let one test's objects outlive it.
        media: noombat_api::media::MediaStore::local(
            std::env::temp_dir().join(format!("noombat-test-media-{}", uuid::Uuid::new_v4())),
        )
        .expect("temp media root"),
    }
}

async fn insert_actor(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem, is_local)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{USERNAME}"))
    .bind(USERNAME)
    .bind(DOMAIN)
    .execute(pool)
    .await
    .expect("actor fixture inserted");
    id
}

async fn access_token(pool: &PgPool, actor_id: Uuid) -> String {
    noombat_identity::session::create_session(
        pool,
        &session_config(),
        actor_id,
        USERNAME,
        noombat_core::actor::InstanceRole::User,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await
    .expect("session created")
    .access_token
}

/// `POST /settings/privacy`, optionally signed in.
async fn post_privacy(state: AppState, token: Option<&str>, body: &'static str) -> StatusCode {
    let mut request = Request::builder()
        .method("POST")
        .uri("/settings/privacy")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");

    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    build_router(state)
        .oneshot(request.body(Body::from(body)).expect("request"))
        .await
        .expect("the router is infallible")
        .status()
}

async fn stored_privacy(pool: &PgPool, actor_id: Uuid) -> Value {
    sqlx::query_scalar("SELECT actor_privacy FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_one(pool)
        .await
        .expect("privacy column readable")
}

// ..... Tests .....

/// The defaults are all permissive, so the interesting direction is off.
///
/// This body ticks nothing at all, which is what a browser sends when a
/// user clears every box.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn clearing_every_toggle_persists_every_false(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = access_token(&pool, actor_id).await;
    let search = Arc::new(RecordingSearch::default());

    let status = post_privacy(
        test_state(pool.clone(), search.clone()),
        Some(&token),
        "cv_download=self",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "the form should have saved");

    let privacy = stored_privacy(&pool, actor_id).await;
    for flag in [
        "discoverable",
        "indexable",
        "federate_profile",
        "require_follow_approval",
        "show_followers_count",
        "chatmail_visible",
    ] {
        assert_eq!(
            privacy[flag],
            Value::Bool(false),
            "{flag} should be false, got {privacy}"
        );
    }
    assert_eq!(privacy["cv_download"], "self", "{privacy}");
}

/// Ticked boxes arrive as `true` and are stored as such.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn ticked_toggles_persist_true(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = access_token(&pool, actor_id).await;
    let search = Arc::new(RecordingSearch::default());

    let status = post_privacy(
        test_state(pool.clone(), search),
        Some(&token),
        "discoverable=true&indexable=true&cv_download=followers",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let privacy = stored_privacy(&pool, actor_id).await;
    assert_eq!(privacy["discoverable"], Value::Bool(true), "{privacy}");
    assert_eq!(privacy["indexable"], Value::Bool(true), "{privacy}");
    assert_eq!(
        privacy["federate_profile"],
        Value::Bool(false),
        "an unticked box must clear, not preserve: {privacy}"
    );
    assert_eq!(privacy["cv_download"], "followers", "{privacy}");
}

/// Turning discoverability off removes the profile from the index.
///
/// The assertion that would pass without the fix is "the setting was
/// saved". This one is about the consequence.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn going_undiscoverable_deletes_the_indexed_document(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = access_token(&pool, actor_id).await;
    let search = Arc::new(RecordingSearch::default());

    let status = post_privacy(
        test_state(pool.clone(), search.clone()),
        Some(&token),
        "indexable=true",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The delete is spawned, so allow the task to run.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let calls = search.calls();
    assert!(
        calls
            .iter()
            .any(|c| c == &format!("delete profiles {actor_id}")),
        "expected the profile to be removed from the index, saw {calls:?}"
    );
}

/// And turning it back on re-indexes rather than waiting for an edit.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn becoming_discoverable_reindexes(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let token = access_token(&pool, actor_id).await;
    let search = Arc::new(RecordingSearch::default());

    let status = post_privacy(
        test_state(pool.clone(), search.clone()),
        Some(&token),
        "discoverable=true",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let calls = search.calls();
    assert!(
        calls.iter().any(|c| c.starts_with("upsert profiles")),
        "expected the profile to be re-indexed, saw {calls:?}"
    );
}

/// No session, no write.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_anonymous_post_changes_nothing(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let search = Arc::new(RecordingSearch::default());
    let before = stored_privacy(&pool, actor_id).await;

    let status = post_privacy(test_state(pool.clone(), search), None, "cv_download=self").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        stored_privacy(&pool, actor_id).await,
        before,
        "an unauthenticated post must not alter anyone's settings"
    );
}

// Known defect: the column default is not conservative; remove `should_panic` once it is. No
// account gets it today, since every creation path writes `ActorPrivacy::default()` itself.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: the column default is not conservative")]
async fn the_column_default_is_conservative(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let stored = stored_privacy(&pool, actor_id).await;
    let parsed = serde_json::from_value::<noombat_core::privacy::ActorPrivacy>(stored.clone())
        .expect("the stored settings read back through ActorPrivacy");

    // The column as stored, not after serde: a key the column left out
    // would be filled in by the Rust default and hide the disagreement.
    let conservative = serde_json::json!({
        "discoverable": true,
        "indexable": false,
        "require_follow_approval": false,
        "federate_profile": false,
        "chatmail_visible": true,
        "show_followers_count": true,
        "list_in_directory": false,
        "cv_download": "public",
    });
    assert_eq!(
        stored, conservative,
        "known defect: the column default is not conservative"
    );
    assert_eq!(
        serde_json::to_value(parsed).expect("ActorPrivacy serialises"),
        conservative,
        "the stored settings must read back unchanged through ActorPrivacy"
    );
}

// Known defect: career sections default to public; remove `should_panic` once they default to
// followers.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: sections default to public")]
async fn a_section_added_without_a_visibility_is_followers_only(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;

    for insert in [
        "INSERT INTO work_experiences (actor_id, title, organization, start_date, ap_object) \
         VALUES ($1, 'Research engineer', 'Example Labs', '2018-01-15', '{}')",
        "INSERT INTO education_entries (actor_id, institution, start_date, ap_object) \
         VALUES ($1, 'University of Example', '2015-09-01', '{}')",
        "INSERT INTO skills (actor_id, name) VALUES ($1, 'Distributed systems')",
        "INSERT INTO verified_links (actor_id, url) VALUES ($1, 'https://alice.example/')",
        "INSERT INTO scholarly_articles \
             (actor_id, doi, title, authors, doi_metadata, fetched_at, ap_object) \
         VALUES ($1, '10.1000/xyz123', 'A paper', '[]', '{}', now(), '{}')",
        "INSERT INTO custom_profile_sections (actor_id, section_type, title, ap_object) \
         VALUES ($1, 'awards', 'Awards', '{}')",
    ] {
        sqlx::query(insert)
            .bind(actor_id)
            .execute(&pool)
            .await
            .expect("section fixture inserted");
    }

    let visibilities: Vec<String> = sqlx::query_scalar(
        "SELECT visibility FROM work_experiences WHERE actor_id = $1 \
         UNION ALL SELECT visibility FROM education_entries WHERE actor_id = $1 \
         UNION ALL SELECT visibility FROM skills WHERE actor_id = $1 \
         UNION ALL SELECT visibility FROM verified_links WHERE actor_id = $1 \
         UNION ALL SELECT visibility FROM scholarly_articles WHERE actor_id = $1 \
         UNION ALL SELECT visibility FROM custom_profile_sections WHERE actor_id = $1",
    )
    .bind(actor_id)
    .fetch_all(&pool)
    .await
    .expect("section visibilities readable");

    assert_eq!(
        visibilities,
        vec!["followers"; 6],
        "known defect: sections default to public"
    );
}

async fn visibility_of(pool: &PgPool, table: &str, actor_id: Uuid) -> String {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT visibility FROM {table} WHERE actor_id = $1"
    )))
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{table} readable: {e}"))
}

// The pages add sections through the profile functions, so a default kept only in the column
// would never apply to them.

// Known defect: the function falls back to public; remove `should_panic` once it defaults to
// followers.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: an experience added without a visibility is public")]
async fn an_experience_added_without_a_visibility_is_followers_only(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let experience: noombat_identity::profile::NewWorkExperience =
        serde_json::from_value(serde_json::json!({
            "title": "Research engineer",
            "organization": "Example Labs",
            "start_date": "2018-01-15",
        }))
        .expect("experience parameters");
    noombat_identity::profile::create_work_experience(&pool, actor_id, &experience)
        .await
        .expect("experience added");

    assert_eq!(
        visibility_of(&pool, "work_experiences", actor_id).await,
        "followers",
        "known defect: an experience added without a visibility is public"
    );
}

// Known defect: the function falls back to public; remove `should_panic` once it defaults to
// followers.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: an education entry added without a visibility is public")]
async fn an_education_entry_added_without_a_visibility_is_followers_only(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let education: noombat_identity::profile::NewEducationEntry =
        serde_json::from_value(serde_json::json!({
            "institution": "University of Example",
            "start_date": "2015-09-01",
        }))
        .expect("education parameters");
    noombat_identity::profile::create_education_entry(&pool, actor_id, &education)
        .await
        .expect("education added");

    assert_eq!(
        visibility_of(&pool, "education_entries", actor_id).await,
        "followers",
        "known defect: an education entry added without a visibility is public"
    );
}

// Known defect: the function falls back to public; remove `should_panic` once it defaults to
// followers. It also admits only public and private, so the fix widens that check too.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: a skill added without a visibility is public")]
async fn a_skill_added_without_a_visibility_is_followers_only(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    noombat_identity::profile::add_skill(&pool, actor_id, "Distributed systems", None)
        .await
        .expect("skill added");

    assert_eq!(
        visibility_of(&pool, "skills", actor_id).await,
        "followers",
        "known defect: a skill added without a visibility is public"
    );
}

/// `GET /settings/privacy` as the owner sees it.
async fn privacy_page(pool: &PgPool, actor_id: Uuid) -> String {
    let token = access_token(pool, actor_id).await;
    let response = build_router(test_state(
        pool.clone(),
        Arc::new(RecordingSearch::default()),
    ))
    .oneshot(
        Request::builder()
            .uri("/settings/privacy")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("page request"),
    )
    .await
    .expect("the router is infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the privacy page must serve its owner"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("page body read");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Whether the page's checkbox for `name` is ticked.
fn ticked(page: &str, name: &str) -> bool {
    let start = page
        .find(&format!("name=\"{name}\""))
        .unwrap_or_else(|| panic!("the privacy page has no {name} checkbox"));
    let end = start + page[start..].find('>').expect("the input tag closes");
    page[start..end].contains("checked")
}

// Known defect: the page falls back to on for unset indexable and federate_profile; remove
// `should_panic` once it falls back to off.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: the privacy page ticks unset indexable and federate_profile"
)]
async fn the_privacy_page_shows_conservative_defaults_for_unset_flags(pool: PgPool) {
    // Saving the page as shown writes what it shows, so a ticked box here
    // would turn a flag on that the stored settings leave unset.
    let actor_id = insert_actor(&pool).await;
    sqlx::query("UPDATE actors SET actor_privacy = '{}' WHERE id = $1")
        .bind(actor_id)
        .execute(&pool)
        .await
        .expect("settings cleared");

    let page = privacy_page(&pool, actor_id).await;

    assert!(
        !ticked(&page, "indexable") && !ticked(&page, "federate_profile"),
        "known defect: the privacy page ticks unset indexable and federate_profile"
    );
}

// Known defect: the page's publications query names a column the table lacks, and the error is
// dropped; remove `should_panic` once fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: the privacy page leaves publications out")]
async fn the_privacy_page_lists_a_publication(pool: PgPool) {
    let actor_id = insert_actor(&pool).await;
    let experience: Uuid = sqlx::query_scalar(
        "INSERT INTO work_experiences (actor_id, title, organization, start_date, ap_object) \
         VALUES ($1, 'Research engineer', 'Example Labs', '2018-01-15', '{}') RETURNING id",
    )
    .bind(actor_id)
    .fetch_one(&pool)
    .await
    .expect("experience fixture");
    let publication: Uuid = sqlx::query_scalar(
        "INSERT INTO scholarly_articles \
             (actor_id, doi, title, authors, doi_metadata, fetched_at, ap_object) \
         VALUES ($1, '10.1000/xyz123', 'A paper', '[]', '{}', now(), '{}') RETURNING id",
    )
    .bind(actor_id)
    .fetch_one(&pool)
    .await
    .expect("publication fixture");

    let page = privacy_page(&pool, actor_id).await;

    assert!(
        page.contains(&format!("/api/v1/sections/{experience}/visibility")),
        "the page lists no section at all, so the check below tests nothing"
    );
    assert!(
        page.contains(&format!("/api/v1/sections/{publication}/visibility")),
        "known defect: the privacy page leaves publications out"
    );
}
