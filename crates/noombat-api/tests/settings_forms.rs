// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The settings pages' forms, sent exactly as a browser sends them.
//!
//! Every one of these pages submits through htmx, which encodes the form
//! as `application/x-www-form-urlencoded` (each name and value through
//! `encodeURIComponent`, empty fields included) and authenticates with
//! the session cookie. A handler that extracts `Json` refuses that
//! request with 415 before it runs, so these send the form body and not
//! the JSON an API client would.
//!
//! The HTTP client cannot reach the network: it is pointed at a proxy on
//! a closed loopback port, so a handler that looks something up (a DOI,
//! a rel="me" page) fails fast rather than depending on the internet.

use std::time::Duration;

use axum::body::Body;
use axum::extract::FromRequest;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse;
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use noombat_identity::session::SessionConfig;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const USERNAME: &str = "alice";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";

// ..... Fixtures .....

fn session_config() -> SessionConfig {
    SessionConfig {
        jwt_secret: JWT_SECRET.to_owned(),
        domain: DOMAIN.to_owned(),
        access_ttl_secs: 900,
        refresh_ttl_secs: 2_592_000,
    }
}

fn offline_client() -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all("http://127.0.0.1:9").expect("proxy URL parses"))
        .timeout(Duration::from_secs(2))
        .build()
        .expect("offline client builds")
}

fn test_state(pool: PgPool) -> AppState {
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        http_client: offline_client(),
        open_registrations: true,
        search: None,
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
        media: noombat_api::media::MediaStore::local(std::env::temp_dir())
            .expect("a local media store over the temp dir"),
        deletion_grace_days: 30,
        allow_unsigned_fetch: false,
    }
}

async fn insert_person(pool: &PgPool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{USERNAME}"))
    .bind(USERNAME)
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("person fixture")
}

/// The `Cookie` header a signed-in page carries.
async fn session_cookie(pool: &PgPool, actor_id: Uuid) -> String {
    let token = noombat_identity::session::create_session(
        pool,
        &session_config(),
        actor_id,
        USERNAME,
        noombat_core::actor::InstanceRole::User,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await
    .expect("session created")
    .access_token;
    format!("{}={token}", noombat_api::cookie::COOKIE_NAME)
}

/// One htmx form submission through the assembled router.
async fn submit(
    pool: &PgPool,
    method: &str,
    uri: &str,
    cookie: &str,
    body: &'static str,
) -> StatusCode {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, cookie)
        .header("hx-request", "true")
        .body(Body::from(body))
        .expect("request builds");

    build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

/// A request through the assembled router, and its answer: the status,
/// the content type and the body.
async fn answer(
    pool: &PgPool,
    uri: &str,
    cookie: &str,
    content_type: &str,
    body: &'static str,
) -> (StatusCode, String, String) {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, content_type)
                .header(header::COOKIE, cookie)
                .body(Body::from(body))
                .expect("request builds"),
        )
        .await
        .expect("the router is infallible");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("answer body read");
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// A settings page as its owner's browser loads it.
async fn page_html(pool: &PgPool, cookie: &str, page: &str) -> String {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .uri(page)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("page request builds"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{page} must serve its owner"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("page body read");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// What `axum::Form` makes of a body, which is what a handler that
/// accepts the form is given.
async fn form_of<T: serde::de::DeserializeOwned>(body: &'static str) -> Result<T, StatusCode> {
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("request builds");

    axum::Form::<T>::from_request(request, &())
        .await
        .map(|axum::Form(value)| value)
        .map_err(|rejection| rejection.into_response().status())
}

/// The settings page must still carry the form a test replays: its target
/// and every field the test sends. A form moved to another route would
/// otherwise leave the test replaying a request no page sends.
async fn page_carries_form(pool: &PgPool, cookie: &str, page: &str, target: &str, fields: &[&str]) {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .uri(page)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .expect("page request builds"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{page} must serve its owner"
    );
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("page body read");
    let html = String::from_utf8_lossy(&bytes);
    assert!(
        html.contains(target),
        "{page} no longer renders the form this test replays ({target})"
    );
    for field in fields {
        assert!(
            html.contains(&format!("name=\"{field}\"")),
            "{page} no longer renders the field {field} this test sends"
        );
    }
}

// ..... Profile .....

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_edit_profile_form_saves_every_field(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/profile",
        &format!("hx-patch=\"/users/{USERNAME}\""),
        &["display_name", "headline", "location", "summary_md"],
    )
    .await;

    let status = submit(
        &pool,
        "PATCH",
        &format!("/users/{USERNAME}"),
        &cookie,
        "display_name=Alice%20Example&headline=Research%20engineer\
         &location=Berlin%2C%20Germany&summary_md=Works%20on%20*federated*%20systems.",
    )
    .await;

    let saved: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT display_name, headline, location, summary_md FROM actors WHERE id = $1",
    )
    .bind(alice)
    .fetch_one(&pool)
    .await
    .expect("profile readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the edit-profile form is refused"
    );
    assert_eq!(
        (status, saved),
        (
            StatusCode::OK,
            (
                Some("Alice Example".to_owned()),
                Some("Research engineer".to_owned()),
                Some("Berlin, Germany".to_owned()),
                Some("Works on *federated* systems.".to_owned()),
            )
        ),
        "the edit-profile form must save what it sends"
    );
}

// ..... Profile sections .....

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_add_skill_form_saves_the_skill(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/skills",
        &format!("hx-post=\"/users/{USERNAME}/skills\""),
        &["name"],
    )
    .await;

    let status = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/skills"),
        &cookie,
        "name=Distributed%20systems",
    )
    .await;

    let saved: Vec<String> = sqlx::query_scalar("SELECT name FROM skills WHERE actor_id = $1")
        .bind(alice)
        .fetch_all(&pool)
        .await
        .expect("skills readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the add-skill form is refused"
    );
    assert_eq!(
        (status, saved),
        (StatusCode::CREATED, vec!["Distributed systems".to_owned()]),
        "the add-skill form must save what it sends"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_education_form_saves_the_entry(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/education",
        &format!("hx-post=\"/users/{USERNAME}/educations\""),
        &[
            "institution",
            "degree",
            "field_of_study",
            "start_date",
            "end_date",
            "visibility",
        ],
    )
    .await;

    // A finished degree, so the end date is filled; an empty one is
    // covered below.
    let status = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/educations"),
        &cookie,
        "institution=University%20of%20Example&degree=MSc&field_of_study=Computer%20Science\
         &start_date=2015-09-01&end_date=2017-06-30&visibility=public",
    )
    .await;

    let saved: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object( \
             'institution', institution, 'degree', degree, 'field_of_study', field_of_study, \
             'start_date', start_date, 'end_date', end_date, 'visibility', visibility) \
         FROM education_entries WHERE actor_id = $1",
    )
    .bind(alice)
    .fetch_all(&pool)
    .await
    .expect("education entries readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the education form is refused"
    );
    assert_eq!(
        (status, saved),
        (
            StatusCode::CREATED,
            vec![serde_json::json!({
                "institution": "University of Example",
                "degree": "MSc",
                "field_of_study": "Computer Science",
                "start_date": "2015-09-01",
                "end_date": "2017-06-30",
                "visibility": "public",
            })]
        ),
        "the education form must save what it sends"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_experience_form_saves_the_entry(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/experience",
        &format!("hx-post=\"/users/{USERNAME}/experiences\""),
        &[
            "title",
            "organization",
            "start_date",
            "end_date",
            "description_md",
            "visibility",
        ],
    )
    .await;

    // A past position, so the end date is filled; an empty one is
    // covered below.
    let status = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/experiences"),
        &cookie,
        "title=Research%20engineer&organization=Example%20Labs&start_date=2018-01-15\
         &end_date=2022-12-31&description_md=Built%20*things*.&visibility=public",
    )
    .await;

    let saved: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object( \
             'title', title, 'organization', organization, 'start_date', start_date, \
             'end_date', end_date, 'description_md', description_md, 'visibility', visibility) \
         FROM work_experiences WHERE actor_id = $1",
    )
    .bind(alice)
    .fetch_all(&pool)
    .await
    .expect("work experiences readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the experience form is refused"
    );
    assert_eq!(
        (status, saved),
        (
            StatusCode::CREATED,
            vec![serde_json::json!({
                "title": "Research engineer",
                "organization": "Example Labs",
                "start_date": "2018-01-15",
                "end_date": "2022-12-31",
                "description_md": "Built *things*.",
                "visibility": "public",
            })]
        ),
        "the experience form must save what it sends"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_publication_form_is_accepted(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;

    page_carries_form(
        &pool,
        &cookie,
        "/settings/publications",
        &format!("hx-post=\"/users/{USERNAME}/publications\""),
        &["doi", "visibility"],
    )
    .await;

    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/users/{USERNAME}/publications"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, cookie.as_str())
                .header("hx-request", "true")
                .body(Body::from("doi=10.1000%2Fxyz123&visibility=public"))
                .expect("request builds"),
        )
        .await
        .expect("the router is infallible");
    let status = response.status();
    let plain_text = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));

    // The form sends a bare DOI, so an accepted body goes on to a CrossRef
    // and DataCite lookup, which the offline client fails. Only the
    // extractor's own refusals, answered in plain text, say the body itself
    // was refused; a handler that maps a failed lookup to 400 or 422 is not
    // this fault.
    let refused_by_extractor = status == StatusCode::UNSUPPORTED_MEDIA_TYPE
        || (plain_text
            && (status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY));
    assert!(
        !refused_by_extractor,
        "the publication form is refused, got {status}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_add_link_form_saves_the_link(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/links",
        &format!("hx-post=\"/users/{USERNAME}/links\""),
        &["url"],
    )
    .await;

    // The rel="me" check runs in the background after the row is written,
    // and fails here without a network; it is not asserted.
    let status = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/links"),
        &cookie,
        "url=https%3A%2F%2Falice.example%2F",
    )
    .await;

    let saved: Vec<String> =
        sqlx::query_scalar("SELECT url FROM verified_links WHERE actor_id = $1")
            .bind(alice)
            .fetch_all(&pool)
            .await
            .expect("links readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the add-link form is refused"
    );
    assert_eq!(
        (status, saved),
        (
            StatusCode::CREATED,
            vec!["https://alice.example/".to_owned()]
        ),
        "the add-link form must save what it sends"
    );
}

/// The skills page appends the form's answer to its list, so a form is
/// answered with the item exactly as the page lists it, its markup
/// escaped, and an API client sending JSON is answered with the skill
/// as JSON.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_add_skill_form_is_answered_with_the_item_the_page_lists(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    let uri = format!("/users/{USERNAME}/skills");

    let (status, content_type, item) = answer(
        &pool,
        &uri,
        &cookie,
        "application/x-www-form-urlencoded",
        "name=Rust%20%26%20%3CWebAssembly%3E",
    )
    .await;
    let page = page_html(&pool, &cookie, "/settings/skills").await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the add-skill form failed: {item}"
    );
    assert!(
        content_type.starts_with("text/html"),
        "the add-skill form was answered with {content_type}: {item}"
    );
    let item = item.trim();
    assert!(
        item.starts_with("<span")
            && item.contains("WebAssembly")
            && !item.contains("<WebAssembly>"),
        "the answer is not the skill's item, escaped: {item}"
    );
    assert!(
        page.contains(item),
        "the answer is not the item the page lists: {item}"
    );

    let (status, content_type, json) = answer(
        &pool,
        &uri,
        &cookie,
        "application/json",
        r#"{"name":"Type theory"}"#,
    )
    .await;
    assert_eq!(
        (status, content_type.starts_with("application/json")),
        (StatusCode::CREATED, true),
        "an API client must get JSON: {content_type} {json}"
    );
    let skill: serde_json::Value = serde_json::from_str(&json).expect("a JSON skill");
    assert_eq!(skill["name"], "Type theory");
}

/// The links page appends the form's answer to its list, so a form is
/// answered with the item exactly as the page lists it, while an API
/// client sending JSON is answered with the link as JSON.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_add_link_form_is_answered_with_the_item_the_page_lists(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    let uri = format!("/users/{USERNAME}/links");

    let (status, content_type, item) = answer(
        &pool,
        &uri,
        &cookie,
        "application/x-www-form-urlencoded",
        "url=https%3A%2F%2Falice.example%2F",
    )
    .await;
    let page = page_html(&pool, &cookie, "/settings/links").await;

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the add-link form failed: {item}"
    );
    assert!(
        content_type.starts_with("text/html"),
        "the add-link form was answered with {content_type}: {item}"
    );
    let item = item.trim();
    assert!(
        item.starts_with("<li") && item.contains("https://alice.example/"),
        "the answer is not the link's item: {item}"
    );
    assert!(
        page.contains(item),
        "the answer is not the item the page lists: {item}"
    );

    let (status, content_type, json) = answer(
        &pool,
        &uri,
        &cookie,
        "application/json",
        r#"{"url":"https://alice.example/cv"}"#,
    )
    .await;
    assert_eq!(
        (status, content_type.starts_with("application/json")),
        (StatusCode::CREATED, true),
        "an API client must get JSON: {content_type} {json}"
    );
    let link: serde_json::Value = serde_json::from_str(&json).expect("a JSON link");
    assert_eq!(link["url"], "https://alice.example/cv");
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_section_visibility_control_changes_the_section(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;

    // One row of every kind: the control tries the section tables in turn,
    // so a fix to the first name alone would pass a test of the first kind.
    let inserts = [
        (
            "work_experiences",
            "INSERT INTO work_experiences (actor_id, title, organization, start_date, ap_object) \
             VALUES ($1, 'Research engineer', 'Example Labs', '2018-01-15', '{}') RETURNING id",
        ),
        (
            "education_entries",
            "INSERT INTO education_entries (actor_id, institution, start_date, ap_object) \
             VALUES ($1, 'University of Example', '2015-09-01', '{}') RETURNING id",
        ),
        (
            "scholarly_articles",
            "INSERT INTO scholarly_articles \
                 (actor_id, doi, title, authors, doi_metadata, fetched_at, ap_object) \
             VALUES ($1, '10.1000/xyz123', 'A paper', '[]', '{}', now(), '{}') RETURNING id",
        ),
        (
            "verified_links",
            "INSERT INTO verified_links (actor_id, url) \
             VALUES ($1, 'https://alice.example/') RETURNING id",
        ),
        (
            "skills",
            "INSERT INTO skills (actor_id, name) VALUES ($1, 'Distributed systems') RETURNING id",
        ),
        (
            "custom_profile_sections",
            "INSERT INTO custom_profile_sections (actor_id, section_type, title, ap_object) \
             VALUES ($1, 'awards', 'Awards', '{}') RETURNING id",
        ),
    ];

    let mut results = Vec::new();
    for (table, insert) in inserts {
        let section: Uuid = sqlx::query_scalar(insert)
            .bind(alice)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("{table} fixture: {e}"));
        let status = submit(
            &pool,
            "PATCH",
            &format!("/api/v1/sections/{section}/visibility"),
            &cookie,
            "visibility=followers",
        )
        .await;
        let visibility: String = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT visibility FROM {table} WHERE id = $1"
        )))
        .bind(section)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("{table} readable: {e}"));
        results.push((table, status, visibility));
    }

    assert!(
        results
            .iter()
            .all(|(_, status, _)| !status.is_server_error()),
        "the section visibility control fails: {results:?}"
    );
    for (table, status, visibility) in results {
        assert_eq!(
            (status, visibility.as_str()),
            (StatusCode::NO_CONTENT, "followers"),
            "the control must change a row of {table}"
        );
    }
}

/// Hiding a section on the privacy page, and showing it again, reaches
/// the followers, whose copy of the profile lists the sections shown.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn a_section_hidden_on_the_privacy_page_leaves_the_followers_copy(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    // A profile withheld from federation carries no sections at all.
    sqlx::query(
        "UPDATE actors SET actor_privacy = actor_privacy || '{\"federate_profile\": true}' \
         WHERE id = $1",
    )
    .bind(alice)
    .execute(&pool)
    .await
    .expect("privacy fixture");
    let follower: Uuid = sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             inbox_url) \
         VALUES ('individual', 'https://peer.example/users/bob', 'bob', 'peer.example', 'KEY', \
                 FALSE, 'https://peer.example/users/bob/inbox') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("remote follower fixture");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(follower)
        .bind(alice)
        .execute(&pool)
        .await
        .expect("follow fixture");
    let mut sections = Vec::new();
    for organization in ["Hidden Labs", "Shown Labs"] {
        let section: Uuid = sqlx::query_scalar(
            "INSERT INTO work_experiences \
                 (actor_id, title, organization, start_date, visibility, ap_object) \
             VALUES ($1, 'Research engineer', $2, '2018-01-15', 'public', '{}') RETURNING id",
        )
        .bind(alice)
        .bind(organization)
        .fetch_one(&pool)
        .await
        .expect("experience fixture");
        sections.push(section);
    }
    let hidden = sections[0];
    page_carries_form(
        &pool,
        &cookie,
        "/settings/privacy",
        &format!("hx-patch=\"/api/v1/sections/{hidden}/visibility\""),
        &["visibility"],
    )
    .await;

    // The follower's queued Update replaces the one before it, so the
    // queue holds the profile as the last change left it.
    for (visibility, hidden_listed) in [("visibility=private", false), ("visibility=public", true)]
    {
        let status = submit(
            &pool,
            "PATCH",
            &format!("/api/v1/sections/{hidden}/visibility"),
            &cookie,
            visibility,
        )
        .await;
        let updates: Vec<String> = sqlx::query_scalar(
            "SELECT payload::text FROM delivery_queue \
             WHERE target_inbox = 'https://peer.example/users/bob/inbox' \
               AND payload->>'type' = 'Update'",
        )
        .fetch_all(&pool)
        .await
        .expect("delivery queue readable");
        assert_eq!(status, StatusCode::NO_CONTENT, "the control failed");
        assert_eq!(
            updates.len(),
            1,
            "the follower must be sent the profile as {visibility} left it"
        );
        let listed = |organization| updates[0].contains(organization);
        assert!(
            listed("Shown Labs") && listed("Hidden Labs") == hidden_listed,
            "after {visibility} the profile sent lists the wrong sections: {}",
            updates[0]
        );
    }
}

/// `create_work_experience` reads the experience page's form into
/// `NewWorkExperience`.
#[tokio::test]
async fn a_current_position_with_no_end_date_reads_from_the_form() {
    let dated = form_of::<noombat_identity::profile::NewWorkExperience>(
        "title=Research%20engineer&organization=Example%20Labs&start_date=2023-01-09\
         &end_date=2025-06-30&description_md=&visibility=public",
    )
    .await;
    assert_eq!(
        dated.map(|experience| experience.end_date.map(|date| date.to_string())),
        Ok(Some("2025-06-30".to_owned())),
        "the same form with a date must keep it, or the check below proves nothing"
    );

    let parsed = form_of::<noombat_identity::profile::NewWorkExperience>(
        "title=Research%20engineer&organization=Example%20Labs&start_date=2023-01-09\
         &end_date=&description_md=&visibility=public",
    )
    .await;

    assert_eq!(
        parsed.map(|experience| experience.end_date),
        Ok(None),
        "an empty end date is refused"
    );

    let malformed = form_of::<noombat_identity::profile::NewWorkExperience>(
        "title=Research%20engineer&organization=Example%20Labs&start_date=2023-01-09\
         &end_date=2025-02-30&description_md=&visibility=public",
    )
    .await;
    assert!(
        malformed.is_err(),
        "a malformed end date must still be refused"
    );
}

/// `create_education_entry` reads the education page's form into
/// `NewEducationEntry`.
#[tokio::test]
async fn a_course_in_progress_with_no_end_date_reads_from_the_form() {
    let dated = form_of::<noombat_identity::profile::NewEducationEntry>(
        "institution=University%20of%20Example&degree=PhD&field_of_study=Computer%20Science\
         &start_date=2024-10-01&end_date=2025-06-30&visibility=public",
    )
    .await;
    assert_eq!(
        dated.map(|entry| entry.end_date.map(|date| date.to_string())),
        Ok(Some("2025-06-30".to_owned())),
        "the same form with a date must keep it, or the check below proves nothing"
    );

    let parsed = form_of::<noombat_identity::profile::NewEducationEntry>(
        "institution=University%20of%20Example&degree=PhD&field_of_study=Computer%20Science\
         &start_date=2024-10-01&end_date=&visibility=public",
    )
    .await;

    assert_eq!(
        parsed.map(|entry| entry.end_date),
        Ok(None),
        "an empty end date is refused"
    );

    let malformed = form_of::<noombat_identity::profile::NewEducationEntry>(
        "institution=University%20of%20Example&degree=PhD&field_of_study=Computer%20Science\
         &start_date=2024-10-01&end_date=2025-02-30&visibility=public",
    )
    .await;
    assert!(
        malformed.is_err(),
        "a malformed end date must still be refused"
    );
}

/// An API client's end date reads as a date, and `null`, an empty string
/// or no field at all reads as none.
#[test]
fn an_api_clients_end_date_reads_from_json() {
    fn experience(end: &str) -> Option<String> {
        let json = format!(
            r#"{{"title":"Research engineer","organization":"Example Labs","start_date":"2023-01-09"{end}}}"#
        );
        serde_json::from_str::<noombat_identity::profile::NewWorkExperience>(&json)
            .expect("the experience reads")
            .end_date
            .map(|date| date.to_string())
    }
    fn education(end: &str) -> Option<String> {
        let json =
            format!(r#"{{"institution":"University of Example","start_date":"2024-10-01"{end}}}"#);
        serde_json::from_str::<noombat_identity::profile::NewEducationEntry>(&json)
            .expect("the education entry reads")
            .end_date
            .map(|date| date.to_string())
    }

    for read in [experience, education] {
        assert_eq!(
            read(r#","end_date":"2025-06-30""#),
            Some("2025-06-30".to_owned())
        );
        assert_eq!(read(r#","end_date":null"#), None);
        assert_eq!(read(r#","end_date":"""#), None);
        assert_eq!(read(""), None);
    }
}

/// A current position and a degree in progress, saved through their
/// pages' forms with the end date left blank, are stored with none.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn entries_saved_with_a_blank_end_date_have_none(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;

    let experience = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/experiences"),
        &cookie,
        "title=Research%20engineer&organization=Example%20Labs&start_date=2023-01-09\
         &end_date=&description_md=&visibility=public",
    )
    .await;
    let education = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/educations"),
        &cookie,
        "institution=University%20of%20Example&degree=PhD&field_of_study=Computer%20Science\
         &start_date=2024-10-01&end_date=&visibility=public",
    )
    .await;

    let ends: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT end_date::text FROM work_experiences WHERE actor_id = $1 \
         UNION ALL SELECT end_date::text FROM education_entries WHERE actor_id = $1",
    )
    .bind(alice)
    .fetch_all(&pool)
    .await
    .expect("entries readable");
    assert_eq!(
        (experience, education, ends),
        (StatusCode::CREATED, StatusCode::CREATED, vec![None, None]),
        "both entries must be saved with no end date"
    );
}

// ..... Migration .....

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_add_alias_form_saves_the_alias(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/migrate",
        &format!("hx-post=\"/users/{USERNAME}/aliases\""),
        &["alias"],
    )
    .await;

    let status = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/aliases"),
        &cookie,
        "alias=https%3A%2F%2Fmastodon.example%2Fusers%2Falice",
    )
    .await;

    let saved: Vec<String> =
        sqlx::query_scalar("SELECT alias FROM actor_aliases WHERE actor_id = $1")
            .bind(alice)
            .fetch_all(&pool)
            .await
            .expect("aliases readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the add-alias form is refused"
    );
    assert_eq!(
        (status, saved),
        (
            StatusCode::CREATED,
            vec!["https://mastodon.example/users/alice".to_owned()]
        ),
        "the add-alias form must save what it sends"
    );
}

#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
async fn the_move_form_records_the_move(pool: PgPool) {
    let alice = insert_person(&pool).await;
    let cookie = session_cookie(&pool, alice).await;
    page_carries_form(
        &pool,
        &cookie,
        "/settings/migrate",
        &format!("hx-post=\"/users/{USERNAME}/move\""),
        &["target"],
    )
    .await;

    // The outbound move fetches nothing: it records the target and queues
    // a Move for each follower.
    let follower: Uuid = sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             inbox_url) \
         VALUES ('individual', 'https://peer.example/users/bob', 'bob', 'peer.example', 'KEY', \
                 FALSE, 'https://peer.example/users/bob/inbox') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("remote follower fixture");
    sqlx::query("INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, TRUE)")
        .bind(follower)
        .bind(alice)
        .execute(&pool)
        .await
        .expect("follow fixture");
    let status = submit(
        &pool,
        "POST",
        &format!("/users/{USERNAME}/move"),
        &cookie,
        "target=https%3A%2F%2Fother.example%2Fusers%2Falice",
    )
    .await;

    let moved_to: Option<String> = sqlx::query_scalar("SELECT moved_to FROM actors WHERE id = $1")
        .bind(alice)
        .fetch_one(&pool)
        .await
        .expect("actor readable");

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the move form is refused"
    );
    assert_eq!(
        (status, moved_to.as_deref()),
        (
            StatusCode::NO_CONTENT,
            Some("https://other.example/users/alice")
        ),
        "the move form must save what it sends"
    );
    let moves: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM delivery_queue \
         WHERE target_inbox = 'https://peer.example/users/bob/inbox' AND payload->>'type' = 'Move'",
    )
    .fetch_one(&pool)
    .await
    .expect("delivery queue readable");
    assert_eq!(moves, 1, "the follower must be sent the Move");
}
