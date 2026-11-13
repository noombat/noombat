// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Who may use the moderation and administration routes, and whether the
//! admin pages' own requests reach them.
//!
//! Driven through the assembled router with real sessions, because a role
//! rule with unit tests of its own still passes when a route forgets to
//! call it. Each refused request is sent with a body the handler would
//! accept, so the role check is the only thing refusing it, and each is
//! followed by a look at the rows it would have changed.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use noombat_api::build_router;
use noombat_api::rate_limit::FallbackRateLimiter;
use noombat_api::state::AppState;
use noombat_core::actor::InstanceRole;
use noombat_federation::nodeinfo::NodeInfoFeatures;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
const JWT_SECRET: &str = "test-secret-that-is-at-least-32-bytes-long";
const FORM: &str = "application/x-www-form-urlencoded";
const JSON: &str = "application/json";

fn test_state(pool: PgPool) -> AppState {
    AppState {
        pool,
        domain: DOMAIN.to_owned(),
        public_port: 8443,
        http_client: reqwest::Client::new(),
        open_registrations: true,
        search: None,
        nodeinfo_features: NodeInfoFeatures::default(),
        redis: None,
        session_config: Some(noombat_identity::session::SessionConfig {
            jwt_secret: JWT_SECRET.to_owned(),
            domain: DOMAIN.to_owned(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
        }),
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

async fn insert_person(pool: &PgPool, username: &str, role: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local, \
                             instance_role) \
         VALUES ('individual', $1, $2, $3, 'KEY', TRUE, $4) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(role)
    .fetch_one(pool)
    .await
    .expect("person fixture")
}

async fn token_for(pool: &PgPool, actor_id: Uuid, username: &str, role: InstanceRole) -> String {
    noombat_identity::session::create_session(
        pool,
        &noombat_identity::session::SessionConfig {
            jwt_secret: JWT_SECRET.to_owned(),
            domain: DOMAIN.to_owned(),
            access_ttl_secs: 900,
            refresh_ttl_secs: 2_592_000,
        },
        actor_id,
        username,
        role,
        noombat_identity::session::SessionContext::sign_in(),
    )
    .await
    .expect("session created")
    .access_token
}

/// A refusal shows a role check only if the caller was signed in: an
/// anonymous caller is refused too. A page any member may open answers 200
/// to a session and sends anyone else to sign in.
async fn assert_signed_in(pool: &PgPool, bearer: &str, who: &str) {
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .uri("/settings/account")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{who}'s session did not resolve, so a refusal would prove nothing"
    );
}

/// A plain member and a moderator, each with a session: the two callers
/// an admin-only route must refuse.
async fn member_and_moderator(pool: &PgPool) -> [(&'static str, String); 2] {
    let member = insert_person(pool, "member", "user").await;
    let moderator = insert_person(pool, "mod", "moderator").await;
    let callers = [
        (
            "a plain member",
            token_for(pool, member, "member", InstanceRole::User).await,
        ),
        (
            "a moderator",
            token_for(pool, moderator, "mod", InstanceRole::Moderator).await,
        ),
    ];
    for (who, token) in &callers {
        assert_signed_in(pool, token, who).await;
    }
    callers
}

/// One request as an API client sends it. `body` is a content type and
/// the body in it.
async fn send(
    pool: &PgPool,
    method: &str,
    uri: &str,
    bearer: &str,
    body: Option<(&str, &str)>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"));
    if let Some((content_type, _)) = body {
        builder = builder.header("content-type", content_type);
    }
    let request = builder
        .body(body.map_or_else(Body::empty, |(_, b)| Body::from(b.to_owned())))
        .expect("request");

    build_router(test_state(pool.clone()))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

async fn actor_status(pool: &PgPool, actor_id: Uuid) -> String {
    sqlx::query_scalar("SELECT actor_status FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_one(pool)
        .await
        .expect("status readable")
}

// ..... Moderator routes refuse a plain member .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_plain_member_cannot_suspend_an_account(pool: PgPool) {
    let member = insert_person(&pool, "member", "user").await;
    let target = insert_person(&pool, "target", "user").await;
    let token = token_for(&pool, member, "member", InstanceRole::User).await;
    assert_signed_in(&pool, &token, "a plain member").await;

    let status = send(
        &pool,
        "POST",
        &format!("/api/v1/admin/actors/{target}/suspend"),
        &token,
        Some((JSON, r#"{"reason":"spam"}"#)),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a plain member suspended an account"
    );
    assert_eq!(
        actor_status(&pool, target).await,
        "active",
        "a refused suspension still suspended the account"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_plain_member_cannot_unsuspend_an_account(pool: PgPool) {
    let member = insert_person(&pool, "member", "user").await;
    let target = insert_person(&pool, "target", "user").await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(target)
        .execute(&pool)
        .await
        .expect("suspension fixture");
    let token = token_for(&pool, member, "member", InstanceRole::User).await;
    assert_signed_in(&pool, &token, "a plain member").await;

    let status = send(
        &pool,
        "POST",
        &format!("/api/v1/admin/actors/{target}/unsuspend"),
        &token,
        None,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a plain member lifted a suspension"
    );
    assert_eq!(
        actor_status(&pool, target).await,
        "suspended",
        "a refused unsuspension still reactivated the account"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_plain_member_cannot_add_or_remove_a_domain_restriction(pool: PgPool) {
    let member = insert_person(&pool, "member", "user").await;
    let token = token_for(&pool, member, "member", InstanceRole::User).await;
    let existing: Uuid = sqlx::query_scalar(
        "INSERT INTO domain_restrictions (domain, restriction) \
         VALUES ('blocked.example', 'block') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("restriction fixture");
    assert_signed_in(&pool, &token, "a plain member").await;

    let added = send(
        &pool,
        "POST",
        "/api/v1/admin/domains",
        &token,
        Some((FORM, "domain=peer.example&restriction=block")),
    )
    .await;
    assert_eq!(
        added,
        StatusCode::FORBIDDEN,
        "a plain member restricted a domain"
    );

    let removed = send(
        &pool,
        "DELETE",
        &format!("/api/v1/admin/domains/{existing}"),
        &token,
        None,
    )
    .await;
    assert_eq!(
        removed,
        StatusCode::FORBIDDEN,
        "a plain member lifted a domain restriction"
    );

    let domains: Vec<String> =
        sqlx::query_scalar("SELECT domain FROM domain_restrictions ORDER BY domain")
            .fetch_all(&pool)
            .await
            .expect("restrictions readable");
    assert_eq!(
        domains,
        vec!["blocked.example".to_owned()],
        "a refused request still changed the domain restrictions"
    );
}

// ..... Admin routes refuse a plain member and a moderator .....

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn neither_a_member_nor_a_moderator_can_change_a_role(pool: PgPool) {
    insert_person(&pool, "target", "user").await;

    for (who, token) in member_and_moderator(&pool).await {
        let status = send(
            &pool,
            "POST",
            "/api/v1/admin/users/target/role",
            &token,
            Some((FORM, "role=admin")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{who} changed an instance role"
        );
    }

    let role: String =
        sqlx::query_scalar("SELECT instance_role FROM actors WHERE username = 'target'")
            .fetch_one(&pool)
            .await
            .expect("role readable");
    assert_eq!(role, "user", "a refused role change still changed the role");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn neither_a_member_nor_a_moderator_can_change_instance_settings(pool: PgPool) {
    for (who, token) in member_and_moderator(&pool).await {
        let status = send(
            &pool,
            "PATCH",
            "/api/v1/admin/settings",
            &token,
            Some((FORM, "registration_mode=closed")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{who} changed the instance settings"
        );
    }

    let mode: String = sqlx::query_scalar("SELECT registration_mode FROM instance_settings")
        .fetch_one(&pool)
        .await
        .expect("settings readable");
    assert_eq!(
        mode, "open",
        "a refused settings change still changed the registration mode"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn neither_a_member_nor_a_moderator_can_manage_relays(pool: PgPool) {
    let relay: Uuid = sqlx::query_scalar(
        "INSERT INTO relay_subscriptions (inbox_url, status) \
         VALUES ('https://relay.example/inbox', 'accepted') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("relay fixture");

    for (who, token) in member_and_moderator(&pool).await {
        let listed = send(&pool, "GET", "/api/v1/admin/relays", &token, None).await;
        assert_eq!(
            listed,
            StatusCode::FORBIDDEN,
            "{who} listed the relay subscriptions"
        );

        let subscribed = send(
            &pool,
            "POST",
            "/api/v1/admin/relays",
            &token,
            Some((JSON, r#"{"inbox_url":"https://other-relay.example/inbox"}"#)),
        )
        .await;
        assert_eq!(
            subscribed,
            StatusCode::FORBIDDEN,
            "{who} subscribed the instance to a relay"
        );

        let unsubscribed = send(
            &pool,
            "DELETE",
            &format!("/api/v1/admin/relays/{relay}"),
            &token,
            None,
        )
        .await;
        assert_eq!(
            unsubscribed,
            StatusCode::FORBIDDEN,
            "{who} unsubscribed the instance from a relay"
        );
    }

    let relays: Vec<String> =
        sqlx::query_scalar("SELECT inbox_url FROM relay_subscriptions ORDER BY inbox_url")
            .fetch_all(&pool)
            .await
            .expect("relays readable");
    assert_eq!(
        relays,
        vec!["https://relay.example/inbox".to_owned()],
        "a refused request still changed the relay subscriptions"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn neither_a_member_nor_a_moderator_can_manage_announcements(pool: PgPool) {
    let existing: Uuid = sqlx::query_scalar(
        "INSERT INTO announcements (content) VALUES ('Maintenance tonight') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("announcement fixture");

    for (who, token) in member_and_moderator(&pool).await {
        let created = send(
            &pool,
            "POST",
            "/api/v1/admin/announcements",
            &token,
            Some((FORM, "content=Free+pizza")),
        )
        .await;
        assert_eq!(
            created,
            StatusCode::FORBIDDEN,
            "{who} published an announcement"
        );

        let deleted = send(
            &pool,
            "DELETE",
            &format!("/api/v1/admin/announcements/{existing}"),
            &token,
            None,
        )
        .await;
        assert_eq!(
            deleted,
            StatusCode::FORBIDDEN,
            "{who} deleted an announcement"
        );
    }

    let contents: Vec<String> =
        sqlx::query_scalar("SELECT content FROM announcements ORDER BY content")
            .fetch_all(&pool)
            .await
            .expect("announcements readable");
    assert_eq!(
        contents,
        vec!["Maintenance tonight".to_owned()],
        "a refused request still changed the announcements"
    );
}

// The pages refuse with a redirect rather than a 403, so a refusal is a 307.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_admin_pages_turn_away_anyone_below_their_role(pool: PgPool) {
    let [(_, member), (_, moderator)] = member_and_moderator(&pool).await;
    let cases = [
        ("/admin/moderation", &member, "a plain member"),
        ("/admin/users", &member, "a plain member"),
        ("/admin/domains", &member, "a plain member"),
        ("/admin/settings", &member, "a plain member"),
        ("/admin/federation", &member, "a plain member"),
        ("/admin/settings", &moderator, "a moderator"),
        ("/admin/federation", &moderator, "a moderator"),
    ];

    for (path, token, who) in cases {
        let response = build_router(test_state(pool.clone()))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("the router is infallible");
        assert_eq!(
            response.status(),
            StatusCode::TEMPORARY_REDIRECT,
            "{who} was served {path}"
        );
        assert_eq!(
            response.headers()["location"],
            "/",
            "{who} was sent to sign in at {path}, so the session did not resolve"
        );
    }
}

// ..... The users page's own request .....

// Known defect: the users page's Suspend form posts url-encoded fields to a
// handler that accepts only JSON, so the request is refused before it runs.
// Remove `should_panic` once it is fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(expected = "known defect: the users page's Suspend form is refused")]
async fn the_users_pages_suspend_button_suspends_the_account(pool: PgPool) {
    let moderator = insert_person(&pool, "mod", "moderator").await;
    let target = insert_person(&pool, "target", "user").await;
    let token = token_for(&pool, moderator, "mod", InstanceRole::Moderator).await;
    let cookie = format!("noombat_session={token}");
    let action = format!("/api/v1/admin/actors/{target}/suspend");

    // The request below replays this page's form, so first check the page
    // still renders that form: its action, its one field, and no htmx
    // extension that would change how the fields are encoded.
    let page = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/admin/users")
                .header("cookie", cookie.as_str())
                .body(Body::empty())
                .expect("page request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(
        page.status(),
        StatusCode::OK,
        "the users page must serve a moderator"
    );
    let page = axum::body::to_bytes(page.into_body(), 4 * 1024 * 1024)
        .await
        .expect("page body read");
    let page = String::from_utf8_lossy(&page);
    assert!(
        page.contains(format!(r#"hx-post="{action}""#).as_str())
            && page.contains(r#"<input type="hidden" name="reason" value="">"#)
            && !page.contains("hx-ext"),
        "the users page no longer renders the form this test replays: {page}"
    );

    // What htmx sends for that form: url-encoded fields, since the form
    // declares no multipart encoding, and the session cookie the browser
    // holds.
    let response = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(action.as_str())
                .header("content-type", FORM)
                .header("hx-request", "true")
                .header("hx-current-url", format!("https://{DOMAIN}/admin/users"))
                .header("origin", format!("https://{DOMAIN}"))
                .header("cookie", cookie.as_str())
                .body(Body::from("reason="))
                .expect("suspend request"),
        )
        .await
        .expect("the router is infallible");
    let status = response.status();

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "known defect: the users page's Suspend form is refused"
    );
    assert!(
        status.is_success() || status.is_redirection(),
        "the Suspend form was refused for another reason: {status}"
    );
    assert_eq!(
        actor_status(&pool, target).await,
        "suspended",
        "the Suspend form was answered with success and the account is still active"
    );
}

/// A page as a moderator's browser loads it.
async fn page_as(pool: &PgPool, cookie: &str, uri: &str) -> String {
    let page = build_router(test_state(pool.clone()))
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", cookie)
                .body(Body::empty())
                .expect("page request"),
        )
        .await
        .expect("the router is infallible");
    assert_eq!(
        page.status(),
        StatusCode::OK,
        "{uri} must serve a moderator"
    );
    let page = axum::body::to_bytes(page.into_body(), 4 * 1024 * 1024)
        .await
        .expect("page body read");
    String::from_utf8_lossy(&page).into_owned()
}

/// What htmx sends for a page's form: its fields url-encoded, the session
/// cookie, and the headers a same-origin browser request carries.
async fn submit_form(
    pool: &PgPool,
    cookie: &str,
    page: &str,
    action: &str,
    fields: &str,
) -> StatusCode {
    let mut builder = Request::builder()
        .method("POST")
        .uri(action)
        .header("hx-request", "true")
        .header("hx-current-url", format!("https://{DOMAIN}{page}"))
        .header("origin", format!("https://{DOMAIN}"))
        .header("cookie", cookie);
    if !fields.is_empty() {
        builder = builder.header("content-type", FORM);
    }
    build_router(test_state(pool.clone()))
        .oneshot(
            builder
                .body(Body::from(fields.to_owned()))
                .expect("form request"),
        )
        .await
        .expect("the router is infallible")
        .status()
}

async fn report_status(pool: &PgPool, report: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM reports WHERE id = $1")
        .bind(report)
        .fetch_one(pool)
        .await
        .expect("report readable")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_users_pages_unsuspend_button_lifts_the_suspension(pool: PgPool) {
    let moderator = insert_person(&pool, "mod", "moderator").await;
    let target = insert_person(&pool, "target", "user").await;
    sqlx::query("UPDATE actors SET actor_status = 'suspended' WHERE id = $1")
        .bind(target)
        .execute(&pool)
        .await
        .expect("suspension fixture");
    let cookie = format!(
        "noombat_session={}",
        token_for(&pool, moderator, "mod", InstanceRole::Moderator).await
    );
    let action = format!("/api/v1/admin/actors/{target}/unsuspend");
    assert!(
        page_as(&pool, &cookie, "/admin/users")
            .await
            .contains(format!(r#"hx-post="{action}""#).as_str()),
        "the users page no longer renders the Unsuspend form this test replays"
    );

    // The form has no fields, so htmx sends an empty body.
    let status = submit_form(&pool, &cookie, "/admin/users", &action, "").await;

    assert!(
        status.is_success(),
        "the Unsuspend form was refused: {status}"
    );
    assert_eq!(actor_status(&pool, target).await, "active");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_moderation_pages_dismiss_closes_a_post_report(pool: PgPool) {
    let moderator = insert_person(&pool, "mod", "moderator").await;
    let reporter = insert_person(&pool, "reporter", "user").await;
    let target = insert_person(&pool, "target", "user").await;
    let report: Uuid = sqlx::query_scalar(
        "INSERT INTO reports (reporter_id, target_actor_id, reason) \
         VALUES ($1, $2, 'spam') RETURNING id",
    )
    .bind(reporter)
    .bind(target)
    .fetch_one(&pool)
    .await
    .expect("report fixture");
    let cookie = format!(
        "noombat_session={}",
        token_for(&pool, moderator, "mod", InstanceRole::Moderator).await
    );
    let action = format!("/api/v1/admin/reports/{report}/resolve");
    assert!(
        page_as(&pool, &cookie, "/admin/moderation")
            .await
            .contains(format!(r#"hx-post="{action}""#).as_str()),
        "the moderation page no longer renders the Dismiss form this test replays"
    );

    let status = submit_form(
        &pool,
        &cookie,
        "/admin/moderation",
        &action,
        "action=dismiss",
    )
    .await;

    assert!(
        status.is_success(),
        "the Dismiss form was refused: {status}"
    );
    assert_eq!(report_status(&pool, report).await, "dismissed");
}

// Known defect: the chat-report Dismiss form posts url-encoded fields to a
// handler that accepts only JSON. Remove `should_panic` once it is fixed.
#[sqlx::test(migrations = "../../migrations")]
#[ignore = "requires a database; run with --include-ignored"]
#[should_panic(
    expected = "known defect: the moderation page's chat-report Dismiss form is refused"
)]
async fn the_moderation_pages_dismiss_closes_a_chat_report(pool: PgPool) {
    let moderator = insert_person(&pool, "mod", "moderator").await;
    let reporter = insert_person(&pool, "reporter", "user").await;
    let report: Uuid = sqlx::query_scalar(
        "INSERT INTO reports (reporter_id, target_chat_addr, reason) \
         VALUES ($1, 'sender@chat.example', 'spam') RETURNING id",
    )
    .bind(reporter)
    .fetch_one(&pool)
    .await
    .expect("report fixture");
    let cookie = format!(
        "noombat_session={}",
        token_for(&pool, moderator, "mod", InstanceRole::Moderator).await
    );
    let action = format!("/api/v1/admin/chat-reports/{report}/resolve");
    assert!(
        page_as(&pool, &cookie, "/admin/moderation")
            .await
            .contains(format!(r#"hx-post="{action}""#).as_str()),
        "the moderation page no longer renders the Dismiss form this test replays"
    );

    let status = submit_form(
        &pool,
        &cookie,
        "/admin/moderation",
        &action,
        "action=dismiss",
    )
    .await;

    assert_ne!(
        status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "known defect: the moderation page's chat-report Dismiss form is refused"
    );
    assert!(
        status.is_success(),
        "the Dismiss form was refused: {status}"
    );
    assert_eq!(report_status(&pool, report).await, "dismissed");
}
