// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! `instance_settings.registration_mode` decides what a sign-up does.
//!
//! The column existed and the administration page wrote it, and nothing
//! read it: closing registration closed nothing, and approval mode
//! admitted every account immediately. These assert the three modes do
//! what their names say, and that the failure direction is refusal.

use noombat_identity::registration::{
    RegisterRequest, RegistrationMode, register, registration_mode,
};
use sqlx::PgPool;

const DOMAIN: &str = "noombat.example";

fn sign_up(username: &str) -> RegisterRequest {
    RegisterRequest {
        username: username.to_owned(),
        display_name: None,
        // 64 hex characters: the browser-derived authentication key, which
        // is all the server ever sees of a password.
        auth_key: "a".repeat(64),
        email: Some(format!("{username}@example.org")),
    }
}

async fn set_mode(pool: &PgPool, mode: &str) {
    sqlx::query("UPDATE instance_settings SET registration_mode = $1")
        .bind(mode)
        .execute(pool)
        .await
        .expect("mode set");
}

async fn status_of(pool: &PgPool, username: &str) -> Option<String> {
    sqlx::query_scalar("SELECT actor_status FROM actors WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
        .expect("actor readable")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn open_registration_admits_an_active_account(pool: PgPool) {
    set_mode(&pool, "open").await;

    let result = register(&pool, DOMAIN, &sign_up("alice"))
        .await
        .expect("registration succeeds");

    assert!(!result.awaiting_approval);
    assert_eq!(status_of(&pool, "alice").await.as_deref(), Some("active"));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn approval_registration_creates_a_pending_account(pool: PgPool) {
    set_mode(&pool, "approval").await;

    let result = register(&pool, DOMAIN, &sign_up("bob"))
        .await
        .expect("registration succeeds");

    assert!(
        result.awaiting_approval,
        "the caller must be told not to mint a session"
    );
    assert_eq!(status_of(&pool, "bob").await.as_deref(), Some("pending"));

    // And the account genuinely cannot sign in, which is the property
    // the status exists for.
    let login = noombat_identity::login::LoginRequest {
        username: "bob".to_owned(),
        auth_key: "a".repeat(64),
        totp_code: None,
    };
    assert!(
        noombat_identity::login::verify_credentials(&pool, &login)
            .await
            .is_err(),
        "a pending account must not sign in"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn closed_registration_creates_nothing(pool: PgPool) {
    set_mode(&pool, "closed").await;

    let result = register(&pool, DOMAIN, &sign_up("carol")).await;

    assert!(result.is_err(), "a closed instance must refuse the sign-up");
    assert_eq!(
        status_of(&pool, "carol").await,
        None,
        "a refused sign-up must not leave a row holding the username"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_settings_row_closes_registration(pool: PgPool) {
    // The check constraint keeps an unknown string out of the column, so
    // the reachable failure is the row being absent. It could as easily
    // have been read as "open", and that is the reading that admits
    // accounts an operator never agreed to.
    sqlx::query("DELETE FROM instance_settings")
        .execute(&pool)
        .await
        .expect("settings cleared");

    assert_eq!(
        registration_mode(&pool).await.expect("mode readable"),
        RegistrationMode::Closed
    );
    assert!(register(&pool, DOMAIN, &sign_up("dave")).await.is_err());
    assert_eq!(status_of(&pool, "dave").await, None);
}

#[test]
fn an_unknown_mode_reads_as_closed() {
    // Unreachable through the column, whose check constraint admits
    // only the three. Asserted anyway because the fallback is what
    // decides the answer if that constraint is ever widened, and
    // `Open` is the wrong default to inherit.
    assert_eq!(
        RegistrationMode::from_stored("invite-only"),
        RegistrationMode::Closed
    );
    assert_eq!(RegistrationMode::from_stored(""), RegistrationMode::Closed);
    assert_eq!(
        RegistrationMode::from_stored("OPEN"),
        RegistrationMode::Closed
    );
    assert_eq!(
        RegistrationMode::from_stored("open"),
        RegistrationMode::Open
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_closed_instance_does_not_disclose_whether_the_name_was_free(pool: PgPool) {
    set_mode(&pool, "open").await;
    register(&pool, DOMAIN, &sign_up("erin"))
        .await
        .expect("registration succeeds");

    set_mode(&pool, "closed").await;

    // The taken name and the free one must produce the same refusal,
    // which is why the mode is checked before uniqueness.
    let taken = register(&pool, DOMAIN, &sign_up("erin")).await;
    let free = register(&pool, DOMAIN, &sign_up("frank")).await;

    assert_eq!(
        format!("{:?}", taken.expect_err("refused")),
        format!("{:?}", free.expect_err("refused")),
    );
}
