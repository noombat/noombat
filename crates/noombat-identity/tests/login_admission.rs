// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Which account states may sign in.
//!
//! The query behind `verify_credentials` is an allowlist, so these tests
//! pin both halves of it: the states it admits and the states it refuses.
//! The refusals are the point. Stated as a denylist the query admitted
//! every status added after it was written, and `pending` is such a
//! status: an account that owns its username and has never been admitted.

use noombat_identity::login::{LoginRequest, verify_credentials};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";
/// 64 hex characters, the shape `validate_auth_key` requires.
const AUTH_KEY: &str = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";

/// Insert a local actor in `status`, with a real Argon2id hash of
/// [`AUTH_KEY`], so a refusal can only come from the status predicate and
/// never from the key comparison.
async fn insert_actor(pool: &PgPool, username: &str, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    let hash = noombat_identity::registration::hash_auth_key(AUTH_KEY)
        .expect("hashing the fixture key failed");

    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, domain, public_key_pem,
                is_local, actor_status, auth_key_hash)
           VALUES ($1, 'individual', $2, $3, $4, 'PEM', TRUE, $5, $6)"#,
    )
    .bind(id)
    .bind(format!("https://{DOMAIN}/users/{username}"))
    .bind(username)
    .bind(DOMAIN)
    .bind(status)
    .bind(hash)
    .execute(pool)
    .await
    .expect("inserting the fixture actor failed");

    id
}

fn login(username: &str) -> LoginRequest {
    LoginRequest {
        username: username.to_owned(),
        auth_key: AUTH_KEY.to_owned(),
        totp_code: None,
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_active_account_signs_in(pool: PgPool) {
    let id = insert_actor(&pool, "active_user", "active").await;

    let (actor_id, username, _role, _has_totp) = verify_credentials(&pool, &login("active_user"))
        .await
        .expect("an active account should sign in");

    assert_eq!(actor_id, id);
    assert_eq!(username, "active_user");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_silenced_account_still_signs_in(pool: PgPool) {
    insert_actor(&pool, "silenced_user", "silenced").await;

    // Silencing withholds reach, not access. This is the case that stops
    // the allowlist being written as `= 'active'`, which would look
    // tighter and would lock out every silenced account.
    verify_credentials(&pool, &login("silenced_user"))
        .await
        .expect("a silenced account should still sign in");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_pending_account_is_refused(pool: PgPool) {
    insert_actor(&pool, "pending_user", "pending").await;

    let result = verify_credentials(&pool, &login("pending_user")).await;

    assert!(
        result.is_err(),
        "an account awaiting approval signed in, so the admission gate admits it"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_suspended_account_is_refused(pool: PgPool) {
    insert_actor(&pool, "suspended_user", "suspended").await;

    let result = verify_credentials(&pool, &login("suspended_user")).await;

    assert!(result.is_err(), "a suspended account signed in");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_refusal_is_the_status_and_not_the_key(pool: PgPool) {
    // The guard against a test that passes for the wrong reason: the same
    // fixture key that signs `active_user` in must be the one refused for
    // `pending_user`. Without this, a typo in the fixture hash would make
    // every refusal above pass while the status predicate did nothing.
    insert_actor(&pool, "twin_active", "active").await;
    insert_actor(&pool, "twin_pending", "pending").await;

    verify_credentials(&pool, &login("twin_active"))
        .await
        .expect("the fixture key does not verify, so the refusals below prove nothing");

    assert!(
        verify_credentials(&pool, &login("twin_pending"))
            .await
            .is_err(),
        "same key, same instance: only the status differs, and it did not decide"
    );
}
