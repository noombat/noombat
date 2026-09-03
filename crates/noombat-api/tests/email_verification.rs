// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Proving control of an email address.
//!
//! The address exists for one reason: `auth_key` is derived in the browser
//! and the server holds only a hash, so a password account with no proved
//! address is one a forgotten password destroys. These assertions pin the
//! properties that make the proof worth anything, rather than that a row
//! can be written.

use noombat_identity::email::{has_verified_email, purge_expired, request_verification, verify};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn account(pool: &PgPool, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/{label}-{id}"))
    .bind(format!("{label}{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert account")
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn redeeming_a_token_proves_the_address(pool: PgPool) {
    let who = account(&pool, "alice").await;
    assert!(!has_verified_email(&pool, who).await.unwrap());

    let challenge = request_verification(&pool, who, "Alice@Example.COM")
        .await
        .expect("issue");
    let verified = verify(&pool, &challenge.token).await.expect("redeem");

    assert_eq!(verified, who);
    assert!(has_verified_email(&pool, who).await.unwrap());

    let stored: Option<String> = sqlx::query_scalar("SELECT email FROM actors WHERE id = $1")
        .bind(who)
        .fetch_one(&pool)
        .await
        .unwrap();
    // Folded on the way in, because every lookup and the unique index go
    // through lower(email).
    assert_eq!(stored.as_deref(), Some("alice@example.com"));
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn nothing_is_written_to_the_actor_before_the_proof(pool: PgPool) {
    let who = account(&pool, "alice").await;
    request_verification(&pool, who, "alice@example.com")
        .await
        .expect("issue");

    let stored: Option<String> = sqlx::query_scalar("SELECT email FROM actors WHERE id = $1")
        .bind(who)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(
        stored, None,
        "an unfinished verification claimed the address, which would hold it against its owner"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_token_works_once(pool: PgPool) {
    let who = account(&pool, "alice").await;
    let challenge = request_verification(&pool, who, "alice@example.com")
        .await
        .unwrap();

    verify(&pool, &challenge.token).await.expect("first use");
    let second = verify(&pool, &challenge.token).await;

    assert!(second.is_err(), "a spent token was accepted again");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_token_is_refused(pool: PgPool) {
    let who = account(&pool, "alice").await;
    let challenge = request_verification(&pool, who, "alice@example.com")
        .await
        .unwrap();

    sqlx::query("UPDATE email_verifications SET expires_at = now() - interval '1 minute'")
        .execute(&pool)
        .await
        .unwrap();

    assert!(verify(&pool, &challenge.token).await.is_err());
    assert!(!has_verified_email(&pool, who).await.unwrap());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_token_is_refused(pool: PgPool) {
    assert!(verify(&pool, "not-a-token").await.is_err());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_token_is_not_stored_in_the_clear(pool: PgPool) {
    let who = account(&pool, "alice").await;
    let challenge = request_verification(&pool, who, "alice@example.com")
        .await
        .unwrap();

    let stored: String = sqlx::query_scalar("SELECT token_hash FROM email_verifications")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_ne!(
        stored, challenge.token,
        "a database copy would be a copy of every live credential"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_address_proved_by_someone_else_is_refused(pool: PgPool) {
    let alice = account(&pool, "alice").await;
    let mallory = account(&pool, "mallory").await;

    let challenge = request_verification(&pool, alice, "shared@example.com")
        .await
        .unwrap();
    verify(&pool, &challenge.token).await.unwrap();

    let refused = request_verification(&pool, mallory, "shared@example.com").await;

    assert!(
        refused.is_err(),
        "the instance would have sent mail to an address it could never assign"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_same_account_may_re_verify_its_own_address(pool: PgPool) {
    let alice = account(&pool, "alice").await;
    let first = request_verification(&pool, alice, "alice@example.com")
        .await
        .unwrap();
    verify(&pool, &first.token).await.unwrap();

    // The counterpart to the refusal above: excluding the actor themselves
    // is what stops "already in use" meaning "in use by you".
    request_verification(&pool, alice, "alice@example.com")
        .await
        .expect("an account was refused its own address");
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn challenges_are_rate_limited(pool: PgPool) {
    let who = account(&pool, "alice").await;

    for i in 0..5 {
        request_verification(&pool, who, &format!("alice{i}@example.com"))
            .await
            .unwrap_or_else(|e| panic!("challenge {i} refused: {e}"));
    }

    let refused = request_verification(&pool, who, "alice5@example.com").await;
    assert!(
        refused.is_err(),
        "an unbounded loop here makes the instance somebody else's spam source"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn text_that_is_not_an_address_is_refused(pool: PgPool) {
    let who = account(&pool, "alice").await;
    for bad in ["", "no-at", "user@nodot", "a b@example.com"] {
        assert!(
            request_verification(&pool, who, bad).await.is_err(),
            "accepted {bad:?}"
        );
    }
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_purge_removes_only_unredeemable_challenges(pool: PgPool) {
    let alice = account(&pool, "alice").await;
    let bob = account(&pool, "bob").await;

    let spent = request_verification(&pool, alice, "alice@example.com")
        .await
        .unwrap();
    verify(&pool, &spent.token).await.unwrap();

    request_verification(&pool, bob, "bob@example.com")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE email_verifications SET expires_at = now() - interval '1 day' \
         WHERE consumed_at IS NULL",
    )
    .execute(&pool)
    .await
    .unwrap();

    let removed = purge_expired(&pool).await.unwrap();
    assert_eq!(removed, 1);

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM email_verifications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        left, 1,
        "the consumed row is the record that an address was proved, and the rate limit counts it"
    );
}
