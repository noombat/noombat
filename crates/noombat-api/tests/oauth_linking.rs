// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Adding a second way into an account.
//!
//! A direct account links ORCID or Mastodon; an OAuth account adds an
//! address and a password. Either way the account ends up reachable two
//! ways, which is what stops one forgotten credential being the end of it.
//!
//! The property that matters most here is whose account gets the identity.
//! It is taken from the session that starts the flow and recorded with the
//! OAuth state, never read back from the redirect, because a callback that
//! believed what it was handed would let an attacker attach their own
//! provider account to somebody else's login.

use noombat_identity::oauth_orcid::{OrcidConfig, build_authorise_url};
use noombat_identity::oauth_util::link_identity;
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
async fn an_account_can_hold_both_providers(pool: PgPool) {
    let who = account(&pool, "alice").await;

    link_identity(&pool, who, "orcid", "0000-0002-1825-0097")
        .await
        .expect("link ORCID");
    link_identity(&pool, who, "mastodon", "alice@mastodon.example")
        .await
        .expect("link Mastodon");

    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oauth_identities WHERE actor_id = $1")
            .bind(who)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked, 2);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn one_external_identity_belongs_to_one_account(pool: PgPool) {
    let alice = account(&pool, "alice").await;
    let mallory = account(&pool, "mallory").await;

    link_identity(&pool, alice, "orcid", "0000-0002-1825-0097")
        .await
        .expect("link");

    let refused = link_identity(&pool, mallory, "orcid", "0000-0002-1825-0097").await;

    assert!(
        refused.is_err(),
        "re-pointing an identity takes the second way in away from whoever holds it"
    );

    // And it is still Alice's.
    let owner: Uuid = sqlx::query_scalar(
        "SELECT actor_id FROM oauth_identities WHERE provider = 'orcid' AND external_id = $1",
    )
    .bind("0000-0002-1825-0097")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(owner, alice);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn linking_to_an_account_that_does_not_exist_is_refused(pool: PgPool) {
    let refused = link_identity(&pool, Uuid::new_v4(), "orcid", "0000-0002-1825-0097").await;
    assert!(refused.is_err());
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_link_flow_records_whose_account_it_is(pool: PgPool) {
    let who = account(&pool, "alice").await;
    let config = OrcidConfig::default();

    let (_url, state) = build_authorise_url(&pool, &config, DOMAIN, Some(who))
        .await
        .expect("start link flow");

    let recorded: Option<Uuid> =
        sqlx::query_scalar("SELECT link_actor_id FROM oauth_states WHERE state = $1")
            .bind(&state)
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        recorded,
        Some(who),
        "the callback would have nothing to link to but what the redirect told it"
    );
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_sign_in_flow_records_no_account(pool: PgPool) {
    let config = OrcidConfig::default();

    let (_url, state) = build_authorise_url(&pool, &config, DOMAIN, None)
        .await
        .expect("start sign-in flow");

    let recorded: Option<Uuid> =
        sqlx::query_scalar("SELECT link_actor_id FROM oauth_states WHERE state = $1")
            .bind(&state)
            .fetch_one(&pool)
            .await
            .unwrap();

    // The counterpart to the test above: if this were also populated, the
    // first one would be asserting nothing.
    assert_eq!(recorded, None);
}

#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn deleting_an_account_takes_its_pending_link_flows(pool: PgPool) {
    let who = account(&pool, "alice").await;
    let config = OrcidConfig::default();
    let (_url, state) = build_authorise_url(&pool, &config, DOMAIN, Some(who))
        .await
        .unwrap();

    sqlx::query("DELETE FROM actors WHERE id = $1")
        .bind(who)
        .execute(&pool)
        .await
        .expect("erase account");

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_states WHERE state = $1")
        .bind(&state)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(
        left, 0,
        "a flow pointing at an erased account would resolve to nothing on callback"
    );
}
