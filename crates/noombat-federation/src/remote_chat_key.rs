// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Chat keys published by members of other noombat instances, kept so that
//! members here can write to them first.
//!
//! A peer's actor document can claim any address, a local member's
//! included. A key is kept only when its address is on the chat domain the
//! actor's own instance publishes in its NodeInfo, that chat domain is the
//! instance's own host or under it, so no instance can claim another's,
//! and the key passes the check a local member's key passes. Whether this
//! relay exchanges mail with that domain is asked when the key is served,
//! since the allowlist can change in the meantime.
//!
//! Keys are read when a member here looks someone up and when an actor's
//! verified `Update` arrives, never while an inbound request's signature
//! is still being checked, so a stranger cannot make this instance read
//! NodeInfo by naming new actors.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use noombat_ap::object::ApActor;
use noombat_ap::vocab;
use noombat_core::actor::Actor;
use noombat_core::error::Result;
use serde_json::Value;
use sqlx::PgPool;
use tracing::{debug, warn};

use crate::{inbox, nodeinfo, webfinger};

/// A chat key as an actor document carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    pub address: String,
    pub key: Vec<u8>,
}

/// The key in a `noombat:chatKey` value, when it has both parts.
pub fn parse(value: &Value) -> Option<PublishedKey> {
    let address = value[vocab::CHAT_KEY_ADDRESS].as_str()?;
    let key = STANDARD
        .decode(value[vocab::CHAT_KEY_DATA].as_str()?)
        .ok()?;
    Some(PublishedKey {
        address: address.to_owned(),
        key,
    })
}

/// Why a published key is not kept, given the chat domain the actor's
/// instance publishes and that instance's host, `actor_domain`, which may
/// carry a port.
pub fn binding(
    published: &PublishedKey,
    chatmail_domain: Option<&str>,
    actor_domain: &str,
) -> std::result::Result<(), String> {
    noombat_core::email_address::qualify(&published.address, "address")
        .map_err(|e| e.to_string())?;
    let (_, domain) = published
        .address
        .rsplit_once('@')
        .ok_or("the address has no domain")?;
    let Some(expected) = chatmail_domain else {
        return Err("the actor's instance publishes no chat domain".into());
    };
    if !domain.eq_ignore_ascii_case(expected) {
        return Err(format!("the address is not on {expected}"));
    }
    let host = actor_domain.split(':').next().unwrap_or(actor_domain);
    let under_host = expected.eq_ignore_ascii_case(host)
        || expected
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", host.to_ascii_lowercase()));
    if !under_host {
        return Err(format!(
            "{expected} is not under the instance's host, {host}"
        ));
    }
    noombat_openpgp::check_public_key(&published.key, &published.address)
        .map_err(|refusal| refusal.to_string())
}

/// Keep or drop a remote actor's chat key, from the document just fetched
/// for them. A local actor is never touched: their key is their own upload.
pub async fn refresh(pool: &PgPool, client: &reqwest::Client, actor: &Actor, document: &ApActor) {
    if actor.is_local {
        return;
    }
    let mut kept = None;
    if let Some(published) = document.chat_key.as_ref().and_then(parse) {
        let chatmail_domain =
            match nodeinfo::remote_chatmail_domain(pool, client, &actor.ap_id).await {
                Ok(chatmail_domain) => chatmail_domain,
                // Unknown, so whatever is kept stays until it can be read.
                Err(error) => {
                    debug!(actor = %actor.ap_id, %error, "a remote chat key left as it was");
                    return;
                }
            };
        match binding(&published, chatmail_domain.as_deref(), &actor.domain) {
            Ok(()) => kept = Some(published),
            Err(why) => debug!(actor = %actor.ap_id, %why, "not keeping a remote chat key"),
        }
    }
    // Written only while the actor's row holds this document: reading
    // NodeInfo takes a while, and an older document's slower refresh must
    // not undo what a newer one's did.
    let stamp = crate::inbox::document_stamp(document);
    let written = match kept {
        Some(published) => {
            sqlx::query(
                "INSERT INTO chat_keys (actor_id, address, key_data) \
                 SELECT $1, $2, $3 FROM actors \
                 WHERE id = $1 AND ($4::timestamptz IS NULL OR document_updated = $4) \
                 ON CONFLICT (actor_id) DO UPDATE \
                 SET address = EXCLUDED.address, key_data = EXCLUDED.key_data, updated_at = now()",
            )
            .bind(actor.id)
            .bind(&published.address)
            .bind(&published.key)
            .bind(stamp)
            .execute(pool)
            .await
        }
        None => {
            sqlx::query(
                "DELETE FROM chat_keys WHERE actor_id = $1 AND EXISTS ( \
                     SELECT 1 FROM actors \
                     WHERE id = $1 AND ($2::timestamptz IS NULL OR document_updated = $2))",
            )
            .bind(actor.id)
            .bind(stamp)
            .execute(pool)
            .await
        }
    };
    if let Err(error) = written {
        warn!(actor = %actor.ap_id, %error, "a remote chat key could not be stored");
    }
}

/// The key kept for `actor`, if any.
pub async fn stored(pool: &PgPool, actor: &Actor) -> Result<Option<PublishedKey>> {
    let row: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT address, key_data FROM chat_keys WHERE actor_id = $1")
            .bind(actor.id)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(address, key)| PublishedKey { address, key }))
}

/// The host a URL reaches, as the URL parser reads it: lower case, with no
/// port or user part, however the text spelled it.
fn host_of(url: &str) -> Option<String> {
    Some(reqwest::Url::parse(url).ok()?.host_str()?.to_owned())
}

/// Whether the host `url` reaches is blocked by this instance, or no host
/// can be read from it.
async fn blocked(pool: &PgPool, url: &str) -> Result<bool> {
    let Some(host) = host_of(url) else {
        return Ok(true);
    };
    let restriction: Option<String> =
        sqlx::query_scalar("SELECT restriction FROM domain_restrictions WHERE lower(domain) = $1")
            .bind(&host)
            .fetch_optional(pool)
            .await?;
    Ok(restriction.as_deref() == Some("block"))
}

/// The key kept for `actor` when it was read within the last day. An
/// `Update` replaces it only for instances with a follower here, so an
/// older one is read again rather than trusted indefinitely.
async fn fresh(pool: &PgPool, actor: &Actor) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat_keys \
         WHERE actor_id = $1 AND updated_at > now() - interval '1 day')",
    )
    .bind(actor.id)
    .fetch_one(pool)
    .await?)
}

/// Whether mail can reach `address`: its domain is one the relay sends to.
pub fn reachable(address: &str, allowlist: &[String]) -> bool {
    address.rsplit_once('@').is_some_and(|(_, domain)| {
        allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain))
    })
}

/// The key published by the member of another instance whom `user` at
/// `domain` names, when mail can reach its address through `allowlist`:
/// the handle looked up through WebFinger, then their actor fetched afresh
/// unless a key is already kept for them, since the `Update` announcing a
/// new key goes to followers only. Nothing from a blocked domain, and
/// nothing for an actor of this instance.
pub async fn find_by_handle(
    pool: &PgPool,
    client: &reqwest::Client,
    user: &str,
    domain: &str,
    allowlist: &[String],
) -> Result<Option<(Actor, PublishedKey)>> {
    // Hosts are compared as parsed, so another spelling of a blocked one,
    // in the handle or in what its WebFinger names, is blocked too.
    if blocked(pool, &format!("https://{domain}/")).await? {
        return Ok(None);
    }
    let actor_uri = webfinger::resolve_handle(client, user, domain).await?;
    if blocked(pool, &actor_uri).await? {
        return Ok(None);
    }
    let actor = match noombat_identity::repo::find_by_ap_id(pool, &actor_uri).await? {
        Some(actor) if actor.is_local => return Ok(None),
        Some(actor) if fresh(pool, &actor).await? => actor,
        _ => {
            let (actor, document) = inbox::fetch_actor_document(pool, client, &actor_uri).await?;
            if let Some(document) = document {
                refresh(pool, client, &actor, &document).await;
            }
            actor
        }
    };
    Ok(stored(pool, &actor)
        .await?
        .filter(|key| reachable(&key.address, allowlist))
        .map(|key| (actor, key)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // Made by OpenPGP.js 6.3.2 as the web client makes a member's key, for
    // bob@chat.other.example.
    const BOB_KEY: &str = concat!(
        "xjMEavj5IBYJKwYBBAHaRw8BAQdA+THJeEdGK+3LSPJBlWzog4ltSKbjFmQxqiTt",
        "SBVD6Q/NGDxib2JAY2hhdC5vdGhlci5leGFtcGxlPsLAEwQTFgoAhQWCavj5IAML",
        "CQcJEKhIQEXrVyoyRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5v",
        "cmdAMqEj4GKqZDVIfAN8B+guLOgc2+2bgUOr7WiHQn+5FgUVCggODAQWAAIBAhkB",
        "ApsDAh4BFiEET+/VVy2ZtDTM2jurqEhARetXKjIAAG4aAQDK0Zfcu63JtkCYoz9G",
        "E50V0mKoGmkg/ZjWwOqqzZ/fmAEAtwAgspdbC+4PVicb9GWz0rTESwRG5F3zF+c9",
        "GuUZNwjOOARq+PkgEgorBgEEAZdVAQUBAQdA6UVKXLwllJ1hOVaPUeeRjZxox79m",
        "nD4IbSYLK6GW9moDAQgHwr4EGBYKAHAFgmr4+SAJEKhIQEXrVyoyRRQAAAAAABwA",
        "IHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmdVDzqKf+od11svOuffB5m8QLsn",
        "C9cIdLTtMjsGmRPovwKbDBYhBE/v1VctmbQ0zNo7q6hIQEXrVyoyAABhnAEA/sV0",
        "izgL/oIXAXuukPoAZ1kmaju4L7oqKAcFhruCBGsBAPQqOyO/5EVNru+fM27PU6KP",
        "bfGsxpbAKt2yboGSRYEI",
    );

    // A second key for the same address.
    const BOB_NEW_KEY: &str = concat!(
        "xjMEavj55BYJKwYBBAHaRw8BAQdAQ5dsDGkzEAJmNgjRfQRPEAdyjQdkG4JdMzZI",
        "OBxqz/vNGDxib2JAY2hhdC5vdGhlci5leGFtcGxlPsLAEwQTFgoAhQWCavj55AML",
        "CQcJENQc+56sTVtaRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5v",
        "cmfYJoWuyq53CZSAQuXhxfjJ+pTbnrxxOfK+pItGZj9eiwUVCggODAQWAAIBAhkB",
        "ApsDAh4BFiEEa+ow/ZyXtrTfi1791Bz7nqxNW1oAACA9AP4v5UKBeYqTWW2zrMr3",
        "6/J9wRLJgjIJ9ta8pJOQ4hwaVAD9HKX9E4JuLAoRXN+T6Di36rFun5N1CFuS3YoL",
        "9yhNrQLOOARq+PnkEgorBgEEAZdVAQUBAQdAYjMjWxoEtts4fnYgmY9JivbazNvO",
        "XnfTeFf+CT3lbUsDAQgHwr4EGBYKAHAFgmr4+eQJENQc+56sTVtaRRQAAAAAABwA",
        "IHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmePJbWHd0Bk2hmSOP5EHJHs2H+4",
        "0XwjHiAsBuGaqoVE7AKbDBYhBGvqMP2cl7a034te/dQc+56sTVtaAACukAEArtAQ",
        "rNfx2vDLGRMnOrCY8jcBwIqk6pyUQ70AGQVZHIgBANogwzUcpHI2GZ56t3U99pDz",
        "sirJAVRx5qUBxrVieNcD",
    );

    const ADDRESS: &str = "bob@chat.other.example";

    fn published() -> PublishedKey {
        PublishedKey {
            address: ADDRESS.into(),
            key: STANDARD.decode(BOB_KEY).expect("a fixture"),
        }
    }

    fn chat_key_value(address: &str) -> Value {
        json!({ "noombat:address": address, "noombat:keyData": BOB_KEY })
    }

    #[test]
    fn an_address_is_reachable_only_on_an_allowlisted_domain() {
        let allowlist = [
            "chat.other.example".to_owned(),
            "chat.third.example".to_owned(),
        ];
        assert!(reachable("bob@chat.other.example", &allowlist));
        assert!(reachable("bob@Chat.Third.Example", &allowlist));
        for unreachable in [
            "bob@chat.elsewhere.example",
            "bob@other.example",
            "bob@sub.chat.other.example",
            "chat.other.example",
            "",
        ] {
            assert!(!reachable(unreachable, &allowlist), "{unreachable}");
        }
        assert!(!reachable("bob@chat.other.example", &[]));
    }

    #[test]
    fn a_published_key_is_read_from_both_parts() {
        assert_eq!(parse(&chat_key_value(ADDRESS)), Some(published()));
        assert_eq!(parse(&json!({ "noombat:address": ADDRESS })), None);
        assert_eq!(parse(&json!({ "noombat:keyData": BOB_KEY })), None);
        let not_base64 = json!({ "noombat:address": ADDRESS, "noombat:keyData": "not base64!" });
        assert_eq!(parse(&not_base64), None);
    }

    #[test]
    fn a_key_binds_only_on_its_own_instances_chat_domain() {
        assert_eq!(
            binding(&published(), Some("chat.other.example"), "other.example"),
            Ok(())
        );
        assert_eq!(
            binding(&published(), Some("CHAT.Other.example"), "other.example"),
            Ok(())
        );
        assert!(binding(&published(), Some("chat.noombat.example"), "other.example").is_err());
        assert!(binding(&published(), Some("other.example"), "other.example").is_err());
        assert!(binding(&published(), None, "other.example").is_err());
    }

    #[test]
    fn a_chat_domain_must_be_the_instances_host_or_under_it() {
        // Another instance's chat domain, published by this one.
        let why =
            binding(&published(), Some("chat.other.example"), "evil.example").expect_err("refused");
        assert!(why.contains("not under"), "{why}");
        for host in [
            "chat.other.example",
            "other.example",
            "OTHER.example:8443",
            "example",
        ] {
            assert_eq!(
                binding(&published(), Some("chat.other.example"), host),
                Ok(()),
                "{host}"
            );
        }
        for host in [
            "her.example",
            "sub.chat.other.example",
            "ther.example",
            "other.example.com",
        ] {
            assert!(
                binding(&published(), Some("chat.other.example"), host).is_err(),
                "{host}"
            );
        }
    }

    #[test]
    fn a_key_must_pass_the_check_for_its_address() {
        // On the right domain, but the key names another address.
        let claimed = PublishedKey {
            address: "carol@chat.other.example".into(),
            ..published()
        };
        let why =
            binding(&claimed, Some("chat.other.example"), "other.example").expect_err("refused");
        assert!(why.contains("names another address"), "{why}");
        let broken = PublishedKey {
            key: vec![0x99, 0x00],
            ..published()
        };
        assert!(binding(&broken, Some("chat.other.example"), "other.example").is_err());
        let no_address = PublishedKey {
            address: "chat.other.example".into(),
            ..published()
        };
        assert!(binding(&no_address, Some("chat.other.example"), "other.example").is_err());
    }

    #[test]
    fn an_address_must_be_shaped_like_one_even_when_the_key_names_it() {
        // Bob's key with its User ID replaced: the key and the primary
        // packet keep one-octet lengths, so the User ID starts at 53.
        let key = STANDARD.decode(BOB_KEY).expect("a fixture");
        assert_eq!(&key[53..55], &[0xCD, 24]);
        let address = "bo/b@chat.other.example";
        let user_id = format!("<{address}>");
        let mut renamed = key[..53].to_vec();
        renamed.extend_from_slice(&[0xCD, user_id.len() as u8]);
        renamed.extend_from_slice(user_id.as_bytes());
        renamed.extend_from_slice(&key[55 + 24..]);
        assert_eq!(noombat_openpgp::check_public_key(&renamed, address), Ok(()));
        let published = PublishedKey {
            address: address.into(),
            key: renamed,
        };
        let why =
            binding(&published, Some("chat.other.example"), "other.example").expect_err("refused");
        assert!(why.contains("path separator"), "{why}");
    }

    async fn insert_actor(pool: &PgPool, ap_id: &str, is_local: bool) -> Actor {
        sqlx::query(
            "INSERT INTO actors (actor_type, ap_id, username, domain, public_key_pem, is_local) \
             VALUES ('individual', $1, 'bob', 'other.example', 'KEY', $2)",
        )
        .bind(ap_id)
        .bind(is_local)
        .execute(pool)
        .await
        .expect("actor");
        noombat_identity::repo::find_by_ap_id(pool, ap_id)
            .await
            .expect("read back")
            .expect("present")
    }

    /// Records `chatmail_domain` as other.example's, fetched just now.
    async fn cache_chatmail_domain(pool: &PgPool, chatmail_domain: Option<&str>) {
        sqlx::query(
            "INSERT INTO remote_chatmail_domains (domain, chatmail_domain) \
             VALUES ('other.example', $1)",
        )
        .bind(chatmail_domain)
        .execute(pool)
        .await
        .expect("cache");
    }

    fn document(chat_key: Option<Value>) -> ApActor {
        let mut doc = json!({
            "id": "https://other.example/users/bob",
            "type": "Person",
            "preferredUsername": "bob",
            "inbox": "https://other.example/users/bob/inbox",
            "outbox": "https://other.example/users/bob/outbox",
            "publicKey": {
                "id": "https://other.example/users/bob#main-key",
                "owner": "https://other.example/users/bob",
                "publicKeyPem": "KEY",
            },
        });
        if let Some(chat_key) = chat_key {
            doc["noombat:chatKey"] = chat_key;
        }
        serde_json::from_value(doc).expect("an actor document")
    }

    async fn kept(pool: &PgPool, actor: &Actor) -> Option<(String, Vec<u8>)> {
        sqlx::query_as("SELECT address, key_data FROM chat_keys WHERE actor_id = $1")
            .bind(actor.id)
            .fetch_optional(pool)
            .await
            .expect("query")
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_bound_key_is_kept_replaced_and_dropped_as_the_document_changes(pool: PgPool) {
        let actor = insert_actor(&pool, "https://other.example/users/bob", false).await;
        cache_chatmail_domain(&pool, Some("chat.other.example")).await;
        let client = reqwest::Client::new();

        refresh(
            &pool,
            &client,
            &actor,
            &document(Some(chat_key_value(ADDRESS))),
        )
        .await;
        assert_eq!(
            kept(&pool, &actor).await,
            Some((ADDRESS.into(), published().key))
        );

        let new_key = json!({ "noombat:address": ADDRESS, "noombat:keyData": BOB_NEW_KEY });
        refresh(&pool, &client, &actor, &document(Some(new_key))).await;
        let replaced = STANDARD.decode(BOB_NEW_KEY).expect("a fixture");
        assert_eq!(kept(&pool, &actor).await, Some((ADDRESS.into(), replaced)));

        refresh(&pool, &client, &actor, &document(None)).await;
        assert_eq!(kept(&pool, &actor).await, None);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_key_off_the_instances_chat_domain_is_dropped(pool: PgPool) {
        let actor = insert_actor(&pool, "https://other.example/users/bob", false).await;
        cache_chatmail_domain(&pool, Some("chat.other.example")).await;
        let client = reqwest::Client::new();
        refresh(
            &pool,
            &client,
            &actor,
            &document(Some(chat_key_value(ADDRESS))),
        )
        .await;
        assert!(kept(&pool, &actor).await.is_some());

        // The same document, now claiming an address on this instance's
        // chat domain: what was kept goes too.
        let claimed =
            json!({ "noombat:address": "bob@chat.noombat.example", "noombat:keyData": BOB_KEY });
        refresh(&pool, &client, &actor, &document(Some(claimed))).await;
        assert_eq!(kept(&pool, &actor).await, None);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn no_key_is_kept_from_an_instance_that_publishes_no_chat_domain(pool: PgPool) {
        let actor = insert_actor(&pool, "https://other.example/users/bob", false).await;
        cache_chatmail_domain(&pool, None).await;
        let client = reqwest::Client::new();
        refresh(
            &pool,
            &client,
            &actor,
            &document(Some(chat_key_value(ADDRESS))),
        )
        .await;
        assert_eq!(kept(&pool, &actor).await, None);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_local_members_key_is_never_touched(pool: PgPool) {
        let actor = insert_actor(&pool, "https://other.example/users/bob", true).await;
        sqlx::query("INSERT INTO chat_keys (actor_id, address, key_data) VALUES ($1, $2, '\\x99')")
            .bind(actor.id)
            .bind(ADDRESS)
            .execute(&pool)
            .await
            .expect("local key");
        cache_chatmail_domain(&pool, Some("chat.other.example")).await;
        let client = reqwest::Client::new();
        refresh(&pool, &client, &actor, &document(None)).await;
        assert_eq!(
            kept(&pool, &actor).await,
            Some((ADDRESS.into(), vec![0x99]))
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_chat_domain_is_used_when_nodeinfo_cannot_be_read(pool: PgPool) {
        // `.invalid` never resolves, so the fetch fails at once.
        sqlx::query(
            "INSERT INTO remote_chatmail_domains (domain, chatmail_domain, fetched_at) \
             VALUES ('other.invalid', 'chat.other.invalid', now() - interval '2 days')",
        )
        .execute(&pool)
        .await
        .expect("expired entry");
        let client = reqwest::Client::new();
        let domain =
            nodeinfo::remote_chatmail_domain(&pool, &client, "https://other.invalid/users/bob")
                .await;
        assert_eq!(
            domain.expect("the expired entry").as_deref(),
            Some("chat.other.invalid")
        );
        let unknown =
            nodeinfo::remote_chatmail_domain(&pool, &client, "https://unknown.invalid/users/bob")
                .await;
        assert!(unknown.is_err(), "not known is not none: {unknown:?}");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_kept_key_stays_while_the_chat_domain_cannot_be_read(pool: PgPool) {
        // `.invalid` never resolves and nothing is cached for it.
        let actor = insert_actor(&pool, "https://other.invalid/users/bob", false).await;
        sqlx::query("INSERT INTO chat_keys (actor_id, address, key_data) VALUES ($1, $2, '\\x99')")
            .bind(actor.id)
            .bind(ADDRESS)
            .execute(&pool)
            .await
            .expect("a kept key");
        let client = reqwest::Client::new();
        refresh(
            &pool,
            &client,
            &actor,
            &document(Some(chat_key_value(ADDRESS))),
        )
        .await;
        assert_eq!(
            kept(&pool, &actor).await,
            Some((ADDRESS.into(), vec![0x99]))
        );
    }
}
