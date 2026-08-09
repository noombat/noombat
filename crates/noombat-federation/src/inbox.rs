// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Inbox handler for processing inbound ActivityPub activities.

use noombat_ap::activity::{Activity, types};
use noombat_ap::context::{AS_PUBLIC, default_context};
use noombat_ap::object::ApActor;
use noombat_core::actor::Actor;
use noombat_core::error::{NoombatError, Result};
use noombat_identity::repo;
use reqwest::Url;
use serde_json::json;
use sqlx::PgPool;
use tracing::{info, warn};

use crate::delivery;
use crate::integrity_proof::VerificationResult;
use crate::relay_verify;

/// Dispatch an inbound activity to the appropriate handler.
///
/// `verified_actor` is the identity whose key actually signed the request,
/// i.e. the HTTP Signature `keyId` with its fragment stripped, as derived by
/// the caller. Every handler below attributes its effect to `activity.actor`
/// alone, so without this binding the signature proves only that *some*
/// fetchable actor signed the bytes, not that it is the actor the activity
/// claims to come from.
///
/// # Errors
///
/// Returns [`NoombatError::Forbidden`] when `verified_actor` does not equal
/// `activity.actor`.
pub async fn process_activity(
    pool: &PgPool,
    http_client: &reqwest::Client,
    verified_actor: &str,
    document: &serde_json::Value,
    activity: Activity,
) -> Result<()> {
    // ..... SIGNER-TO-ACTOR BINDING .....
    //
    // This must precede every other statement: the handlers below trust
    // `activity.actor` completely, and `find_by_ap_id` does not filter on
    // `is_local`, so an unbound activity can attribute an effect to a local
    // actor as readily as to a third-party remote one.
    if verified_actor != activity.actor {
        warn!(
            verified_actor,
            claimed_actor = %activity.actor,
            activity_type = %activity.activity_type,
            "rejecting activity whose actor does not match the signing key"
        );
        return Err(NoombatError::Forbidden);
    }

    // ..... ENVELOPE INTEGRITY PROOF .....
    //
    // Checked against `document`, the bytes as received, not against a
    // re-serialisation of `activity`: `Activity` models only the
    // properties it needs and JCS hashes every property that was
    // present, so a round trip through the struct cannot reproduce the
    // signed form.
    //
    // An absent proof is not an error. Direct delivery is authenticated
    // by the HTTP Signature the guard above binds to `activity.actor`.
    // What a proof adds is evidence that outlives the transport, which
    // is what a Group or a relay redistributing this activity will have
    // to rely on.
    if relay_verify::verify_inbound_proof(pool, http_client, document, &activity.actor).await
        == VerificationResult::Invalid
    {
        warn!(
            actor = %activity.actor,
            activity_type = %activity.activity_type,
            "rejecting activity whose envelope integrity proof does not verify"
        );
        return Err(NoombatError::Forbidden);
    }

    let activity_type = activity.activity_type.as_str();
    info!(
        actor = %activity.actor,
        activity_type,
        "processing inbound activity"
    );

    match activity_type {
        types::FOLLOW => handle_follow(pool, http_client, &activity).await,
        types::UNDO => handle_undo(pool, http_client, &activity).await,
        types::CREATE => handle_create(pool, http_client, &activity).await,
        types::DELETE => handle_delete(pool, &activity).await,
        types::ACCEPT => handle_accept(pool, http_client, &activity).await,
        types::REJECT => handle_reject(pool, http_client, &activity).await,
        types::ANNOUNCE => handle_announce(pool, http_client, &activity).await,
        types::LIKE => handle_like(pool, http_client, &activity).await,
        types::UPDATE => handle_update(pool, http_client, &activity).await,
        types::BLOCK => handle_block(pool, http_client, &activity).await,
        types::MOVE => crate::move_actor::handle_inbound_move(pool, http_client, &activity).await,
        types::FLAG => crate::flag::handle_inbound_flag(pool, http_client, &activity).await,
        other => {
            warn!(activity_type = other, "unsupported activity type; ignoring");
            Ok(())
        }
    }
}

// ..... ACTOR RESOLUTION .....

/// Fetch and persist an actor's ActivityPub profile.
///
/// Checks the local database cache first. On cache miss, fetches the
/// profile over HTTP and upserts it into the `actors` table.
///
/// **Resolves local actors as well as remote ones**, deliberately. The
/// cache lookup is [`repo::find_by_ap_id`], which does not filter on
/// `is_local`, so passing a local actor's URI yields that local row.
/// Several callers depend on this: blocking or muting a local user
/// (`noombat-api::routes::interactions`) and an inbound `Move` whose
/// target is an account on this instance (`move_actor`) both resolve a
/// local URI through here legitimately.
///
/// Callers for which a local actor would be nonsense (anything treating
/// the result as a counterparty on another instance) must use
/// [`resolve_inbound_signer`] instead.
///
/// This was called `resolve_remote_actor` until the name was found to be
/// actively misleading: it had been read as a promise that the result is
/// remote, which it never was.
pub async fn resolve_actor(
    pool: &PgPool,
    http_client: &reqwest::Client,
    actor_uri: &str,
) -> Result<Actor> {
    if let Some(cached) = repo::find_by_ap_id(pool, actor_uri).await? {
        return Ok(cached);
    }

    // Check whether this actor has been tombstoned (410 Gone) before
    // incurring an HTTP round-trip.
    let is_tombstoned: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tombstoned_actors WHERE ap_id = $1)")
            .bind(actor_uri)
            .fetch_one(pool)
            .await
            .unwrap_or(false);

    if is_tombstoned {
        return Err(NoombatError::Federation(format!(
            "actor {actor_uri} is tombstoned (previously returned 410 Gone)"
        )));
    }

    let response = http_client
        .get(actor_uri)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("failed to fetch {actor_uri}: {e}")))?;

    if response.status().as_u16() == 410 {
        // Record the tombstone for future short-circuiting.
        let _ = sqlx::query(
            "INSERT INTO tombstoned_actors (ap_id) VALUES ($1) \
             ON CONFLICT (ap_id) DO NOTHING",
        )
        .bind(actor_uri)
        .execute(pool)
        .await;
        return Err(NoombatError::Federation(format!(
            "remote actor {actor_uri} returned 410 Gone; tombstoned"
        )));
    }

    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "remote actor returned HTTP {}",
            response.status()
        )));
    }

    // `Response::json` consumes the response, so the URL the document was
    // actually served from (after any redirects) has to be taken now.
    let final_url = response.url().clone();

    let ap_actor: ApActor = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid actor JSON: {e}")))?;

    let remote = ap_actor_to_remote(&ap_actor, &final_url, actor_uri)?;

    repo::upsert_remote_actor(pool, &remote).await
}

/// Resolve the actor whose key signed an inbound request.
///
/// Identical to [`resolve_actor`] except that a local actor is
/// refused. This instance never sends signed requests to its own inbox,
/// so a signer URI that resolves to a local row is always illegitimate:
/// it means a peer named one of our actors as the signer.
///
/// That is not currently reachable as a forgery: the signature would
/// still have to verify against the local actor's published key, which
/// an attacker does not hold, and `process_activity` separately requires
/// `activity.actor` to equal the verified signer. This guard exists so
/// that neither of those has to stay true for the property to hold.
///
/// # Errors
///
/// Returns [`NoombatError::Forbidden`] when `actor_uri` resolves to a
/// local actor; otherwise propagates [`resolve_actor`].
pub async fn resolve_inbound_signer(
    pool: &PgPool,
    http_client: &reqwest::Client,
    actor_uri: &str,
) -> Result<Actor> {
    let actor = resolve_actor(pool, http_client, actor_uri).await?;

    if actor.is_local {
        warn!(
            actor_uri,
            "refusing an inbound request whose signer resolves to a local actor"
        );
        return Err(NoombatError::Forbidden);
    }

    Ok(actor)
}

/// Normalise an actor URI for comparison.
///
/// [`Url`] parsing already lowercases the scheme and host and drops a
/// default port, so `HTTPS://Example.COM:443/users/alice` and
/// `https://example.com/users/alice` converge here. On top of that a
/// single trailing slash is trimmed from the path, so `/users/alice`
/// and `/users/alice/` compare equal, and the fragment is dropped
/// (fragments are never sent to the origin).
///
/// Percent-encoding is deliberately NOT decoded. `/users/%61lice` is a
/// different path from `/users/alice` as far as the origin server is
/// concerned; treating them as equal would let a document claim an id
/// it was not actually served from.
fn normalise_actor_uri(url: &Url) -> String {
    let mut url = url.clone();
    url.set_fragment(None);
    let trimmed = url.path().trim_end_matches('/').to_owned();
    url.set_path(&trimmed);
    url.to_string()
}

/// Whether two actor URIs denote the same actor.
///
/// Both sides are normalised with [`normalise_actor_uri`], so a trailing
/// slash, a default port or a difference in scheme/host case does not
/// make two references to one actor look like two actors. A string that
/// will not parse as a URL is compared literally: it cannot match a
/// normalised URL, which is the safe direction for a guard.
pub(crate) fn same_actor_uri(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(a), Ok(b)) => normalise_actor_uri(&a) == normalise_actor_uri(&b),
        _ => a == b,
    }
}

/// Re-fetch a remote actor, bypassing the cache, and return the
/// `assertionMethod` key that `vm_id` names.
///
/// Used when a cached key fails to verify a proof, which is as likely to
/// mean "the peer rotated" as "this is a forgery". Two things differ from
/// [`resolve_actor`]: the cache is not consulted, and the key returned is
/// the one whose `id` matches the verification method rather than
/// whichever Multikey happens to come first. A peer that publishes two
/// keys, or that rotates, is otherwise unverifiable forever.
///
/// The refreshed key is written back so the next activity from this peer
/// verifies from cache instead of fetching again.
///
/// Returns `None` on any failure, including the concurrency cap: the
/// caller treats that as "no new key to try", never as proof of forgery.
pub(crate) async fn refresh_assertion_key(
    pool: &PgPool,
    http_client: &reqwest::Client,
    actor_uri: &str,
    vm_id: &str,
) -> Option<String> {
    let _permit = crate::relay_verify::origin_fetch_permit().await?;

    let signing_actor_id = crate::signed_fetch::find_local_signing_actor(pool)
        .await
        .ok()?;
    let response = crate::signed_fetch::signed_get(pool, http_client, actor_uri, signing_actor_id)
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }

    // Taken before `json()` consumes the response; see `resolve_actor`.
    let final_url = response.url().clone();
    let ap_actor: ApActor = response.json().await.ok()?;

    // The document still has to be entitled to the `id` it claims (P0-3);
    // a refresh is not a licence to skip that.
    let mut remote = ap_actor_to_remote(&ap_actor, &final_url, actor_uri).ok()?;

    let named = ap_actor.assertion_method.as_ref().and_then(|methods| {
        methods
            .iter()
            .find(|m| {
                m.key_type == "Multikey"
                    && m.id == vm_id
                    && crate::integrity_proof::is_ed25519_multikey(&m.public_key_multibase)
            })
            .map(|m| m.public_key_multibase.clone())
    });

    // Cache the key that the proof actually names, so a peer with several
    // keys does not force a fetch on every activity.
    if let Some(ref key) = named {
        remote.ed25519_public_key = Some(key.clone());
    }
    let cached = remote.ed25519_public_key.clone();
    let _ = repo::upsert_remote_actor(pool, &remote).await;

    named.or(cached)
}

/// Whether two URLs share a scheme, host and effective port.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Check that a fetched actor document is entitled to the `id` it claims.
///
/// Two conditions must hold, and they guard different attacks:
///
/// 1. **Same origin.** `reqwest` follows up to ten redirects by default,
///    so the document may have arrived from somewhere other than the URI
///    requested. A cross-origin redirect is refused outright: without
///    this, `good.example` could 302 to `evil.example` and have the
///    result persisted under `evil.example`'s id, while the caller (and,
///    for inbound activities, the HTTP Signature) believed it was talking
///    to `good.example`.
/// 2. **Id matches the URL it came from.** Otherwise a remote server can
///    return a document claiming `id` of a LOCAL actor, and
///    `upsert_remote_actor`'s `ON CONFLICT (ap_id)` overwrites that
///    actor's published signing key from an unauthenticated request.
///
/// Same-origin redirects (a trailing-slash canonicalisation, say) are
/// permitted, and the document's `id` is then compared against the URL
/// actually served, not the one requested.
///
/// # Errors
///
/// Returns [`NoombatError::Federation`] when either condition fails, or
/// when the requested URI or the document's `id` will not parse.
fn verify_fetched_actor_id(doc_id: &str, final_url: &Url, requested_uri: &str) -> Result<()> {
    let requested = Url::parse(requested_uri).map_err(|e| {
        NoombatError::Federation(format!("actor URI {requested_uri} is not a valid URL: {e}"))
    })?;

    if !same_origin(final_url, &requested) {
        return Err(NoombatError::Federation(format!(
            "actor fetch for {requested_uri} redirected across origins to {final_url}; refusing"
        )));
    }

    let claimed = Url::parse(doc_id).map_err(|e| {
        NoombatError::Federation(format!(
            "actor document id {doc_id} is not a valid URL: {e}"
        ))
    })?;

    if normalise_actor_uri(&claimed) != normalise_actor_uri(final_url) {
        return Err(NoombatError::Federation(format!(
            "actor document claims id {doc_id} but was served from {final_url}; refusing"
        )));
    }

    Ok(())
}

/// Convert a fetched [`ApActor`] into a [`repo::RemoteActor`] for
/// persistence, rejecting documents that claim an `id` they were not
/// served from.
///
/// This function is the single conversion point used by both
/// [`resolve_actor`] and `handle_update_actor`, ensuring
/// that the field mapping (and now the `id` check) remains
/// consistent.
///
/// `final_url` must be the URL the document was actually served from
/// (`Response::url()`, i.e. after redirects), not the one requested;
/// `requested_uri` is the original, and is used for the same-origin
/// check. `domain` is derived from `final_url` so that it can never
/// disagree with the persisted `ap_id`.
///
/// # Errors
///
/// Propagates [`verify_fetched_actor_id`].
fn ap_actor_to_remote(
    ap_actor: &ApActor,
    final_url: &Url,
    requested_uri: &str,
) -> Result<repo::RemoteActor> {
    verify_fetched_actor_id(&ap_actor.id, final_url, requested_uri)?;

    let domain = extract_domain(final_url.as_str()).unwrap_or_default();

    let shared_inbox_url = ap_actor
        .endpoints
        .as_ref()
        .and_then(|ep| ep.get("sharedInbox"))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Extract the Ed25519 public key from `assertionMethod` (FEP-521a).
    //
    // The first `Multikey` entry that actually decodes as Ed25519 wins.
    // Selecting on the `z` prefix alone was wrong: that is base58btc,
    // which every Multikey type uses, so an actor publishing a P-256 or
    // RSA key first had it stored in `ed25519_public_key`, where it fails
    // every proof they ever send. Remote actors publishing no Ed25519 key
    // yield `None`, which is the honest answer.
    let ed25519_public_key = ap_actor.assertion_method.as_ref().and_then(|methods| {
        methods
            .iter()
            .find(|m| {
                m.key_type == "Multikey"
                    && crate::integrity_proof::is_ed25519_multikey(&m.public_key_multibase)
            })
            .map(|m| m.public_key_multibase.clone())
    });

    Ok(repo::RemoteActor {
        ap_id: ap_actor.id.clone(),
        username: ap_actor.preferred_username.clone(),
        domain,
        display_name: ap_actor.name.clone(),
        // The fourth remote-HTML sink, and the one the three post paths
        // do not cover: a peer's `summary` is raw HTML, rendered with
        // `|safe` on the profile page. Sanitised and bounded here, via
        // `sanitise_remote_html`, which `crate::backfill` also calls so
        // that stored rows are re-derived by the same rule.
        summary_html: ap_actor.summary.as_deref().map(sanitise_remote_html),
        sanitiser_version: noombat_markup::sanitise::STRICT_VERSION,
        public_key_pem: ap_actor.public_key.public_key_pem.clone(),
        actor_type: match ap_actor.actor_type.as_str() {
            "Person" => "individual".to_owned(),
            "Organization" => "company".to_owned(),
            "Group" => "group".to_owned(),
            _ => "individual".to_owned(),
        },
        inbox_url: ap_actor.inbox.clone(),
        shared_inbox_url,
        ed25519_public_key,
    })
}

/// The renderable content of a remote object, sanitised.
///
/// Constructed only by [`extract_remote_content`], and its fields are
/// only ever produced by passing peer input through
/// [`noombat_markup::sanitise::clean_strict`]. That is the point: three
/// ingestion paths used to repeat the extraction inline, and a fourth
/// added later would have had to remember to sanitise. Here it cannot
/// be forgotten, because there is no other way to obtain the values.
pub(crate) struct RemoteContent {
    /// Sanitised HTML, safe to render with Askama's `|safe`.
    pub content_html: String,
    /// The peer's Markdown source from the Mastodon-convention `source`
    /// property, when it declared `text/markdown`.
    ///
    /// `None` when the peer sent no Markdown. It previously fell back to
    /// a copy of `content_html`, i.e. it stored HTML in a column named
    /// for Markdown, which is why unsanitised input reached two columns
    /// from one binding. `None` says what is actually true.
    pub content_md: Option<String>,
    /// The [`noombat_markup::sanitise::STRICT_VERSION`] that produced
    /// `content_html`, persisted so the value can be re-derived when the
    /// policy changes.
    pub sanitiser_version: i16,
}

/// Upper bound on a single peer-supplied string before sanitisation.
///
/// Generous, because Noombat federates long-form Articles and not just
/// Notes, but bounded, because `content` arrives from an unauthenticated
/// stranger and every byte of it is sanitised, indexed into Meilisearch
/// and rendered into other people's feeds. Without a cap the only limit
/// is the HTTP body limit, and one `Create` can force megabytes of
/// `ammonia` parsing per delivery.
///
/// Truncation happens *before* sanitisation, so a cut that lands inside a
/// tag cannot produce broken markup: `ammonia` reparses what is left and
/// closes whatever the cut opened.
pub(crate) const MAX_REMOTE_HTML_BYTES: usize = 512 * 1024;

/// Truncate at the last UTF-8 character boundary at or before `max`.
///
/// `String` is not indexable at arbitrary byte offsets, so slicing on a
/// raw length would panic on multi-byte input, which is trivially
/// attacker-reachable by padding a document with non-ASCII text.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Bound and sanitise one piece of peer-supplied HTML.
///
/// The whole of the ingestion policy in one place:
/// [`extract_remote_content`] applies it to `content`,
/// [`ap_actor_to_remote`] to an actor `summary`, and [`crate::backfill`]
/// to rows already in the table. Sanitising is not a property any of
/// those sites can choose to skip, because none of them has the raw
/// string in hand any other way.
///
/// Actor summaries matter here in a way post content does not: `actors`
/// has no column holding the document verbatim. Unlike
/// `posts.ap_object`, there is no wire record to re-derive a summary
/// from. The stored `summary_html` *is* the only copy, so the backfill
/// re-cleans it in place and must apply exactly this rule to do so.
pub(crate) fn sanitise_remote_html(html: &str) -> String {
    noombat_markup::sanitise::clean_strict(truncate_on_char_boundary(html, MAX_REMOTE_HTML_BYTES))
}

/// Verify an inbound object's integrity proof and reduce it to the
/// value stored in `integrity_proof_verified`.
///
/// Returns `Err(Forbidden)` when a proof is present and fails: a
/// document that contradicts its own proof is discarded, not stored, so
/// the column never has to mean "kept, but known bad". `Ok(None)` covers
/// both "no proof" and "proof present but the author's key is not
/// cached", which are the same thing from the column's point of view:
/// nothing was checked.
///
/// `expected_author` is the actor the row will be attributed to. The
/// proof has to come from that actor, or a `TRUE` here would certify the
/// wrong party; see [`relay_verify::verify_inbound_proof`].
///
/// `object` must be the document exactly as received. JCS hashes bytes,
/// so this has to run before anything derives from or rewrites the
/// document. It is the same constraint that requires `ap_object` to be
/// persisted verbatim rather than sanitised in place: rewriting the
/// record would destroy the bytes a stored `TRUE` refers to.
async fn verify_object_proof(
    pool: &PgPool,
    http_client: &reqwest::Client,
    object: &serde_json::Value,
    expected_author: &str,
    ap_id: &str,
) -> Result<Option<bool>> {
    match relay_verify::verify_inbound_proof(pool, http_client, object, expected_author).await {
        VerificationResult::Valid => Ok(Some(true)),
        VerificationResult::Absent => Ok(None),
        VerificationResult::Invalid => {
            warn!(
                ap_id,
                "object carries an integrity proof that does not verify; discarding"
            );
            Err(NoombatError::Forbidden)
        }
    }
}

/// Extract and sanitise the renderable content of a remote object.
///
/// This is the single point at which peer-supplied HTML becomes storable.
/// Every federated ingestion path goes through it, and so does
/// [`crate::backfill`] when it re-derives already-stored rows. The
/// re-derivation has to agree with ingestion byte for byte, which it can
/// only guarantee by calling the same function.
///
/// The peer's original bytes are not discarded: they remain in
/// `posts.ap_object`, which is stored verbatim precisely so that FEP-8b32
/// proofs stay verifiable. What is sanitised here is the *projection*
/// that gets rendered.
pub(crate) fn extract_remote_content(object: &serde_json::Value) -> RemoteContent {
    let raw_html = object
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    // The Mastodon-convention `source` property, when it declares
    // Markdown. Not sanitised: it is Markdown, not HTML, and nothing
    // renders it as HTML. If that ever changes it must be rendered
    // through `noombat_markup::render`, which sanitises its own output.
    // Capped all the same, since it is peer-supplied and persisted.
    let content_md = object
        .get("source")
        .and_then(|src| {
            let media = src.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
            if media == "text/markdown" {
                src.get("content").and_then(|v| v.as_str())
            } else {
                None
            }
        })
        .map(|md| truncate_on_char_boundary(md, MAX_REMOTE_HTML_BYTES).to_owned());

    RemoteContent {
        content_html: sanitise_remote_html(raw_html),
        content_md,
        sanitiser_version: noombat_markup::sanitise::STRICT_VERSION,
    }
}

/// Extract the domain from a URI (e.g. `https://noombat.social/users/alice` to `noombat.social`).
pub fn extract_domain(uri: &str) -> Option<String> {
    uri.strip_prefix("https://")
        .or_else(|| uri.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .map(String::from)
}

/// Extract the local username from an actor URI.
///
/// Accepts URIs of the form `https://{domain}/users/{username}` (with
/// an optional trailing slash). Returns `None` if the URI does not
/// contain a `/users/` segment or if the extracted username is empty.
fn extract_local_username(actor_uri: &str) -> Option<&str> {
    // Strip the scheme and domain prefix, leaving `/users/{username}[/]`.
    let path = actor_uri
        .strip_prefix("https://")
        .or_else(|| actor_uri.strip_prefix("http://"))
        .and_then(|rest| rest.find('/').map(|pos| &rest[pos..]))?;

    let after_users = path.strip_prefix("/users/")?;
    let username = after_users.strip_suffix('/').unwrap_or(after_users);

    // Reject empty usernames and paths with additional segments
    // (e.g. `/users/alice/inbox` contains '/' after stripping).
    if username.is_empty() || username.contains('/') {
        return None;
    }

    Some(username)
}

// ..... FOLLOW .....

async fn handle_follow(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let target_uri = activity
        .object
        .as_str()
        .ok_or_else(|| NoombatError::BadRequest("Follow object must be a string URI".into()))?;

    let target_username = extract_local_username(target_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

    info!(follower = %activity.actor, target = %target_uri, "received Follow");

    // Resolve the remote follower and the local target concurrently.
    let (remote_actor, local_actor) = tokio::try_join!(
        resolve_actor(pool, http_client, &activity.actor),
        repo::find_local_by_username(pool, target_username),
    )?;

    // Determine whether to auto-accept based on the local actor's privacy settings.
    let auto_accept = !local_actor.actor_privacy.require_follow_approval;

    // Persist the follow relationship, recording the Follow activity's
    // AP id so that Accept / Reject can reference it.
    repo::create_follow_with_ap_id(
        pool,
        remote_actor.id,
        local_actor.id,
        auto_accept,
        Some(&activity.id),
    )
    .await?;

    if auto_accept {
        // Construct and deliver an Accept { Follow } activity.
        let accept_id = format!(
            "{}#accept-follow-{}",
            local_actor.ap_id,
            chrono::Utc::now().timestamp()
        );
        let accept_activity = json!({
            "@context": default_context(),
            "id": accept_id,
            "type": "Accept",
            "actor": local_actor.ap_id,
            "object": {
                "id": activity.id,
                "type": "Follow",
                "actor": remote_actor.ap_id,
                "object": local_actor.ap_id
            }
        });

        let remote_inbox = remote_actor
            .inbox_url
            .clone()
            .unwrap_or_else(|| format!("{}/inbox", remote_actor.ap_id));
        delivery::enqueue(pool, local_actor.id, &accept_activity, &remote_inbox).await?;

        info!(
            follower = %remote_actor.ap_id,
            target = %local_actor.ap_id,
            "follow auto-accepted; Accept enqueued"
        );
    } else {
        info!(
            follower = %remote_actor.ap_id,
            target = %local_actor.ap_id,
            "follow pending approval"
        );
    }

    Ok(())
}

// ..... UNDO .....

async fn handle_undo(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // The `object` of an Undo is the activity being reversed.
    let inner_type = activity
        .object
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match inner_type {
        "Follow" => {
            let target_uri = activity
                .object
                .get("object")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    NoombatError::BadRequest("Undo Follow: missing inner object".into())
                })?;

            // Extract the inner Follow activity's AP id (if present)
            // for inclusion in the deletion predicate, consistent with
            // the Undo { Like } and Undo { Announce } branches.
            let inner_ap_id = activity.object.get("id").and_then(|v| v.as_str());

            let target_username = extract_local_username(target_uri)
                .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

            let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;
            let local_actor = repo::find_local_by_username(pool, target_username).await?;

            // Delete by relationship IDs (the unique constraint) and,
            // when available, verify the Follow activity's AP id.
            // The ap_id check is a secondary guard: if the inner
            // Follow's id does not match the stored row, the deletion
            // is a no-op (the Undo targets a different Follow).
            if let Some(follow_ap_id) = inner_ap_id {
                sqlx::query(
                    "DELETE FROM follows \
                     WHERE follower_id = $1 AND following_id = $2 AND ap_id = $3",
                )
                .bind(remote_actor.id)
                .bind(local_actor.id)
                .bind(follow_ap_id)
                .execute(pool)
                .await?;
            } else {
                // Fallback: some implementations omit the inner
                // Follow's id. Delete by relationship IDs only.
                repo::delete_follow(pool, remote_actor.id, local_actor.id).await?;
            }

            info!(
                follower = %remote_actor.ap_id,
                target = %local_actor.ap_id,
                "follow undone"
            );
        }
        "Like" => {
            let inner_ap_id = activity
                .object
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NoombatError::BadRequest("Undo Like: missing id".into()))?;

            let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;
            sqlx::query("DELETE FROM likes WHERE ap_id = $1 AND actor_id = $2")
                .bind(inner_ap_id)
                .bind(remote_actor.id)
                .execute(pool)
                .await?;
            info!(ap_id = %inner_ap_id, "like undone");
        }
        "Announce" => {
            let inner_ap_id = activity
                .object
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| NoombatError::BadRequest("Undo Announce: missing id".into()))?;

            let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;
            sqlx::query("DELETE FROM boosts WHERE ap_id = $1 AND actor_id = $2")
                .bind(inner_ap_id)
                .bind(remote_actor.id)
                .execute(pool)
                .await?;
            info!(ap_id = %inner_ap_id, "boost undone");
        }
        "Block" => {
            // The inner object of Undo { Block } is the blocked actor's URI.
            let target_uri = activity
                .object
                .get("object")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    NoombatError::BadRequest("Undo Block: missing inner object".into())
                })?;

            let target_username = extract_local_username(target_uri)
                .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

            let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;
            let local_actor = repo::find_local_by_username(pool, target_username).await?;

            sqlx::query("DELETE FROM blocks WHERE actor_id = $1 AND target_id = $2")
                .bind(remote_actor.id)
                .bind(local_actor.id)
                .execute(pool)
                .await?;
            info!(
                actor = %remote_actor.ap_id,
                target = %local_actor.ap_id,
                "block undone"
            );
        }
        other => {
            warn!(inner_type = other, "unsupported Undo target; ignoring");
        }
    }

    Ok(())
}

// ..... CREATE .....

async fn handle_create(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object = &activity.object;

    let object_type = object.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let ap_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Create object missing id".into()))?;

    // Before `extract_remote_content`, which is the first thing to
    // derive from the document. The row is attributed to `activity.actor`
    // (see `remote_actor` below), so that is who the proof must come from.
    let integrity_proof_verified =
        verify_object_proof(pool, http_client, object, &activity.actor, ap_id).await?;

    let content = extract_remote_content(object);

    let post_type = match object_type {
        "Note" => "note",
        "Article" => "article",
        _ => {
            warn!(object_type, "unsupported Create object type; ignoring");
            return Ok(());
        }
    };

    info!(actor = %activity.actor, object_type, ap_id, "received Create");

    // ..... ARTICLE-SPECIFIC FIELDS .....
    //
    // Articles carry a title in the `name` property (ActivityStreams)
    // and may carry a featured image as the `image` property (used by
    // Ghost) or as the first `Image`-typed element in `attachment`
    // (used by WordPress, Mastodon, and others).

    let title = object
        .get("name")
        .and_then(|v| v.as_str())
        .map(String::from);

    let featured_image_url = extract_image_url(object);

    // Resolve the remote author.
    let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;

    // Derive visibility from the activity's to/cc addressing.
    //
    // Some implementations place to/cc only on the inner object (the
    // Note or Article) rather than on the wrapping Create activity.
    // Fall back to the inner object's addressing when the envelope
    // fields are absent.
    let to = activity
        .to
        .clone()
        .or_else(|| extract_string_array(&activity.object, "to"));
    let cc = activity
        .cc
        .clone()
        .or_else(|| extract_string_array(&activity.object, "cc"));
    let visibility = derive_visibility(&to, &cc);

    // Cross-post de-duplication: if an existing local post matches
    // the canonical URI or URL of the inbound object, link to it
    // rather than creating a duplicate.
    if let Ok(Some(existing_id)) = crate::crosspost::try_dedup(pool, &activity.object).await {
        info!(
            ap_id,
            existing_id = %existing_id,
            "inbound Create de-duplicated; skipping insertion"
        );
        return Ok(());
    }

    // Extract the `inReplyTo` property for reply threading. The
    // property may be a string URI (Mastodon) or an object with an
    // `id` field (some other implementations).
    let in_reply_to = extract_in_reply_to(object);

    // Persist the remote post.
    let remote_post = repo::RemotePost {
        actor_id: remote_actor.id,
        ap_id: ap_id.to_owned(),
        post_type: post_type.to_owned(),
        title,
        featured_image_url,
        content_md: content.content_md,
        content_html: content.content_html,
        sanitiser_version: content.sanitiser_version,
        in_reply_to,
        visibility,
        ap_object: activity.object.clone(),
        integrity_proof_verified,
    };

    let post_id = repo::create_remote_post(pool, &remote_post).await?;

    // A concurrent delivery won the insert. The proof this delivery
    // verified still applies to the same bytes, so hand it over rather
    // than dropping it; nothing re-verifies a stored row later.
    if post_id.is_none()
        && integrity_proof_verified == Some(true)
        && let Err(e) = repo::record_verified_proof(pool, ap_id).await
    {
        warn!(
            ap_id,
            "failed to record a verified proof on an existing row: {e}"
        );
    }

    // ..... HASHTAG LINKING .....
    //
    // The ActivityPub `tag` array carries `Hashtag` objects (the same
    // format used by Mastodon, Lemmy, and others):
    //
    //   { "type": "Hashtag", "name": "#rust", "href": "https://..." }
    //
    // Extract the names and link them to the newly persisted post so
    // that hashtag-following feeds include federated content.

    if let Some(post_id) = post_id {
        // Record the canonical URI (if present) so that future
        // cross-post de-duplication can match this post.
        if let Some(canonical) = crate::crosspost::extract_canonical_uri(object)
            && let Err(e) = crate::crosspost::set_canonical_uri(pool, post_id, &canonical).await
        {
            warn!(ap_id, "failed to set canonical_uri: {e}");
        }

        let hashtag_names = extract_hashtags_from_tags(object);
        if !hashtag_names.is_empty()
            && let Err(e) =
                noombat_identity::hashtags::link_post_hashtags(pool, post_id, &hashtag_names).await
        {
            warn!(ap_id, "failed to link hashtags for remote post: {e}");
        }
        info!(ap_id, "remote post persisted");
    } else {
        info!(ap_id, "remote post already known; skipped");
    }

    Ok(())
}

// ..... DELETE .....

async fn handle_delete(pool: &PgPool, activity: &Activity) -> Result<()> {
    let object_id = activity
        .object
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| activity.object.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Delete: missing object id".into()))?;

    info!(actor = %activity.actor, object = %object_id, "received Delete");

    // Verify that the requesting actor owns the post before deleting.
    let is_authorised = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM posts p
           JOIN actors a ON a.id = p.actor_id
           WHERE p.ap_id = $1 AND a.ap_id = $2"#,
    )
    .bind(object_id)
    .bind(&activity.actor)
    .fetch_one(pool)
    .await?;

    if is_authorised == 0 {
        // Either the post does not exist locally, or the requesting
        // actor is not its author.  Both cases are safe to ignore:
        // the post may have already been deleted, or the request is
        // unauthorised.
        warn!(
            actor = %activity.actor,
            object = %object_id,
            "Delete ignored: post not found or actor mismatch"
        );
        return Ok(());
    }

    sqlx::query("DELETE FROM posts WHERE ap_id = $1")
        .bind(object_id)
        .execute(pool)
        .await?;

    info!(object = %object_id, "post deleted");
    Ok(())
}

// ..... UPDATE .....

async fn handle_update(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object = &activity.object;

    // Determine what kind of object is being updated.
    let object_type = object
        .get("type")
        .and_then(|v| {
            // `type` may be a string or an array (dual-typed objects).
            v.as_str().map(String::from).or_else(|| {
                v.as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
        })
        .unwrap_or_default();

    let object_id = object.get("id").and_then(|v| v.as_str()).unwrap_or("");

    info!(
        actor = %activity.actor,
        object_type = %object_type,
        object_id = %object_id,
        "received Update"
    );

    match object_type.as_str() {
        // Actor profile update: re-fetch and upsert the remote actor.
        "Person" | "Organization" | "Group" | "Application" | "Service" => {
            handle_update_actor(pool, http_client, activity).await
        }
        // Post edit: update the cached remote post.
        "Note" | "Article" => handle_update_post(pool, http_client, activity).await,
        _ => {
            warn!(
                object_type = %object_type,
                "Update for unsupported object type; ignoring"
            );
            Ok(())
        }
    }
}

/// Handle an `Update` activity targeting a remote actor (profile refresh).
///
/// Verifies that the activity's `actor` matches the object's `id`
/// (an actor may only update itself), then re-fetches the actor
/// profile and upserts it (the `upsert_remote_actor` function's
/// `ON CONFLICT` clause updates the existing row in place, preserving
/// all FK-dependent data such as follows and posts).
async fn handle_update_actor(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object_id = activity
        .object
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Security: an actor may only update its own profile.
    if activity.actor != object_id {
        warn!(
            actor = %activity.actor,
            object = %object_id,
            "Update actor mismatch; ignoring"
        );
        return Ok(());
    }

    // Re-fetch the remote actor profile and upsert it. The inbound
    // Update may carry the full actor object in its body, but
    // re-fetching from the authoritative source is safer (the Update
    // body could be stale or tampered with by a relay).
    //
    // To force a fresh HTTP fetch, we must bypass the local cache.
    // Rather than deleting the row (which would cascade-delete all
    // dependent data, e.g. follows, posts, likes), we fetch directly and
    // let upsert_remote_actor's ON CONFLICT clause update in place,
    // unless the conflicting row is local, which it refuses.
    //
    // Bypassing the cache is what makes this the more dangerous of the
    // two conversion call sites: the fetched document goes straight to
    // persistence. `ap_actor_to_remote` checking the document's `id`
    // against the URL it was served from is what makes the bypass safe.
    //
    // Use a signed fetch so that instances requiring authenticated
    // requests (e.g. GotoSocial with
    // `accounts-allow-incoming-from-known-instances-only`) do not
    // reject the lookup.
    let signing_actor_id = crate::signed_fetch::find_local_signing_actor(pool).await?;
    let response =
        crate::signed_fetch::signed_get(pool, http_client, &activity.actor, signing_actor_id)
            .await?;

    if !response.status().is_success() {
        warn!(
            actor = %activity.actor,
            status = response.status().as_u16(),
            "failed to re-fetch actor during Update; ignoring"
        );
        return Ok(());
    }

    // Taken before `json()` consumes the response; see `resolve_actor`.
    let final_url = response.url().clone();

    let ap_actor: ApActor = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid actor JSON on re-fetch: {e}")))?;

    // This handler treats every soft failure as "ignore and accept the
    // delivery" (see the non-2xx branch above): propagating an error here
    // would turn an inbound Update into a non-2xx inbox response and make
    // the sending instance retry a request that can never succeed.
    let remote = match ap_actor_to_remote(&ap_actor, &final_url, &activity.actor) {
        Ok(remote) => remote,
        Err(e) => {
            warn!(
                actor = %activity.actor,
                error = %e,
                "actor document failed id validation on Update; ignoring"
            );
            return Ok(());
        }
    };

    repo::upsert_remote_actor(pool, &remote).await?;
    info!(actor = %activity.actor, "remote actor profile refreshed via Update");

    Ok(())
}

/// Handle an `Update` activity targeting a remote post (edit).
///
/// Verifies that the activity's `actor` matches the post's
/// `attributedTo`, then updates the cached content.
async fn handle_update_post(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object = &activity.object;

    let ap_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Update object missing id".into()))?;

    let attributed_to = object
        .get("attributedTo")
        .and_then(|v| {
            v.as_str().or_else(|| {
                v.as_array()
                    .and_then(|arr| arr.iter().find_map(|item| item.as_str()))
            })
        })
        .unwrap_or("");

    // Security: the activity actor must match the post author.
    if activity.actor != attributed_to {
        warn!(
            actor = %activity.actor,
            attributed_to = %attributed_to,
            "Update post: actor does not match attributedTo; ignoring"
        );
        return Ok(());
    }

    // Resolve the remote author (may already be cached).
    let _remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;

    let integrity_proof_verified =
        verify_object_proof(pool, http_client, object, &activity.actor, ap_id).await?;

    let content = extract_remote_content(object);

    let title = object.get("name").and_then(|v| v.as_str());

    let featured_image_url = extract_image_url(object);

    // Derive updated visibility from the object's to/cc addressing.
    let to = extract_string_array(object, "to");
    let cc = extract_string_array(object, "cc");
    let visibility = derive_visibility(&to, &cc);

    // Extract `inReplyTo` for consistency with the create path.
    let in_reply_to = extract_in_reply_to(object);

    let rows_affected = sqlx::query(
        r#"UPDATE posts
           SET content_md = $2,
               content_html = $3,
               sanitiser_version = $4,
               title = $5,
               featured_image_url = $6,
               visibility = $7,
               in_reply_to = $8,
               ap_object = $9,
               integrity_proof_verified = $10
           WHERE ap_id = $1
             AND actor_id = (SELECT id FROM actors WHERE ap_id = $11)"#,
    )
    .bind(ap_id)
    .bind(&content.content_md)
    .bind(&content.content_html)
    .bind(content.sanitiser_version)
    .bind(title)
    .bind(&featured_image_url)
    .bind(&visibility)
    .bind(&in_reply_to)
    .bind(object)
    .bind(integrity_proof_verified)
    .bind(&activity.actor)
    .execute(pool)
    .await?
    .rows_affected();

    if rows_affected > 0 {
        // Refresh hashtag links: the edit may have added or removed
        // hashtags. Delete existing links and re-insert from the
        // updated `tag` array.
        let post_id = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM posts WHERE ap_id = $1")
            .bind(ap_id)
            .fetch_optional(pool)
            .await?;

        if let Some(post_id) = post_id {
            sqlx::query("DELETE FROM post_hashtags WHERE post_id = $1")
                .bind(post_id)
                .execute(pool)
                .await?;

            let hashtag_names = extract_hashtags_from_tags(object);
            if !hashtag_names.is_empty()
                && let Err(e) =
                    noombat_identity::hashtags::link_post_hashtags(pool, post_id, &hashtag_names)
                        .await
            {
                warn!(ap_id, "failed to re-link hashtags after post Update: {e}");
            }
        }

        info!(ap_id, "remote post updated via Update activity");
    } else {
        // The post is not known locally; this is common when the
        // instance does not follow the author.
        info!(ap_id, "Update for unknown post; ignoring");
    }

    Ok(())
}

// ..... ACCEPT .....

async fn handle_accept(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // An Accept wraps the original Follow activity.
    let inner_type = activity
        .object
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if inner_type != "Follow" {
        warn!(inner_type, "Accept of non-Follow; ignoring");
        return Ok(());
    }

    // Check whether this is a relay accepting our subscription
    // before proceeding with normal follow-accept logic.
    if let Ok(true) = crate::relay::try_handle_relay_accept(pool, &activity.actor).await {
        return Ok(());
    }

    // The Follow's actor is the local user who sent the follow request.
    let follower_uri = activity
        .object
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Accept: missing Follow actor".into()))?;

    let follower_username = extract_local_username(follower_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse follower URI".into()))?;

    let local_actor = repo::find_local_by_username(pool, follower_username).await?;
    let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;

    repo::accept_follow(pool, local_actor.id, remote_actor.id).await?;
    info!(
        follower = %local_actor.ap_id,
        target = %remote_actor.ap_id,
        "outbound follow accepted by remote"
    );

    Ok(())
}

// ..... REJECT .....

async fn handle_reject(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // A Reject wraps the original Follow activity.
    let inner_type = activity
        .object
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if inner_type != "Follow" {
        warn!(inner_type, "Reject of non-Follow; ignoring");
        return Ok(());
    }

    // The Follow's actor is the local user who sent the follow request.
    let follower_uri = activity
        .object
        .get("actor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::BadRequest("Reject: missing Follow actor".into()))?;

    let follower_username = extract_local_username(follower_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse follower URI".into()))?;

    let local_actor = repo::find_local_by_username(pool, follower_username).await?;
    let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;

    // Delete the pending follow: local_actor follows remote_actor.
    repo::delete_follow(pool, local_actor.id, remote_actor.id).await?;
    info!(
        follower = %local_actor.ap_id,
        target = %remote_actor.ap_id,
        "outbound follow rejected by remote; follow deleted"
    );

    Ok(())
}

// ..... ANNOUNCE .....

async fn handle_announce(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // The `object` of an Announce is the AP ID of the boosted post.
    let object_uri = activity
        .object
        .as_str()
        .or_else(|| activity.object.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| NoombatError::BadRequest("Announce: missing object id".into()))?;

    info!(actor = %activity.actor, object = %object_uri, "received Announce");

    let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;

    // Look up the boosted post locally; if absent, fetch it from the
    // remote instance so that boosts of non-local content are visible
    // in timelines. This mirrors Mastodon's dereference-on-boost
    // behaviour.
    let post_id =
        match sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
            .bind(object_uri)
            .fetch_optional(pool)
            .await?
        {
            Some(id) => id,
            None => match fetch_and_persist_remote_post(pool, http_client, object_uri).await {
                Ok(id) => id,
                Err(e) => {
                    warn!(
                        object = %object_uri,
                        error = %e,
                        "Announce: failed to fetch remote post; ignoring"
                    );
                    return Ok(());
                }
            },
        };

    let boost_ap_id = &activity.id;
    sqlx::query(
        r#"INSERT INTO boosts (id, actor_id, post_id, ap_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (actor_id, post_id) DO NOTHING"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(remote_actor.id)
    .bind(post_id)
    .bind(boost_ap_id)
    .execute(pool)
    .await?;

    info!(actor = %remote_actor.ap_id, post = %object_uri, "boost recorded");
    Ok(())
}

/// Fetch a remote post by its AP URI, resolve its author, persist both,
/// and return the new post's local UUID.
///
/// Used by [`handle_announce`] when the boosted object is not already
/// known locally. The fetched object must be a `Note` or `Article`;
/// other types are rejected.
async fn fetch_and_persist_remote_post(
    pool: &PgPool,
    http_client: &reqwest::Client,
    object_uri: &str,
) -> Result<uuid::Uuid> {
    let response = http_client
        .get(object_uri)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("failed to fetch {object_uri}: {e}")))?;

    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "remote object returned HTTP {}",
            response.status()
        )));
    }

    let object: serde_json::Value = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("invalid object JSON: {e}")))?;

    let object_type = object.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let post_type = match object_type {
        "Note" => "note",
        "Article" => "article",
        _ => {
            return Err(NoombatError::Federation(format!(
                "Announce references unsupported object type: {object_type}"
            )));
        }
    };

    let ap_id = object
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| NoombatError::Federation("fetched object missing id".into()))?;

    // `attributedTo` may be a single URI string (Mastodon) or an array
    // of URIs or objects (Lemmy, PeerTube). Extract the first usable
    // string in either case.
    let author_uri = object
        .get("attributedTo")
        .and_then(|v| {
            v.as_str().or_else(|| {
                v.as_array()
                    .and_then(|arr| arr.iter().find_map(|item| item.as_str()))
            })
        })
        .ok_or_else(|| NoombatError::Federation("fetched object missing attributedTo".into()))?;

    // The proof check comes first on this path too, ahead of both the
    // content extraction below and the de-duplication further down.
    // `author_uri` is the document's own `attributedTo`, and it is also
    // what `actor_id` is set from, so it is exactly the party the proof
    // has to come from.
    let integrity_proof_verified =
        verify_object_proof(pool, http_client, &object, author_uri, ap_id).await?;

    let content = extract_remote_content(&object);

    let title = object
        .get("name")
        .and_then(|v| v.as_str())
        .map(String::from);

    let featured_image_url = extract_image_url(&object);

    // Derive visibility from the object's own to/cc addressing.
    let to = extract_string_array(&object, "to");
    let cc = extract_string_array(&object, "cc");
    let visibility = derive_visibility(&to, &cc);

    // Cross-post de-duplication: if a local post already matches
    // the canonical URI or URL of this object, return its UUID
    // rather than creating a duplicate.
    //
    // Deliberately below the proof check above: a document that fails its
    // own proof must be refused whether or not it happens to collide with
    // something we already hold, and returning early here would have
    // skipped the check entirely.
    if let Ok(Some(existing_id)) = crate::crosspost::try_dedup(pool, &object).await {
        info!(
            ap_id,
            existing_id = %existing_id,
            "fetched remote post de-duplicated; returning existing"
        );
        return Ok(existing_id);
    }

    // Extract the `inReplyTo` property for reply threading.
    let in_reply_to = extract_in_reply_to(&object);

    // Resolve the author (creates a remote actor record if needed).
    let author = resolve_actor(pool, http_client, author_uri).await?;

    let remote_post = repo::RemotePost {
        actor_id: author.id,
        ap_id: ap_id.to_owned(),
        post_type: post_type.to_owned(),
        title,
        featured_image_url,
        content_md: content.content_md,
        content_html: content.content_html,
        sanitiser_version: content.sanitiser_version,
        in_reply_to,
        visibility,
        ap_object: object.clone(),
        integrity_proof_verified,
    };

    // Persist the post. If it was inserted by a concurrent request in
    // the meantime, `create_remote_post` returns `None`; fall back to
    // a lookup.
    if integrity_proof_verified == Some(true) {
        // Same reasoning as the `Create` path: the row may already exist,
        // and a verified proof about these bytes should not be lost to a
        // race. A no-op when the insert below wins.
        if let Err(e) = repo::record_verified_proof(pool, ap_id).await {
            warn!(
                ap_id,
                "failed to record a verified proof on an existing row: {e}"
            );
        }
    }

    let post_id = match repo::create_remote_post(pool, &remote_post).await? {
        Some(id) => {
            // Record the canonical URI (if present) so that future
            // cross-post de-duplication can match this post.
            if let Some(canonical) = crate::crosspost::extract_canonical_uri(&object)
                && let Err(e) = crate::crosspost::set_canonical_uri(pool, id, &canonical).await
            {
                warn!(ap_id, "failed to set canonical_uri: {e}");
            }

            // Link hashtags from the tag array (best-effort).
            let hashtag_names = extract_hashtags_from_tags(&object);
            if !hashtag_names.is_empty()
                && let Err(e) =
                    noombat_identity::hashtags::link_post_hashtags(pool, id, &hashtag_names).await
            {
                warn!(ap_id, "failed to link hashtags for fetched post: {e}");
            }
            info!(ap_id, "remote post fetched and persisted via Announce");
            id
        }
        None => {
            // Concurrent insert; look up the existing row.
            sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
                .bind(ap_id)
                .fetch_one(pool)
                .await
                .map_err(|e| {
                    NoombatError::Internal(format!(
                        "post {ap_id} not found after concurrent insert: {e}"
                    ))
                })?
        }
    };

    Ok(post_id)
}

// ..... LIKE .....

async fn handle_like(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    let object_uri = activity
        .object
        .as_str()
        .or_else(|| activity.object.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| NoombatError::BadRequest("Like: missing object id".into()))?;

    info!(actor = %activity.actor, object = %object_uri, "received Like");

    let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;

    let post_id = sqlx::query_scalar::<_, uuid::Uuid>(r#"SELECT id FROM posts WHERE ap_id = $1"#)
        .bind(object_uri)
        .fetch_optional(pool)
        .await?;

    let post_id = match post_id {
        Some(id) => id,
        None => {
            warn!(object = %object_uri, "Like references unknown post; ignoring");
            return Ok(());
        }
    };

    let like_ap_id = &activity.id;
    sqlx::query(
        r#"INSERT INTO likes (id, actor_id, post_id, ap_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (actor_id, post_id) DO NOTHING"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(remote_actor.id)
    .bind(post_id)
    .bind(like_ap_id)
    .execute(pool)
    .await?;

    info!(actor = %remote_actor.ap_id, post = %object_uri, "like recorded");
    Ok(())
}

// ..... BLOCK .....

async fn handle_block(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Activity,
) -> Result<()> {
    // The `object` of a Block is the URI of the actor being blocked.
    let target_uri = activity
        .object
        .as_str()
        .or_else(|| activity.object.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| NoombatError::BadRequest("Block: missing target actor id".into()))?;

    let target_username = extract_local_username(target_uri)
        .ok_or_else(|| NoombatError::BadRequest("cannot parse target actor URI".into()))?;

    info!(actor = %activity.actor, target = %target_uri, "received Block");

    let remote_actor = resolve_actor(pool, http_client, &activity.actor).await?;
    let local_actor = repo::find_local_by_username(pool, target_username).await?;

    // Persist the block (idempotent).
    sqlx::query(
        r#"INSERT INTO blocks (id, actor_id, target_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (actor_id, target_id) DO NOTHING"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(remote_actor.id)
    .bind(local_actor.id)
    .execute(pool)
    .await?;

    // Sever any follow relationships in both directions.
    repo::delete_follow(pool, remote_actor.id, local_actor.id).await?;
    repo::delete_follow(pool, local_actor.id, remote_actor.id).await?;

    info!(
        actor = %remote_actor.ap_id,
        target = %local_actor.ap_id,
        "block recorded; mutual follows severed"
    );
    Ok(())
}

// ..... VISIBILITY DERIVATION .....

/// Derive post visibility from the `to` and `cc` addressing arrays of
/// an inbound ActivityPub activity.
///
/// The ActivityStreams Public collection URI ([`AS_PUBLIC`]) determines
/// the audience:
///
/// | `to` contains Public | `cc` contains Public | Result       |
/// |----------------------|----------------------|--------------|
/// | yes                  | n/a                  | `"public"`   |
/// | no                   | yes                  | `"unlisted"` |
/// | no                   | no                   | `"followers"`|
///
/// Some implementations use the shorthand `"Public"` (case-insensitive)
/// in place of the full URI; this function accepts both forms.
fn derive_visibility(to: &Option<Vec<String>>, cc: &Option<Vec<String>>) -> String {
    if list_contains_public(to) {
        "public".to_owned()
    } else if list_contains_public(cc) {
        "unlisted".to_owned()
    } else {
        "followers".to_owned()
    }
}

/// Whether an addressing list contains the ActivityStreams Public
/// collection URI or the `"Public"` shorthand.
fn list_contains_public(list: &Option<Vec<String>>) -> bool {
    list.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|uri| uri == AS_PUBLIC || uri.eq_ignore_ascii_case("Public"))
    })
}

/// Extract an addressing field (`to` or `cc`) from a JSON object.
///
/// ActivityStreams allows addressing to be either an array of strings
/// or a single string. This function normalises both forms into
/// `Option<Vec<String>>`.
fn extract_string_array(value: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    let field = value.get(key)?;
    if let Some(arr) = field.as_array() {
        let strings: Vec<String> = arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if strings.is_empty() {
            None
        } else {
            Some(strings)
        }
    } else {
        field.as_str().map(|s| vec![s.to_owned()])
    }
}

// ..... REPLY THREAD EXTRACTION .....

/// Extract the `inReplyTo` URI from an inbound ActivityPub object.
///
/// The `inReplyTo` property may be:
///
/// - A string URI (Mastodon, GotoSocial).
/// - An object with an `id` field (some other implementations).
/// - An array of URIs or objects (uncommon; the first usable entry
///   is returned).
/// - `null` or absent for top-level posts.
///
/// Returns `None` if the property is absent or not extractable.
fn extract_in_reply_to(object: &serde_json::Value) -> Option<String> {
    let field = object.get("inReplyTo")?;

    // String URI (most common).
    if let Some(uri) = field.as_str() {
        return Some(uri.to_owned());
    }

    // Object with an `id` field.
    if let Some(id) = field.get("id").and_then(|v| v.as_str()) {
        return Some(id.to_owned());
    }

    // Array: extract the first usable string or object-with-id.
    if let Some(arr) = field.as_array() {
        for item in arr {
            if let Some(uri) = item.as_str() {
                return Some(uri.to_owned());
            }
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                return Some(id.to_owned());
            }
        }
    }

    None
}

// ..... ARTICLE FIELD EXTRACTION .....

/// Extract a featured-image URL from an inbound ActivityPub object.
///
/// Checks two locations, in order:
///
/// 1. The `image` property: used by Ghost and some CMS-based
///    Fediverse publishers. May be a bare URL string or an object
///    with a `url` field.
/// 2. The first element of the `attachment` array whose `type` is
///    `"Image"`: used by WordPress and Mastodon.
///
/// Returns `None` if neither location contains a usable URL.
fn extract_image_url(object: &serde_json::Value) -> Option<String> {
    // 1. `image` property (string or object).
    if let Some(image) = object.get("image") {
        if let Some(url) = image.as_str() {
            return Some(url.to_owned());
        }
        if let Some(url) = image.get("url").and_then(|v| v.as_str()) {
            return Some(url.to_owned());
        }
    }

    // 2. First `Image` in `attachment`.
    if let Some(attachments) = object.get("attachment").and_then(|v| v.as_array()) {
        for att in attachments {
            let att_type = att.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if att_type == "Image"
                && let Some(url) = att.get("url").and_then(|v| v.as_str())
            {
                return Some(url.to_owned());
            }
        }
    }

    None
}

// ..... HASHTAG EXTRACTION FROM TAG ARRAY .....

/// Extract hashtag names from the `tag` array of an inbound object.
///
/// Mastodon, Lemmy, GotoSocial, and other Fediverse software include
/// hashtags as:
///
/// ```json
/// { "type": "Hashtag", "name": "#rust", "href": "https://.../tags/rust" }
/// ```
///
/// Returns a `Vec<String>` of normalised names (lowercase, leading
/// `#` stripped), suitable for passing to
/// [`noombat_identity::hashtags::link_post_hashtags`].
fn extract_hashtags_from_tags(object: &serde_json::Value) -> Vec<String> {
    let tags = match object.get("tag").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    tags.iter()
        .filter_map(|tag| {
            let tag_type = tag.get("type").and_then(|v| v.as_str())?;
            if tag_type != "Hashtag" {
                return None;
            }
            let name = tag.get("name").and_then(|v| v.as_str())?;
            let stripped = name.strip_prefix('#').unwrap_or(name);
            if stripped.is_empty() {
                return None;
            }
            Some(stripped.to_lowercase())
        })
        .collect()
}

// ..... TESTS .....

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_https() {
        assert_eq!(
            extract_domain("https://noombat.social/users/alice"),
            Some("noombat.social".to_owned())
        );
    }

    #[test]
    fn extract_domain_with_port() {
        assert_eq!(
            extract_domain("http://localhost:8443/users/alice"),
            Some("localhost:8443".to_owned())
        );
    }

    #[test]
    fn extract_local_username_valid() {
        assert_eq!(
            extract_local_username("https://noombat.social/users/alice"),
            Some("alice")
        );
    }

    #[test]
    fn extract_local_username_with_port() {
        assert_eq!(
            extract_local_username("http://localhost:8443/users/alice"),
            Some("alice")
        );
    }

    #[test]
    fn extract_local_username_trailing_slash() {
        assert_eq!(
            extract_local_username("https://noombat.social/users/alice/"),
            Some("alice")
        );
    }

    #[test]
    fn extract_local_username_rejects_subpath() {
        // `/users/alice/inbox` has an additional segment; must return None.
        assert_eq!(
            extract_local_username("https://noombat.social/users/alice/inbox"),
            None
        );
    }

    #[test]
    fn extract_local_username_rejects_non_users_path() {
        assert_eq!(
            extract_local_username("https://noombat.social/@alice"),
            None
        );
    }

    #[test]
    fn extract_local_username_rejects_empty() {
        assert_eq!(
            extract_local_username("https://noombat.social/users/"),
            None
        );
    }

    #[test]
    fn extract_local_username_rejects_bare_domain() {
        assert_eq!(extract_local_username("https://noombat.social"), None);
    }

    #[test]
    fn visibility_public_in_to() {
        let to = Some(vec![AS_PUBLIC.to_owned()]);
        assert_eq!(derive_visibility(&to, &None), "public");
    }

    #[test]
    fn visibility_public_shorthand_in_to() {
        let to = Some(vec!["Public".to_owned()]);
        assert_eq!(derive_visibility(&to, &None), "public");
    }

    #[test]
    fn visibility_unlisted_public_in_cc() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned(),
        ]);
        let cc = Some(vec![AS_PUBLIC.to_owned()]);
        assert_eq!(derive_visibility(&to, &cc), "unlisted");
    }

    #[test]
    fn visibility_unlisted_shorthand_in_cc() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned(),
        ]);
        let cc = Some(vec!["Public".to_owned()]);
        assert_eq!(derive_visibility(&to, &cc), "unlisted");
    }

    #[test]
    fn visibility_followers_no_public() {
        let to = Some(vec![
            "https://noombat.social/users/alice/followers".to_owned(),
        ]);
        assert_eq!(derive_visibility(&to, &None), "followers");
    }

    #[test]
    fn visibility_followers_empty_addressing() {
        assert_eq!(derive_visibility(&None, &None), "followers");
    }

    #[test]
    fn extract_string_array_from_array() {
        let obj = serde_json::json!({
            "to": ["https://www.w3.org/ns/activitystreams#Public"]
        });
        let result = extract_string_array(&obj, "to");
        assert_eq!(result, Some(vec![AS_PUBLIC.to_owned()]));
    }

    #[test]
    fn extract_string_array_from_single_string() {
        let obj = serde_json::json!({
            "to": "https://www.w3.org/ns/activitystreams#Public"
        });
        let result = extract_string_array(&obj, "to");
        assert_eq!(result, Some(vec![AS_PUBLIC.to_owned()]));
    }

    #[test]
    fn extract_string_array_missing_key() {
        let obj = serde_json::json!({});
        assert_eq!(extract_string_array(&obj, "to"), None);
    }

    // ..... extract_image_url .....

    #[test]
    fn image_url_from_string_property() {
        let obj = serde_json::json!({
            "type": "Article",
            "image": "https://example.com/photo.jpg"
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/photo.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_from_object_property() {
        let obj = serde_json::json!({
            "type": "Article",
            "image": { "type": "Image", "url": "https://example.com/photo.jpg" }
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/photo.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_from_attachment_array() {
        let obj = serde_json::json!({
            "type": "Article",
            "attachment": [
                { "type": "Document", "url": "https://example.com/file.pdf" },
                { "type": "Image", "url": "https://example.com/photo.jpg" }
            ]
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/photo.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_prefers_image_property_over_attachment() {
        let obj = serde_json::json!({
            "type": "Article",
            "image": "https://example.com/featured.jpg",
            "attachment": [
                { "type": "Image", "url": "https://example.com/other.jpg" }
            ]
        });
        assert_eq!(
            extract_image_url(&obj),
            Some("https://example.com/featured.jpg".to_owned())
        );
    }

    #[test]
    fn image_url_none_when_absent() {
        let obj = serde_json::json!({ "type": "Note", "content": "hello" });
        assert_eq!(extract_image_url(&obj), None);
    }

    // ..... extract_hashtags_from_tags .....

    #[test]
    fn hashtags_from_tag_array() {
        let obj = serde_json::json!({
            "type": "Note",
            "tag": [
                { "type": "Hashtag", "name": "#Rust", "href": "https://example.com/tags/rust" },
                { "type": "Mention", "name": "@alice", "href": "https://example.com/users/alice" },
                { "type": "Hashtag", "name": "#ActivityPub" }
            ]
        });
        let tags = extract_hashtags_from_tags(&obj);
        assert_eq!(tags, vec!["rust".to_owned(), "activitypub".to_owned()]);
    }

    #[test]
    fn hashtags_without_leading_hash() {
        let obj = serde_json::json!({
            "tag": [
                { "type": "Hashtag", "name": "noHash" }
            ]
        });
        let tags = extract_hashtags_from_tags(&obj);
        assert_eq!(tags, vec!["nohash".to_owned()]);
    }

    #[test]
    fn hashtags_empty_when_no_tag_array() {
        let obj = serde_json::json!({ "type": "Note" });
        assert!(extract_hashtags_from_tags(&obj).is_empty());
    }

    #[test]
    fn hashtags_skips_empty_names() {
        let obj = serde_json::json!({
            "tag": [
                { "type": "Hashtag", "name": "#" },
                { "type": "Hashtag", "name": "" }
            ]
        });
        assert!(extract_hashtags_from_tags(&obj).is_empty());
    }

    // ..... extract_in_reply_to .....

    #[test]
    fn in_reply_to_string_uri() {
        let obj = serde_json::json!({
            "type": "Note",
            "inReplyTo": "https://remote.example/users/bob/statuses/42"
        });
        assert_eq!(
            extract_in_reply_to(&obj),
            Some("https://remote.example/users/bob/statuses/42".to_owned())
        );
    }

    #[test]
    fn in_reply_to_object_with_id() {
        let obj = serde_json::json!({
            "type": "Note",
            "inReplyTo": { "id": "https://remote.example/posts/99", "type": "Note" }
        });
        assert_eq!(
            extract_in_reply_to(&obj),
            Some("https://remote.example/posts/99".to_owned())
        );
    }

    #[test]
    fn in_reply_to_array_of_uris() {
        let obj = serde_json::json!({
            "type": "Note",
            "inReplyTo": ["https://remote.example/posts/1", "https://remote.example/posts/2"]
        });
        assert_eq!(
            extract_in_reply_to(&obj),
            Some("https://remote.example/posts/1".to_owned())
        );
    }

    #[test]
    fn in_reply_to_null() {
        let obj = serde_json::json!({
            "type": "Note",
            "inReplyTo": null
        });
        assert_eq!(extract_in_reply_to(&obj), None);
    }

    #[test]
    fn in_reply_to_absent() {
        let obj = serde_json::json!({ "type": "Note", "content": "hello" });
        assert_eq!(extract_in_reply_to(&obj), None);
    }

    // ..... SIGNER-TO-ACTOR BINDING .....
    //
    // These two exercise `process_activity`'s guard without a database. Both
    // use an unrecognised activity type, which falls through to the `other`
    // arm and returns `Ok(())` without issuing a query, so the pool below is
    // never connected and the outcome depends only on the guard.

    fn unconnected_pool() -> PgPool {
        PgPool::connect_lazy("postgres://noombat:noombat@localhost/noombat")
            .expect("connect_lazy parses the URL without connecting")
    }

    fn activity_from(actor: &str) -> Activity {
        serde_json::from_value(serde_json::json!({
            "id": "https://remote.example/activities/1",
            "type": "ZzzUnsupported",
            "actor": actor,
            "object": {}
        }))
        .expect("test activity deserialises")
    }

    #[tokio::test]
    async fn process_activity_rejects_actor_mismatch() {
        let pool = unconnected_pool();
        let client = reqwest::Client::new();

        // The key at `attacker.example` signed the request, but the activity
        // claims to come from a local actor.
        let activity = activity_from("https://noombat.social/users/admin");
        let document = serde_json::to_value(&activity).expect("activity serialises");
        let result = process_activity(
            &pool,
            &client,
            "https://attacker.example/users/mallory",
            &document,
            activity,
        )
        .await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "expected Forbidden for a signer/actor mismatch, got {result:?}"
        );
    }

    #[tokio::test]
    async fn process_activity_accepts_matching_actor() {
        let pool = unconnected_pool();
        let client = reqwest::Client::new();

        // `verified_actor` is the keyId with its fragment stripped by the
        // caller (see noombat-api::routes::federation), so a legitimate
        // `...#main-key` signature matches the bare actor URI here.
        let activity = activity_from("https://remote.example/users/alice");
        let document = serde_json::to_value(&activity).expect("activity serialises");
        let result = process_activity(
            &pool,
            &client,
            "https://remote.example/users/alice",
            &document,
            activity,
        )
        .await;

        assert!(
            result.is_ok(),
            "a matching signer must not be rejected, got {result:?}"
        );
    }

    // ..... ACTOR DOCUMENT ID VALIDATION .....

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test URL parses")
    }

    #[test]
    fn normalise_trims_one_trailing_slash() {
        assert_eq!(
            normalise_actor_uri(&url("https://remote.example/users/alice/")),
            normalise_actor_uri(&url("https://remote.example/users/alice"))
        );
    }

    #[test]
    fn normalise_folds_case_and_default_port() {
        assert_eq!(
            normalise_actor_uri(&url("https://Remote.EXAMPLE:443/users/alice")),
            normalise_actor_uri(&url("https://remote.example/users/alice"))
        );
    }

    #[test]
    fn normalise_keeps_non_default_port_distinct() {
        assert_ne!(
            normalise_actor_uri(&url("https://remote.example:8443/users/alice")),
            normalise_actor_uri(&url("https://remote.example/users/alice"))
        );
    }

    #[test]
    fn normalise_does_not_decode_percent_escapes() {
        // `%61` is `a`. Decoding it here would let a document claim an id
        // it was not served from.
        assert_ne!(
            normalise_actor_uri(&url("https://remote.example/users/%61lice")),
            normalise_actor_uri(&url("https://remote.example/users/alice"))
        );
    }

    #[test]
    fn actor_id_accepts_exact_match() {
        assert!(
            verify_fetched_actor_id(
                "https://remote.example/users/alice",
                &url("https://remote.example/users/alice"),
                "https://remote.example/users/alice",
            )
            .is_ok()
        );
    }

    #[test]
    fn actor_id_accepts_same_origin_redirect() {
        // A trailing-slash canonicalisation on the origin's own host is
        // legitimate; the id is then checked against the FINAL url.
        assert!(
            verify_fetched_actor_id(
                "https://remote.example/users/alice/",
                &url("https://remote.example/users/alice/"),
                "https://remote.example/users/alice",
            )
            .is_ok()
        );
    }

    #[test]
    fn actor_id_rejects_cross_origin_redirect() {
        let result = verify_fetched_actor_id(
            "https://evil.example/actor",
            &url("https://evil.example/actor"),
            "https://good.example/users/alice",
        );
        assert!(
            matches!(result, Err(NoombatError::Federation(_))),
            "cross-origin redirect must be refused, got {result:?}"
        );
    }

    #[test]
    fn actor_id_rejects_claiming_a_local_actor() {
        // The attack the guard exists for: a remote server returns a
        // document claiming a LOCAL actor's id, so that the upsert's
        // ON CONFLICT overwrites that actor's published signing key.
        let result = verify_fetched_actor_id(
            "https://noombat.social/users/admin",
            &url("https://remote.example/users/mallory"),
            "https://remote.example/users/mallory",
        );
        assert!(
            matches!(result, Err(NoombatError::Federation(_))),
            "a document claiming another origin's id must be refused, got {result:?}"
        );
    }

    #[test]
    fn actor_id_rejects_unparseable_document_id() {
        let result = verify_fetched_actor_id(
            "not a url",
            &url("https://remote.example/users/alice"),
            "https://remote.example/users/alice",
        );
        assert!(matches!(result, Err(NoombatError::Federation(_))));
    }

    // ..... REMOTE CONTENT SANITISATION .....

    #[test]
    fn remote_content_strips_script_tags() {
        let obj = serde_json::json!({
            "content": "<p>hi</p><script>alert(1)</script>"
        });
        let c = extract_remote_content(&obj);
        assert!(
            !c.content_html.contains("<script"),
            "got {}",
            c.content_html
        );
        assert!(c.content_html.contains("<p>hi</p>"));
    }

    #[test]
    fn remote_content_strips_event_handlers_and_js_urls() {
        let obj = serde_json::json!({
            "content": "<img src=x onerror=\"alert(1)\"><a href=\"javascript:alert(1)\">x</a>"
        });
        let c = extract_remote_content(&obj);
        assert!(
            !c.content_html.contains("onerror"),
            "got {}",
            c.content_html
        );
        assert!(
            !c.content_html.contains("javascript:"),
            "got {}",
            c.content_html
        );
    }

    #[test]
    fn remote_content_records_the_sanitiser_version() {
        let c = extract_remote_content(&serde_json::json!({ "content": "<p>x</p>" }));
        assert_eq!(
            c.sanitiser_version,
            noombat_markup::sanitise::STRICT_VERSION
        );
        assert_ne!(
            c.sanitiser_version, 0,
            "0 is reserved for un-backfilled rows"
        );
    }

    #[test]
    fn remote_content_keeps_a_declared_markdown_source() {
        let obj = serde_json::json!({
            "content": "<p>rendered</p>",
            "source": { "mediaType": "text/markdown", "content": "*rendered*" }
        });
        let c = extract_remote_content(&obj);
        assert_eq!(c.content_md.as_deref(), Some("*rendered*"));
    }

    #[test]
    fn remote_content_has_no_markdown_when_the_peer_sent_none() {
        // The old code copied content_html here, putting HTML in a column
        // named for Markdown, which is how one unsanitised binding
        // reached two columns.
        let c = extract_remote_content(&serde_json::json!({ "content": "<p>x</p>" }));
        assert_eq!(c.content_md, None);
    }

    #[test]
    fn remote_content_ignores_a_non_markdown_source() {
        let obj = serde_json::json!({
            "content": "<p>x</p>",
            "source": { "mediaType": "text/html", "content": "<p>x</p>" }
        });
        assert_eq!(extract_remote_content(&obj).content_md, None);
    }

    #[test]
    fn remote_content_caps_an_oversized_document() {
        let huge = format!("<p>{}</p>", "a".repeat(MAX_REMOTE_HTML_BYTES * 2));
        let c = extract_remote_content(&serde_json::json!({ "content": huge }));
        assert!(
            c.content_html.len() <= MAX_REMOTE_HTML_BYTES + 64,
            "cap not applied: {} bytes",
            c.content_html.len()
        );
        // Truncation happens before sanitisation, so ammonia closes the
        // paragraph the cut left open rather than emitting torn markup.
        assert!(c.content_html.ends_with("</p>"), "markup left unbalanced");
    }

    #[test]
    fn remote_content_caps_the_markdown_source_too() {
        let huge = "b".repeat(MAX_REMOTE_HTML_BYTES * 2);
        let obj = serde_json::json!({
            "content": "<p>x</p>",
            "source": { "mediaType": "text/markdown", "content": huge }
        });
        let c = extract_remote_content(&obj);
        assert_eq!(c.content_md.map(|s| s.len()), Some(MAX_REMOTE_HTML_BYTES));
    }

    #[test]
    fn truncation_does_not_split_a_multibyte_character() {
        // Slicing on a raw byte length would panic here, and the input
        // needed to trigger it is just a document padded with non-ASCII.
        let padded = "é".repeat(MAX_REMOTE_HTML_BYTES);
        let cut = truncate_on_char_boundary(&padded, MAX_REMOTE_HTML_BYTES);
        assert!(cut.len() <= MAX_REMOTE_HTML_BYTES);
        assert!(padded.starts_with(cut), "truncation must be a prefix");
        // Round-trips as valid UTF-8 by construction: `&str` cannot hold
        // a split code point, so reaching this line is the assertion.
        assert!(cut.chars().all(|c| c == 'é'));
    }

    #[test]
    fn remote_content_tolerates_a_missing_content_field() {
        let c = extract_remote_content(&serde_json::json!({ "type": "Note" }));
        assert_eq!(c.content_html, "");
        assert_eq!(c.content_md, None);
    }

    // ..... INBOUND SIGNER RESOLUTION .....
    //
    // These hit the database. A cached actor short-circuits
    // `resolve_actor` before any HTTP, so the client below is
    // never actually used and no network stub is needed.

    async fn insert_actor(pool: &PgPool, ap_id: &str, is_local: bool) {
        sqlx::query(
            r#"INSERT INTO actors
                   (actor_type, ap_id, username, domain, public_key_pem, is_local)
               VALUES ('individual', $1, 'someone', 'example.test', 'KEY', $2)"#,
        )
        .bind(ap_id)
        .bind(is_local)
        .execute(pool)
        .await
        .expect("actor fixture inserted");
    }

    /// Insert a remote actor whose Ed25519 public key is cached, which
    /// is what `attempt_proof_verification` looks up. Returns the raw
    /// 32-byte secret so the test can sign as that actor.
    async fn insert_actor_with_ed25519(pool: &PgPool, ap_id: &str) -> [u8; 32] {
        let keypair =
            noombat_identity::keys::generate_ed25519_keypair().expect("keypair generated");
        // Username derived from the URI so two fixtures can coexist.
        let username = ap_id.rsplit('/').next().unwrap_or("someone").to_owned();
        sqlx::query(
            r#"INSERT INTO actors
                   (actor_type, ap_id, username, domain, public_key_pem, is_local,
                    ed25519_public_key)
               VALUES ('individual', $1, $3, 'example.test', 'KEY', FALSE, $2)"#,
        )
        .bind(ap_id)
        .bind(&keypair.public_multibase)
        .bind(&username)
        .execute(pool)
        .await
        .expect("actor fixture inserted");

        crate::integrity_proof::decode_private_key_base64(&keypair.private_base64)
            .expect("private key decodes")
    }

    async fn post_count(pool: &PgPool, ap_id: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM posts WHERE ap_id = $1")
            .bind(ap_id)
            .fetch_one(pool)
            .await
            .expect("count runs")
    }

    /// Build a `Create` whose inner object is the given value.
    fn create_activity(actor_uri: &str, object: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "id": "https://remote.example/activities/1",
            "type": "Create",
            "actor": actor_uri,
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "object": object,
        })
    }

    /// Half of the P1-8 acceptance criterion: a valid proof is recorded.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_valid_proof_records_it_verified(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        let secret = insert_actor_with_ed25519(&pool, actor_uri).await;

        let mut object = serde_json::json!({
            "id": post_uri,
            "type": "Note",
            "attributedTo": actor_uri,
            "content": "<p>signed</p>",
        });
        crate::integrity_proof::sign(&mut object, &secret, &format!("{actor_uri}#ed25519-key"))
            .expect("object signs");

        let document = create_activity(actor_uri, object);
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await
        .expect("create processes");

        let verified: Option<bool> =
            sqlx::query_scalar("SELECT integrity_proof_verified FROM posts WHERE ap_id = $1")
                .bind(post_uri)
                .fetch_one(&pool)
                .await
                .expect("post row present");

        assert_eq!(
            verified,
            Some(true),
            "a valid proof must be recorded as TRUE"
        );
    }

    /// The other half: a proof that does not match the document it
    /// travels with is not merely flagged, the object is not stored.
    ///
    /// The audit's criterion also asks that this row read `FALSE`. Both
    /// cannot hold at once, and discarding is the safer of the two: see
    /// the note on `verify_object_proof`.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_tampered_proof_is_not_persisted(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        let secret = insert_actor_with_ed25519(&pool, actor_uri).await;

        let mut object = serde_json::json!({
            "id": post_uri,
            "type": "Note",
            "attributedTo": actor_uri,
            "content": "<p>original</p>",
        });
        crate::integrity_proof::sign(&mut object, &secret, &format!("{actor_uri}#ed25519-key"))
            .expect("object signs");

        // Flip the content after signing, leaving the proof in place.
        object["content"] = serde_json::json!("<p>substituted</p>");

        let document = create_activity(actor_uri, object);
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        let result = process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "expected Forbidden for a proof that does not match its document, got {result:?}"
        );

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM posts WHERE ap_id = $1")
            .bind(post_uri)
            .fetch_one(&pool)
            .await
            .expect("count runs");
        assert_eq!(
            rows, 0,
            "a document failing its own proof must not be stored"
        );
    }

    /// An unproven object is ordinary: the HTTP Signature already
    /// authenticated the delivery, so it is stored with a NULL rather
    /// than being treated as suspect.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_without_proof_records_null(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        insert_actor(&pool, actor_uri, false).await;

        let document = create_activity(
            actor_uri,
            serde_json::json!({
                "id": post_uri,
                "type": "Note",
                "attributedTo": actor_uri,
                "content": "<p>unproven</p>",
            }),
        );
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await
        .expect("create processes");

        let verified: Option<bool> =
            sqlx::query_scalar("SELECT integrity_proof_verified FROM posts WHERE ap_id = $1")
                .bind(post_uri)
                .fetch_one(&pool)
                .await
                .expect("post row present");

        assert_eq!(verified, None, "no proof must record NULL, not FALSE");
    }

    /// An `Update` may only rewrite a post its sender owns.
    ///
    /// The guard above the statement compares `activity.actor` to the
    /// object's `attributedTo`, both of which the sender supplies, so it
    /// is self-satisfying. The predicate in the SQL is the real check.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn update_cannot_rewrite_another_actors_post(pool: PgPool) {
        let alice = "https://remote.example/users/alice";
        let mallory = "https://remote.example/users/mallory";
        let post_uri = "https://remote.example/posts/1";
        insert_actor(&pool, alice, false).await;
        insert_actor_with_ed25519(&pool, mallory).await;

        let alice_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM actors WHERE ap_id = $1")
            .bind(alice)
            .fetch_one(&pool)
            .await
            .expect("actor present");

        sqlx::query(
            r#"INSERT INTO posts (actor_id, ap_id, post_type, content_md, content_html,
                                  visibility, ap_object, integrity_proof_verified)
               VALUES ($1, $2, 'note', NULL, '<p>alice wrote this</p>', 'public', '{}'::jsonb, TRUE)"#,
        )
        .bind(alice_id)
        .bind(post_uri)
        .execute(&pool)
        .await
        .expect("post fixture inserted");

        // Mallory claims the post as her own and rewrites it. Both fields
        // the pre-existing guard compares are hers, so it lets her past.
        let document = serde_json::json!({
            "id": "https://remote.example/activities/9",
            "type": "Update",
            "actor": mallory,
            "object": {
                "id": post_uri,
                "type": "Note",
                "attributedTo": mallory,
                "content": "<p>mallory wrote this</p>"
            }
        });
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        process_activity(&pool, &reqwest::Client::new(), mallory, &document, activity)
            .await
            .expect("update is ignored, not an error");

        let (html, verified): (String, Option<bool>) = sqlx::query_as(
            "SELECT content_html, integrity_proof_verified FROM posts WHERE ap_id = $1",
        )
        .bind(post_uri)
        .fetch_one(&pool)
        .await
        .expect("post row present");

        assert_eq!(html, "<p>alice wrote this</p>", "content must be untouched");
        assert_eq!(verified, Some(true), "the integrity flag must be untouched");
    }

    /// A proof carrying the wrong purpose is not an authorship assertion,
    /// so it must not produce a `TRUE`, and must not discard the post
    /// either.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_a_non_assertion_proof_records_null(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        let secret = insert_actor_with_ed25519(&pool, actor_uri).await;

        let mut object = serde_json::json!({
            "id": post_uri,
            "type": "Note",
            "attributedTo": actor_uri,
            "content": "<p>signed for something else</p>",
        });
        // Minted as an authentication proof. Editing a signed one would
        // break the signature and test the `Invalid` branch instead.
        crate::integrity_proof::sign_with_config_for_test(
            &mut object,
            &secret,
            serde_json::json!({
                "type": crate::integrity_proof::PROOF_TYPE,
                "cryptosuite": crate::integrity_proof::CRYPTOSUITE,
                "verificationMethod": format!("{actor_uri}#ed25519-key"),
                "proofPurpose": "authentication",
                "created": "2026-01-01T00:00:00Z",
            }),
        )
        .expect("object signs");

        let document = create_activity(actor_uri, object);
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await
        .expect("the post is still accepted");

        let verified: Option<bool> =
            sqlx::query_scalar("SELECT integrity_proof_verified FROM posts WHERE ap_id = $1")
                .bind(post_uri)
                .fetch_one(&pool)
                .await
                .expect("post row present");
        assert_eq!(
            verified, None,
            "an authentication proof is not an assertion"
        );
    }

    /// A proof is only evidence of authorship if it comes from the
    /// author. Two cached actors is all it takes to show the difference.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_a_proof_from_another_actor_is_refused(pool: PgPool) {
        let alice = "https://remote.example/users/alice";
        let bob = "https://remote.example/users/bob";
        let post_uri = "https://remote.example/posts/1";
        insert_actor_with_ed25519(&pool, alice).await;
        let bob_secret = insert_actor_with_ed25519(&pool, bob).await;

        // Attributed to alice, delivered by alice, signed by bob.
        let mut object = serde_json::json!({
            "id": post_uri,
            "type": "Note",
            "attributedTo": alice,
            "content": "<p>put words in alice's mouth</p>",
        });
        crate::integrity_proof::sign(&mut object, &bob_secret, &format!("{bob}#ed25519-key"))
            .expect("object signs");

        let document = create_activity(alice, object);
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        let result =
            process_activity(&pool, &reqwest::Client::new(), alice, &document, activity).await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "a proof signed by someone other than the author must be refused, got {result:?}"
        );
        assert_eq!(post_count(&pool, post_uri).await, 0);
    }

    /// Naming an actor we hold no key for must not be a way to switch
    /// verification off: that would turn the discard into a store.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_with_a_proof_naming_an_unknown_actor_is_refused(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        let secret = insert_actor_with_ed25519(&pool, actor_uri).await;

        let mut object = serde_json::json!({
            "id": post_uri,
            "type": "Note",
            "attributedTo": actor_uri,
            "content": "<p>tampered</p>",
        });
        crate::integrity_proof::sign(
            &mut object,
            &secret,
            "https://elsewhere.example/users/nobody#ed25519-key",
        )
        .expect("object signs");
        object["content"] = serde_json::json!("<p>substituted</p>");

        let document = create_activity(actor_uri, object);
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        let result = process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "a proof naming a stranger must be refused, got {result:?}"
        );
        assert_eq!(post_count(&pool, post_uri).await, 0);
    }

    /// The envelope gate had no test at all: deleting it left the whole
    /// suite green. These two cover both of its branches.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn envelope_proof_that_does_not_verify_rejects_the_activity(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        let secret = insert_actor_with_ed25519(&pool, actor_uri).await;

        let mut document = create_activity(
            actor_uri,
            serde_json::json!({
                "id": post_uri,
                "type": "Note",
                "attributedTo": actor_uri,
                "content": "<p>original</p>",
            }),
        );
        crate::integrity_proof::sign(&mut document, &secret, &format!("{actor_uri}#ed25519-key"))
            .expect("envelope signs");
        // Tamper with the envelope after signing it.
        document["object"]["content"] = serde_json::json!("<p>substituted</p>");

        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");
        let result = process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "a broken envelope proof must reject the activity, got {result:?}"
        );
        assert_eq!(post_count(&pool, post_uri).await, 0);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn envelope_proof_that_verifies_lets_the_activity_through(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        let secret = insert_actor_with_ed25519(&pool, actor_uri).await;

        let mut document = create_activity(
            actor_uri,
            serde_json::json!({
                "id": post_uri,
                "type": "Note",
                "attributedTo": actor_uri,
                "content": "<p>intact</p>",
            }),
        );
        crate::integrity_proof::sign(&mut document, &secret, &format!("{actor_uri}#ed25519-key"))
            .expect("envelope signs");

        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");
        process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await
        .expect("a valid envelope proof must not block the activity");

        assert_eq!(post_count(&pool, post_uri).await, 1);

        // The envelope is transport and is not stored, so the column
        // still describes the object, which carries no proof of its own.
        let verified: Option<bool> =
            sqlx::query_scalar("SELECT integrity_proof_verified FROM posts WHERE ap_id = $1")
                .bind(post_uri)
                .fetch_one(&pool)
                .await
                .expect("post row present");
        assert_eq!(verified, None);
    }

    /// The acceptance criterion for P0-4: deliver the attack payload
    /// down the real `Create` path and read the row back.
    ///
    /// The unit tests above cover `extract_remote_content` in isolation,
    /// but isolation is exactly what was wrong before: the sanitiser
    /// existed and was tested, and the federation path simply did not
    /// call it. Only an end-to-end delivery proves the wiring.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_note_persists_no_hostile_markup(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        insert_actor(&pool, actor_uri, false).await;

        let hostile = "<img src=x onerror=alert(1)>\
                       <script>alert(1)</script>\
                       <style>body{display:none}</style>\
                       <p>legitimate</p>";

        let document = serde_json::json!({
            "id": "https://remote.example/activities/1",
            "type": "Create",
            "actor": actor_uri,
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "object": {
                "id": post_uri,
                "type": "Note",
                "attributedTo": actor_uri,
                "content": hostile
            }
        });
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await
        .expect("create processes");

        let (html, md, ver): (String, Option<String>, i16) = sqlx::query_as(
            "SELECT content_html, content_md, sanitiser_version FROM posts WHERE ap_id = $1",
        )
        .bind(post_uri)
        .fetch_one(&pool)
        .await
        .expect("post persisted");

        for banned in ["<script", "onerror", "<style"] {
            assert!(
                !html.contains(banned),
                "{banned} survived ingestion: {html}"
            );
        }
        assert!(html.contains("legitimate"), "real content lost: {html}");
        assert_eq!(md, None, "no source means NULL, not a copy of the HTML");
        assert_eq!(ver, noombat_markup::sanitise::STRICT_VERSION);

        // The wire record keeps the payload: FEP-8b32 proofs are
        // computed over these bytes, so sanitising them would destroy
        // the ability to verify the object later.
        let wire: serde_json::Value =
            sqlx::query_scalar("SELECT ap_object FROM posts WHERE ap_id = $1")
                .bind(post_uri)
                .fetch_one(&pool)
                .await
                .expect("post readable");
        assert_eq!(
            wire["content"].as_str(),
            Some(hostile),
            "ap_object must survive verbatim"
        );
    }

    /// The `Update` path writes with an inline `UPDATE ... SET` whose
    /// `$n` placeholders must line up with its `.bind()` sequence. The
    /// workspace uses sqlx's runtime API, so a mismatch compiles cleanly
    /// and only misbehaves when executed. This is the test that sees it.
    /// A cached actor makes `resolve_actor` short-circuit, so no HTTP.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn update_post_sanitises_and_lands_columns_correctly(pool: PgPool) {
        let actor_uri = "https://remote.example/users/alice";
        let post_uri = "https://remote.example/posts/1";
        insert_actor(&pool, actor_uri, false).await;

        let actor_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM actors WHERE ap_id = $1")
            .bind(actor_uri)
            .fetch_one(&pool)
            .await
            .expect("actor present");

        sqlx::query(
            r#"INSERT INTO posts (actor_id, ap_id, post_type, content_md, content_html,
                                  visibility, ap_object)
               VALUES ($1, $2, 'note', NULL, '<p>old</p>', 'public', '{}'::jsonb)"#,
        )
        .bind(actor_id)
        .bind(post_uri)
        .execute(&pool)
        .await
        .expect("post fixture inserted");

        let document = serde_json::json!({
            "id": "https://remote.example/activities/1",
            "type": "Update",
            "actor": actor_uri,
            "object": {
                "id": post_uri,
                "type": "Note",
                "attributedTo": actor_uri,
                "content": "<p>new</p><script>alert(1)</script>"
            }
        });
        let activity: Activity =
            serde_json::from_value(document.clone()).expect("activity deserialises");

        process_activity(
            &pool,
            &reqwest::Client::new(),
            actor_uri,
            &document,
            activity,
        )
        .await
        .expect("update processes");

        let (html, ver, title): (String, i16, Option<String>) = sqlx::query_as(
            "SELECT content_html, sanitiser_version, title FROM posts WHERE ap_id = $1",
        )
        .bind(post_uri)
        .fetch_one(&pool)
        .await
        .expect("post readable");

        assert!(
            !html.contains("<script"),
            "edit must be sanitised, got {html}"
        );
        assert!(
            html.contains("<p>new</p>"),
            "edit must be applied, got {html}"
        );
        assert_eq!(
            ver,
            noombat_markup::sanitise::STRICT_VERSION,
            "sanitiser_version must land in its own column"
        );
        assert_eq!(title, None, "title must not receive a shifted value");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn inbound_signer_refuses_a_local_actor(pool: PgPool) {
        let ap_id = "https://noombat.social/users/admin";
        insert_actor(&pool, ap_id, true).await;

        let result = resolve_inbound_signer(&pool, &reqwest::Client::new(), ap_id).await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "a signer resolving to a local actor must be refused, got {:?}",
            result.map(|a| a.ap_id)
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn inbound_signer_accepts_a_remote_actor(pool: PgPool) {
        // The guard must not break the path it sits on.
        let ap_id = "https://remote.example/users/alice";
        insert_actor(&pool, ap_id, false).await;

        let actor = resolve_inbound_signer(&pool, &reqwest::Client::new(), ap_id)
            .await
            .expect("a genuine remote signer must resolve");

        assert_eq!(actor.ap_id, ap_id);
        assert!(!actor.is_local);
    }
}
