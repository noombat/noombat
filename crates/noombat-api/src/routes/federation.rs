// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Federation-facing routes: WebFinger, NodeInfo, and actor inbox.

use std::collections::BTreeMap;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_signature_normalization::Config as SigConfig;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use serde::Deserialize;

use noombat_ap::activity::Activity;
use noombat_core::error::NoombatError;
use noombat_federation::integrity_proof::MAX_PROOF_DOCUMENT_BYTES;
use noombat_federation::{digest, inbox, nodeinfo, webfinger};

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger_handler))
        .route("/.well-known/nodeinfo", get(nodeinfo_well_known))
        .route("/nodeinfo/2.1", get(nodeinfo_handler))
        // The body limit is the proof bound, deliberately.
        //
        // axum's 2 MiB default sat above `MAX_PROOF_DOCUMENT_BYTES`, so a
        // signed document between the two was accepted by the transport
        // and then refused by the verifier, while the same document with
        // its proof removed was stored. Signing content must not be what
        // makes it undeliverable, so the two limits are one limit.
        .route(
            "/users/{username}/inbox",
            post(inbox_handler).layer(DefaultBodyLimit::max(MAX_PROOF_DOCUMENT_BYTES)),
        )
        .route(
            "/inbox",
            post(shared_inbox_handler).layer(DefaultBodyLimit::max(MAX_PROOF_DOCUMENT_BYTES)),
        )
}

#[derive(Deserialize)]
struct WebFingerQuery {
    resource: String,
}

async fn webfinger_handler(
    State(state): State<AppState>,
    Query(query): Query<WebFingerQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let (username, domain) = webfinger::parse_acct_uri(&query.resource).ok_or_else(|| {
        noombat_core::error::NoombatError::BadRequest(
            "invalid resource URI; expected acct:user@domain".into(),
        )
    })?;

    if domain != state.domain {
        return Err(noombat_core::error::NoombatError::ActorNotFound(format!(
            "{username}@{domain}"
        ))
        .into());
    }

    // Verify the actor exists locally.
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let response = webfinger::build_response(&username, &state.domain, &actor.ap_id);

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/jrd+json; charset=utf-8",
        )],
        Json(response),
    ))
}

async fn nodeinfo_well_known(State(state): State<AppState>) -> impl IntoResponse {
    Json(nodeinfo::well_known(&state.domain))
}

async fn nodeinfo_handler(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    // Execute the four independent COUNT queries concurrently.
    let (total_users, active_month, active_half_year, local_posts) = tokio::try_join!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM actors WHERE is_local = TRUE")
            .fetch_one(&state.pool),
        // NodeInfo defines both windows as users who SIGNED IN during
        // them, so they count `last_sign_in_at` and nothing else. They
        // used to count `updated_at`, which `trg_actors_updated_at`
        // bumps on every write to the row: setting `moved_to`, i.e. the
        // user migrating away, marked them active for another thirty
        // days, as did requesting deletion and as did a moderator
        // flagging chat reprovisioning, while a user who signed in daily
        // and posted was never counted, because posting does not write
        // to `actors`.
        //
        // `last_sign_in_at IS NULL` for anyone who has not signed in
        // since the column was added, and those rows are excluded by the
        // comparison. That under-counts a freshly migrated instance
        // rather than over-counting it, and corrects itself as people
        // sign in.
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM actors \
                 WHERE is_local = TRUE AND last_sign_in_at > now() - interval '30 days'"
        )
        .fetch_one(&state.pool),
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM actors \
                 WHERE is_local = TRUE AND last_sign_in_at > now() - interval '180 days'"
        )
        .fetch_one(&state.pool),
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM posts \
                 WHERE actor_id IN (SELECT id FROM actors WHERE is_local = TRUE)"
        )
        .fetch_one(&state.pool),
    )
    .map_err(noombat_core::error::NoombatError::from)?;

    let params = nodeinfo::NodeInfoParams {
        total_users: total_users as u64,
        active_month: active_month as u64,
        active_half_year: active_half_year as u64,
        local_posts: local_posts as u64,
        open_registrations: state.open_registrations,
        features: state.nodeinfo_features.clone(),
    };
    Ok(Json(nodeinfo::build(&params)))
}

// ..... INBOX HANDLERS .....

/// Per-actor inbox: `POST /users/{username}/inbox`.
async fn inbox_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    // Verify the local target actor exists.
    let _local_actor =
        noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    let path = format!("/users/{username}/inbox");
    verify_and_process_inbound(&state, &headers, &body, &path).await
}

/// Instance-level shared inbox: `POST /inbox`.
///
/// Remote instances that know this instance's `endpoints.sharedInbox`
/// URI deliver a single copy of an activity here instead of POSTing
/// to each follower's individual inbox.
async fn shared_inbox_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    verify_and_process_inbound(&state, &headers, &body, "/inbox").await
}

// ..... SHARED VERIFICATION AND DISPATCH .....

/// Longest public-key PEM accepted from a remote actor. rsa decodes the
/// whole modulus before it checks the key's size, so the length is checked
/// first and a hostile key of any size never reaches the parser. An
/// 8192-bit key, the largest rsa accepts, is about 1.5 KiB.
const MAX_REMOTE_KEY_PEM_BYTES: usize = 2048;

fn parse_remote_public_key(pem: &str) -> Option<rsa::PublicKey> {
    if pem.len() > MAX_REMOTE_KEY_PEM_BYTES {
        return None;
    }
    rsa::PublicKey::from_public_key_pem(pem).ok()
}

/// Whether `signature_b64` is an `rsa-sha256` (RSA PKCS#1 v1.5 with SHA-256)
/// signature of `signing_string` under the remote actor's key.
fn rsa_sha256_verifies(public_key_pem: &str, signing_string: &str, signature_b64: &str) -> bool {
    let Some(public_key) = parse_remote_public_key(public_key_pem) else {
        return false;
    };
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key);

    let Ok(sig_bytes) = BASE64.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };

    verifying_key
        .verify(signing_string.as_bytes(), &signature)
        .is_ok()
}

/// Verify the HTTP Signature, body digest, domain restrictions, and
/// per-domain rate limit for an inbound ActivityPub delivery, then
/// dispatch the activity for processing.
///
/// This function is the shared core of both [`inbox_handler`] (per-actor)
/// and [`shared_inbox_handler`] (instance-level). The only difference
/// between the two entry points is the `path` used in the signing-string
/// reconstruction (which the HTTP Signature specification requires to
/// match the actual request URI).
async fn verify_and_process_inbound(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    path: &str,
) -> Result<StatusCode, ApiError> {
    // ..... CONTENT-TYPE VALIDATION .....
    //
    // Mastodon and GotoSocial require inbound POST requests to carry
    // an ActivityPub-compatible Content-Type. Reject requests that
    // do not match to avoid processing malformed payloads.
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        let ct_lower = ct.to_ascii_lowercase();
        let valid = ct_lower.starts_with("application/activity+json")
            || ct_lower.starts_with("application/ld+json")
            || ct_lower.starts_with("application/json");
        if !valid {
            return Err(NoombatError::BadRequest(format!(
                "unsupported Content-Type: {ct}; \
                 expected application/activity+json or application/ld+json"
            ))
            .into());
        }
    }
    // A missing Content-Type header is tolerated: some older
    // implementations omit it. The body is still validated as JSON
    // during deserialisation below.

    // ..... HTTP SIGNATURE VERIFICATION .....
    //
    // The default `SigConfig` accepts both `hs2019` signatures (with
    // `(created)` and `(expires)` pseudo-headers) and legacy `rsa-sha256`
    // signatures (with `date`), providing forward compatibility with
    // implementations that adopt newer drafts.
    //
    // `.require_header("digest")` ensures that the signature's
    // `headers` parameter includes `digest`, binding the body digest
    // to the signature. Without this, a man-in-the-middle could
    // replace both the body and the `Digest` header while the
    // signature (covering only request-target, host, date) remains
    // valid.
    let config = SigConfig::default().require_header("digest");

    // Collect HTTP headers into the `BTreeMap<String, String>` that the
    // library expects.
    let mut sig_headers = BTreeMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            sig_headers.insert(name.as_str().to_owned(), v.to_owned());
        }
    }

    // A signature that is absent or malformed is the sender's fault, and
    // the status says so: peers treat 5xx as "retry later" and keep
    // redelivering. Same status as the digest checks below, which reject
    // the same class of request.
    let unverified = config
        .begin_verify("POST", path, sig_headers)
        .map_err(|e| {
            tracing::debug!(error = %e, "inbound signature parse/validate failed");
            NoombatError::SignatureVerification
        })?;

    // Verify the body digest.
    let digest_header = headers
        .get("digest")
        .and_then(|v| v.to_str().ok())
        .ok_or(NoombatError::SignatureVerification)?;
    let expected_digest = digest_header
        .strip_prefix("SHA-256=")
        .ok_or(NoombatError::SignatureVerification)?;
    let actual_digest = digest::sha256(body);
    if expected_digest != actual_digest {
        return Err(NoombatError::SignatureVerification.into());
    }

    // Resolve the remote actor's public key.
    let key_id = unverified.key_id().to_owned();
    let actor_uri = key_id.split('#').next().unwrap_or(&key_id);

    // ..... DOMAIN RESTRICTION ENFORCEMENT .....
    //
    // Check the `domain_restrictions` table before incurring the cost
    // of actor resolution and cryptographic signature verification.
    // A blocked domain's activities are rejected outright.
    if let Some(sending_domain) = inbox::extract_domain(actor_uri) {
        let restriction: Option<String> =
            sqlx::query_scalar("SELECT restriction FROM domain_restrictions WHERE domain = $1")
                .bind(&sending_domain)
                .fetch_optional(&state.pool)
                .await
                .unwrap_or(None);

        if restriction.as_deref() == Some("block") {
            return Err(NoombatError::Forbidden.into());
        }
        // "silence" restrictions are not enforced at the inbox level;
        // silenced domains are excluded from public timelines by the
        // feed and search queries.
    }

    let remote_actor =
        inbox::resolve_signer_by_key_id(&state.pool, &state.http_client, &key_id).await?;

    // Perform the cryptographic verification.
    //
    // NOTE: `block_in_place` is used here because `Unverified::verify`
    // accepts a synchronous `FnOnce(&str, &str) -> bool`; an async
    // `.await` inside the closure is not possible. `block_in_place`
    // is safe on the multi-threaded Tokio runtime used by the server.
    let public_key_pem = remote_actor.public_key_pem.clone();
    let verified = unverified.verify(|signature_b64, signing_string| {
        let sig_b64 = signature_b64.to_owned();
        let sig_str = signing_string.to_owned();

        tokio::task::block_in_place(move || {
            rsa_sha256_verifies(&public_key_pem, &sig_str, &sig_b64)
        })
    });

    if !verified {
        return Err(NoombatError::SignatureVerification.into());
    }

    // ..... PER-DOMAIN FEDERATION RATE LIMIT .....
    //
    // Enforce a stricter rate limit on inbound deliveries keyed by the
    // sending domain rather than the remote IP (federation traffic is
    // often relayed through proxies). Uses an atomic Lua script to
    // avoid the INCR/EXPIRE race condition.
    //
    // When Redis is unavailable the in-process governor-backed fallback
    // limiter is used, preventing fail-open bypass.

    let sending_domain = actor_uri
        .strip_prefix("https://")
        .or_else(|| actor_uri.strip_prefix("http://"))
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("unknown");

    // `503` rather than the middleware's `429`, which is why this maps
    // the decision itself instead of taking the response.
    let decision = crate::rate_limit::check_key(
        state,
        &format!("rl:fed:{sending_domain}"),
        state.fed_rate_limit,
        state.fed_rate_limit_window_secs,
    )
    .await;

    if decision != crate::rate_limit::Decision::Allowed {
        return Err(
            NoombatError::ServiceUnavailable("federation rate limit exceeded".into()).into(),
        );
    }

    // ..... PARSE AND PROCESS .....

    // Parsed twice, on purpose.
    //
    // The FEP-8b32 proof is computed over every property the sender
    // included and `Activity` models only the ones Noombat acts on, so
    // the raw `Value` is needed as well as the typed view. Deriving the
    // typed view from the `Value` would be cheaper, but `Value` keeps the
    // last of a duplicated key while the derived `Deserialize` rejects
    // the duplicate outright. Going through `Value` would therefore
    // silently accept documents this route refuses, and a parser
    // differential between the signature check, the proof check and the
    // typed view is the exact failure FEP-8b32 exists to prevent. The
    // second parse is bounded by the body limit on this route.
    let document: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| NoombatError::BadRequest(format!("invalid JSON: {e}")))?;
    let activity: Activity = serde_json::from_slice(body)
        .map_err(|e| NoombatError::BadRequest(format!("invalid JSON: {e}")))?;

    // For the shared inbox, verify that at least one addressed
    // recipient is hosted on this instance. Without this check,
    // a remote server could deliver activities addressed to
    // actors on a third instance.
    if path == "/inbox" && !activity_addresses_local_actor(&activity, &state.domain) {
        return Err(NoombatError::BadRequest(
            "shared inbox: activity does not address any local actor".into(),
        )
        .into());
    }

    // The verified identity is the actor that owns the key, which is not
    // the `keyId` when a peer serves its keys at their own URLs.
    inbox::process_activity(
        &state.pool,
        &state.http_client,
        &remote_actor.ap_id,
        &document,
        activity,
    )
    .await?;
    Ok(StatusCode::ACCEPTED)
}

/// Check whether an activity's `to` or `cc` fields contain at least
/// one URI hosted on the local domain, or the ActivityStreams Public
/// collection (which is implicitly local).
///
/// This implements the shared-inbox recipient verification: a server
/// should only process activities delivered to its shared inbox if
/// at least one addressed recipient is local.
fn activity_addresses_local_actor(activity: &Activity, domain: &str) -> bool {
    let public = "https://www.w3.org/ns/activitystreams#Public";
    let domain_prefix = format!("https://{domain}/");

    let addresses = activity
        .to
        .iter()
        .flatten()
        .chain(activity.cc.iter().flatten());

    for addr in addresses {
        if addr == public || addr.eq_ignore_ascii_case("Public") || addr.starts_with(&domain_prefix)
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An 8192-bit public key, the largest rsa accepts.
    const RSA_8192_PUBLIC_PEM: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAnwsP9V+dnpAMJ6OdX6gA\n\
1f6mdJgBZ7dyalXU7lpvJqwrSeugZFTAtK5qPBbS+0fzHh9qvqqhaF4vCfk8L8sG\n\
0ISn0ZB2ftXdx3fRaglY1D8b7TkoN8vGIsj/LgGA/9fg2YXPtVa0ZyY+u+CSrBxv\n\
OhRATXo6rPqUrslT+jpDVDjlc0+yvVmUKWDKxBRGqOVoYzjoyDCtuf7OXiCZ+AdX\n\
xU7/7FV4hUsJmpXs2FscwwlTN3s5lr5UHrVrOzuqfqxtoMcrxzQnIyVUk1K7zytH\n\
iOChNsjQIcwrQbriWz4WEud6Cea+LKjWngeIgUm/m3qStq+gOgveEOXOBhADBPWI\n\
RUczREJKaB6kNy0XdXzHLvjrLvDvRKlq2Dam4sPcH1EvIIyJo3WIl9entIn/ldZE\n\
7sS3S0U6pPuZghhK9YFRJWT2DNLQC/46/XlBKRec5Otm1jFXJGqnTKa9vxy4A5QJ\n\
JxrIog2VjgY932zMA8nrtjHkmu7fnkwKVBKNhKo6aDaE4QuPMd+4KfxEYDQaG8P/\n\
YZvL9muMyXQVMy0OakgciAr3aakifgXCWF9UGjb1a0L7icp05+PTkXpZv9gpZ4eP\n\
upiZFLZD8zuou5iaJ3UjQAtvVMTs9KZuGwC3mkxkev7nyHQOORZTVufNWHV7unIB\n\
lUbqTY8/DlIHCvz39+l4Ool9SDImvJANisv2QHZ1A3SVOdGVXivPn3nd/zm8B+9H\n\
GUBGFbke6Elfbmf+/c/nUEqfgVVLXpA84AH1MmtBdL9montXg7E2u4jh0bIobROn\n\
eZXr3CmYSom+Wd3VzNge3d0pKd7tICzSM+RaQYfFhtIu6yBTvaDGUdVeVJD6dIiK\n\
XtVThNlAQcrdRYdnefdihosT6OppLXu/AXfr07kL1SraU9YiJ+FwsExdyCtbDAF3\n\
7A7pY29tf7ypKULKERCt/hSjb6BxoGiHYZSeNd6dXDSvh74y7LjfTXU+2OH0LtD9\n\
ZMfYfr3Yt8HJeo5HPo7Z4vLlQ2Ru/0t8nTJhGAIkf1S84Q5AogcNlFDbxFWHM1en\n\
UIgpHQlKOVtXqvkNOwayM0wpPYV6uLeWVbTjQcGCPHAQtw9IaWm9lr9LWwbFdhQ1\n\
+vyd6wumNooLp5lTL+HWPbfLnlpw7yMUYPT9pPfd3a6Xp/0s0j3DeM0gdUtAT9op\n\
18d/DGI28Mbb3n2/hNdP6SMHEZvdkcSvDXR2UmMKoE4P+kdYCOz6X+NOfKnsuoNy\n\
CxUWRBhxe/HE1rd93i7nfJhCIvU4hmqAqY6p6e4JgdHqxR9Qm0GAhaT/2moTW6lz\n\
119CixO/octXQknGsVL/YzLUdEZ+btPsCART3b1AaWyJFmjmO3pETlYOfIJ9KHoU\n\
TQIDAQAB\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn the_largest_key_rsa_accepts_fits_the_bound() {
        let crlf = RSA_8192_PUBLIC_PEM.replace('\n', "\r\n");
        for pem in [RSA_8192_PUBLIC_PEM, crlf.as_str()] {
            assert!(pem.len() <= MAX_REMOTE_KEY_PEM_BYTES);
            assert!(parse_remote_public_key(pem).is_some());
        }
    }

    #[test]
    fn a_key_rsa_accepts_is_refused_past_the_bound() {
        // PEM parsing skips text before the BEGIN line, so rsa alone
        // accepts this key although it is longer than the bound.
        let padded = format!(
            "{}\n{RSA_8192_PUBLIC_PEM}",
            "x".repeat(MAX_REMOTE_KEY_PEM_BYTES)
        );
        assert!(rsa::PublicKey::from_public_key_pem(&padded).is_ok());
        assert!(parse_remote_public_key(&padded).is_none());
    }

    /// A 2048-bit public key, and an `rsa-sha256` signature made with its
    /// private key over an HTTP Signatures signing string.
    const KAT_PUBLIC_PEM: &str = "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzA5JmvFcGI29MS+obkz8\n\
I1I44AMRgLB7BpA8Dan5iWef341ikpkQjXMFHEltkSXF4L7Xs+bDFHU9GAopKtLh\n\
k/VoE7gXZGnhbEwDANbd8EVNI4BNUWXWa0EQkOXuq/QFLtA2sN+XkyKYeoCy/Bzh\n\
fAFhex3f/OETVPP6Hl+5oWMxqhrMOZIFL+H+39E/GLz7ONsZ/hC5K4Gc1nKB5mGx\n\
d3+zgL516mp8FQKg5aHFeH88UEsV/F2NUSespASkHtD3kwixSX8JeCa9GR03Q4aD\n\
Vmqoe82XbjLpFtKJyMBv/U1urvjqsAzu79tBUuFG/8T6gzaoljX9QvpC6okD0Gnt\n\
dwIDAQAB\n\
-----END PUBLIC KEY-----\n";
    const KAT_SIGNING_STRING: &str = "(request-target): post /users/alice/inbox\n\
        host: remote.example\n\
        date: Tue, 10 Nov 2026 00:00:00 GMT\n\
        digest: SHA-256=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    const KAT_SIGNATURE_B64: &str = "\
        Jfqe+OlNrOKHpHIjvcE9WQyVDS1aS52SOe1TpGa7g3U7jkOhUJo6jOx5hcZa/oODUb+IrhFS\
        qDpopUDl4dg5C7IKuio0z7kEl0N8ufbQn+WkfgfcqV+bJS26SgIluOw50P6DIlwovS7ATc1Z\
        ZJa8iD4OWc86B5IocDI1eHGl1jTCCF0L3YRHtFOTPEXNre6DA6n/5jBY93XHTodcgG+zVsWb\
        QnanywOq5vEMFUlu7MMgM0fJ3SBZ21CbzR537hYEt3dESwuFCgQBjJsxGGkelhvNnow+yCyr\
        IIDkZCnGNnBBEqc+TXjokB0/sZBLnlNMg7Au67DoyVT5ou86dzm1Vg==";

    #[test]
    fn a_known_good_signature_verifies() {
        assert!(rsa_sha256_verifies(
            KAT_PUBLIC_PEM,
            KAT_SIGNING_STRING,
            KAT_SIGNATURE_B64
        ));
    }

    #[test]
    fn a_signature_verifies_only_for_its_own_string_and_bytes() {
        let other = "(request-target): post /inbox";
        assert!(!rsa_sha256_verifies(
            KAT_PUBLIC_PEM,
            other,
            KAT_SIGNATURE_B64
        ));
        let mut tampered = BASE64.decode(KAT_SIGNATURE_B64).unwrap();
        tampered[10] ^= 1;
        let tampered = BASE64.encode(tampered);
        assert!(!rsa_sha256_verifies(
            KAT_PUBLIC_PEM,
            KAT_SIGNING_STRING,
            &tampered
        ));
    }
}
