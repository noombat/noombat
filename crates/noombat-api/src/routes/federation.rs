// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Federation-facing routes: WebFinger, NodeInfo, and actor inbox.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
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
use noombat_federation::{digest, inbox, nodeinfo, webfinger};

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger_handler))
        .route("/.well-known/nodeinfo", get(nodeinfo_well_known))
        .route("/nodeinfo/2.1", get(nodeinfo_handler))
        .route("/users/{username}/inbox", post(inbox_handler))
        .route("/inbox", post(shared_inbox_handler))
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
    // Execute the five independent COUNT queries concurrently.
    let (total_users, active_month, active_half_year, local_posts, active_job_listings) =
        tokio::try_join!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM actors WHERE is_local = TRUE")
                .fetch_one(&state.pool),
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM actors \
                 WHERE is_local = TRUE AND updated_at > now() - interval '30 days'"
            )
            .fetch_one(&state.pool),
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM actors \
                 WHERE is_local = TRUE AND updated_at > now() - interval '180 days'"
            )
            .fetch_one(&state.pool),
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM posts \
                 WHERE actor_id IN (SELECT id FROM actors WHERE is_local = TRUE)"
            )
            .fetch_one(&state.pool),
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM job_listings jl \
                 JOIN actors a ON a.id = jl.actor_id \
                 WHERE a.is_local = TRUE \
                   AND jl.published_at IS NOT NULL \
                   AND (jl.expires_at IS NULL OR jl.expires_at > now())"
            )
            .fetch_one(&state.pool),
        )
        .map_err(noombat_core::error::NoombatError::from)?;

    let params = nodeinfo::NodeInfoParams {
        total_users: total_users as u64,
        active_month: active_month as u64,
        active_half_year: active_half_year as u64,
        local_posts: local_posts as u64,
        active_job_listings: active_job_listings as u64,
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
    let config = SigConfig::default();

    // Collect HTTP headers into the `BTreeMap<String, String>` that the
    // library expects.
    let mut sig_headers = BTreeMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            sig_headers.insert(name.as_str().to_owned(), v.to_owned());
        }
    }

    let unverified = config
        .begin_verify("POST", path, sig_headers)
        .map_err(|e| NoombatError::Federation(format!("signature parse/validate: {e}")))?;

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
        inbox::resolve_remote_actor(&state.pool, &state.http_client, actor_uri).await?;

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
            let Ok(public_key) = rsa::RsaPublicKey::from_public_key_pem(&public_key_pem) else {
                return false;
            };
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key);

            let Ok(sig_bytes) = BASE64.decode(&sig_b64) else {
                return false;
            };
            let Ok(signature) = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()) else {
                return false;
            };

            verifying_key.verify(sig_str.as_bytes(), &signature).is_ok()
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

    if let Some(mut redis) = state.redis.clone() {
        let domain = actor_uri
            .strip_prefix("https://")
            .or_else(|| actor_uri.strip_prefix("http://"))
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("unknown");

        let key = format!("rl:fed:{domain}");
        let fed_window_secs: i64 = 60;
        let fed_limit: i64 = 300;

        let result: Vec<i64> = redis::cmd("EVAL")
            .arg(
                r"local count = redis.call('INCR', KEYS[1])
                  if count == 1 then
                      redis.call('EXPIRE', KEYS[1], ARGV[1])
                  end
                  return count",
            )
            .arg(1i64)
            .arg(&key)
            .arg(fed_window_secs)
            .query_async(&mut redis)
            .await
            .unwrap_or_default();

        let count = result.first().copied().unwrap_or(0);
        if count > fed_limit {
            return Err(
                NoombatError::ServiceUnavailable("federation rate limit exceeded".into()).into(),
            );
        }
    }

    // ..... PARSE AND PROCESS .....

    let activity: Activity = serde_json::from_slice(body)
        .map_err(|e| NoombatError::BadRequest(format!("invalid JSON: {e}")))?;

    // For the shared inbox, verify that at least one addressed
    // recipient is hosted on this instance. Without this check,
    // a remote server could deliver activities addressed to
    // actors on a third instance.
    if path == "/inbox"
        && !activity_addresses_local_actor(&activity, &state.domain)
    {
        return Err(NoombatError::BadRequest(
            "shared inbox: activity does not address any local actor".into(),
        )
        .into());
    }

    inbox::process_activity(&state.pool, &state.http_client, activity).await?;
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
        if addr == public
            || addr.eq_ignore_ascii_case("Public")
            || addr.starts_with(&domain_prefix)
        {
            return true;
        }
    }

    false
}
