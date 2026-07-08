// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Federation-facing routes: WebFinger, NodeInfo, and actor inbox.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use noombat_ap::activity::Activity;
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger_handler))
        .route("/.well-known/nodeinfo", get(nodeinfo_well_known))
        .route("/nodeinfo/2.1", get(nodeinfo_handler))
        .route("/users/{username}/inbox", post(inbox_handler))
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

async fn inbox_handler(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    // Verify the local target actor exists.
    let _local_actor =
        noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // ..... HTTP SIGNATURE VERIFICATION .....
    //
    // Parse the Signature header, reconstruct the signing string,
    // resolve the remote actor's public key, and verify.

    let sig_header = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(noombat_core::error::NoombatError::SignatureVerification)?;

    let parsed = noombat_federation::http_sig::parse_signature_header(sig_header)?;

    // Collect request headers needed for signing string reconstruction.
    let mut request_headers: Vec<(String, String)> = Vec::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            request_headers.push((name.as_str().to_owned(), v.to_owned()));
        }
    }

    // Verify the body digest if the signing string includes it.
    if parsed.headers.iter().any(|h| h == "digest") {
        let expected_digest = headers
            .get("digest")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("SHA-256="))
            .ok_or(noombat_core::error::NoombatError::SignatureVerification)?;
        let actual_digest = noombat_federation::http_sig::digest_body(&body);
        if expected_digest != actual_digest {
            return Err(noombat_core::error::NoombatError::SignatureVerification.into());
        }
    }

    let path = format!("/users/{username}/inbox");
    let signing_string = noombat_federation::http_sig::reconstruct_signing_string(
        &parsed.headers,
        "post",
        &path,
        &request_headers,
    )?;

    // Resolve the remote actor's public key from the key_id URI.
    // The key_id typically ends with `#main-key`; strip it to get the actor URI.
    let actor_uri = parsed.key_id.split('#').next().unwrap_or(&parsed.key_id);
    let remote_actor =
        inbox::resolve_remote_actor(&state.pool, &state.http_client, actor_uri).await?;

    // ..... PER-DOMAIN FEDERATION RATE LIMIT .....
    //
    // Enforce a stricter rate limit on inbound deliveries keyed by the
    // sending domain rather than the remote IP (federation traffic is
    // often relayed through proxies).  Uses an atomic Lua script to
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
            return Err(NoombatError::ServiceUnavailable(
                "federation rate limit exceeded".into(),
    )
            .into());
        }
    }

    // ..... PROCESS THE VERIFIED ACTIVITY .....

    let activity: Activity = serde_json::from_slice(&body)
        .map_err(|e| noombat_core::error::NoombatError::BadRequest(format!("invalid JSON: {e}")))?;

    inbox::process_activity(&state.pool, &state.http_client, activity).await?;
    Ok(StatusCode::ACCEPTED)
}
