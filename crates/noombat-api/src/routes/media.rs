// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Avatar upload, and the route that serves uploaded media.
//!
//! The reader's browser talks to this application and never to the
//! storage backend. That is what keeps the request log here, under the
//! operator's control, rather than at an object store that would learn
//! who looked at whose profile; and it is what keeps an access rule
//! added later applicable to media already uploaded.
//!
//! The upload route carries no username in its path. The target is
//! whoever the session says it is, so there is no other account to
//! authorise against and no confused-deputy shape to get wrong. This is
//! deliberately not `PATCH /users/{username}`, whose bearer check
//! authenticates the caller as an administrator without establishing
//! that they own the account named in the path.

use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};

use crate::media::{MAX_UPLOAD_BYTES, MediaError, new_object_key, process_avatar};
use crate::middleware::Viewer;
use crate::state::AppState;

/// How long a shared cache may keep an object.
///
/// Not `immutable`, though the content at a key never changes: an object
/// key is unique per upload, so the only thing that changes is whether
/// the object still exists. Erasure deletes the bytes, and a cache
/// holding an avatar indefinitely would serve an erased account's
/// picture after the account was gone. Five minutes bounds that without
/// giving up caching.
const MEDIA_MAX_AGE_SECS: u32 = 300;

pub fn router() -> Router<AppState> {
    Router::new().route("/media/{key}", get(serve_media)).route(
        "/settings/avatar",
        post(upload_avatar)
            // Refuse an oversized body without reading it. The field
            // is bounded again after extraction, because one limit
            // covers the whole multipart body rather than each part.
            .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
    )
}

fn actor_uuid(viewer: &Option<axum::Extension<Viewer>>) -> Option<uuid::Uuid> {
    viewer.as_ref().map(|p| p.actor_id)
}

/// Serve an uploaded object.
///
/// Unauthenticated: an avatar appears wherever a person does, including
/// to signed-out readers. What is *not* public is who asked for it, and
/// that is the whole reason this route exists rather than a bucket URL.
async fn serve_media(
    State(state): State<AppState>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT object_key, media_type FROM media_attachments WHERE object_key = $1",
    )
    .bind(&key)
    .fetch_optional(&state.pool)
    .await;

    let (object_key, media_type) = match row {
        Ok(Some(found)) => found,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!(%error, "media lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // The object key is a strong validator by construction: it is unique
    // per upload and the bytes at it never change, so a matching
    // If-None-Match cannot be stale.
    let etag = format!("\"{object_key}\"");
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|candidate| candidate.trim() == etag))
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }

    let bytes = match state.media.get(&object_key).await {
        Ok(bytes) => bytes,
        Err(error) => {
            // The row exists and the object does not. Worth an error
            // rather than a bare 404: it means storage and database have
            // diverged, which no user action can cause.
            tracing::error!(%error, %object_key, "media row has no object behind it");
            return StatusCode::NOT_FOUND.into_response();
        }
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, media_type),
            (
                header::CACHE_CONTROL,
                format!("public, max-age={MEDIA_MAX_AGE_SECS}"),
            ),
            (header::ETAG, etag),
            // Served inline as an image, and never as something the
            // browser is invited to run or download under a name the
            // uploader chose.
            (header::CONTENT_DISPOSITION, "inline".to_owned()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
        ],
        bytes,
    )
        .into_response()
}

/// Accept an avatar for the signed-in actor.
///
/// Replaces rather than accumulates: the previous object is deleted once
/// the new row is written, and a unique index on `(actor_id, purpose)`
/// is what makes that true rather than a convention.
async fn upload_avatar(
    State(state): State<AppState>,
    viewer: Option<axum::Extension<Viewer>>,
    mut multipart: Multipart,
) -> Response {
    let Some(actor_id) = actor_uuid(&viewer) else {
        return (StatusCode::UNAUTHORIZED, "sign in to change your avatar").into_response();
    };

    // Read the one field this route expects. The field name is checked;
    // the filename and the declared content type are read by nothing,
    // because neither is evidence of anything.
    let mut raw: Option<Vec<u8>> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() == Some("avatar") {
                    match field.bytes().await {
                        Ok(bytes) => raw = Some(bytes.to_vec()),
                        Err(_) => {
                            return (StatusCode::PAYLOAD_TOO_LARGE, "that image is too large")
                                .into_response();
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => return (StatusCode::BAD_REQUEST, "malformed upload").into_response(),
        }
    }

    let Some(raw) = raw else {
        return (StatusCode::BAD_REQUEST, "no image was attached").into_response();
    };

    let processed = match process_avatar(&raw) {
        Ok(processed) => processed,
        Err(MediaError::TooLarge) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "that image is larger than 4 MB",
            )
                .into_response();
        }
        Err(MediaError::UnsupportedFormat) => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "that file is not a JPEG or PNG",
            )
                .into_response();
        }
        Err(MediaError::TooManyPixels | MediaError::Undecodable) => {
            return (
                StatusCode::BAD_REQUEST,
                "the image could not be processed; try another file",
            )
                .into_response();
        }
    };

    let object_key = new_object_key();
    if let Err(error) = state.media.put(&object_key, &processed.bytes).await {
        tracing::error!(%error, %actor_id, "could not write the avatar object");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not store the image",
        )
            .into_response();
    }

    // The URL a page renders, and the URL a peer fetches: this route,
    // never the backend. Absolute, because `icon` in the federated actor
    // document must be dereferenceable from another instance.
    let url = format!("https://{}/media/{}", state.domain, object_key);

    let previous = sqlx::query_scalar::<_, String>(
        "SELECT object_key FROM media_attachments WHERE actor_id = $1 AND purpose = 'avatar'",
    )
    .bind(actor_id)
    .fetch_optional(&state.pool)
    .await
    .unwrap_or(None);

    let written = sqlx::query(
        "INSERT INTO media_attachments
             (actor_id, media_type, object_key, backend, purpose, url, byte_size)
         VALUES ($1, $2, $3, $4, 'avatar', $5, $6)
         ON CONFLICT (actor_id, purpose) WHERE purpose IN ('avatar', 'header')
         DO UPDATE SET media_type = EXCLUDED.media_type,
                       object_key = EXCLUDED.object_key,
                       backend    = EXCLUDED.backend,
                       url        = EXCLUDED.url,
                       byte_size  = EXCLUDED.byte_size,
                       created_at = now()",
    )
    .bind(actor_id)
    .bind(processed.media_type)
    .bind(&object_key)
    .bind(state.media.backend())
    .bind(&url)
    .bind(processed.bytes.len() as i64)
    .execute(&state.pool)
    .await;

    if let Err(error) = written {
        tracing::error!(%error, %actor_id, "could not record the avatar");
        // Do not leave the object behind: nothing references it.
        let _ = state.media.delete(&object_key).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not save the image",
        )
            .into_response();
    }

    if let Err(error) = sqlx::query("UPDATE actors SET avatar_url = $1 WHERE id = $2")
        .bind(&url)
        .bind(actor_id)
        .execute(&state.pool)
        .await
    {
        tracing::error!(%error, %actor_id, "could not point the actor at the new avatar");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not save the image",
        )
            .into_response();
    }

    // Only now: the row that referenced it is gone, so the bytes are
    // unreachable. Deleting earlier would break the page for anyone
    // mid-request on the old object.
    if let Some(previous) = previous.filter(|p| p != &object_key)
        && let Err(error) = state.media.delete(&previous).await
    {
        tracing::warn!(%error, %previous, "replaced an avatar but could not remove the old object");
    }

    // Peers cache the actor document, so a new avatar that is never
    // pushed is a new avatar nobody else sees.
    if let Ok(actor) = noombat_identity::repo::find_by_id(&state.pool, actor_id).await {
        noombat_federation::update::enqueue_actor_update(&state.pool, &actor, &state.domain).await;
    }

    Redirect::to("/settings/profile").into_response()
}
