// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Connection routes: the mutual half of the social graph.
//!
//! - `GET    /users/{username}/connections`          the collection
//! - `POST   /users/{username}/connections`          invite somebody
//! - `GET    /users/{username}/pending_connections`  invitations to answer
//! - `POST   /users/{username}/pending_connections/{id}/accept`
//! - `POST   /users/{username}/pending_connections/{id}/reject`
//! - `DELETE /users/{username}/connections/{id}`     withdraw or disconnect
//!
//! The lifecycle is an AS2 `Relationship` carried by `Invite`, answered
//! with `Accept` or `Reject`. Local-only in v1: both sides are local
//! actors, so nothing is delivered to a peer, but the activities are
//! built here rather than at the point federation is switched on, so the
//! shapes are settled and testable now.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use noombat_ap::context::{Extension, context_with};
use noombat_core::error::NoombatError;
use noombat_core::privacy::ListVisibility;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::require_local_actor;
use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/users/{username}/connections",
            get(get_connections).post(invite_connection),
        )
        .route(
            "/users/{username}/connections/{id}",
            axum::routing::delete(remove_connection),
        )
        .route(
            "/users/{username}/pending_connections",
            get(list_pending_connections),
        )
        .route(
            "/users/{username}/pending_connections/{id}/accept",
            post(accept_pending_connection),
        )
        .route(
            "/users/{username}/pending_connections/{id}/reject",
            post(reject_pending_connection),
        )
}

// ..... The AS2 Relationship .....

/// The `Invite` that carries an AS2 `Relationship` between two actors.
///
/// One predicate, `schema:knows`, decided with the namespace audit.
/// `rel:colleagueOf` was considered and dropped: it asserts a workplace
/// in common, which this instance has no way to establish and which a
/// reader would take as employer-confirmed.
fn invite_activity(
    requester_ap_id: &str,
    addressee_ap_id: &str,
    invite_id: &str,
) -> serde_json::Value {
    json!({
        "@context": context_with(&[Extension::Schema]),
        "id": invite_id,
        "type": "Invite",
        "actor": requester_ap_id,
        "object": {
            "type": "Relationship",
            "subject": requester_ap_id,
            "relationship": "schema:knows",
            "object": addressee_ap_id,
        },
        "to": addressee_ap_id,
    })
}

/// The answer to an `Invite`, which is an `Accept` or a `Reject` of the
/// original activity by its id.
fn answer_activity(answerer_ap_id: &str, invite_id: &str, accepted: bool) -> serde_json::Value {
    json!({
        "@context": context_with(&[]),
        "id": format!("{answerer_ap_id}#answer-{}", chrono::Utc::now().timestamp_millis()),
        "type": if accepted { "Accept" } else { "Reject" },
        "actor": answerer_ap_id,
        "object": invite_id,
    })
}

// ..... GET /users/{username}/connections .....

/// The connections collection, subject to the owner's list setting.
///
/// A refusal is `404`, matching the CV route: a `403` would confirm both
/// that the account exists and that it has connections worth hiding.
async fn get_connections(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let viewer_id = viewer.as_ref().map(|v| v.actor_id);

    let settings = noombat_identity::connections::list_settings(&state.pool, actor.id).await?;
    let relationship =
        noombat_identity::connections::relationship(&state.pool, viewer_id, actor.id).await?;

    if !noombat_core::authorisation::list_visible_to(
        settings.connections,
        viewer_id,
        actor.id,
        &relationship,
    ) {
        return Err(ApiError(NoombatError::ActorNotFound(username)));
    }

    let total = noombat_identity::connections::count_connections(&state.pool, actor.id).await?;
    let items =
        noombat_identity::connections::list_connection_ap_ids(&state.pool, actor.id, 40, 0).await?;

    let mut collection = json!({
        "@context": context_with(&[Extension::Schema]),
        "id": format!("{}/connections", actor.ap_id),
        "type": "OrderedCollection",
        "orderedItems": items,
    });

    // Same rule as the followers and following collections: the count
    // is a separate disclosure from the list, and omitted rather than
    // zeroed when the owner has turned it off.
    if viewer_id == Some(actor.id) || actor.shows_followers_count() {
        collection["totalItems"] = json!(total);
    }

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/activity+json; charset=utf-8")],
        Json(collection),
    ))
}

// ..... POST /users/{username}/connections .....

#[derive(Deserialize)]
struct InviteTarget {
    /// The local username to invite.
    username: String,
}

/// Invite another local actor to connect.
async fn invite_connection(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    Json(body): Json<InviteTarget>,
) -> Result<impl IntoResponse, ApiError> {
    let requester = require_local_actor(&state.pool, &viewer, &username).await?;
    let addressee =
        noombat_identity::repo::find_local_by_username(&state.pool, body.username.trim()).await?;

    if requester.id == addressee.id {
        return Err(ApiError(NoombatError::BadRequest(
            "an actor cannot connect to itself".into(),
        )));
    }

    // A block in either direction refuses the invitation, and refuses it
    // the same way an unknown account would, so an invitation cannot be
    // used to discover that somebody has blocked you.
    use noombat_core::authorisation::InteractionService;
    let interactions = crate::interactions::Interactions::new(state.pool.clone());
    let blocked = !interactions
        .owner_restriction(&addressee.id, &requester.id)
        .await
        .may_send_message()
        || !interactions
            .owner_restriction(&requester.id, &addressee.id)
            .await
            .may_send_message();
    if blocked {
        return Err(ApiError(NoombatError::ActorNotFound(body.username)));
    }

    let invite_id = format!(
        "{}#invite-{}",
        requester.ap_id,
        chrono::Utc::now().timestamp_millis()
    );

    let created = noombat_identity::connections::invite(
        &state.pool,
        requester.id,
        addressee.id,
        Some(&invite_id),
    )
    .await?;

    // `None` means a row already existed for the pair, in either
    // direction. Answered with the same 204 as a fresh invitation: the
    // caller's intent is satisfied either way, and distinguishing them
    // would report whether the other side had already invited them.
    if created.is_none() {
        return Ok(StatusCode::NO_CONTENT);
    }

    // Built and discarded in v1, where both sides are local and there is
    // nobody to deliver to. It exists so the activity shape is settled
    // and exercised by the tests below rather than invented later.
    let _activity = invite_activity(&requester.ap_id, &addressee.ap_id, &invite_id);

    Ok(StatusCode::NO_CONTENT)
}

// ..... Pending invitations .....

/// Invitations awaiting this account's answer.
async fn list_pending_connections(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;
    let pending = noombat_identity::connections::list_pending_for(&state.pool, actor.id).await?;

    let items: Vec<_> = pending
        .into_iter()
        .map(|(id, username)| json!({ "actor_id": id, "username": username }))
        .collect();

    Ok(Json(json!({ "pending": items })))
}

/// Accept an invitation. `id` is the requester's actor id.
async fn accept_pending_connection(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, Uuid)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    if !noombat_identity::connections::accept(&state.pool, actor.id, id).await? {
        return Err(ApiError(NoombatError::NotFound {
            entity: "connection",
            id,
        }));
    }

    let requester = noombat_identity::repo::find_by_id(&state.pool, id).await?;
    let invite_id = format!("{}#invite", requester.ap_id);
    let _activity = answer_activity(&actor.ap_id, &invite_id, true);

    Ok(StatusCode::NO_CONTENT)
}

/// Reject an invitation. `id` is the requester's actor id.
async fn reject_pending_connection(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, Uuid)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    if !noombat_identity::connections::reject(&state.pool, actor.id, id).await? {
        return Err(ApiError(NoombatError::NotFound {
            entity: "connection",
            id,
        }));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ..... DELETE /users/{username}/connections/{id} .....

/// Withdraw an unanswered invitation, or end an accepted connection.
///
/// One route for both because the caller's intent is the same, and which
/// applies is a fact about the row rather than about the request.
async fn remove_connection(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, Uuid)>,
    viewer: Option<axum::Extension<Viewer>>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_local_actor(&state.pool, &viewer, &username).await?;

    let withdrawn = noombat_identity::connections::withdraw(&state.pool, actor.id, id).await?;
    let disconnected = if withdrawn {
        false
    } else {
        noombat_identity::connections::disconnect(&state.pool, actor.id, id).await?
    };

    if !withdrawn && !disconnected {
        return Err(ApiError(NoombatError::NotFound {
            entity: "connection",
            id,
        }));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ..... List-visibility settings .....

/// Parse a list-visibility form field, refusing an unknown value rather
/// than silently narrowing it, so a typo in a settings form is reported
/// instead of quietly changing what the owner asked for.
pub fn parse_list_setting(value: &str) -> Result<ListVisibility, NoombatError> {
    match value {
        "public" => Ok(ListVisibility::Public),
        "followers" => Ok(ListVisibility::Followers),
        "connections" => Ok(ListVisibility::Connections),
        "private" => Ok(ListVisibility::Private),
        other => Err(NoombatError::BadRequest(format!(
            "list visibility must be 'public', 'followers', \
             'connections' or 'private', not {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_invite_carries_a_relationship_typed_schema_knows() {
        let activity = invite_activity(
            "https://noombat.social/users/alice",
            "https://noombat.social/users/bob",
            "https://noombat.social/users/alice#invite-1",
        );

        assert_eq!(activity["type"], "Invite");
        assert_eq!(activity["object"]["type"], "Relationship");
        // The predicate, and there is exactly one.
        assert_eq!(activity["object"]["relationship"], "schema:knows");
        assert_eq!(
            activity["object"]["subject"],
            "https://noombat.social/users/alice"
        );
        assert_eq!(
            activity["object"]["object"],
            "https://noombat.social/users/bob"
        );
    }

    #[test]
    fn the_invite_declares_the_prefix_its_predicate_uses() {
        // `schema:knows` expands to nothing without the binding, so a
        // strict processor would drop the predicate and keep the
        // Relationship, which reads as a connection of unstated kind.
        let activity = invite_activity("https://e/a", "https://e/b", "https://e/a#i");
        let context = activity["@context"].as_array().expect("an array context");
        assert!(
            context.iter().any(|entry| entry.get("schema").is_some()),
            "the context does not bind the schema prefix: {context:?}"
        );
    }

    #[test]
    fn an_answer_names_the_invitation_it_answers() {
        let accept = answer_activity("https://e/b", "https://e/a#invite-1", true);
        assert_eq!(accept["type"], "Accept");
        assert_eq!(accept["object"], "https://e/a#invite-1");

        let reject = answer_activity("https://e/b", "https://e/a#invite-1", false);
        assert_eq!(reject["type"], "Reject");
        assert_eq!(reject["object"], "https://e/a#invite-1");
    }

    #[test]
    fn an_unknown_list_setting_is_refused_not_narrowed() {
        assert!(parse_list_setting("private").is_ok());
        assert!(parse_list_setting("connections").is_ok());
        // Silently returning `Private` here would tell an owner their
        // choice was saved when it was not.
        assert!(parse_list_setting("friends").is_err());
        assert!(parse_list_setting("").is_err());
    }
}
