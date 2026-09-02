// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Authorisation helpers for routes keyed on one account.
//!
//! Every write route under `/users/{username}` acts on exactly one
//! account, so they all ask the same question: may this request act for
//! that account? Asking it in one place is what keeps the answer the
//! same at every call site.

use axum::Extension;
use noombat_core::actor::Actor;
use noombat_core::authorisation::OrganizationRole;
use noombat_core::error::NoombatError;

use crate::error::ApiError;
use crate::middleware::Viewer;

/// Whether the authenticated viewer may act for `subject_id`.
///
/// Two ways to qualify: being that account, or holding a role in it
/// where it is an organisation. The account's own session counts
/// because an enrolled organisation owns its actor row; a member's
/// counts because an organisation otherwise never signs in.
///
/// `Ok(None)` means the caller is the account itself; `Ok(Some(role))`
/// means they act for an organisation and carry that standing, which
/// saves the caller a second query before applying the predicates that
/// take an `OrganizationRole`.
///
/// Both failures are `Forbidden` rather than `NotFound`, so somebody
/// outside an organisation cannot learn whether it exists from the
/// error they get back.
pub async fn require_acts_for(
    pool: &sqlx::PgPool,
    subject_id: uuid::Uuid,
    viewer: &Option<Extension<Viewer>>,
) -> Result<Option<OrganizationRole>, ApiError> {
    let actor_id = viewer
        .as_ref()
        .ok_or(ApiError(NoombatError::Forbidden))?
        .actor_id;

    if actor_id == subject_id {
        return Ok(None);
    }

    let role: Option<OrganizationRole> = sqlx::query_scalar(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND member_id = $2",
    )
    .bind(subject_id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| ApiError(NoombatError::Internal(e.to_string())))?;

    role.map(Some).ok_or(ApiError(NoombatError::Forbidden))
}

/// Resolve the local account named in the path and require that the
/// request may act for it.
///
/// The match is on the account's UUID and never on the username in the
/// path. A username is mutable, and comparing on it would let a rename
/// carry one account's session into another account's authorisation.
pub async fn require_local_actor(
    pool: &sqlx::PgPool,
    viewer: &Option<Extension<Viewer>>,
    username: &str,
) -> Result<Actor, ApiError> {
    // Authentication is checked before the lookup, so an anonymous
    // caller cannot tell an existing account from a missing one by the
    // difference between 403 and 404.
    if viewer.is_none() {
        return Err(ApiError(NoombatError::Forbidden));
    }

    let actor = noombat_identity::repo::find_local_by_username(pool, username).await?;
    require_acts_for(pool, actor.id, viewer).await?;
    Ok(actor)
}
