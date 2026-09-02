// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! CV PDF download endpoint.
//!
//! The aggregate is the asset here. Section-level filtering alone is
//! not access control: a typeset, paginated, machine-parsable PDF of
//! whatever sections a requester can see is exactly the harvesting
//! surface the `cv_download` setting exists to close. So this route
//! gates on `cv_downloadable_by` before generating anything, filters
//! sections by the same relationship it just established, counts the
//! download, and rate-limits the requester.
//!
//! Denials are `404`, never `403`: a `403` would confirm the profile
//! exists.

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::IntoResponse;
use axum::routing::get;
use noombat_core::actor::Actor;
use noombat_core::error::NoombatError;
use noombat_core::privacy::SectionVisibility;
use serde::Deserialize;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::Viewer;
use crate::state::AppState;

/// Query parameters for `GET /users/{username}/cv`.
#[derive(Debug, Deserialize)]
pub struct CvParams {
    /// Typst template name (default: `"default"`).
    #[serde(default = "default_template")]
    pub template: String,
    /// Citation style for publications: `apa`, `ieee`, or `vancouver`
    /// (default: `"apa"`).
    #[serde(default = "default_citation_style")]
    pub citation_style: String,
}

fn default_template() -> String {
    "default".to_owned()
}

fn default_citation_style() -> String {
    "apa".to_owned()
}

pub fn router() -> Router<AppState> {
    Router::new().route("/users/{username}/cv", get(download_cv))
}

/// Whether the viewer may download `owner`'s CV, and if so which
/// sections it may contain.
///
/// The two questions are answered together because they turn on the
/// same fact, the viewer's relationship to the owner, and answering
/// them apart is how the route came to filter sections correctly while
/// enforcing nothing.
///
/// A denial is [`NoombatError::ActorNotFound`], the same error a missing
/// username produces, so the two are indistinguishable to a caller.
///
/// The gate is [`noombat_core::actor::Actor::cv_downloadable_by`] and
/// nothing else. This contributes the relationship and the tier; a
/// second opinion here is what let the route filter sections correctly
/// while enforcing nothing.
pub(crate) async fn resolve_cv_access(
    pool: &PgPool,
    owner: &Actor,
    viewer_id: Option<Uuid>,
) -> Result<SectionVisibility, NoombatError> {
    // Identity is the actor's id, never the username in the path. A
    // username is mutable, so matching on it would let a rename decide
    // who reaches a CV.
    //
    // Owners always reach their own, including the `private` entries
    // that exist only for it.
    if viewer_id == Some(owner.id) {
        return Ok(SectionVisibility::Private);
    }

    let relationship =
        noombat_identity::connections::relationship(pool, viewer_id, owner.id).await?;

    if !owner.cv_downloadable_by(viewer_id, &relationship) {
        return Err(NoombatError::ActorNotFound(owner.username.clone()));
    }

    // Which tier the viewer qualifies for, and so what the PDF may
    // contain. The same helper the profile page uses, so the CV and the
    // page it is generated from cannot show different sections.
    Ok(noombat_core::authorisation::section_tier_for(
        viewer_id,
        owner.id,
        &relationship,
    ))
}

/// `GET /users/{username}/cv?template=default`
///
/// Generates and streams a PDF curriculum vitae, subject to the owner's
/// `cv_download` setting. See [`resolve_cv_access`] for the rule and the
/// section table.
async fn download_cv(
    State(state): State<AppState>,
    Path(username): Path<String>,
    viewer: Option<axum::Extension<Viewer>>,
    client: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    Query(params): Query<CvParams>,
) -> Result<impl IntoResponse, ApiError> {
    let viewer_username = viewer.as_ref().map(|p| p.username.as_str());

    // Counted before anything is looked up, so that probing for
    // profiles costs the prober the same budget as downloading. Keyed
    // per account when there is one, so rotating through targets from a
    // single session does not buy extra budget.
    let limit_key = match viewer_username {
        Some(name) => format!("cv:acct:{name}"),
        None => match client.as_ref() {
            Some(info) => format!("cv:ip:{}", info.0.0.ip()),
            None => "cv:ip:unknown".to_owned(),
        },
    };

    if let Some(limited) = crate::rate_limit::check_key(
        &state,
        &limit_key,
        state.cv_download_limit,
        state.cv_download_window_secs,
    )
    .await
    .into_response()
    {
        return Ok(limited);
    }

    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // Reject template names that could escape the templates directory.
    if params.template.contains('/')
        || params.template.contains('\\')
        || params.template.contains("..")
        || params.template.is_empty()
    {
        return Err(ApiError(NoombatError::BadRequest(
            "template name must not contain path separators or '..'".into(),
        )));
    }

    let viewer_id = viewer.as_ref().map(|p| p.actor_id);
    let effective_vis = resolve_cv_access(&state.pool, &actor, viewer_id).await?;

    let template_dir = std::path::Path::new("templates");
    let pdf_bytes = noombat_identity::cv::generate_cv_pdf(
        &state.pool,
        actor.id,
        &effective_vis,
        template_dir,
        &params.template,
        &params.citation_style,
    )
    .await?;

    // Counted only once a PDF exists, so the figure is downloads rather
    // than attempts, and never fatal: this is a counter, not a control,
    // and the download has already succeeded by this point.
    if let Some(analytics) = state.analytics.as_ref()
        && let Err(e) = analytics
            .increment("profile", &actor.id.to_string(), "download")
            .await
    {
        warn!(actor = %actor.username, "failed to record a CV download: {e}");
    }

    let filename = format!("{}_cv.pdf", actor.username);
    Ok((
        StatusCode::OK,
        [
            (CONTENT_TYPE, "application/pdf".to_owned()),
            (
                CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        pdf_bytes,
    )
        .into_response())
}

/// The access decision, against real rows.
///
/// These drive [`resolve_cv_access`] rather than `cv_downloadable_by`
/// directly, and deliberately so: the domain method already had a
/// passing unit test while nothing on this route called it, so a test
/// at that level proves nothing about the route. What is exercised here
/// is the gate the handler runs, including the `follows` lookup and the
/// `actor_privacy` JSONB round trip.
///
/// What these do *not* cover is the HTTP mapping and the fact that the
/// handler calls the gate at all. `tests/cv_access.rs` covers that
/// through the assembled router.
#[cfg(test)]
mod tests {
    use super::*;
    use noombat_core::privacy::{ActorPrivacy, CvDownload};
    use sqlx::PgPool;
    use uuid::Uuid;

    const OWNER: &str = "owner";
    const FOLLOWER: &str = "follower";
    const STRANGER: &str = "stranger";

    async fn insert_actor(pool: &PgPool, username: &str, cv_download: CvDownload) -> Uuid {
        let id = Uuid::new_v4();
        let privacy = ActorPrivacy {
            cv_download,
            ..ActorPrivacy::default()
        };

        sqlx::query(
            r#"INSERT INTO actors
                   (id, actor_type, ap_id, username, domain, public_key_pem, is_local, actor_privacy)
               VALUES ($1, 'individual', $2, $3, 'noombat.example', 'PEM', TRUE, $4)"#,
        )
        .bind(id)
        .bind(format!("https://noombat.example/users/{username}"))
        .bind(username)
        .bind(serde_json::to_value(&privacy).expect("privacy serialises"))
        .execute(pool)
        .await
        .expect("actor fixture inserted");

        id
    }

    async fn insert_follow(pool: &PgPool, follower: Uuid, following: Uuid, accepted: bool) {
        sqlx::query(
            "INSERT INTO follows (follower_id, following_id, accepted) VALUES ($1, $2, $3)",
        )
        .bind(follower)
        .bind(following)
        .bind(accepted)
        .execute(pool)
        .await
        .expect("follow fixture inserted");
    }

    /// Every requester against every setting.
    ///
    /// `None` means the download is refused. The owner row is the one
    /// that would regress silently: `Followers` denies everyone who is
    /// not an accepted follower, and nobody follows themselves.
    fn expected(setting: CvDownload, viewer: Option<&str>) -> Option<SectionVisibility> {
        match (setting, viewer) {
            (_, Some(OWNER)) => Some(SectionVisibility::Private),

            (CvDownload::Public, Some(FOLLOWER)) => Some(SectionVisibility::Followers),
            (CvDownload::Public, _) => Some(SectionVisibility::Public),

            (CvDownload::Followers, Some(FOLLOWER)) => Some(SectionVisibility::Followers),
            (CvDownload::Followers, _) => None,

            (CvDownload::SelfOnly, _) => None,
        }
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn cv_access_matrix(pool: PgPool) {
        for setting in [
            CvDownload::Public,
            CvDownload::Followers,
            CvDownload::SelfOnly,
        ] {
            sqlx::query("DELETE FROM follows")
                .execute(&pool)
                .await
                .expect("follows cleared");
            sqlx::query("DELETE FROM actors")
                .execute(&pool)
                .await
                .expect("actors cleared");

            let owner_id = insert_actor(&pool, OWNER, setting).await;
            let follower_id = insert_actor(&pool, FOLLOWER, CvDownload::Public).await;
            let stranger_id = insert_actor(&pool, STRANGER, CvDownload::Public).await;
            insert_follow(&pool, follower_id, owner_id, true).await;

            let owner = noombat_identity::repo::find_local_by_username(&pool, OWNER)
                .await
                .expect("owner row");

            // The name drives the expectation, the id drives the call:
            // the decision is made on the id, and reading it back by
            // name is what makes a failure legible.
            let ids = [
                (OWNER, owner_id),
                (FOLLOWER, follower_id),
                (STRANGER, stranger_id),
            ];

            for viewer in [Some(OWNER), Some(FOLLOWER), Some(STRANGER), None] {
                let viewer_id = viewer.map(|name| {
                    ids.iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, id)| *id)
                        .expect("every named viewer was inserted")
                });
                let got = resolve_cv_access(&pool, &owner, viewer_id).await;

                match expected(setting, viewer) {
                    Some(vis) => assert_eq!(
                        got.as_ref().ok(),
                        Some(&vis),
                        "{viewer:?} under {setting:?} must be allowed with {vis:?}, got {got:?}"
                    ),
                    None => assert!(
                        matches!(got, Err(NoombatError::ActorNotFound(_))),
                        "{viewer:?} under {setting:?} must be refused as not-found, got {got:?}"
                    ),
                }
            }
        }
    }

    /// A pending follow is not an accepted one.
    ///
    /// `follows.accepted` defaults to `FALSE`, so a request that was
    /// never approved would otherwise read as a relationship.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn pending_follow_does_not_grant_access(pool: PgPool) {
        let owner_id = insert_actor(&pool, OWNER, CvDownload::Followers).await;
        let follower_id = insert_actor(&pool, FOLLOWER, CvDownload::Public).await;
        insert_follow(&pool, follower_id, owner_id, false).await;

        let owner = noombat_identity::repo::find_local_by_username(&pool, OWNER)
            .await
            .expect("owner row");

        let got = resolve_cv_access(&pool, &owner, Some(follower_id)).await;
        assert!(
            matches!(got, Err(NoombatError::ActorNotFound(_))),
            "a pending follower must be refused, got {got:?}"
        );
    }
}
