// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Profile section routes: CRUD for experiences, educations, skills,
//! publications, and verified links.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch};
use axum::{Json, Router};
use noombat_core::privacy::SectionVisibility;

use crate::auth::verify_bearer_token;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        // Experiences.
        .route(
            "/users/{username}/experiences",
            get(list_experiences).post(create_experience),
        )
        .route(
            "/users/{username}/experiences/{id}",
            patch(update_experience).delete(delete_experience),
        )
        // Educations.
        .route(
            "/users/{username}/educations",
            get(list_educations).post(create_education),
        )
        .route(
            "/users/{username}/educations/{id}",
            patch(update_education).delete(delete_education),
        )
        // Skills.
        .route("/users/{username}/skills", get(list_skills).post(add_skill))
        .route("/users/{username}/skills/{id}", delete(delete_skill))
        // Publications.
        .route(
            "/users/{username}/publications",
            get(list_publications).post(create_publication),
        )
        .route(
            "/users/{username}/publications/{id}",
            delete(delete_publication),
        )
        // Verified links.
        .route(
            "/users/{username}/links",
            get(list_verified_links).post(add_verified_link),
        )
        .route("/users/{username}/links/{id}", delete(delete_verified_link))
        // Custom profile sections (extension point).
        .route(
            "/users/{username}/sections",
            get(list_custom_sections).post(create_custom_section),
        )
        .route(
            "/users/{username}/sections/{id}",
            delete(delete_custom_section),
        )
        // DOI resolution (lookup only: not persisted until user confirms).
        .route("/api/v1/doi/{doi_prefix}/{doi_suffix}", get(resolve_doi))
}

// ..... Experiences .....

async fn list_experiences(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    // Public view: only public sections.
    let items = noombat_identity::profile::list_experiences(
        &state.pool,
        actor.id,
        &SectionVisibility::Public,
    )
    .await?;
    Ok((StatusCode::OK, Json(items)))
}

async fn create_experience(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(params): Json<noombat_identity::profile::NewExperience>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let exp = noombat_identity::profile::create_experience(&state.pool, actor.id, &params).await?;
    Ok((StatusCode::CREATED, Json(exp)))
}

async fn delete_experience(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::profile::delete_experience(&state.pool, actor.id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_experience(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
    Json(params): Json<noombat_identity::profile::UpdateExperience>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let exp =
        noombat_identity::profile::update_experience(&state.pool, actor.id, id, &params).await?;
    Ok((StatusCode::OK, Json(exp)))
}

// ..... Educations .....

async fn list_educations(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let items = noombat_identity::profile::list_educations(
        &state.pool,
        actor.id,
        &SectionVisibility::Public,
    )
    .await?;
    Ok((StatusCode::OK, Json(items)))
}

async fn create_education(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(params): Json<noombat_identity::profile::NewEducation>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let edu = noombat_identity::profile::create_education(&state.pool, actor.id, &params).await?;
    Ok((StatusCode::CREATED, Json(edu)))
}

async fn delete_education(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::profile::delete_education(&state.pool, actor.id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_education(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
    Json(params): Json<noombat_identity::profile::UpdateEducation>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let edu =
        noombat_identity::profile::update_education(&state.pool, actor.id, id, &params).await?;
    Ok((StatusCode::OK, Json(edu)))
}

// ..... Skills .....

async fn list_skills(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let items = noombat_identity::profile::list_skills(&state.pool, actor.id, false).await?;
    Ok((StatusCode::OK, Json(items)))
}

#[derive(serde::Deserialize)]
struct AddSkillBody {
    name: String,
    visibility: Option<String>,
}

async fn add_skill(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(params): Json<AddSkillBody>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let skill = noombat_identity::profile::add_skill(
        &state.pool,
        actor.id,
        &params.name,
        params.visibility.as_deref(),
    )
    .await?;

    // Re-index profile with updated skills (fire-and-forget).
    reindex_profile_skills(&state, &actor).await;

    Ok((StatusCode::CREATED, Json(skill)))
}

async fn delete_skill(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::profile::delete_skill(&state.pool, actor.id, id).await?;

    // Re-index profile with updated skills (fire-and-forget).
    reindex_profile_skills(&state, &actor).await;

    Ok(StatusCode::NO_CONTENT)
}

// ..... Publications .....

async fn list_publications(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let items = noombat_identity::profile::list_publications(
        &state.pool,
        actor.id,
        &SectionVisibility::Public,
    )
    .await?;
    Ok((StatusCode::OK, Json(items)))
}

/// Request body for publication creation.
///
/// If only `doi` is provided, metadata is resolved automatically via
/// the CrossRef and DataCite APIs. If `title` and `authors` are also
/// provided, they are used as-is (skipping resolution).
#[derive(serde::Deserialize)]
struct CreatePublicationRequest {
    doi: String,
    title: Option<String>,
    authors: Option<serde_json::Value>,
    abstract_md: Option<String>,
    journal: Option<String>,
    publisher: Option<String>,
    published_date: Option<chrono::NaiveDate>,
    doi_metadata: Option<serde_json::Value>,
    visibility: Option<String>,
}

async fn create_publication(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreatePublicationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;

    // When the caller supplies only a bare DOI, resolve the metadata
    // server-side so that clients need not call the DOI endpoint first.
    let params = if body.title.is_some() && body.authors.is_some() {
        noombat_identity::profile::NewPublication {
            doi: body.doi,
            title: body.title.unwrap_or_default(),
            authors: body.authors.unwrap_or(serde_json::json!([])),
            abstract_md: body.abstract_md,
            journal: body.journal,
            publisher: body.publisher,
            published_date: body.published_date,
            doi_metadata: body.doi_metadata.unwrap_or(serde_json::json!({})),
            visibility: body.visibility,
        }
    } else {
        let mailto = format!("admin@{}", state.domain);
        let meta =
            noombat_identity::doi_client::resolve(&state.http_client, &body.doi, &mailto).await?;

        let authors_json = serde_json::to_value(&meta.authors).unwrap_or(serde_json::json!([]));
        let published_date = meta.published_date.as_deref().and_then(parse_partial_date);

        noombat_identity::profile::NewPublication {
            doi: body.doi,
            title: meta.title,
            authors: authors_json,
            abstract_md: body.abstract_md,
            journal: meta.journal,
            publisher: meta.publisher,
            published_date,
            doi_metadata: meta.raw,
            visibility: body.visibility,
        }
    };

    let pub_ =
        noombat_identity::profile::create_publication(&state.pool, actor.id, &params).await?;
    Ok((StatusCode::CREATED, Json(pub_)))
}

async fn delete_publication(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::profile::delete_publication(&state.pool, actor.id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ..... Verified links .....

async fn list_verified_links(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let links = noombat_identity::verification::list_links(&state.pool, actor.id).await?;
    Ok((StatusCode::OK, Json(links)))
}

#[derive(serde::Deserialize)]
struct AddLinkBody {
    url: String,
}

async fn add_verified_link(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(params): Json<AddLinkBody>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let link = noombat_identity::verification::add_link(&state.pool, actor.id, &params.url).await?;

    // Trigger immediate verification (non-blocking).
    let pool = state.pool.clone();
    let client = state.http_client.clone();
    let ap_url = format!("https://{}/users/{}", state.domain, username);
    let human_url = format!("https://{}/@{}", state.domain, username);
    let link_clone = link.clone();
    tokio::spawn(async move {
        let _ =
            noombat_identity::verification::verify_link(
                &pool, &client, &link_clone, &[&ap_url, &human_url],
            )
                .await;
    });

    Ok((StatusCode::CREATED, Json(link)))
}

async fn delete_verified_link(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::verification::delete_link(&state.pool, actor.id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ..... Custom profile sections .....

async fn list_custom_sections(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let items = noombat_identity::profile::list_custom_sections(
        &state.pool,
        actor.id,
        &SectionVisibility::Public,
    )
    .await?;
    Ok((StatusCode::OK, Json(items)))
}

async fn create_custom_section(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(params): Json<noombat_identity::profile::NewCustomSection>,
) -> Result<impl IntoResponse, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    let section =
        noombat_identity::profile::create_custom_section(&state.pool, actor.id, &params).await?;
    Ok((StatusCode::CREATED, Json(section)))
}

async fn delete_custom_section(
    State(state): State<AppState>,
    Path((username, id)): Path<(String, uuid::Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_bearer_token(&headers, &state.admin_token)?;
    let actor = noombat_identity::repo::find_local_by_username(&state.pool, &username).await?;
    noombat_identity::profile::delete_custom_section(&state.pool, actor.id, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ..... DOI resolution .....

async fn resolve_doi(
    State(state): State<AppState>,
    Path((prefix, suffix)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let doi = format!("{prefix}/{suffix}");
    let mailto = format!("admin@{}", state.domain);
    let meta = noombat_identity::doi_client::resolve(&state.http_client, &doi, &mailto).await?;
    Ok((StatusCode::OK, Json(meta)))
}

// ..... Search-index re-sync .....

/// Fetch the actor's current public skills and re-index the profile
/// in Meilisearch. Errors are logged, not propagated.
async fn reindex_profile_skills(state: &AppState, actor: &noombat_core::actor::Actor) {
    let skills = noombat_identity::profile::list_skills(&state.pool, actor.id, false)
        .await
        .unwrap_or_default();
    let names: Vec<String> = skills.into_iter().map(|s| s.name).collect();
    crate::search_sync::index_profile(&state.search, actor, &names);
}

/// Parse a date string that may be partial: `"2024"`, `"2024-06"`, or `"2024-06-15"`.
/// Missing month defaults to January; missing day defaults to the first of the month.
fn parse_partial_date(s: &str) -> Option<chrono::NaiveDate> {
    // Full date: "2024-06-15"
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d);
    }
    let parts: Vec<&str> = s.split('-').collect();
    let year: i32 = parts.first()?.parse().ok()?;
    let month: u32 = parts.get(1).and_then(|m| m.parse().ok()).unwrap_or(1);
    chrono::NaiveDate::from_ymd_opt(year, month, 1)
}
