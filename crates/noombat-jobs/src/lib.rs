// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Job posting CRUD, search, and matching, plus the application write
//! path and the capability an employer reads an application with.

pub mod applications;

use chrono::{DateTime, Utc};
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// A job posting row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct JobPosting {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub ap_id: String,
    pub title: String,
    pub description_md: String,
    pub description_html: String,
    pub location: Option<String>,
    pub remote: bool,
    pub salary_min: Option<i64>,
    pub salary_max: Option<i64>,
    pub currency: Option<String>,
    pub requirements: Option<serde_json::Value>,
    pub published_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a new job posting.
#[derive(Debug, Clone, Deserialize)]
pub struct NewJobPosting {
    pub title: String,
    pub description_md: String,
    pub location: Option<String>,
    pub remote: Option<bool>,
    pub salary_min: Option<i64>,
    pub salary_max: Option<i64>,
    pub currency: Option<String>,
    pub requirements: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// If `true`, the posting is published immediately.
    #[serde(default = "default_true")]
    pub publish: bool,
}

fn default_true() -> bool {
    true
}

/// Create a new job posting.
///
/// The `description_md` field is rendered through the markup pipeline.
/// The posting is published immediately if `params.publish` is `true`.
/// `created_by` is the member who wrote it, where `actor_id` is the
/// organisation that publishes it, and `None` where an actor posted as
/// itself. It is what `is_creator` reads, so the whole `PostingAccess`
/// model turns on it being written: with no writer, every posting looked
/// as though nobody had created it, and a recruiter could not reach
/// their own applications.
pub async fn create_job(
    pool: &PgPool,
    actor_id: Uuid,
    created_by: Option<Uuid>,
    domain: &str,
    params: &NewJobPosting,
) -> Result<JobPosting> {
    let id = Uuid::new_v4();
    let ap_id = format!("https://{domain}/jobs/{id}");
    let output = noombat_markup::render_async(params.description_md.clone()).await?;

    let requirements_json = params
        .requirements
        .as_ref()
        .map(|r| serde_json::to_value(r).unwrap_or_default());

    let published_at = if params.publish {
        Some(Utc::now())
    } else {
        None
    };

    let row = sqlx::query_as::<_, JobPosting>(
        r#"INSERT INTO job_postings
               (id, actor_id, ap_id, title, description_md, description_html,
                location, remote, salary_min, salary_max, currency,
                requirements, published_at, expires_at, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
           RETURNING id, actor_id, ap_id, title, description_md, description_html,
                     location, remote, salary_min, salary_max, currency,
                     requirements, published_at, expires_at, created_at"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(&ap_id)
    .bind(&params.title)
    .bind(&params.description_md)
    .bind(&output.html)
    .bind(&params.location)
    .bind(params.remote.unwrap_or(false))
    .bind(params.salary_min)
    .bind(params.salary_max)
    .bind(&params.currency)
    .bind(&requirements_json)
    .bind(published_at)
    .bind(params.expires_at)
    // NULL where the publishing actor wrote it themselves, which the
    // schema comment already specifies.
    .bind(created_by.filter(|id| *id != actor_id))
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Retrieve a job posting by UUID.
pub async fn get_job(pool: &PgPool, id: Uuid) -> Result<JobPosting> {
    let row = sqlx::query_as::<_, JobPosting>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_postings
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "job_posting",
        id,
    })?;

    Ok(row)
}

/// List published job postings by a specific actor.
pub async fn list_jobs_by_actor(
    pool: &PgPool,
    actor_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<JobPosting>> {
    let rows = sqlx::query_as::<_, JobPosting>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_postings
           WHERE actor_id = $1 AND published_at IS NOT NULL
           ORDER BY published_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(actor_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// List all published, non-expired job postings (for the public jobs page).
pub async fn list_published_jobs(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<JobPosting>> {
    let rows = sqlx::query_as::<_, JobPosting>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_postings
           WHERE published_at IS NOT NULL
             AND (expires_at IS NULL OR expires_at > now())
           ORDER BY published_at DESC
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete a job posting owned by the given actor.
pub async fn delete_job(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM job_postings WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "job_posting",
            id,
        });
    }
    Ok(())
}

/// Parameters for updating a job posting.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateJobPosting {
    pub title: Option<String>,
    pub description_md: Option<String>,
    pub location: Option<String>,
    pub remote: Option<bool>,
    pub salary_min: Option<i64>,
    pub salary_max: Option<i64>,
    pub currency: Option<String>,
    pub requirements: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Update a job posting. Only provided fields are changed.
pub async fn update_job(
    pool: &PgPool,
    actor_id: Uuid,
    id: Uuid,
    params: &UpdateJobPosting,
) -> Result<JobPosting> {
    // Fetch the existing posting to verify ownership.
    let existing = sqlx::query_as::<_, JobPosting>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_postings
           WHERE id = $1 AND actor_id = $2"#,
    )
    .bind(id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "job_posting",
        id,
    })?;

    let title = params.title.as_deref().unwrap_or(&existing.title);

    let (desc_md, desc_html) = match &params.description_md {
        Some(md) => {
            let output = noombat_markup::render_async(md.clone()).await?;
            (md.as_str(), output.html)
        }
        None => (
            existing.description_md.as_str(),
            existing.description_html.clone(),
        ),
    };

    let requirements_json = params
        .requirements
        .as_ref()
        .map(|r| serde_json::to_value(r).unwrap_or_default())
        .or(existing.requirements);

    let row = sqlx::query_as::<_, JobPosting>(
        r#"UPDATE job_postings SET
               title = $3, description_md = $4, description_html = $5,
               location = COALESCE($6, location),
               remote = COALESCE($7, remote),
               salary_min = COALESCE($8, salary_min),
               salary_max = COALESCE($9, salary_max),
               currency = COALESCE($10, currency),
               requirements = $11,
               expires_at = COALESCE($12, expires_at)
           WHERE id = $1 AND actor_id = $2
           RETURNING id, actor_id, ap_id, title, description_md, description_html,
                     location, remote, salary_min, salary_max, currency,
                     requirements, published_at, expires_at, created_at"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(title)
    .bind(desc_md)
    .bind(&desc_html)
    .bind(&params.location)
    .bind(params.remote)
    .bind(params.salary_min)
    .bind(params.salary_max)
    .bind(&params.currency)
    .bind(&requirements_json)
    .bind(params.expires_at)
    .fetch_one(pool)
    .await?;

    Ok(row)
}
