// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Job listing CRUD, search, and matching.

use chrono::{DateTime, Utc};
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// A job listing row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct JobListing {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub ap_id: String,
    pub title: String,
    pub description_md: String,
    pub description_html: String,
    pub location: Option<String>,
    pub remote: bool,
    pub salary_min: Option<i32>,
    pub salary_max: Option<i32>,
    pub currency: Option<String>,
    pub requirements: Option<serde_json::Value>,
    pub published_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Parameters for creating a new job listing.
#[derive(Debug, Clone, Deserialize)]
pub struct NewJobListing {
    pub title: String,
    pub description_md: String,
    pub location: Option<String>,
    pub remote: Option<bool>,
    pub salary_min: Option<i32>,
    pub salary_max: Option<i32>,
    pub currency: Option<String>,
    pub requirements: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    /// If `true`, the listing is published immediately.
    #[serde(default = "default_true")]
    pub publish: bool,
}

fn default_true() -> bool {
    true
}

/// Create a new job listing.
///
/// The `description_md` field is rendered through the markup pipeline.
/// The listing is published immediately if `params.publish` is `true`.
pub async fn create_job(
    pool: &PgPool,
    actor_id: Uuid,
    domain: &str,
    params: &NewJobListing,
) -> Result<JobListing> {
    let id = Uuid::new_v4();
    let ap_id = format!("https://{domain}/jobs/{id}");
    let output = noombat_markup::render(&params.description_md);

    let requirements_json = params
        .requirements
        .as_ref()
        .map(|r| serde_json::to_value(r).unwrap_or_default());

    let published_at = if params.publish {
        Some(Utc::now())
    } else {
        None
    };

    let row = sqlx::query_as::<_, JobListing>(
        r#"INSERT INTO job_listings
               (id, actor_id, ap_id, title, description_md, description_html,
                location, remote, salary_min, salary_max, currency,
                requirements, published_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
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
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Retrieve a job listing by UUID.
pub async fn get_job(pool: &PgPool, id: Uuid) -> Result<JobListing> {
    let row = sqlx::query_as::<_, JobListing>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_listings
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "job_listing",
        id,
    })?;

    Ok(row)
}

/// List published job listings by a specific actor.
pub async fn list_jobs_by_actor(
    pool: &PgPool,
    actor_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<JobListing>> {
    let rows = sqlx::query_as::<_, JobListing>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_listings
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

/// List all published, non-expired job listings (for the public jobs page).
pub async fn list_published_jobs(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<JobListing>> {
    let rows = sqlx::query_as::<_, JobListing>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_listings
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

/// Delete a job listing owned by the given actor.
pub async fn delete_job(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query(
        "DELETE FROM job_listings WHERE id = $1 AND actor_id = $2",
    )
    .bind(id)
    .bind(actor_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "job_listing",
            id,
        });
    }
    Ok(())
}

/// Parameters for updating a job listing.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateJobListing {
    pub title: Option<String>,
    pub description_md: Option<String>,
    pub location: Option<String>,
    pub remote: Option<bool>,
    pub salary_min: Option<i32>,
    pub salary_max: Option<i32>,
    pub currency: Option<String>,
    pub requirements: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Update a job listing. Only provided fields are changed.
pub async fn update_job(
    pool: &PgPool,
    actor_id: Uuid,
    id: Uuid,
    params: &UpdateJobListing,
) -> Result<JobListing> {
    // Fetch the existing listing to verify ownership.
    let existing = sqlx::query_as::<_, JobListing>(
        r#"SELECT id, actor_id, ap_id, title, description_md, description_html,
                  location, remote, salary_min, salary_max, currency,
                  requirements, published_at, expires_at, created_at
           FROM job_listings
           WHERE id = $1 AND actor_id = $2"#,
    )
    .bind(id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "job_listing",
        id,
    })?;

    let title = params.title.as_deref().unwrap_or(&existing.title);

    let (desc_md, desc_html) = match &params.description_md {
        Some(md) => {
            let output = noombat_markup::render(md);
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

    let row = sqlx::query_as::<_, JobListing>(
        r#"UPDATE job_listings SET
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
