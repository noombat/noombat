// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Profile section CRUD: experiences, educations, skills, publications.

use chrono::NaiveDate;
use noombat_core::error::{NoombatError, Result};
use noombat_core::privacy::SectionVisibility;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

// ..... Experiences .....

/// A work experience entry on a profile.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Experience {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub title: String,
    pub company: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub description_md: Option<String>,
    pub description_html: Option<String>,
    pub sort_order: i16,
    pub visibility: String,
}

/// Parameters for creating a new experience entry.
#[derive(Debug, Clone, Deserialize)]
pub struct NewExperience {
    pub title: String,
    pub company: String,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub description_md: Option<String>,
    pub sort_order: Option<i16>,
    pub visibility: Option<String>,
}

/// Insert a new experience entry.
pub async fn create_experience(
    pool: &PgPool,
    actor_id: Uuid,
    params: &NewExperience,
) -> Result<Experience> {
    let id = Uuid::new_v4();
    let visibility = params.visibility.as_deref().unwrap_or("public");
    validate_section_visibility(visibility)?;

    // Render Markdown description if provided.
    let (desc_md, desc_html) = render_optional_markdown(params.description_md.as_deref()).await?;

    let ap_object = build_experience_ap_object(
        &id,
        &params.title,
        &params.company,
        params.start_date,
        params.end_date,
        desc_html.as_deref(),
    );

    let row = sqlx::query_as::<_, Experience>(
        r#"INSERT INTO experiences
               (id, actor_id, title, company, start_date, end_date,
                description_md, description_html, sort_order, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING id, actor_id, title, company, start_date, end_date,
                     description_md, description_html, sort_order, visibility"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(&params.title)
    .bind(&params.company)
    .bind(params.start_date)
    .bind(params.end_date)
    .bind(&desc_md)
    .bind(&desc_html)
    .bind(params.sort_order.unwrap_or(0))
    .bind(visibility)
    .bind(&ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List experience entries for an actor, filtered by maximum visibility.
pub async fn list_experiences(
    pool: &PgPool,
    actor_id: Uuid,
    max_visibility: &SectionVisibility,
) -> Result<Vec<Experience>> {
    let allowed = visibility_filter(max_visibility);
    let rows = sqlx::query_as::<_, Experience>(
        r#"SELECT id, actor_id, title, company, start_date, end_date,
                  description_md, description_html, sort_order, visibility
           FROM experiences
           WHERE actor_id = $1 AND visibility = ANY($2)
           ORDER BY sort_order ASC, start_date DESC"#,
    )
    .bind(actor_id)
    .bind(&allowed)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete an experience entry owned by the given actor.
pub async fn delete_experience(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM experiences WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "experience",
            id,
        });
    }
    Ok(())
}

/// Parameters for updating an existing experience entry.
///
/// All fields are optional; only supplied fields are modified.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateExperience {
    pub title: Option<String>,
    pub company: Option<String>,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<Option<NaiveDate>>,
    pub description_md: Option<Option<String>>,
    pub sort_order: Option<i16>,
    pub visibility: Option<String>,
}

/// Update an existing experience entry.
pub async fn update_experience(
    pool: &PgPool,
    actor_id: Uuid,
    id: Uuid,
    params: &UpdateExperience,
) -> Result<Experience> {
    if let Some(ref v) = params.visibility {
        validate_section_visibility(v)?;
    }

    // Fetch the current row to merge with partial updates.
    let current = sqlx::query_as::<_, Experience>(
        r#"SELECT id, actor_id, title, company, start_date, end_date,
                  description_md, description_html, sort_order, visibility
           FROM experiences
           WHERE id = $1 AND actor_id = $2"#,
    )
    .bind(id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::NotFound {
        entity: "experience",
        id,
    })?;

    let title = params.title.as_deref().unwrap_or(&current.title);
    let company = params.company.as_deref().unwrap_or(&current.company);
    let start_date = params.start_date.unwrap_or(current.start_date);
    let end_date = params.end_date.unwrap_or(current.end_date);
    let sort_order = params.sort_order.unwrap_or(current.sort_order);
    let visibility = params.visibility.as_deref().unwrap_or(&current.visibility);

    let desc_md_source = match &params.description_md {
        Some(inner) => inner.as_deref(),
        None => current.description_md.as_deref(),
    };
    let (desc_md, desc_html) = render_optional_markdown(desc_md_source).await?;

    let ap_object = build_experience_ap_object(
        &id,
        title,
        company,
        start_date,
        end_date,
        desc_html.as_deref(),
    );

    let row = sqlx::query_as::<_, Experience>(
        r#"UPDATE experiences
           SET title = $3, company = $4, start_date = $5, end_date = $6,
               description_md = $7, description_html = $8, sort_order = $9,
               visibility = $10, ap_object = $11
           WHERE id = $1 AND actor_id = $2
           RETURNING id, actor_id, title, company, start_date, end_date,
                     description_md, description_html, sort_order, visibility"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(title)
    .bind(company)
    .bind(start_date)
    .bind(end_date)
    .bind(&desc_md)
    .bind(&desc_html)
    .bind(sort_order)
    .bind(visibility)
    .bind(&ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

// ..... Educations .....

/// An educational history entry on a profile.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Education {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub institution: String,
    pub degree: Option<String>,
    pub field_of_study: Option<String>,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub description_md: Option<String>,
    pub description_html: Option<String>,
    pub sort_order: i16,
    pub visibility: String,
}

/// Parameters for creating a new education entry.
#[derive(Debug, Clone, Deserialize)]
pub struct NewEducation {
    pub institution: String,
    pub degree: Option<String>,
    pub field_of_study: Option<String>,
    pub start_date: NaiveDate,
    pub end_date: Option<NaiveDate>,
    pub description_md: Option<String>,
    pub sort_order: Option<i16>,
    pub visibility: Option<String>,
}

/// Insert a new education entry.
pub async fn create_education(
    pool: &PgPool,
    actor_id: Uuid,
    params: &NewEducation,
) -> Result<Education> {
    let id = Uuid::new_v4();
    let visibility = params.visibility.as_deref().unwrap_or("public");
    validate_section_visibility(visibility)?;

    let (desc_md, desc_html) = render_optional_markdown(params.description_md.as_deref()).await?;

    let ap_object = serde_json::json!({
        "type": "noombat:Education",
        "noombat:institution": params.institution,
        "noombat:degree": params.degree,
        "noombat:fieldOfStudy": params.field_of_study,
    });

    let row = sqlx::query_as::<_, Education>(
        r#"INSERT INTO educations
               (id, actor_id, institution, degree, field_of_study,
                start_date, end_date, description_md, description_html,
                sort_order, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
           RETURNING id, actor_id, institution, degree, field_of_study,
                     start_date, end_date, description_md, description_html,
                     sort_order, visibility"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(&params.institution)
    .bind(&params.degree)
    .bind(&params.field_of_study)
    .bind(params.start_date)
    .bind(params.end_date)
    .bind(&desc_md)
    .bind(&desc_html)
    .bind(params.sort_order.unwrap_or(0))
    .bind(visibility)
    .bind(&ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List education entries for an actor, filtered by maximum visibility.
pub async fn list_educations(
    pool: &PgPool,
    actor_id: Uuid,
    max_visibility: &SectionVisibility,
) -> Result<Vec<Education>> {
    let allowed = visibility_filter(max_visibility);
    let rows = sqlx::query_as::<_, Education>(
        r#"SELECT id, actor_id, institution, degree, field_of_study,
                  start_date, end_date, description_md, description_html,
                  sort_order, visibility
           FROM educations
           WHERE actor_id = $1 AND visibility = ANY($2)
           ORDER BY sort_order ASC, start_date DESC"#,
    )
    .bind(actor_id)
    .bind(&allowed)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete an education entry owned by the given actor.
pub async fn delete_education(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM educations WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "education",
            id,
        });
    }
    Ok(())
}

/// Parameters for updating an existing education entry.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateEducation {
    pub institution: Option<String>,
    pub degree: Option<Option<String>>,
    pub field_of_study: Option<Option<String>>,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<Option<NaiveDate>>,
    pub description_md: Option<Option<String>>,
    pub sort_order: Option<i16>,
    pub visibility: Option<String>,
}

/// Update an existing education entry.
pub async fn update_education(
    pool: &PgPool,
    actor_id: Uuid,
    id: Uuid,
    params: &UpdateEducation,
) -> Result<Education> {
    if let Some(ref v) = params.visibility {
        validate_section_visibility(v)?;
    }

    let current = sqlx::query_as::<_, Education>(
        r#"SELECT id, actor_id, institution, degree, field_of_study,
                  start_date, end_date, description_md, description_html,
                  sort_order, visibility
           FROM educations
           WHERE id = $1 AND actor_id = $2"#,
    )
    .bind(id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::NotFound {
        entity: "education",
        id,
    })?;

    let institution = params
        .institution
        .as_deref()
        .unwrap_or(&current.institution);
    let degree = params
        .degree
        .as_ref()
        .map_or_else(|| current.degree.as_deref(), |v| v.as_deref());
    let field_of_study = params
        .field_of_study
        .as_ref()
        .map_or_else(|| current.field_of_study.as_deref(), |v| v.as_deref());
    let start_date = params.start_date.unwrap_or(current.start_date);
    let end_date = params.end_date.unwrap_or(current.end_date);
    let sort_order = params.sort_order.unwrap_or(current.sort_order);
    let visibility = params.visibility.as_deref().unwrap_or(&current.visibility);

    let desc_md_source = match &params.description_md {
        Some(inner) => inner.as_deref(),
        None => current.description_md.as_deref(),
    };
    let (desc_md, desc_html) = render_optional_markdown(desc_md_source).await?;

    let ap_object = serde_json::json!({
        "type": "noombat:Education",
        "id": id.to_string(),
        "noombat:institution": institution,
        "noombat:degree": degree,
        "noombat:fieldOfStudy": field_of_study,
        "noombat:startDate": start_date.to_string(),
        "noombat:endDate": end_date.map(|d| d.to_string()),
        "content": desc_html.as_deref(),
    });

    let row = sqlx::query_as::<_, Education>(
        r#"UPDATE educations
           SET institution = $3, degree = $4, field_of_study = $5,
               start_date = $6, end_date = $7,
               description_md = $8, description_html = $9,
               sort_order = $10, visibility = $11, ap_object = $12
           WHERE id = $1 AND actor_id = $2
           RETURNING id, actor_id, institution, degree, field_of_study,
                     start_date, end_date, description_md, description_html,
                     sort_order, visibility"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(institution)
    .bind(degree)
    .bind(field_of_study)
    .bind(start_date)
    .bind(end_date)
    .bind(&desc_md)
    .bind(&desc_html)
    .bind(sort_order)
    .bind(visibility)
    .bind(&ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

// ..... Skills .....

/// A declared professional skill.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Skill {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub name: String,
    pub visibility: String,
}

/// Add a skill to an actor's profile. Upserts on conflict.
pub async fn add_skill(
    pool: &PgPool,
    actor_id: Uuid,
    name: &str,
    visibility: Option<&str>,
) -> Result<Skill> {
    let vis = visibility.unwrap_or("public");
    if vis != "public" && vis != "private" {
        return Err(NoombatError::BadRequest(
            "skill visibility must be 'public' or 'private'".into(),
        ));
    }

    let id = Uuid::new_v4();
    let row = sqlx::query_as::<_, Skill>(
        r#"INSERT INTO skills (id, actor_id, name, visibility)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (actor_id, name) DO UPDATE SET visibility = $4
           RETURNING id, actor_id, name, visibility"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(name)
    .bind(vis)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List skills for an actor, filtered by maximum visibility.
pub async fn list_skills(
    pool: &PgPool,
    actor_id: Uuid,
    include_private: bool,
) -> Result<Vec<Skill>> {
    let rows = if include_private {
        sqlx::query_as::<_, Skill>(
            "SELECT id, actor_id, name, visibility FROM skills
             WHERE actor_id = $1 ORDER BY name",
        )
        .bind(actor_id)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, Skill>(
            "SELECT id, actor_id, name, visibility FROM skills
             WHERE actor_id = $1 AND visibility = 'public' ORDER BY name",
        )
        .bind(actor_id)
        .fetch_all(pool)
        .await?
    };
    Ok(rows)
}

/// Remove a skill from an actor's profile.
pub async fn delete_skill(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM skills WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "skill",
            id,
        });
    }
    Ok(())
}

// ..... Publications .....

/// A scholarly publication linked via DOI.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Publication {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub doi: String,
    pub title: String,
    pub authors: serde_json::Value,
    pub abstract_md: Option<String>,
    pub abstract_html: Option<String>,
    pub journal: Option<String>,
    pub publisher: Option<String>,
    pub published_date: Option<NaiveDate>,
    pub visibility: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

/// Parameters for creating a new publication entry.
#[derive(Debug, Clone, Deserialize)]
pub struct NewPublication {
    pub doi: String,
    pub title: String,
    pub authors: serde_json::Value,
    pub abstract_md: Option<String>,
    pub journal: Option<String>,
    pub publisher: Option<String>,
    pub published_date: Option<NaiveDate>,
    pub doi_metadata: serde_json::Value,
    pub visibility: Option<String>,
}

/// Insert a new publication entry.
pub async fn create_publication(
    pool: &PgPool,
    actor_id: Uuid,
    params: &NewPublication,
) -> Result<Publication> {
    let id = Uuid::new_v4();
    let visibility = params.visibility.as_deref().unwrap_or("public");
    validate_section_visibility(visibility)?;

    let (abs_md, abs_html) = render_optional_markdown(params.abstract_md.as_deref()).await?;
    let now = chrono::Utc::now();

    let ap_object = serde_json::json!({
        "type": "noombat:Publication",
        "noombat:doi": params.doi,
        "noombat:doiMetadata": params.doi_metadata,
        "name": params.title,
    });

    let row = sqlx::query_as::<_, Publication>(
        r#"INSERT INTO publications
               (id, actor_id, doi, title, authors, abstract_md, abstract_html,
                journal, publisher, published_date, doi_metadata, fetched_at,
                visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
           ON CONFLICT (actor_id, doi) DO UPDATE SET
               title = EXCLUDED.title,
               authors = EXCLUDED.authors,
               doi_metadata = EXCLUDED.doi_metadata,
               fetched_at = EXCLUDED.fetched_at
           RETURNING id, actor_id, doi, title, authors, abstract_md,
                     abstract_html, journal, publisher, published_date,
                     visibility, fetched_at"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(&params.doi)
    .bind(&params.title)
    .bind(&params.authors)
    .bind(&abs_md)
    .bind(&abs_html)
    .bind(&params.journal)
    .bind(&params.publisher)
    .bind(params.published_date)
    .bind(&params.doi_metadata)
    .bind(now)
    .bind(visibility)
    .bind(&ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List publications for an actor, filtered by maximum visibility.
pub async fn list_publications(
    pool: &PgPool,
    actor_id: Uuid,
    max_visibility: &SectionVisibility,
) -> Result<Vec<Publication>> {
    let allowed = visibility_filter(max_visibility);
    let rows = sqlx::query_as::<_, Publication>(
        r#"SELECT id, actor_id, doi, title, authors, abstract_md,
                  abstract_html, journal, publisher, published_date,
                  visibility, fetched_at
           FROM publications
           WHERE actor_id = $1 AND visibility = ANY($2)
           ORDER BY published_date DESC NULLS LAST"#,
    )
    .bind(actor_id)
    .bind(&allowed)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete a publication entry owned by the given actor.
pub async fn delete_publication(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM publications WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "publication",
            id,
        });
    }
    Ok(())
}

// ..... Privacy settings update .....

/// Update the `actor_privacy` JSONB column for a local actor.
pub async fn update_actor_privacy(
    pool: &PgPool,
    actor_id: Uuid,
    privacy: &noombat_core::privacy::ActorPrivacy,
) -> Result<()> {
    let json = serde_json::to_value(privacy)?;
    sqlx::query("UPDATE actors SET actor_privacy = $2 WHERE id = $1 AND is_local = TRUE")
        .bind(actor_id)
        .bind(&json)
        .execute(pool)
        .await?;
    Ok(())
}

// ..... Custom Profile Sections (extension point) .....

/// A custom profile section row.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct CustomSection {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub section_type: String,
    pub title: String,
    pub content_md: Option<String>,
    pub content_html: Option<String>,
    pub data: Option<serde_json::Value>,
    pub sort_order: i16,
    pub visibility: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Parameters for creating a custom section.
#[derive(Debug, Clone, Deserialize)]
pub struct NewCustomSection {
    pub section_type: String,
    pub title: String,
    pub content_md: Option<String>,
    pub data: Option<serde_json::Value>,
    pub sort_order: Option<i16>,
    pub visibility: Option<String>,
}

/// Create a custom profile section.
pub async fn create_custom_section(
    pool: &PgPool,
    actor_id: Uuid,
    params: &NewCustomSection,
) -> Result<CustomSection> {
    let id = Uuid::new_v4();
    let visibility = params.visibility.as_deref().unwrap_or("public");
    validate_section_visibility(visibility)?;

    let (content_md, content_html) = render_optional_markdown(params.content_md.as_deref()).await?;

    let ap_object = serde_json::json!({
        "type": "noombat:CustomSection",
        "id": id.to_string(),
        "noombat:sectionType": params.section_type,
        "name": params.title,
        "content": content_html,
    });

    let row = sqlx::query_as::<_, CustomSection>(
        r#"INSERT INTO custom_profile_sections
               (id, actor_id, section_type, title, content_md, content_html,
                data, sort_order, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING id, actor_id, section_type, title, content_md,
                     content_html, data, sort_order, visibility, created_at"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(&params.section_type)
    .bind(&params.title)
    .bind(&content_md)
    .bind(&content_html)
    .bind(&params.data)
    .bind(params.sort_order.unwrap_or(0))
    .bind(visibility)
    .bind(&ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List custom sections for an actor, filtered by maximum visibility.
pub async fn list_custom_sections(
    pool: &PgPool,
    actor_id: Uuid,
    max_visibility: &SectionVisibility,
) -> Result<Vec<CustomSection>> {
    let allowed = visibility_filter(max_visibility);
    let rows = sqlx::query_as::<_, CustomSection>(
        r#"SELECT id, actor_id, section_type, title, content_md,
                  content_html, data, sort_order, visibility, created_at
           FROM custom_profile_sections
           WHERE actor_id = $1 AND visibility = ANY($2)
           ORDER BY sort_order ASC, created_at DESC"#,
    )
    .bind(actor_id)
    .bind(&allowed)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Delete a custom section owned by the given actor.
pub async fn delete_custom_section(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM custom_profile_sections WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "custom_section",
            id,
        });
    }
    Ok(())
}

// ..... Helpers .....

/// Validate a section visibility string.
fn validate_section_visibility(v: &str) -> Result<()> {
    match v {
        "public" | "followers" | "private" => Ok(()),
        _ => Err(NoombatError::BadRequest(
            "visibility must be 'public', 'followers', or 'private'".into(),
        )),
    }
}

/// Compute the set of visibility values allowed for a given maximum level.
fn visibility_filter(max: &SectionVisibility) -> Vec<String> {
    match max {
        SectionVisibility::Private => {
            vec!["public".into(), "followers".into(), "private".into()]
        }
        SectionVisibility::Followers => {
            vec!["public".into(), "followers".into()]
        }
        SectionVisibility::Public => {
            vec!["public".into()]
        }
    }
}

/// Render an optional Markdown field through the markup pipeline.
///
/// Returns `(source, html)`. If the input is `None`, both are `None`.
async fn render_optional_markdown(
    input: Option<&str>,
) -> noombat_core::error::Result<(Option<String>, Option<String>)> {
    match input {
        Some(md) => {
            let source = md.to_owned();
            let output = noombat_markup::render_async(source.clone()).await?;
            Ok((Some(source), Some(output.html)))
        }
        None => Ok((None, None)),
    }
}

/// Build an ActivityPub object for an experience entry.
fn build_experience_ap_object(
    id: &Uuid,
    title: &str,
    company: &str,
    start_date: NaiveDate,
    end_date: Option<NaiveDate>,
    description_html: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "type": "noombat:Experience",
        "id": id.to_string(),
        "noombat:title": title,
        "noombat:company": company,
        "noombat:startDate": start_date.to_string(),
        "noombat:endDate": end_date.map(|d| d.to_string()),
        "content": description_html,
    })
}
