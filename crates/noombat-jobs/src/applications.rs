// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Applying to a posting, and the capability an employer reads it with.
//!
//! The tables for all of this existed and nothing wrote to them: four
//! routes read applications, the revocation path was built, and no code
//! outside the test files ever created an application or minted a grant.
//! This is the write half.
//!
//! **The application is not sent to the employer. A capability to read
//! it is.** The applicant keeps the record, the grant carries a use
//! budget and an expiry, it names one audience and cannot be re-pointed,
//! and every dereference is logged where the applicant can see it. That
//! is what makes withdrawal mean something: revoking the grant ends the
//! employer's access, which handing over a copy never could.

use chrono::{DateTime, Duration, Utc};
use noombat_core::error::{NoombatError, Result};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// How long a grant stands before it expires on its own.
///
/// A hiring round that outlives this asks for a fresh grant, which is
/// the applicant's decision to make again rather than one they made once
/// and cannot revisit.
const GRANT_TTL_DAYS: i64 = 90;

/// How many times the application document may be fetched.
///
/// Budgets rather than unlimited reads, because a capability with no
/// budget is a copy handed over with extra steps. Generous enough for a
/// panel to read it and for the tab to be reopened.
const DOCUMENT_USES: i32 = 50;

/// How many times the CV may be fetched, where one was attached.
const CV_USES: i32 = 20;

/// A freshly created application, and the grant that came with it.
#[derive(Debug)]
pub struct Application {
    pub id: Uuid,
    pub ap_id: String,
    /// The capability token, which appears here once and is never
    /// stored. What the database holds is its hash.
    pub grant_token: String,
    pub grant_expires_at: DateTime<Utc>,
}

/// What an applicant submits.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NewApplication {
    #[serde(default)]
    pub cover_letter_md: Option<String>,
    /// Whether the CV is offered alongside the application.
    #[serde(default = "default_true")]
    pub include_cv: bool,
}

fn default_true() -> bool {
    true
}

/// Hex-encoded SHA-256 of a token.
///
/// A high-entropy bearer token, so a digest is the right hash here: the
/// lookup is by unique index on it, and a database copy yields nothing
/// usable. Argon2 is for guessable secrets, and this is not one.
fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 32 bytes of randomness, hex encoded.
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The origin half of an actor's AP id, which is what pins a grant's
/// audience to one host.
///
/// An audience of `https://acme.example/users/hr` is bound to
/// `https://acme.example`, so a token leaked to another instance
/// dereferences nowhere.
fn origin_of(ap_id: &str) -> Result<String> {
    let rest = ap_id
        .strip_prefix("https://")
        .or_else(|| ap_id.strip_prefix("http://"))
        .ok_or_else(|| NoombatError::BadRequest(format!("actor id is not a URL: {ap_id}")))?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return Err(NoombatError::BadRequest(format!(
            "actor id names no host: {ap_id}"
        )));
    }
    let scheme = if ap_id.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    Ok(format!("{scheme}://{host}"))
}

/// Apply to a posting, minting the grant the employer reads it with.
///
/// One transaction: an application without a grant is unreadable by the
/// employer it was sent to, and a grant without an application points at
/// nothing. Either half alone is worse than neither.
///
/// The posting's title and organisation are denormalised at insert. They
/// are NOT NULL on purpose, so an application stays meaningful once the
/// posting is deleted ("I applied to X at Y on Z"), and copying them at
/// erasure instead would mean reading a row that is about to be removed.
pub async fn apply(
    pool: &PgPool,
    applicant_id: Uuid,
    job_id: Uuid,
    domain: &str,
    params: &NewApplication,
    cv_snapshot: Option<Vec<u8>>,
) -> Result<Application> {
    let job = crate::get_job(pool, job_id).await?;

    // An unpublished posting is not open. `published_at` is the
    // verification gate as well as the publication flag, so this also
    // refuses a posting whose organisation has lost its domain.
    if job.published_at.is_none() {
        return Err(NoombatError::NotFound {
            entity: "job_posting",
            id: job_id,
        });
    }

    if job.actor_id == applicant_id {
        return Err(NoombatError::BadRequest(
            "an organisation cannot apply to its own posting".into(),
        ));
    }

    let (organisation_ap_id, organisation_name): (String, String) =
        sqlx::query_as("SELECT ap_id, COALESCE(display_name, username) FROM actors WHERE id = $1")
            .bind(job.actor_id)
            .fetch_optional(pool)
            .await?
            .ok_or(NoombatError::NotFound {
                entity: "job_posting",
                id: job_id,
            })?;

    let audience_origin = origin_of(&organisation_ap_id)?;

    let cover_letter_html = match params.cover_letter_md.as_deref() {
        Some(md) if !md.trim().is_empty() => {
            Some(noombat_markup::render_async(md.to_owned()).await?.html)
        }
        _ => None,
    };

    let id = Uuid::new_v4();
    let ap_id = format!("https://{domain}/applications/{id}");
    let token = mint_token();
    let expires_at = Utc::now() + Duration::days(GRANT_TTL_DAYS);

    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"INSERT INTO job_applications
               (id, applicant_id, job_posting_id, posting_title, posting_organization,
                ap_id, cover_letter_md, cover_letter_html, include_cv, cv_snapshot)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(id)
    .bind(applicant_id)
    .bind(job_id)
    .bind(&job.title)
    .bind(&organisation_name)
    .bind(&ap_id)
    .bind(&params.cover_letter_md)
    .bind(&cover_letter_html)
    .bind(params.include_cv)
    // The CV as it stood when they applied, not as it stands when the
    // employer opens it. Regenerating live would show the employer
    // every edit made since, which is neither what the applicant sent
    // nor what they would expect to be read.
    .bind(cv_snapshot.filter(|_| params.include_cv))
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db) if db.code().as_deref() == Some("23505") => {
            NoombatError::BadRequest("you have already applied to this posting".into())
        }
        other => NoombatError::from(other),
    })?;

    sqlx::query(
        r#"INSERT INTO job_application_grants
               (job_application_id, token_hash, audience_ap_id, audience_origin,
                expires_at, document_uses_remaining, cv_uses_remaining)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(hash_token(&token))
    .bind(&organisation_ap_id)
    .bind(&audience_origin)
    .bind(expires_at)
    .bind(DOCUMENT_USES)
    .bind(if params.include_cv { CV_USES } else { 0 })
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Application {
        id,
        ap_id,
        grant_token: token,
        grant_expires_at: expires_at,
    })
}

/// What a redeemed grant admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Document {
    /// The application itself.
    Application,
    /// The CV attached to it.
    Cv,
}

/// A grant that has been checked and charged.
#[derive(Debug)]
pub struct Redeemed {
    pub grant_id: Uuid,
    pub job_application_id: Uuid,
    pub applicant_id: Uuid,
}

/// Redeem a capability token for one read.
///
/// Every path through this writes a `job_application_accesses` row,
/// including a refusal, and every row carries the `grant_id`. That
/// column had no writer at all, so the disclosure log could record a
/// moderator's read and structurally could not record the one it was
/// designed for.
///
/// The checks are made in the statement rather than read-then-write, so
/// two simultaneous dereferences cannot both spend the last use.
pub async fn redeem(
    pool: &PgPool,
    token: &str,
    reader_origin: &str,
    document: Document,
) -> Result<Redeemed> {
    let hash = hash_token(token);

    // One statement: find a live grant for this hash and audience with
    // budget left, spend one, and return what it points at. A grant that
    // is expired, revoked, exhausted or addressed elsewhere matches
    // nothing and spends nothing.
    //
    // Two statements rather than one with the column name interpolated:
    // the workspace forbids a dynamic SQL string, and rightly, since a
    // column name assembled at runtime is one refactor away from being
    // assembled from input.
    let spent = match document {
        Document::Application => {
            sqlx::query_as::<_, (Uuid, Uuid)>(
                r#"UPDATE job_application_grants
                      SET document_uses_remaining = document_uses_remaining - 1
                    WHERE token_hash = $1
                      AND audience_origin = $2
                      AND revoked_at IS NULL
                      AND expires_at > now()
                      AND document_uses_remaining > 0
                RETURNING id, job_application_id"#,
            )
            .bind(&hash)
            .bind(reader_origin)
            .fetch_optional(pool)
            .await?
        }
        Document::Cv => {
            sqlx::query_as::<_, (Uuid, Uuid)>(
                r#"UPDATE job_application_grants
                      SET cv_uses_remaining = cv_uses_remaining - 1
                    WHERE token_hash = $1
                      AND audience_origin = $2
                      AND revoked_at IS NULL
                      AND expires_at > now()
                      AND cv_uses_remaining > 0
                RETURNING id, job_application_id"#,
            )
            .bind(&hash)
            .bind(reader_origin)
            .fetch_optional(pool)
            .await?
        }
    };

    let Some((grant_id, job_application_id)) = spent else {
        // A refusal is logged too, where the grant can be identified at
        // all: an applicant is owed the attempt as much as the success.
        if let Ok(Some((grant_id, application_id))) = sqlx::query_as::<_, (Uuid, Uuid)>(
            "SELECT id, job_application_id FROM job_application_grants WHERE token_hash = $1",
        )
        .bind(&hash)
        .fetch_optional(pool)
        .await
        {
            let _ = log_access(pool, application_id, Some(grant_id), None, "denied", None).await;
        }
        return Err(NoombatError::Forbidden);
    };

    let applicant_id: Uuid =
        sqlx::query_scalar("SELECT applicant_id FROM job_applications WHERE id = $1")
            .bind(job_application_id)
            .fetch_one(pool)
            .await?;

    log_access(
        pool,
        job_application_id,
        Some(grant_id),
        None,
        "disclosed",
        None,
    )
    .await?;

    Ok(Redeemed {
        grant_id,
        job_application_id,
        applicant_id,
    })
}

/// Record one disclosure, or one refusal.
///
/// A moderator's read lands here as well as an employer's, because it is
/// a disclosure like any other and the applicant is shown both.
pub async fn log_access(
    pool: &PgPool,
    job_application_id: Uuid,
    grant_id: Option<Uuid>,
    reader_id: Option<Uuid>,
    outcome: &str,
    reason: Option<&str>,
) -> Result<()> {
    let kind = if grant_id.is_some() {
        "grant_dereference"
    } else {
        "moderator_review"
    };

    sqlx::query(
        r#"INSERT INTO job_application_accesses
               (job_application_id, grant_id, reader_id, kind, outcome, reason)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(job_application_id)
    .bind(grant_id)
    .bind(reader_id)
    .bind(kind)
    .bind(outcome)
    .bind(reason)
    .execute(pool)
    .await?;

    Ok(())
}

/// Revoke an applicant's own grants for one application.
///
/// This is what withdrawal means: the employer's access ends, which
/// handing over a copy of the document could never have achieved.
pub async fn revoke_for_application(
    pool: &PgPool,
    applicant_id: Uuid,
    job_application_id: Uuid,
    reason: &str,
) -> Result<u64> {
    let affected = sqlx::query(
        r#"UPDATE job_application_grants g
              SET state = 'revoked', revoked_at = now(), revoked_reason = $3
             FROM job_applications a
            WHERE g.job_application_id = a.id
              AND a.id = $2
              AND a.applicant_id = $1
              AND g.revoked_at IS NULL"#,
    )
    .bind(applicant_id)
    .bind(job_application_id)
    .bind(reason)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_audience_is_pinned_to_one_origin() {
        assert_eq!(
            origin_of("https://acme.example/users/hr").expect("parsed"),
            "https://acme.example"
        );
        // A port is part of the origin: two services on one host are two
        // audiences.
        assert_eq!(
            origin_of("https://acme.example:8443/users/hr").expect("parsed"),
            "https://acme.example:8443"
        );
        assert_eq!(
            origin_of("http://localhost:8443/users/hr").expect("parsed"),
            "http://localhost:8443"
        );
    }

    #[test]
    fn an_actor_id_that_is_not_a_url_is_refused() {
        // Rather than defaulting to an empty origin, which would match
        // every reader.
        assert!(origin_of("acme.example/users/hr").is_err());
        assert!(origin_of("https://").is_err());
        assert!(origin_of("").is_err());
    }

    #[test]
    fn the_token_is_not_its_own_hash() {
        let token = mint_token();
        assert_eq!(token.len(), 64, "32 bytes, hex encoded");
        let hash = hash_token(&token);
        assert_ne!(hash, token);
        assert_eq!(hash.len(), 64);
        // Deterministic, because the lookup is by unique index on it.
        assert_eq!(hash, hash_token(&token));
    }

    #[test]
    fn two_tokens_do_not_collide() {
        let a = mint_token();
        let b = mint_token();
        assert_ne!(a, b);
    }
}
