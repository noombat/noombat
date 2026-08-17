// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! ORCID publication import.
//!
//! Fetches the user's publication list from the ORCID Public API v3
//! and resolves DOIs via the existing `doi_client` pipeline. Works
//! without DOIs are imported as structured entries with metadata from
//! the ORCID record. The import is incremental: subsequent
//! synchronisations add new works without duplicating existing entries.

use noombat_core::error::{NoombatError, Result};
use serde::Deserialize;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::doi_client;
use crate::profile;

/// Summary of an import operation.
#[derive(Debug, Default)]
pub struct ImportSummary {
    pub total_works: usize,
    pub imported: usize,
    pub skipped_duplicate: usize,
    pub skipped_no_doi: usize,
    pub failed: usize,
}

// ..... ORCID API response types .....

#[derive(Debug, Deserialize)]
struct OrcidWorksResponse {
    group: Vec<WorkGroup>,
}

#[derive(Debug, Deserialize)]
struct WorkGroup {
    #[serde(rename = "work-summary")]
    work_summary: Vec<WorkSummary>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields deserialised from the ORCID API response.
struct WorkSummary {
    title: Option<WorkTitle>,
    #[serde(rename = "external-ids")]
    external_ids: Option<ExternalIds>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct WorkTitle {
    title: Option<TitleValue>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TitleValue {
    value: String,
}

#[derive(Debug, Deserialize)]
struct ExternalIds {
    #[serde(rename = "external-id")]
    external_id: Vec<ExternalId>,
}

#[derive(Debug, Deserialize)]
struct ExternalId {
    #[serde(rename = "external-id-type")]
    external_id_type: String,
    #[serde(rename = "external-id-value")]
    external_id_value: String,
}

/// Import publications from the ORCID Public API v3 for the given
/// actor.
///
/// Resolves each DOI via the existing `doi_client` pipeline and
/// inserts the publication into the `publications` table if it does
/// not already exist.
///
/// `mailto` is sent to the CrossRef polite pool per their usage
/// guidelines, so operators should configure a real administrative
/// address.
pub async fn import_orcid_publications(
    pool: &PgPool,
    http_client: &reqwest::Client,
    actor_id: Uuid,
    orcid: &str,
    pub_api_uri: &str,
    mailto: &str,
) -> Result<ImportSummary> {
    let works_url = format!("{pub_api_uri}/v3.0/{orcid}/works");

    let resp = http_client
        .get(&works_url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| NoombatError::Internal(format!("ORCID works fetch failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(NoombatError::Internal(format!(
            "ORCID works API returned {}",
            resp.status()
        )));
    }

    let works: OrcidWorksResponse = resp
        .json()
        .await
        .map_err(|e| NoombatError::Internal(format!("malformed ORCID works response: {e}")))?;

    let mut summary = ImportSummary {
        total_works: works.group.len(),
        ..Default::default()
    };

    for group in &works.group {
        let Some(work) = group.work_summary.first() else {
            continue;
        };

        // Extract the DOI from external identifiers.
        let doi = work.external_ids.as_ref().and_then(|ids| {
            ids.external_id
                .iter()
                .find(|id| id.external_id_type.eq_ignore_ascii_case("doi"))
                .map(|id| id.external_id_value.clone())
        });

        let Some(doi) = doi else {
            summary.skipped_no_doi += 1;
            continue;
        };

        // Check whether this DOI already exists for the actor.
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM publications WHERE actor_id = $1 AND doi = $2)",
        )
        .bind(actor_id)
        .bind(&doi)
        .fetch_one(pool)
        .await
        .unwrap_or(false);

        if exists {
            summary.skipped_duplicate += 1;
            continue;
        }

        // Resolve the DOI via CrossRef or DataCite.
        match doi_client::resolve(http_client, &doi, mailto).await {
            Ok(metadata) => {
                let authors: serde_json::Value =
                    serde_json::to_value(&metadata.authors).unwrap_or(serde_json::json!([]));
                let params = profile::NewPublication {
                    doi: metadata.doi.clone(),
                    title: metadata.title.clone(),
                    authors,
                    abstract_md: None,
                    journal: metadata.journal.clone(),
                    publisher: metadata.publisher.clone(),
                    published_date: metadata
                        .published_date
                        .as_deref()
                        .and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok()),
                    doi_metadata: metadata.raw.clone(),
                    visibility: Some("public".into()),
                };
                if let Err(e) = profile::create_publication(pool, actor_id, &params).await {
                    warn!(doi = %doi, error = %e, "failed to insert ORCID publication");
                    summary.failed += 1;
                } else {
                    summary.imported += 1;
                }
            }
            Err(e) => {
                warn!(doi = %doi, error = %e, "DOI resolution failed during ORCID import");
                summary.failed += 1;
            }
        }
    }

    info!(
        orcid = %orcid,
        total = summary.total_works,
        imported = summary.imported,
        skipped_dup = summary.skipped_duplicate,
        skipped_no_doi = summary.skipped_no_doi,
        failed = summary.failed,
        "ORCID publication import complete"
    );

    Ok(summary)
}
