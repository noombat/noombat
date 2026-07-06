// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! DOI metadata resolution via the CrossRef and DataCite REST APIs.
//!
//! Resolves a bare DOI string (e.g. `10.1000/xyz123`) into structured
//! bibliographic metadata (title, authors, journal, publisher, date).

use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Resolved metadata for a DOI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoiMetadata {
    pub doi: String,
    pub title: String,
    pub authors: Vec<String>,
    pub journal: Option<String>,
    pub publisher: Option<String>,
    pub published_date: Option<String>,
    /// The full raw JSON response from the API (cached for re-use).
    pub raw: serde_json::Value,
}

/// Resolve a DOI via CrossRef, falling back to DataCite on failure.
///
/// The `mailto` address is included in CrossRef requests per their
/// [polite-pool guidelines](https://github.com/CrossRef/rest-api-doc#good-manners--more-reliable-service),
/// which grant higher rate limits to identifiable callers.
pub async fn resolve(client: &reqwest::Client, doi: &str, mailto: &str) -> Result<DoiMetadata> {
    info!(doi, "resolving DOI metadata");

    match resolve_crossref(client, doi, mailto).await {
        Ok(meta) => return Ok(meta),
        Err(e) => {
            warn!(doi, "CrossRef lookup failed: {e}; trying DataCite");
        }
    }

    resolve_datacite(client, doi).await
}

// ..... CrossRef .....

/// CrossRef REST API response wrapper.
#[derive(Deserialize)]
struct CrossRefResponse {
    message: serde_json::Value,
}

async fn resolve_crossref(
    client: &reqwest::Client,
    doi: &str,
    mailto: &str,
) -> Result<DoiMetadata> {
    let url = format!(
        "https://api.crossref.org/works/{doi}?mailto={mailto}",
        doi = urlencoding_encode(doi),
        mailto = urlencoding_encode(mailto),
    );

    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("CrossRef HTTP error: {e}")))?;

    if !resp.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "CrossRef returned HTTP {}",
            resp.status()
        )));
    }

    let body: CrossRefResponse = resp
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("CrossRef JSON parse error: {e}")))?;

    let msg = &body.message;

    let title = msg
        .get("title")
        .and_then(|t| t.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("(untitled)")
        .to_owned();

    let authors = msg
        .get("author")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let given = a.get("given").and_then(|v| v.as_str()).unwrap_or("");
                    let family = a.get("family").and_then(|v| v.as_str()).unwrap_or("");
                    if family.is_empty() {
                        None
                    } else if given.is_empty() {
                        Some(family.to_owned())
                    } else {
                        Some(format!("{given} {family}"))
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let journal = msg
        .get("container-title")
        .and_then(|t| t.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(String::from);

    let publisher = msg
        .get("publisher")
        .and_then(|v| v.as_str())
        .map(String::from);

    let published_date = msg
        .get("published-print")
        .or_else(|| msg.get("published-online"))
        .or_else(|| msg.get("issued"))
        .and_then(|d| d.get("date-parts"))
        .and_then(|dp| dp.as_array())
        .and_then(|a| a.first())
        .and_then(|parts| parts.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|v| v.as_i64().map(|n| n.to_string()))
                .collect::<Vec<_>>()
                .join("-")
        });

    Ok(DoiMetadata {
        doi: doi.to_owned(),
        title,
        authors,
        journal,
        publisher,
        published_date,
        raw: body.message,
    })
}

// ..... DataCite .....

async fn resolve_datacite(client: &reqwest::Client, doi: &str) -> Result<DoiMetadata> {
    let url = format!(
        "https://api.datacite.org/dois/{doi}",
        doi = urlencoding_encode(doi),
    );

    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("DataCite HTTP error: {e}")))?;

    if !resp.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "DataCite returned HTTP {}",
            resp.status()
        )));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("DataCite JSON parse error: {e}")))?;

    let data = body.get("data").and_then(|d| d.get("attributes"));

    let attrs = data.ok_or_else(|| {
        NoombatError::Federation("DataCite response missing data.attributes".into())
    })?;

    let title = attrs
        .get("titles")
        .and_then(|t| t.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.get("title"))
        .and_then(|v| v.as_str())
        .unwrap_or("(untitled)")
        .to_owned();

    let authors = attrs
        .get("creators")
        .and_then(|c| c.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.get("name").and_then(|v| v.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let publisher = attrs
        .get("publisher")
        .and_then(|v| v.as_str())
        .map(String::from);

    let published_date = attrs
        .get("publicationYear")
        .and_then(|v| v.as_i64())
        .map(|y| y.to_string());

    Ok(DoiMetadata {
        doi: doi.to_owned(),
        title,
        authors,
        journal: None,
        publisher,
        published_date,
        raw: body,
    })
}

/// Percent-encode a DOI for use in a URL path segment.
///
/// DOIs may contain characters such as `/`, `(`, `)`, `<`, `>` that
/// require encoding in a URL.
fn urlencoding_encode(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoding_basic() {
        assert_eq!(urlencoding_encode("10.1000/xyz"), "10.1000%2Fxyz");
    }

    #[test]
    fn urlencoding_passthrough() {
        assert_eq!(urlencoding_encode("simple"), "simple");
    }
}
