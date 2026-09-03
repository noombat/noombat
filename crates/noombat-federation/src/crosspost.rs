// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Cross-post aggregation and de-duplication.
//!
//! When the same content (job posting, article, or post) is shared
//! across multiple Noombat instances or federated communities,
//! duplicate entries may clutter feeds and fragment discussion.
//!
//! Each post carries a `canonical_uri` column (nullable). When the
//! federation service receives a `Create` or `Announce` whose object
//! matches an already-known `canonical_uri`, the existing post is
//! referenced rather than a duplicate created.
//!
//! For objects that lack an explicit `canonical_uri`, the federation
//! service falls back to URL-based matching: if the `url` field of an
//! incoming object matches the `url` of an existing local post, they
//! are treated as the same content.

use noombat_ap::vocab;
use noombat_core::error::Result;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

/// Attempt to find a local post that matches the given canonical URI.
///
/// Returns the UUID of the matching post, if any.
pub async fn find_by_canonical_uri(pool: &PgPool, canonical_uri: &str) -> Result<Option<Uuid>> {
    let id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM posts WHERE canonical_uri = $1 LIMIT 1")
        .bind(canonical_uri)
        .fetch_optional(pool)
        .await?;
    Ok(id)
}

/// Attempt to find a local post whose `ap_id` or `canonical_uri`
/// matches the given URL.
///
/// This is the fallback heuristic: when an inbound object has no
/// explicit `canonical_uri`, the `url` field is checked against
/// both `canonical_uri` and `ap_id`.
pub async fn find_by_url_heuristic(pool: &PgPool, url: &str) -> Result<Option<Uuid>> {
    let id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM posts \
         WHERE canonical_uri = $1 OR ap_id = $1 \
         LIMIT 1",
    )
    .bind(url)
    .fetch_optional(pool)
    .await?;
    Ok(id)
}

/// Extract a canonical URI from an inbound ActivityPub object.
///
/// Checks the following locations, in priority order:
///
/// 1. `noombat:canonicalUri`: the Noombat extension property.
/// 2. `url`: the standard ActivityStreams URL property. Used as
///    a heuristic when no explicit canonical URI is present.
///
/// Returns `None` if neither property exists.
pub fn extract_canonical_uri(object: &serde_json::Value) -> Option<String> {
    // Prefer the explicit Noombat extension property.
    if let Some(uri) = object.get(vocab::CANONICAL_URI).and_then(|v| v.as_str()) {
        return Some(uri.to_owned());
    }

    // Fall back to the `url` property.
    object.get("url").and_then(|v| v.as_str()).map(String::from)
}

/// Attempt to de-duplicate an inbound object against existing local
/// posts.
///
/// Returns `Some(uuid)` if a matching local post was found (the
/// caller should skip insertion and link to the existing post
/// instead), or `None` if the object is novel.
pub async fn try_dedup(pool: &PgPool, object: &serde_json::Value) -> Result<Option<Uuid>> {
    // 1. Check for explicit canonical_uri match.
    if let Some(canonical) = object.get(vocab::CANONICAL_URI).and_then(|v| v.as_str())
        && let Some(id) = find_by_canonical_uri(pool, canonical).await?
    {
        info!(canonical_uri = canonical, post_id = %id, "cross-post de-duplicated via canonical URI");
        return Ok(Some(id));
    }

    // 2. Heuristic: check `url` field against canonical_uri and ap_id.
    if let Some(url) = object.get("url").and_then(|v| v.as_str())
        && let Some(id) = find_by_url_heuristic(pool, url).await?
    {
        info!(url, post_id = %id, "cross-post de-duplicated via URL heuristic");
        return Ok(Some(id));
    }

    Ok(None)
}

/// Record or update the canonical URI for a local post.
///
/// Called when a local post is first created (to set its own canonical
/// URI) or when a de-duplicated cross-post is linked.
pub async fn set_canonical_uri(pool: &PgPool, post_id: Uuid, canonical_uri: &str) -> Result<()> {
    sqlx::query("UPDATE posts SET canonical_uri = $1 WHERE id = $2")
        .bind(canonical_uri)
        .bind(post_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_canonical_uri_from_noombat_extension() {
        let obj = json!({
            "type": "Note",
            "noombat:canonicalUri": "https://original.example/posts/1",
            "url": "https://mirror.example/posts/1",
        });
        assert_eq!(
            extract_canonical_uri(&obj),
            Some("https://original.example/posts/1".to_owned())
        );
    }

    #[test]
    fn extract_canonical_uri_falls_back_to_url() {
        let obj = json!({
            "type": "Note",
            "url": "https://example.com/posts/42",
        });
        assert_eq!(
            extract_canonical_uri(&obj),
            Some("https://example.com/posts/42".to_owned())
        );
    }

    #[test]
    fn extract_canonical_uri_none_when_absent() {
        let obj = json!({ "type": "Note", "content": "hello" });
        assert_eq!(extract_canonical_uri(&obj), None);
    }
}
