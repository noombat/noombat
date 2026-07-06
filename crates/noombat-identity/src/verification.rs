// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Domain verification via `rel="me"` bidirectional linking.
//!
//! Verifies that an external URL links back to the user's Noombat
//! profile using `<a rel="me" href="...">` or `<link rel="me" href="...">`.

use noombat_core::error::{NoombatError, Result};
use regex::Regex;
use sqlx::PgPool;
use std::sync::LazyLock;
use tracing::{info, warn};
use uuid::Uuid;

/// Regex to find `rel="me"` links in HTML.
///
/// Matches `<a ...>` or `<link ...>` elements whose `rel` attribute
/// contains `me` and captures the `href` value.
static REL_ME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<(?:a|link)\s[^>]*\brel\s*=\s*"[^"]*\bme\b[^"]*"[^>]*\bhref\s*=\s*"([^"]+)"[^>]*/?\s*>"#,
    )
    .unwrap()
});

/// Also match when href comes before rel.
static REL_ME_RE_ALT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<(?:a|link)\s[^>]*\bhref\s*=\s*"([^"]+)"[^>]*\brel\s*=\s*"[^"]*\bme\b[^"]*"[^>]*/?\s*>"#,
    )
    .unwrap()
});

/// A row from the `verified_links` table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct VerifiedLink {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub url: String,
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_checked: chrono::DateTime<chrono::Utc>,
    pub visibility: String,
}

/// Add a URL to the user's verified links (initially unverified).
pub async fn add_link(pool: &PgPool, actor_id: Uuid, url: &str) -> Result<VerifiedLink> {
    let id = Uuid::new_v4();
    let row = sqlx::query_as::<_, VerifiedLink>(
        r#"INSERT INTO verified_links (id, actor_id, url)
           VALUES ($1, $2, $3)
           ON CONFLICT (actor_id, url) DO UPDATE SET last_checked = now()
           RETURNING id, actor_id, url, verified_at, last_checked, visibility"#,
    )
    .bind(id)
    .bind(actor_id)
    .bind(url)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// List verified links for an actor.
pub async fn list_links(pool: &PgPool, actor_id: Uuid) -> Result<Vec<VerifiedLink>> {
    let rows = sqlx::query_as::<_, VerifiedLink>(
        r#"SELECT id, actor_id, url, verified_at, last_checked, visibility
           FROM verified_links
           WHERE actor_id = $1
           ORDER BY url"#,
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Remove a verified link.
pub async fn delete_link(pool: &PgPool, actor_id: Uuid, id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM verified_links WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "verified_link",
            id,
        });
    }
    Ok(())
}

/// Verify a single link by fetching the URL and checking for a
/// `rel="me"` back-link to the user's profile.
///
/// Updates the `verified_at` and `last_checked` columns.
pub async fn verify_link(
    pool: &PgPool,
    client: &reqwest::Client,
    link: &VerifiedLink,
    profile_url: &str,
) -> Result<bool> {
    info!(url = %link.url, "verifying rel=\"me\" link");

    let html = match client.get(&link.url).send().await {
        Ok(resp) if resp.status().is_success() => resp.text().await.unwrap_or_default(),
        Ok(resp) => {
            warn!(url = %link.url, status = resp.status().as_u16(), "verification fetch failed");
            mark_checked(pool, link.id, false).await?;
            return Ok(false);
        }
        Err(e) => {
            warn!(url = %link.url, "verification fetch error: {e}");
            mark_checked(pool, link.id, false).await?;
            return Ok(false);
        }
    };

    let verified = check_rel_me(&html, profile_url);
    mark_checked(pool, link.id, verified).await?;

    if verified {
        info!(url = %link.url, "rel=\"me\" verified");
    } else {
        info!(url = %link.url, "rel=\"me\" not found");
    }

    Ok(verified)
}

/// Check whether the HTML body contains a `rel="me"` link pointing
/// to the given profile URL.
fn check_rel_me(html: &str, profile_url: &str) -> bool {
    for cap in REL_ME_RE.captures_iter(html) {
        if let Some(href) = cap.get(1) {
            if href.as_str() == profile_url {
                return true;
            }
        }
    }
    for cap in REL_ME_RE_ALT.captures_iter(html) {
        if let Some(href) = cap.get(1) {
            if href.as_str() == profile_url {
                return true;
            }
        }
    }
    false
}

/// Update the `verified_at` and `last_checked` timestamps.
async fn mark_checked(pool: &PgPool, link_id: Uuid, verified: bool) -> Result<()> {
    if verified {
        sqlx::query(
            r#"UPDATE verified_links
               SET verified_at = now(), last_checked = now()
               WHERE id = $1"#,
        )
        .bind(link_id)
        .execute(pool)
        .await?;
    } else {
        sqlx::query(
            r#"UPDATE verified_links
               SET verified_at = NULL, last_checked = now()
               WHERE id = $1"#,
        )
        .bind(link_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Background worker: re-verify all links that have not been checked
/// within the given interval (in days).
pub async fn reverify_stale_links(
    pool: &PgPool,
    client: &reqwest::Client,
    domain: &str,
    max_age_days: i32,
) -> Result<u64> {
    let links = sqlx::query_as::<_, VerifiedLink>(
        r#"SELECT vl.id, vl.actor_id, vl.url, vl.verified_at, vl.last_checked, vl.visibility
           FROM verified_links vl
           WHERE vl.last_checked < now() - make_interval(days => $1)
           LIMIT 50"#,
    )
    .bind(max_age_days)
    .fetch_all(pool)
    .await?;

    let mut count = 0u64;
    for link in &links {
        let username = sqlx::query_scalar::<_, String>("SELECT username FROM actors WHERE id = $1")
            .bind(link.actor_id)
            .fetch_optional(pool)
            .await?;

        if let Some(username) = username {
            let profile_url = format!("https://{domain}/users/{username}");
            let _ = verify_link(pool, client, link, &profile_url).await;
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_rel_me_link() {
        let html = r#"<html><body>
            <a rel="me" href="https://noombat.social/users/alice">Noombat</a>
        </body></html>"#;
        assert!(check_rel_me(html, "https://noombat.social/users/alice"));
    }

    #[test]
    fn finds_rel_me_link_element() {
        let html = r#"<link rel="me" href="https://noombat.social/users/alice" />"#;
        assert!(check_rel_me(html, "https://noombat.social/users/alice"));
    }

    #[test]
    fn finds_rel_me_href_first() {
        let html = r#"<a href="https://noombat.social/users/alice" rel="me">Noombat</a>"#;
        assert!(check_rel_me(html, "https://noombat.social/users/alice"));
    }

    #[test]
    fn does_not_match_wrong_url() {
        let html = r#"<a rel="me" href="https://other.example/alice">link</a>"#;
        assert!(!check_rel_me(html, "https://noombat.social/users/alice"));
    }

    #[test]
    fn does_not_match_missing_rel_me() {
        let html = r#"<a href="https://noombat.social/users/alice">link</a>"#;
        assert!(!check_rel_me(html, "https://noombat.social/users/alice"));
    }
}
