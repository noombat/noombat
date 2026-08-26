// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Domain verification via `rel="me"` bidirectional linking.
//!
//! Verifies that an external URL links back to the user's Noombat
//! profile using `<a rel="me" href="...">` or `<link rel="me" href="...">`.

use noombat_core::error::{NoombatError, Result};
use scraper::{Html, Selector};
use sqlx::PgPool;
use std::sync::LazyLock;
use tracing::{info, warn};
use uuid::Uuid;

/// CSS selector matching `<a>` and `<link>` elements whose `rel`
/// attribute contains `me`.
static REL_ME_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("a[rel~=me][href], link[rel~=me][href]").unwrap());

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
    profile_urls: &[&str],
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

    let verified = check_rel_me(&html, profile_urls);
    mark_checked(pool, link.id, verified).await?;

    if verified {
        info!(url = %link.url, "rel=\"me\" verified");
    } else {
        info!(url = %link.url, "rel=\"me\" not found");
    }

    Ok(verified)
}

/// Check whether the HTML body contains a `rel="me"` link pointing
/// to any of the given profile URLs.
///
/// Accepts multiple URLs so that the caller can pass both the AP ID
/// (`/users/{username}`) and the human-facing URL (`/@{username}`);
/// a match on either form constitutes verification.
///
/// Uses the `scraper` crate (backed by `html5ever`) to parse the HTML,
/// handling arbitrary attribute ordering, single-quoted values,
/// multi-line elements, and other edge cases that regex cannot cover.
/// A back-link URL reduced to what identifies it, for comparison.
///
/// Only the parts that cannot change *which* URL is named: the scheme and
/// host are case-folded, a default port is dropped, and a trailing slash
/// and fragment are removed. The host itself is left alone, so a link to
/// `www.` or to another domain stays a different URL.
///
/// Comparing raw strings instead refuses five back-links a person would
/// reasonably write, and refuses them silently: the link simply never
/// verifies and nothing says why.
fn normalise_back_link(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => (String::new(), url),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let mut authority = authority.to_ascii_lowercase();
    for default in [":443", ":80"] {
        if let Some(stripped) = authority.strip_suffix(default) {
            authority = stripped.to_owned();
        }
    }
    let path = path.split('#').next().unwrap_or("");
    let path = path.strip_suffix('/').unwrap_or(path);
    // The scheme is dropped rather than compared. The href lives on the
    // claimant's own site and points back here; whether they wrote http
    // or https changes nothing about which profile is named.
    let _ = scheme;
    format!("{authority}{path}")
}

fn check_rel_me(html: &str, profile_urls: &[&str]) -> bool {
    let wanted: Vec<String> = profile_urls
        .iter()
        .map(|u| normalise_back_link(u))
        .collect();
    let document = Html::parse_document(html);
    for element in document.select(&REL_ME_SELECTOR) {
        if let Some(href) = element.value().attr("href")
            && wanted.contains(&normalise_back_link(href))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod back_link_tests {
    use super::*;

    const AP: &str = "https://noombat.example/users/alice";
    const HUMAN: &str = "https://noombat.example/@alice";

    fn links_back(href: &str) -> bool {
        let html = format!(r#"<html><body><a rel="me" href="{href}">me</a></body></html>"#);
        check_rel_me(&html, &[AP, HUMAN])
    }

    #[test]
    fn the_ways_a_person_reasonably_writes_the_same_link_all_verify() {
        for href in [
            "https://noombat.example/@alice",
            "https://noombat.example/@alice/",
            "http://noombat.example/@alice",
            "https://NOOMBAT.example/@alice",
            "https://noombat.example:443/@alice",
            "https://noombat.example/@alice#me",
            "https://noombat.example/users/alice",
        ] {
            assert!(links_back(href), "should verify: {href}");
        }
    }

    #[test]
    fn another_host_or_another_account_still_does_not() {
        // Normalisation must not loosen which URL is named. `www.` is
        // included deliberately: it is a different host unless the
        // instance serves it, and assuming it would verify against a
        // domain this instance may not control.
        for href in [
            "https://evil.example/@alice",
            "https://noombat.example/@bob",
            "https://noombat.example.evil.test/@alice",
            "https://www.noombat.example/@alice",
            "https://noombat.example/users/bob",
        ] {
            assert!(!links_back(href), "must not verify: {href}");
        }
    }

    #[test]
    fn a_page_with_no_rel_me_does_not_verify() {
        // Guards the tests above: were the selector to match anything,
        // every case would pass and prove nothing.
        let html = r#"<html><body><a href="https://noombat.example/@alice">me</a></body></html>"#;
        assert!(!check_rel_me(html, &[AP, HUMAN]));
    }
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
///
/// Returns the set of actor UUIDs whose verification state changed
/// during this sweep (either verified to unverified or unverified to
/// verified). The caller may use these to broadcast `Update`
/// activities so that followers see the updated verification badges.
pub async fn reverify_stale_links(
    pool: &PgPool,
    client: &reqwest::Client,
    domain: &str,
    max_age_days: i32,
) -> Result<Vec<Uuid>> {
    let links = sqlx::query_as::<_, VerifiedLink>(
        r#"SELECT vl.id, vl.actor_id, vl.url, vl.verified_at, vl.last_checked, vl.visibility
           FROM verified_links vl
           WHERE vl.last_checked < now() - make_interval(days => $1)
           LIMIT 50"#,
    )
    .bind(max_age_days)
    .fetch_all(pool)
    .await?;

    let mut changed_actors: Vec<Uuid> = Vec::new();
    for link in &links {
        let username = sqlx::query_scalar::<_, String>("SELECT username FROM actors WHERE id = $1")
            .bind(link.actor_id)
            .fetch_optional(pool)
            .await?;

        if let Some(username) = username {
            let was_verified = link.verified_at.is_some();
            let ap_url = format!("https://{domain}/users/{username}");
            let human_url = format!("https://{domain}/@{username}");

            let is_verified = verify_link(pool, client, link, &[&ap_url, &human_url])
                .await
                .unwrap_or(false);

            if was_verified != is_verified {
                changed_actors.push(link.actor_id);
            }
        }
    }

    // Deduplicate: multiple links for the same actor may have changed
    // in the same sweep.
    changed_actors.sort();
    changed_actors.dedup();

    Ok(changed_actors)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both URL forms, as passed by `reverify_stale_links`.
    const BOTH: &[&str] = &[
        "https://noombat.social/users/alice",
        "https://noombat.social/@alice",
    ];

    #[test]
    fn finds_rel_me_link() {
        let html = r#"<html><body>
            <a rel="me" href="https://noombat.social/users/alice">Noombat</a>
        </body></html>"#;
        assert!(check_rel_me(html, BOTH));
    }

    #[test]
    fn finds_rel_me_link_element() {
        let html = r#"<link rel="me" href="https://noombat.social/users/alice" />"#;
        assert!(check_rel_me(html, BOTH));
    }

    #[test]
    fn finds_rel_me_href_first() {
        let html = r#"<a href="https://noombat.social/users/alice" rel="me">Noombat</a>"#;
        assert!(check_rel_me(html, BOTH));
    }

    #[test]
    fn does_not_match_wrong_url() {
        let html = r#"<a rel="me" href="https://other.example/alice">link</a>"#;
        assert!(!check_rel_me(html, BOTH));
    }

    #[test]
    fn does_not_match_missing_rel_me() {
        let html = r#"<a href="https://noombat.social/users/alice">link</a>"#;
        assert!(!check_rel_me(html, BOTH));
    }

    #[test]
    fn finds_rel_me_single_quotes() {
        let html = "<a rel='me' href='https://noombat.social/users/alice'>Noombat</a>";
        assert!(check_rel_me(html, BOTH));
    }

    #[test]
    fn finds_rel_me_multiline() {
        let html = r#"<a
            rel="me"
            href="https://noombat.social/users/alice"
        >Noombat</a>"#;
        assert!(check_rel_me(html, BOTH));
    }

    #[test]
    fn finds_rel_me_among_multiple_rels() {
        let html = r#"<a rel="noopener me" href="https://noombat.social/users/alice">link</a>"#;
        assert!(check_rel_me(html, BOTH));
    }

    // ..... /@{username} form .....

    #[test]
    fn finds_rel_me_at_prefix_url() {
        let html = r#"<a rel="me" href="https://noombat.social/@alice">Noombat</a>"#;
        assert!(check_rel_me(html, BOTH));
    }

    #[test]
    fn at_prefix_url_alone_is_sufficient() {
        // Only the /@alice form is in the href; only that form is
        // in the accepted list. Verification should still succeed.
        let html = r#"<a rel="me" href="https://noombat.social/@alice">Noombat</a>"#;
        assert!(check_rel_me(html, &["https://noombat.social/@alice"]));
    }
}

// ..... Domain control .....

/// The registrable domain of a host, or `None` if it has no public suffix.
///
/// Public-suffix aware, and it has to be. Comparing the last two labels
/// makes every `.co.uk` host look like every other, because `co.uk` is
/// the suffix rather than a registration; `evil.co.uk` would then satisfy
/// a claim on `acme.co.uk`. It also keeps `careers.acme.example` and
/// `acme.example` the same organisation while `acme.example.evil.test`
/// stays a different one.
pub fn registrable_domain(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let domain = psl::domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_owned)
}

/// The registrable domain of a URL's host.
pub fn registrable_domain_of_url(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest
        .split(['/', '?', '#'])
        .next()?
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or_else(|| rest.split(['/', '?', '#']).next().unwrap_or(""));
    let host = host.split(':').next()?;
    registrable_domain(host)
}

/// Whether this actor holds a verified link proving control of the domain
/// it claims.
///
/// Both halves are required. A verified link to some other domain proves
/// control of that domain and says nothing about the claim; a claim with
/// no verified link is an assertion. `verified_at` non-NULL is what
/// `verify_link` writes only when the back-link was actually found, so a
/// lapsed domain demotes the actor as soon as re-verification clears it.
pub async fn controls_claimed_domain(pool: &PgPool, actor_id: Uuid) -> Result<bool> {
    let claimed: Option<String> =
        sqlx::query_scalar("SELECT claimed_domain FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(pool)
            .await?
            .flatten();

    let Some(claimed) = claimed.as_deref().and_then(registrable_domain) else {
        return Ok(false);
    };

    let urls: Vec<String> = sqlx::query_scalar(
        "SELECT url FROM verified_links WHERE actor_id = $1 AND verified_at IS NOT NULL",
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await?;

    Ok(urls
        .iter()
        .filter_map(|u| registrable_domain_of_url(u))
        .any(|d| d == claimed))
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    #[test]
    fn a_subdomain_is_the_same_organisation() {
        assert_eq!(
            registrable_domain("careers.acme.example").as_deref(),
            Some("acme.example")
        );
        assert_eq!(
            registrable_domain("acme.example").as_deref(),
            Some("acme.example")
        );
    }

    #[test]
    fn a_lookalike_suffix_is_a_different_organisation() {
        // The attack the claim exists to stop: registering the claimed
        // name as a label under a domain you control.
        assert_ne!(
            registrable_domain("acme.example.evil.test").as_deref(),
            Some("acme.example")
        );
        assert_eq!(
            registrable_domain("acme.example.evil.test").as_deref(),
            Some("evil.test")
        );
    }

    #[test]
    fn a_multi_label_public_suffix_is_not_a_registration() {
        // Comparing the last two labels would make these equal, and every
        // .co.uk host would satisfy every .co.uk claim.
        assert_eq!(
            registrable_domain("acme.co.uk").as_deref(),
            Some("acme.co.uk")
        );
        assert_eq!(
            registrable_domain("evil.co.uk").as_deref(),
            Some("evil.co.uk")
        );
        assert_ne!(
            registrable_domain("acme.co.uk"),
            registrable_domain("evil.co.uk")
        );
        // The bare suffix is not registrable at all.
        assert_eq!(registrable_domain("co.uk"), None);
    }

    #[test]
    fn a_url_is_reduced_to_its_registrable_domain() {
        for url in [
            "https://careers.acme.example/jobs",
            "http://acme.example",
            "https://acme.example:8443/x?y=1#z",
        ] {
            assert_eq!(
                registrable_domain_of_url(url).as_deref(),
                Some("acme.example"),
                "{url}"
            );
        }
    }

    #[test]
    fn case_and_a_trailing_dot_do_not_change_the_answer() {
        assert_eq!(
            registrable_domain("ACME.Example.").as_deref(),
            Some("acme.example")
        );
    }
}

/// Unpublish the listings of organisations that no longer control the
/// domain they claim. Returns how many were unpublished.
///
/// Run after re-verification. A lapsed corporate domain is the classic
/// recruitment-fraud vector: an expired domain is bought cheaply and the
/// listings keep running under a badge that is no longer true. Refusing
/// new listings is not enough on its own, because the ones already
/// published are the ones applicants answer.
pub async fn demote_lapsed_organizations(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE job_listings SET published_at = NULL \
         WHERE published_at IS NOT NULL \
           AND actor_id IN ( \
               SELECT a.id FROM actors a \
               WHERE a.actor_type = 'organization' \
                 AND NOT EXISTS ( \
                     SELECT 1 FROM verified_links v \
                     WHERE v.actor_id = a.id AND v.verified_at IS NOT NULL \
                 ) \
           )",
    )
    .execute(pool)
    .await?;

    let unpublished = result.rows_affected();
    if unpublished > 0 {
        warn!(
            unpublished,
            "unpublished listings of organisations with no verified domain"
        );
    }
    Ok(unpublished)
}
