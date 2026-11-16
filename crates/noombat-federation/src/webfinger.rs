// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
// crates/noombat-federation/src/webfinger.rs
//! WebFinger (RFC 7033) implementation for actor discovery.

use noombat_core::error::{NoombatError, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::http;

/// A WebFinger response (JRD: JSON Resource Descriptor).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFingerResponse {
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    pub links: Vec<WebFingerLink>,
}

/// A single link within a WebFinger response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFingerLink {
    pub rel: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub link_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

/// Construct a WebFinger response for a local actor, whose subject is
/// `acct:{username}@{domain}`.
pub fn build_response(username: &str, domain: &str, ap_id: &str) -> WebFingerResponse {
    WebFingerResponse {
        subject: format!("acct:{username}@{domain}"),
        aliases: Some(vec![ap_id.to_owned()]),
        links: vec![WebFingerLink {
            rel: "self".to_owned(),
            link_type: Some("application/activity+json".to_owned()),
            href: Some(ap_id.to_owned()),
        }],
    }
}

/// Parse an `acct:` URI into `(username, domain)`.
///
/// Returns `None` if the resource string does not match the expected pattern.
pub fn parse_acct_uri(resource: &str) -> Option<(String, String)> {
    let resource = resource.strip_prefix("acct:")?;
    let (user, domain) = resource.split_once('@')?;
    if user.is_empty() || domain.is_empty() {
        return None;
    }
    Some((user.to_owned(), domain.to_owned()))
}

/// The user and domain of a handle, written `@user@domain` or
/// `user@domain`. A domain may carry a port, as a development instance's
/// does.
pub fn parse_handle(handle: &str) -> Option<(&str, &str)> {
    let handle = handle.strip_prefix('@').unwrap_or(handle);
    let (user, domain) = handle.split_once('@')?;
    let user_ok = !user.is_empty()
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    let domain_ok = !domain.is_empty()
        && !domain.starts_with(['.', '-', ':'])
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    (user_ok && domain_ok).then_some((user, domain))
}

/// The ActivityPub actor a WebFinger response names: its `self` link with
/// an ActivityPub media type.
pub fn actor_link(response: &WebFingerResponse) -> Option<&str> {
    response
        .links
        .iter()
        .filter(|link| link.rel == "self")
        .filter(|link| {
            link.link_type.as_deref().is_some_and(|media_type| {
                media_type == "application/activity+json"
                    || media_type.starts_with("application/ld+json")
            })
        })
        .find_map(|link| link.href.as_deref())
}

/// The actor URI a handle's own domain names for it, through WebFinger.
pub async fn resolve_handle(client: &reqwest::Client, user: &str, domain: &str) -> Result<String> {
    let mut url = Url::parse(&format!(
        "{}://{domain}/.well-known/webfinger",
        http::scheme_for(domain)
    ))
    .map_err(|e| NoombatError::BadRequest(format!("no WebFinger URL for {domain}: {e}")))?;
    url.query_pairs_mut()
        .append_pair("resource", &format!("acct:{user}@{domain}"));
    let response = http::guarded_get(client, url.as_str()).await?;
    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "WebFinger answered HTTP {}",
            response.status()
        )));
    }
    let response: WebFingerResponse = http::json_within_limit(response, "WebFinger").await?;
    actor_link(&response)
        .map(str::to_owned)
        .ok_or_else(|| NoombatError::Federation("WebFinger names no ActivityPub actor".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acct_uri() {
        let (user, domain) = parse_acct_uri("acct:alice@noombat.social").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "noombat.social");
    }

    #[test]
    fn a_handle_is_read_with_or_without_its_leading_at() {
        assert_eq!(
            parse_handle("@bob@other.example"),
            Some(("bob", "other.example"))
        );
        assert_eq!(
            parse_handle("bob@other.example"),
            Some(("bob", "other.example"))
        );
        assert_eq!(
            parse_handle("@b.o_b-1@localhost:8443"),
            Some(("b.o_b-1", "localhost:8443"))
        );
        for refused in [
            "bob",
            "@bob",
            "@@other.example",
            "@bob@",
            "@bob@other.example@third.example",
            "@bob@other.example/path",
            "@bob@other.example?x=1",
            "@b b@other.example",
            "@bob@.other.example",
            "@bob@:8443",
            "@b%40c@other.example",
        ] {
            assert_eq!(parse_handle(refused), None, "{refused}");
        }
    }

    fn response(links: &[(&str, Option<&str>, Option<&str>)]) -> WebFingerResponse {
        WebFingerResponse {
            subject: "acct:bob@other.example".into(),
            aliases: None,
            links: links
                .iter()
                .map(|(rel, link_type, href)| WebFingerLink {
                    rel: (*rel).into(),
                    link_type: link_type.map(Into::into),
                    href: href.map(Into::into),
                })
                .collect(),
        }
    }

    #[test]
    fn the_actor_is_the_self_link_of_an_activitypub_type() {
        let actor = "https://other.example/users/bob";
        let ld = r#"application/ld+json; profile="https://www.w3.org/ns/activitystreams""#;
        for (link_type, expected) in [
            (Some("application/activity+json"), Some(actor)),
            (Some(ld), Some(actor)),
            (Some("text/html"), None),
            (None, None),
        ] {
            let jrd = response(&[("self", link_type, Some(actor))]);
            assert_eq!(actor_link(&jrd), expected, "{link_type:?}");
        }
        let profile_page = (
            "http://webfinger.net/rel/profile-page",
            Some("text/html"),
            Some("x"),
        );
        let elsewhere = ("alternate", Some("application/activity+json"), Some("y"));
        let jrd = response(&[
            profile_page,
            elsewhere,
            ("self", Some("application/activity+json"), Some(actor)),
        ]);
        assert_eq!(actor_link(&jrd), Some(actor));
    }

    #[test]
    fn test_parse_acct_uri_invalid() {
        assert!(parse_acct_uri("alice@noombat.social").is_none());
        assert!(parse_acct_uri("acct:@noombat.social").is_none());
        assert!(parse_acct_uri("acct:alice@").is_none());
    }
}
