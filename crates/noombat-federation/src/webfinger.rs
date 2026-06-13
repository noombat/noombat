// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
// crates/noombat-federation/src/webfinger.rs
//! WebFinger (RFC 7033) implementation for actor discovery.

use serde::{Deserialize, Serialize};

/// A WebFinger response (JRD — JSON Resource Descriptor).
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

/// Construct a WebFinger response for a local actor.
///
/// # Arguments
/// * `username` — the local part (e.g. `alice`)
/// * `domain` — the instance domain (e.g. `noombat.social`)
/// * `ap_id` — the fully-qualified ActivityPub identifier
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
    fn test_parse_acct_uri_invalid() {
        assert!(parse_acct_uri("alice@noombat.social").is_none());
        assert!(parse_acct_uri("acct:@noombat.social").is_none());
        assert!(parse_acct_uri("acct:alice@").is_none());
    }
}
