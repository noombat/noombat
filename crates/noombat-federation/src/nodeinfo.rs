// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! NodeInfo 2.1 response builder.

use serde::Serialize;
use serde_json::{Value, json};

/// The NodeInfo well-known link relation.
pub const NODEINFO_REL: &str = "http://nodeinfo.diaspora.software/ns/schema/2.1";

/// NodeInfo well-known response (served at `/.well-known/nodeinfo`).
#[derive(Debug, Clone, Serialize)]
pub struct NodeInfoWellKnown {
    pub links: Vec<NodeInfoWellKnownLink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeInfoWellKnownLink {
    pub rel: String,
    pub href: String,
}

/// Build the well-known discovery document.
pub fn well_known(domain: &str) -> NodeInfoWellKnown {
    NodeInfoWellKnown {
        links: vec![NodeInfoWellKnownLink {
            rel: NODEINFO_REL.to_owned(),
            href: format!("https://{domain}/nodeinfo/2.1"),
        }],
    }
}

/// Parameters for building the full NodeInfo 2.1 document.
pub struct NodeInfoParams {
    pub total_users: u64,
    pub active_month: u64,
    pub active_half_year: u64,
    pub local_posts: u64,
    /// Number of currently active (published, non-expired) job listings.
    pub active_job_listings: u64,
    pub open_registrations: bool,
    /// Instance-level feature flags exposed in the `metadata` object.
    pub features: NodeInfoFeatures,
}

/// Noombat-specific feature flags included in the NodeInfo metadata.
///
/// Each field defaults to `false`; the server binary populates them
/// from configuration at startup.
#[derive(Debug, Clone, Default)]
pub struct NodeInfoFeatures {
    pub chatmail_available: bool,
    pub chatmail_domain: Option<String>,
    pub groups_enabled: bool,
    pub events_enabled: bool,
    pub articles_enabled: bool,
    /// Whether FEP-8b32 integrity proofs (`eddsa-jcs-2022`) are
    /// attached to all outbound activities.
    pub integrity_proofs_enabled: bool,
    /// Whether relay subscriptions are accepted and the verification
    /// policy in effect.
    pub relay_verification_policy: Option<String>,
}

/// Build the full NodeInfo 2.1 document with Noombat-specific metadata.
pub fn build(params: &NodeInfoParams) -> Value {
    let mut metadata = json!({
        "noombat:supportedVocabulary": [
            "noombat:JobListing",
            "noombat:Experience",
            "noombat:Education",
            "noombat:Skill",
            "noombat:Publication",
            "noombat:Application",
            "noombat:EventExtensions"
        ],
        "noombat:jobListingsEnabled": true,
        "noombat:activeJobListings": params.active_job_listings,
        "noombat:chatmailAvailable": params.features.chatmail_available,
        "noombat:groupsEnabled": params.features.groups_enabled,
        "noombat:eventsEnabled": params.features.events_enabled,
        "noombat:articlesEnabled": params.features.articles_enabled,
    });
    if let Some(ref domain) = params.features.chatmail_domain {
        metadata["noombat:chatmailDomain"] = json!(domain);
    }
    if params.features.integrity_proofs_enabled {
        metadata["noombat:integrityProofsEnabled"] = json!(true);
        metadata["noombat:integrityProofsCryptosuite"] = json!("eddsa-jcs-2022");
    }
    if let Some(ref policy) = params.features.relay_verification_policy {
        metadata["noombat:relaySupported"] = json!(true);
        metadata["noombat:relayVerificationPolicy"] = json!(policy);
    }

    json!({
        "version": "2.1",
        "software": {
            "name": "noombat",
            "version": env!("CARGO_PKG_VERSION"),
            "repository": "https://github.com/noombat/noombat"
        },
        "protocols": ["activitypub"],
        "usage": {
            "users": {
                "total": params.total_users,
                "activeMonth": params.active_month,
                "activeHalfyear": params.active_half_year
            },
            "localPosts": params.local_posts
        },
        "openRegistrations": params.open_registrations,
        "metadata": metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_contains_link() {
        let wk = well_known("noombat.social");
        assert_eq!(wk.links.len(), 1);
        assert_eq!(wk.links[0].rel, NODEINFO_REL);
        assert!(wk.links[0].href.contains("noombat.social"));
    }

    #[test]
    fn build_contains_software_name() {
        let params = NodeInfoParams {
            total_users: 10,
            active_month: 5,
            active_half_year: 8,
            local_posts: 42,
            active_job_listings: 7,
            open_registrations: true,
            features: NodeInfoFeatures::default(),
        };
        let doc = build(&params);
        assert_eq!(doc["software"]["name"], "noombat");
        assert_eq!(doc["usage"]["users"]["total"], 10);
        assert_eq!(doc["usage"]["localPosts"], 42);
        assert_eq!(doc["openRegistrations"], true);
        assert_eq!(doc["metadata"]["noombat:activeJobListings"], 7);
    }

    #[test]
    fn build_reflects_feature_flags() {
        let params = NodeInfoParams {
            total_users: 1,
            active_month: 1,
            active_half_year: 1,
            local_posts: 0,
            active_job_listings: 0,
            open_registrations: false,
            features: NodeInfoFeatures {
                chatmail_available: true,
                chatmail_domain: Some("chat.example.org".to_owned()),
                groups_enabled: true,
                events_enabled: false,
                articles_enabled: true,
                integrity_proofs_enabled: false,
                relay_verification_policy: None,
            },
        };
        let doc = build(&params);
        assert_eq!(doc["metadata"]["noombat:chatmailAvailable"], true);
        assert_eq!(
            doc["metadata"]["noombat:chatmailDomain"],
            "chat.example.org"
        );
        assert_eq!(doc["metadata"]["noombat:groupsEnabled"], true);
        assert_eq!(doc["metadata"]["noombat:eventsEnabled"], false);
        assert_eq!(doc["metadata"]["noombat:articlesEnabled"], true);
    }
}
