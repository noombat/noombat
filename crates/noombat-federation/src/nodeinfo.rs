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
        // `jobListingsEnabled` is a capability: it tells a peer this
        // software supports job listings, which is what discovery needs.
        //
        // A count such as `noombat:activeJobListings` is not a
        // capability, and must not join it. This endpoint is
        // unauthenticated and polled on a schedule by Fediverse
        // observatories, so publishing one makes a machine-readable
        // hiring-volume time series out of an instance, and on a
        // single-company instance the inference is direct. NodeInfo 2.1
        // treats `metadata` as free-form and tells clients not to rely on
        // specific keys, so nothing federates worse for its absence.
        "noombat:jobListingsEnabled": true,
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
            open_registrations: true,
            features: NodeInfoFeatures::default(),
        };
        let doc = build(&params);
        assert_eq!(doc["software"]["name"], "noombat");
        assert_eq!(doc["usage"]["users"]["total"], 10);
        assert_eq!(doc["usage"]["localPosts"], 42);
        assert_eq!(doc["openRegistrations"], true);
        // The capability is published; the count deliberately is not.
        assert_eq!(doc["metadata"]["noombat:jobListingsEnabled"], true);
        assert!(
            doc["metadata"].get("noombat:activeJobListings").is_none(),
            "the active job listing count is a business metric and must not be \
             published on an unauthenticated, observatory-polled endpoint"
        );
    }

    /// Every key `build` can emit, as a flat path list.
    ///
    /// A golden list whose point is the failure it causes: adding a key
    /// to `build` without adding it here fails the test below, and the
    /// fix is to add it in both places, here and in the NodeInfo section
    /// of the federation documentation, so an operator can still learn
    /// what their instance discloses by reading it.
    ///
    /// Hard-coded rather than parsed out of that document, which would
    /// couple this crate to the repository layout above it and require
    /// the document to be present for the workspace to build.
    const EMITTED_PATHS: &[&str] = &[
        "version",
        "software.name",
        "software.version",
        "software.repository",
        "protocols",
        "usage.users.total",
        "usage.users.activeMonth",
        "usage.users.activeHalfyear",
        "usage.localPosts",
        "openRegistrations",
        "metadata.noombat:supportedVocabulary",
        "metadata.noombat:jobListingsEnabled",
        "metadata.noombat:chatmailAvailable",
        "metadata.noombat:groupsEnabled",
        "metadata.noombat:eventsEnabled",
        "metadata.noombat:articlesEnabled",
        // Conditional: emitted only when the feature is configured.
        "metadata.noombat:chatmailDomain",
        "metadata.noombat:integrityProofsEnabled",
        "metadata.noombat:integrityProofsCryptosuite",
        "metadata.noombat:relaySupported",
        "metadata.noombat:relayVerificationPolicy",
    ];

    /// Flatten a JSON object into dotted paths, stopping at non-objects.
    fn paths(value: &Value, prefix: &str, out: &mut Vec<String>) {
        match value.as_object() {
            Some(map) => {
                for (key, child) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    paths(child, &path, out);
                }
            }
            None => out.push(prefix.to_owned()),
        }
    }

    fn emitted_paths(params: &NodeInfoParams) -> Vec<String> {
        let mut out = Vec::new();
        paths(&build(params), "", &mut out);
        out.sort();
        out
    }

    #[test]
    fn every_emitted_key_is_accounted_for() {
        // Every conditional field turned on, so the document is at its
        // widest and the golden list is exercised in full.
        let params = NodeInfoParams {
            total_users: 1,
            active_month: 1,
            active_half_year: 1,
            local_posts: 1,
            open_registrations: true,
            features: NodeInfoFeatures {
                chatmail_available: true,
                chatmail_domain: Some("chat.example.org".to_owned()),
                groups_enabled: true,
                events_enabled: true,
                articles_enabled: true,
                integrity_proofs_enabled: true,
                relay_verification_policy: Some("allowlist".to_owned()),
            },
        };

        let mut expected: Vec<String> = EMITTED_PATHS.iter().map(|p| (*p).to_owned()).collect();
        expected.sort();

        assert_eq!(
            emitted_paths(&params),
            expected,
            "the NodeInfo document changed shape. Update EMITTED_PATHS above and the \
             NodeInfo section of the federation documentation in the same change, so an \
             operator can still learn what their instance discloses by reading it"
        );
    }

    #[test]
    fn a_default_instance_emits_no_conditional_keys() {
        // Absence is the contract for the conditional keys: they are
        // never emitted as `false`, so a peer must test for presence.
        let params = NodeInfoParams {
            total_users: 0,
            active_month: 0,
            active_half_year: 0,
            local_posts: 0,
            open_registrations: false,
            features: NodeInfoFeatures::default(),
        };

        let emitted = emitted_paths(&params);
        for conditional in [
            "metadata.noombat:chatmailDomain",
            "metadata.noombat:integrityProofsEnabled",
            "metadata.noombat:integrityProofsCryptosuite",
            "metadata.noombat:relaySupported",
            "metadata.noombat:relayVerificationPolicy",
        ] {
            assert!(
                !emitted.contains(&conditional.to_owned()),
                "{conditional} must be absent on a default instance, not present and false"
            );
        }
    }

    #[test]
    fn build_reflects_feature_flags() {
        let params = NodeInfoParams {
            total_users: 1,
            active_month: 1,
            active_half_year: 1,
            local_posts: 0,
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
