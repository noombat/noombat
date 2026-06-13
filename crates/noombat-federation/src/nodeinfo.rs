// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! NodeInfo 2.1 response builder.

use serde::Serialize;
use serde_json::{json, Value};

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
}

/// Build the full NodeInfo 2.1 document with Noombat-specific metadata.
pub fn build(params: &NodeInfoParams) -> Value {
    json!({
        "version": "2.1",
        "software": {
            "name": "noombat",
            "version": env!("CARGO_PKG_VERSION"),
            "repository": "https://codeberg.org/noombat/noombat"
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
        "metadata": {
            "noombat:supportedVocabulary": [
                "noombat:JobListing",
                "noombat:Experience",
                "noombat:Education",
                "noombat:Skill",
                "noombat:Publication",
                "noombat:Application"
            ],
            "noombat:jobListingsEnabled": true,
            "noombat:chatmailAvailable": false,
            "noombat:groupsEnabled": false,
            "noombat:eventsEnabled": false,
            "noombat:articlesEnabled": false
        }
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
        };
        let doc = build(&params);
        assert_eq!(doc["software"]["name"], "noombat");
        assert_eq!(doc["usage"]["users"]["total"], 10);
        assert_eq!(doc["usage"]["localPosts"], 42);
        assert_eq!(doc["openRegistrations"], true);
    }
}
