// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! NodeInfo 2.1 response builder, and the reader for a remote instance's
//! chat domain.

use noombat_core::error::{NoombatError, Result};
use reqwest::Url;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgPool;
use tracing::warn;

use crate::http;

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
    /// Whether relay subscriptions are accepted, and the instance-wide
    /// default verification policy. Typed rather than a string so that a
    /// value this instance cannot enforce cannot be published: the only
    /// way to fill this in is to parse the operator's configuration.
    pub relay_verification_policy: Option<crate::relay_verify::RelayVerificationPolicy>,
}

/// The FEPs this instance implements, published under
/// `metadata.activitypub.extensions`.
///
/// A list of names and nothing else. A peer must not read a capability
/// out of it and change behaviour: the endpoint is unauthenticated, so
/// anything derived from it is derived from a claim the claimant
/// controls. This instance reads no peer's NodeInfo for the same reason.
///
/// Adding an entry here is a statement that the mechanism is wired, not
/// that a type for it exists. Two of these were added by the phases that
/// wired them: FEP-8b32 proofs are checked on every inbound activity,
/// and c180 is what `MoveRejected` gives its own error code.
/// - `FEP-8b32`: integrity proofs (eddsa-jcs-2022), verified on
///   ingestion and on relayed activities.
/// - `FEP-c180`: typed error bodies on the inbox.
/// - `FEP-fb2a`: actor metadata as `attachment` PropertyValue entries.
const AP_EXTENSIONS: &[&str] = &["FEP-8b32", "FEP-c180", "FEP-fb2a"];

/// Build the full NodeInfo 2.1 document with Noombat-specific metadata.
pub fn build(params: &NodeInfoParams) -> Value {
    let mut metadata = json!({
        "noombat:supportedVocabulary": [
            "noombat:JobPosting",
            "noombat:WorkExperience",
            "noombat:EducationEntry",
            "noombat:Skill",
            "noombat:ScholarlyArticle",
            "noombat:JobApplication",
            "noombat:eventExtensions"
        ],
        // `jobPostingsEnabled` is a capability: it tells a peer this
        // software supports job postings, which is what discovery needs.
        //
        // A count such as `noombat:activeJobPostings` is not a
        // capability, and must not join it. This endpoint is
        // unauthenticated and polled on a schedule by Fediverse
        // observatories, so publishing one makes a machine-readable
        // hiring-volume time series out of an instance, and on a
        // single-company instance the inference is direct. NodeInfo 2.1
        // treats `metadata` as free-form and tells clients not to rely on
        // specific keys, so nothing federates worse for its absence.
        "noombat:jobPostingsEnabled": true,
        "noombat:chatmailAvailable": params.features.chatmail_available,
        "noombat:groupsEnabled": params.features.groups_enabled,
        "noombat:eventsEnabled": params.features.events_enabled,
        "noombat:articlesEnabled": params.features.articles_enabled,
        // The interoperable half of the same disclosure. A peer looking
        // for "does this instance sign its objects" should not have to
        // learn a `noombat:` key to find out, and `supportedVocabulary`
        // answers a different question: which object types exist here,
        // not which mechanisms are implemented.
        //
        // Names, not capabilities inferred from them. Nothing on this
        // instance reads a peer's NodeInfo to decide anything, and this
        // array is published on the same terms: informational, and not
        // a negotiation.
        "activitypub": {
            "extensions": AP_EXTENSIONS,
        },
    });
    if let Some(ref domain) = params.features.chatmail_domain {
        metadata["noombat:chatmailDomain"] = json!(domain);
    }
    if params.features.integrity_proofs_enabled {
        metadata["noombat:integrityProofsEnabled"] = json!(true);
        metadata["noombat:integrityProofsCryptosuite"] = json!("eddsa-jcs-2022");
    }
    if let Some(policy) = params.features.relay_verification_policy {
        metadata["noombat:relaySupported"] = json!(true);
        // `Display`, not `Serialize`. The derived Serialize emits the
        // variant names ("VerifyOrFetch"), which are neither the three
        // documented policy names nor what the CHECK constraint on
        // `relay_subscriptions.verification_policy` accepts.
        metadata["noombat:relayVerificationPolicy"] = json!(policy.to_string());
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

// ..... A remote instance's chat domain .....

/// The NodeInfo 2.x document a well-known response links to, when it is on
/// the same host and port as `origin`. A link elsewhere is not followed,
/// though the origin may still redirect the fetch.
pub fn linked_document(well_known: &Value, origin: &Url) -> Option<Url> {
    well_known["links"]
        .as_array()?
        .iter()
        .filter(|link| {
            link["rel"].as_str().is_some_and(|rel| {
                rel.starts_with("http://nodeinfo.diaspora.software/ns/schema/2.")
            })
        })
        .filter_map(|link| Url::parse(link["href"].as_str()?).ok())
        .find(|url| {
            url.host_str() == origin.host_str()
                && url.port_or_known_default() == origin.port_or_known_default()
        })
}

/// The chat domain a NodeInfo document publishes, in lower case.
pub fn published_chatmail_domain(document: &Value) -> Option<String> {
    let domain = document["metadata"]["noombat:chatmailDomain"]
        .as_str()?
        .trim();
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

/// The chat domain the instance at `origin` publishes, read from its
/// NodeInfo: `None` when it publishes none.
pub async fn fetch_chatmail_domain(
    client: &reqwest::Client,
    origin: &Url,
) -> Result<Option<String>> {
    let well_known_url = origin
        .join("/.well-known/nodeinfo")
        .map_err(|e| NoombatError::BadRequest(format!("no NodeInfo URL for {origin}: {e}")))?;
    let response = http::guarded_get(client, well_known_url.as_str()).await?;
    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "NodeInfo links answered HTTP {}",
            response.status()
        )));
    }
    let well_known: Value = http::json_within_limit(response, "NodeInfo links").await?;
    let Some(url) = linked_document(&well_known, origin) else {
        return Ok(None);
    };
    let response = http::guarded_get(client, url.as_str()).await?;
    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "NodeInfo answered HTTP {}",
            response.status()
        )));
    }
    let document: Value = http::json_within_limit(response, "NodeInfo").await?;
    Ok(published_chatmail_domain(&document))
}

/// The chat domain the instance serving `actor_uri` publishes, `None` when
/// it publishes none, through a cache kept for a day. A failed read falls
/// back to an expired entry, and is an error when there is none: not
/// knowing is not the same as the instance publishing none.
pub async fn remote_chatmail_domain(
    pool: &PgPool,
    client: &reqwest::Client,
    actor_uri: &str,
) -> Result<Option<String>> {
    let origin = Url::parse(actor_uri)
        .map_err(|e| NoombatError::BadRequest(format!("not an actor URL: {e}")))?;
    let domain = crate::inbox::extract_domain(actor_uri)
        .ok_or_else(|| NoombatError::BadRequest("an actor URL with no domain".into()))?;
    let cached: Option<(Option<String>, bool)> = sqlx::query_as(
        "SELECT chatmail_domain, fetched_at > now() - interval '1 day' \
         FROM remote_chatmail_domains WHERE domain = $1",
    )
    .bind(&domain)
    .fetch_optional(pool)
    .await
    .unwrap_or_else(|error| {
        warn!(%domain, %error, "the chat domain cache could not be read");
        None
    });
    if let Some((chatmail_domain, true)) = cached {
        return Ok(chatmail_domain);
    }

    match fetch_chatmail_domain(client, &origin).await {
        Ok(chatmail_domain) => {
            if let Err(error) = sqlx::query(
                "INSERT INTO remote_chatmail_domains (domain, chatmail_domain) VALUES ($1, $2) \
                 ON CONFLICT (domain) DO UPDATE \
                 SET chatmail_domain = EXCLUDED.chatmail_domain, fetched_at = now()",
            )
            .bind(&domain)
            .bind(&chatmail_domain)
            .execute(pool)
            .await
            {
                warn!(%domain, %error, "the chat domain could not be cached");
            }
            Ok(chatmail_domain)
        }
        Err(error) => {
            warn!(%domain, %error, "the chat domain could not be read from NodeInfo");
            cached
                .map(|(chatmail_domain, _)| chatmail_domain)
                .ok_or(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_nodeinfo_2_document_on_the_same_host_and_port_is_linked() {
        let origin = Url::parse("https://other.example/users/bob").expect("url");
        let links = |rel: &str, href: &str| json!({ "links": [{ "rel": rel, "href": href }] });
        let rel_21 = "http://nodeinfo.diaspora.software/ns/schema/2.1";
        let rel_20 = "http://nodeinfo.diaspora.software/ns/schema/2.0";
        for (rel, href, expected) in [
            (rel_21, "https://other.example/nodeinfo/2.1", true),
            (rel_20, "https://other.example/nodeinfo/2.0", true),
            (rel_21, "https://other.example:443/nodeinfo/2.1", true),
            (
                "http://nodeinfo.diaspora.software/ns/schema/1.0",
                "https://other.example/1.0",
                false,
            ),
            (rel_21, "https://elsewhere.example/nodeinfo/2.1", false),
            (rel_21, "https://other.example:8443/nodeinfo/2.1", false),
            (rel_21, "https://sub.other.example/nodeinfo/2.1", false),
        ] {
            let linked = linked_document(&links(rel, href), &origin);
            assert_eq!(linked.is_some(), expected, "{rel} {href}");
        }
        let two = json!({ "links": [
            { "rel": rel_21, "href": "https://elsewhere.example/nodeinfo/2.1" },
            { "rel": rel_21, "href": "https://other.example/nodeinfo/2.1" },
        ] });
        let linked = linked_document(&two, &origin).expect("the second link");
        assert_eq!(linked.as_str(), "https://other.example/nodeinfo/2.1");
    }

    #[test]
    fn the_published_chat_domain_is_read_in_lower_case() {
        let document = |value: Value| json!({ "metadata": { "noombat:chatmailDomain": value } });
        assert_eq!(
            published_chatmail_domain(&document(json!(" Chat.Other.Example "))).as_deref(),
            Some("chat.other.example")
        );
        assert_eq!(published_chatmail_domain(&document(json!(""))), None);
        assert_eq!(published_chatmail_domain(&document(json!(7))), None);
        assert_eq!(published_chatmail_domain(&json!({ "metadata": {} })), None);
    }

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
        assert_eq!(doc["metadata"]["noombat:jobPostingsEnabled"], true);
        assert!(
            doc["metadata"].get("noombat:activeJobPostings").is_none(),
            "the active job posting count is a business metric and must not be \
             published on an unauthenticated, observatory-polled endpoint"
        );
    }

    #[test]
    fn the_implemented_feps_are_published_under_activitypub() {
        let params = NodeInfoParams {
            total_users: 0,
            active_month: 0,
            active_half_year: 0,
            local_posts: 0,
            open_registrations: false,
            features: NodeInfoFeatures::default(),
        };
        let doc = build(&params);

        let extensions = doc["metadata"]["activitypub"]["extensions"]
            .as_array()
            .expect("the extensions array is published");

        // Unconditional, unlike the `noombat:` feature keys: these
        // describe mechanisms this build implements, not what an
        // operator switched on.
        assert!(extensions.iter().any(|v| v == "FEP-8b32"));
        assert!(extensions.iter().any(|v| v == "FEP-c180"));

        // Names only. Anything structured here invites a peer to derive
        // a capability from an unauthenticated claim.
        for entry in extensions {
            assert!(entry.is_string(), "not a bare name: {entry}");
        }
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
        "metadata.noombat:jobPostingsEnabled",
        "metadata.noombat:chatmailAvailable",
        "metadata.noombat:groupsEnabled",
        "metadata.noombat:eventsEnabled",
        "metadata.noombat:articlesEnabled",
        "metadata.activitypub.extensions",
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
                relay_verification_policy: Some(
                    crate::relay_verify::RelayVerificationPolicy::TrustRelay,
                ),
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
    fn the_published_relay_policy_is_one_the_instance_can_enforce() {
        // The golden list above records key paths and discards values, so
        // nothing there can see a policy string that is not a policy. Every
        // variant must serialise to a name `from_str_opt` accepts, which is
        // also what the CHECK constraint on
        // `relay_subscriptions.verification_policy` allows.
        use crate::relay_verify::RelayVerificationPolicy as P;
        for policy in [P::Verify, P::VerifyOrFetch, P::TrustRelay] {
            let params = NodeInfoParams {
                total_users: 0,
                active_month: 0,
                active_half_year: 0,
                local_posts: 0,
                open_registrations: false,
                features: NodeInfoFeatures {
                    relay_verification_policy: Some(policy),
                    ..Default::default()
                },
            };
            let doc = build(&params);
            let published = doc["metadata"]["noombat:relayVerificationPolicy"]
                .as_str()
                .expect("the policy is published as a JSON string");
            assert_eq!(
                P::from_str_opt(published),
                Some(policy),
                "published {published:?}, which this instance cannot parse back to a policy"
            );
        }
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
