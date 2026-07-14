// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Downgrade serialisation for `noombat:*` vocabulary extensions.
//!
//! When delivering activities to non-Noombat instances, custom object
//! types (e.g. `noombat:JobListing`, `noombat:Publication`) must degrade
//! gracefully to standard ActivityStreams types (`Note`, `Article`) so
//! that Mastodon, Lemmy, GotoSocial, and other Fediverse software can
//! render them. The dual-typing approach follows the pattern established
//! by Lemmy (`Page`) and PeerTube (`Video`).
//!
//! Profile data downgrade additionally respects the `federate_profile`
//! privacy setting and per-section visibility.

use noombat_ap::context::default_context;
use noombat_ap::vocab;
use noombat_core::actor::Actor;
use noombat_core::privacy::SectionVisibility;
use serde_json::{Value, json};

/// Default profile data TTL in seconds (7 days).
pub const DEFAULT_TTL_SECS: u64 = 604_800;

/// Escape HTML-significant characters in untrusted text before
/// interpolation into an HTML `content` string.
fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ..... Object downgrade .....

/// Produce a federated `Create` activity whose `object` is dual-typed:
/// the original `noombat:*` type is preserved alongside a standard
/// `Note` fallback.
///
/// Noombat instances parse the `noombat:*` type and its extension
/// properties; non-Noombat instances see a valid `Note` with a
/// human-readable summary in the `content` field.
pub fn downgrade_job_listing(listing: &Value, actor_ap_id: &str) -> Value {
    let title = listing
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Job Listing");
    let description_html = listing
        .get("description_html")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let location = listing
        .get("location")
        .and_then(|v| v.as_str())
        .unwrap_or("Not specified");
    let remote = listing
        .get("remote")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ap_id = listing.get("ap_id").and_then(|v| v.as_str()).unwrap_or("");

    let location_label = if remote {
        format!("{location} (Remote)")
    } else {
        location.to_owned()
    };

    let title_escaped = escape_html(title);
    let location_escaped = escape_html(&location_label);

    // Build the dual-typed (Note + noombat:JobListing) object.
    let mut object = json!({
        "type": ["Note", vocab::JOB_LISTING],
        "id": ap_id,
        "attributedTo": actor_ap_id,
        "name": title,
        "content": format!(
            "<p><b>{title_escaped}</b> — {location_escaped}</p>{description_html}",
        ),
        "url": ap_id,
    });

    // Attach noombat:* extension properties.
    if let Some(salary_min) = listing.get("salary_min")
        && let Some(salary_max) = listing.get("salary_max")
    {
        let currency = listing
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("USD");
        object["noombat:salaryRange"] = json!({
            "min": salary_min,
            "max": salary_max,
            "currency": currency,
        });
    }
    if let Some(requirements) = listing.get("requirements") {
        object["noombat:requirements"] = requirements.clone();
    }

    // Provide the Mastodon-convention `source` for Markdown-aware clients.
    if let Some(md) = listing.get("description_md").and_then(|v| v.as_str()) {
        object["source"] = json!({
            "content": md,
            "mediaType": "text/markdown",
        });
    }

    object
}

/// Produce a federated representation of a `noombat:Publication` that
/// degrades to a `Note` containing a formatted citation with a
/// clickable DOI link.
pub fn downgrade_publication(publication: &Value, actor_ap_id: &str) -> Value {
    let doi = publication
        .get("doi")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let title = publication
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled");
    let authors = publication
        .get("authors")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let journal = publication
        .get("journal")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let doi_url = format!("https://doi.org/{doi}");
    let doi_escaped = escape_html(doi);
    let doi_url_escaped = escape_html(&doi_url);

    let authors_escaped = escape_html(&authors);
    let title_escaped = escape_html(title);
    let journal_escaped = escape_html(journal);

    let content = format!(
        "<p>{authors_escaped}. <i>{title_escaped}</i>. {journal_escaped}. \
         DOI: <a href=\"{doi_url_escaped}\">{doi_escaped}</a></p>"
    );

    json!({
        "type": ["Note", vocab::PUBLICATION],
        "attributedTo": actor_ap_id,
        "content": content,
        "url": doi_url,
        "noombat:doi": doi,
        "noombat:doiMetadata": publication.get("doi_metadata").cloned().unwrap_or(json!(null)),
    })
}

// ..... Profile downgrade (respecting privacy) .....

/// A profile section with its visibility, used for filtered federation.
pub struct FederatedSection {
    pub section_type: &'static str,
    pub visibility: SectionVisibility,
    pub data: Value,
}

/// Build the federated AP actor object for a local actor, respecting
/// the `federate_profile` and per-section visibility settings.
///
/// When `federate_profile` is `false`, only the minimal actor fields
/// (name, summary, avatar) are included. When `true`, only sections
/// whose visibility is [`SectionVisibility::Public`] are included in
/// unsolicited deliveries.
///
/// The returned object includes the `noombat:ttl` hint.
pub fn build_federated_actor(
    actor: &Actor,
    domain: &str,
    sections: &[FederatedSection],
    aliases: &[String],
    ttl_secs: Option<u64>,
) -> Value {
    let profile_url = format!("https://{domain}/@{}", actor.username);
    let ap_type = match actor.actor_type {
        noombat_core::actor::ActorType::Individual => "Person",
        noombat_core::actor::ActorType::Company => "Organization",
        noombat_core::actor::ActorType::Group => "Group",
    };

    let mut obj = json!({
        "@context": default_context(),
        "id": actor.ap_id,
        "type": ap_type,
        "preferredUsername": actor.username,
        "name": actor.display_name,
        "summary": actor.summary_html,
        "url": profile_url,
        "inbox": format!("{}/inbox", actor.ap_id),
        "outbox": format!("{}/outbox", actor.ap_id),
        "followers": format!("{}/followers", actor.ap_id),
        "following": format!("{}/following", actor.ap_id),
        "endpoints": {
            "sharedInbox": format!("https://{domain}/inbox"),
        },
        "publicKey": {
            "id": format!("{}#main-key", actor.ap_id),
            "owner": actor.ap_id,
            "publicKeyPem": actor.public_key_pem,
        },
        "noombat:ttl": ttl_secs.unwrap_or(DEFAULT_TTL_SECS),
    });

    // Include movedTo if the actor has migrated.
    if let Some(ref target) = actor.moved_to {
        obj["movedTo"] = json!(target);
    }

    // Include alsoKnownAs if the actor has declared aliases.
    if !aliases.is_empty() {
        obj["alsoKnownAs"] = json!(aliases);
    }

    // Include icon (avatar) if present.
    if let Some(ref url) = actor.avatar_url {
        obj["icon"] = json!({
            "type": "Image",
            "url": url,
        });
    }

    // Include image (header) if present.
    if let Some(ref url) = actor.header_url {
        obj["image"] = json!({
            "type": "Image",
            "url": url,
        });
    }

    // Attachment array (verified links, ORCID, chatmail).
    let mut attachments: Vec<Value> = Vec::new();

    if let Some(ref orcid) = actor.orcid {
        attachments.push(json!({
            "type": "PropertyValue",
            "name": "ORCID",
            "value": format!("<a href=\"https://orcid.org/{orcid}\" rel=\"me\">{orcid}</a>"),
        }));
    }

    if actor.actor_privacy.chatmail_visible
        && let Some(ref addr) = actor.chatmail_addr
    {
        attachments.push(json!({
            "type": "PropertyValue",
            "name": "Chat",
            "value": addr,
        }));
    }

    if !attachments.is_empty() {
        obj["attachment"] = json!(attachments);
    }

    // If the user has disabled profile federation, stop here,
    // i.e. remote instances see only the minimal actor object.
    if !actor.actor_privacy.federate_profile {
        return obj;
    }

    // Include public sections as noombat:* extension properties.
    let public_sections: Vec<&FederatedSection> = sections
        .iter()
        .filter(|s| s.visibility == SectionVisibility::Public)
        .collect();

    if !public_sections.is_empty() {
        let mut section_map: serde_json::Map<String, Value> = serde_json::Map::new();
        for section in public_sections {
            let key = format!("noombat:{}", section.section_type);
            // If multiple sections of the same type exist, collect
            // them into an array.
            let entry = section_map.entry(key).or_insert_with(|| json!([]));
            if let Some(arr) = entry.as_array_mut() {
                arr.push(section.data.clone());
            }
        }
        for (key, value) in section_map {
            obj[key] = value;
        }
    }

    obj
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_listing_dual_typed() {
        let listing = json!({
            "ap_id": "https://acme.example/jobs/1",
            "title": "Rust Engineer",
            "description_html": "<p>Build things.</p>",
            "description_md": "Build things.",
            "location": "Berlin",
            "remote": true,
            "salary_min": 80_000,
            "salary_max": 120_000,
            "currency": "EUR",
            "requirements": ["Rust", "PostgreSQL"],
        });

        let object = downgrade_job_listing(&listing, "https://acme.example/actor");
        let types = object["type"].as_array().unwrap();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], "Note");
        assert_eq!(types[1], vocab::JOB_LISTING);
        assert!(
            object["content"]
                .as_str()
                .unwrap()
                .contains("Rust Engineer")
        );
        assert_eq!(object["noombat:salaryRange"]["currency"], "EUR");
        assert!(
            object["source"]["mediaType"]
                .as_str()
                .unwrap()
                .contains("markdown")
        );
    }

    #[test]
    fn publication_dual_typed() {
        let pub_data = json!({
            "doi": "10.1000/xyz123",
            "title": "Federated Networks",
            "authors": ["Alice", "Bob"],
            "journal": "Journal of Networks",
            "doi_metadata": { "source": "crossref" },
        });

        let object = downgrade_publication(&pub_data, "https://example.org/users/alice");
        let types = object["type"].as_array().unwrap();
        assert_eq!(types[1], vocab::PUBLICATION);
        assert_eq!(object["noombat:doi"], "10.1000/xyz123");
        assert!(object["content"].as_str().unwrap().contains("doi.org"));
    }

    #[test]
    fn federated_actor_omits_sections_when_federate_profile_disabled() {
        let mut actor = test_actor();
        actor.actor_privacy.federate_profile = false;

        let sections = vec![FederatedSection {
            section_type: "experience",
            visibility: SectionVisibility::Public,
            data: json!({"title": "Engineer"}),
        }];

        let obj = build_federated_actor(&actor, "noombat.social", &sections, &[], None);
        assert!(obj.get("noombat:experience").is_none());
        assert!(obj.get("noombat:ttl").is_some());
    }

    #[test]
    fn federated_actor_excludes_non_public_sections() {
        let actor = test_actor();
        let sections = vec![
            FederatedSection {
                section_type: "experience",
                visibility: SectionVisibility::Public,
                data: json!({"title": "Public role"}),
            },
            FederatedSection {
                section_type: "education",
                visibility: SectionVisibility::Private,
                data: json!({"institution": "Secret Uni"}),
            },
            FederatedSection {
                section_type: "experience",
                visibility: SectionVisibility::Followers,
                data: json!({"title": "Followers-only role"}),
            },
        ];

        let obj = build_federated_actor(&actor, "noombat.social", &sections, &[], None);

        // Only the public experience section should be present.
        let exp = obj["noombat:experience"].as_array().unwrap();
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0]["title"], "Public role");

        // Private education must be absent.
        assert!(obj.get("noombat:education").is_none());
    }

    #[test]
    fn federated_actor_includes_ttl() {
        let actor = test_actor();
        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], Some(3600));
        assert_eq!(obj["noombat:ttl"], 3600);
    }

    #[test]
    fn federated_actor_includes_moved_to() {
        let mut actor = test_actor();
        actor.moved_to = Some("https://new.example/users/alice".into());
        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], None);
        assert_eq!(obj["movedTo"], "https://new.example/users/alice");
    }

    #[test]
    fn federated_actor_includes_also_known_as() {
        let actor = test_actor();
        let aliases = vec!["https://old.example/users/alice".to_owned()];
        let obj = build_federated_actor(&actor, "noombat.social", &[], &aliases, None);
        let aka = obj["alsoKnownAs"].as_array().unwrap();
        assert_eq!(aka.len(), 1);
        assert_eq!(aka[0], "https://old.example/users/alice");
    }

    /// Construct a minimal [`Actor`] for unit tests.
    fn test_actor() -> Actor {
        use noombat_core::actor::ActorType;
        use noombat_core::privacy::ActorPrivacy;

        Actor {
            id: uuid::Uuid::new_v4(),
            actor_type: ActorType::Individual,
            ap_id: "https://noombat.social/users/alice".into(),
            username: "alice".into(),
            display_name: Some("Alice".into()),
            headline: None,
            avatar_url: None,
            header_url: None,
            summary_md: None,
            summary_html: Some("<p>Hello</p>".into()),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".into(),
            private_key_pem: None,
            domain: "noombat.social".into(),
            is_local: true,
            inbox_url: None,
            instance_role: "user".into(),
            actor_status: "active".into(),
            chatmail_addr: None,
            orcid: None,
            moved_to: None,
            actor_privacy: ActorPrivacy::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}
