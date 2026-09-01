// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Downgrade serialisation for `noombat:*` vocabulary extensions.
//!
//! When delivering activities to non-Noombat instances, custom object
//! types (e.g. `noombat:JobPosting`, `noombat:ScholarlyArticle`) must degrade
//! gracefully to standard ActivityStreams types (`Note`, `Article`) so
//! that Mastodon, Lemmy, GotoSocial, and other Fediverse software can
//! render them. The dual-typing approach follows the pattern established
//! by Lemmy (`Page`) and PeerTube (`Video`).
//!
//! Profile data downgrade additionally respects the `federate_profile`
//! privacy setting and per-section visibility.

use std::borrow::Cow;

use noombat_ap::context::{actor_context, default_context};
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
pub fn downgrade_job_posting(posting: &Value, actor_ap_id: &str) -> Value {
    let title = posting
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Job Posting");
    let description_html = posting
        .get("description_html")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let location = posting
        .get("location")
        .and_then(|v| v.as_str())
        .unwrap_or("Not specified");
    let remote = posting
        .get("remote")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let ap_id = posting.get("ap_id").and_then(|v| v.as_str()).unwrap_or("");

    let location_label = if remote {
        format!("{location} (Remote)")
    } else {
        location.to_owned()
    };

    let title_escaped = escape_html(title);
    let location_escaped = escape_html(&location_label);

    // Build the dual-typed (Note + noombat:JobPosting) object.
    let mut object = json!({
        "type": ["Note", vocab::JOB_POSTING],
        "id": ap_id,
        "attributedTo": actor_ap_id,
        "name": title,
        "content": format!(
            "<p><b>{title_escaped}</b> - {location_escaped}</p>{description_html}",
        ),
        "url": ap_id,
    });

    // Attach noombat:* extension properties.
    if let Some(salary_min) = posting.get("salary_min")
        && let Some(salary_max) = posting.get("salary_max")
    {
        let currency = posting
            .get("currency")
            .and_then(|v| v.as_str())
            .unwrap_or("USD");
        object["noombat:salaryRange"] = json!({
            "min": salary_min,
            "max": salary_max,
            "currency": currency,
        });
    }
    if let Some(requirements) = posting.get("requirements") {
        object["noombat:requirements"] = requirements.clone();
    }

    // Provide the Mastodon-convention `source` for Markdown-aware clients.
    if let Some(md) = posting.get("description_md").and_then(|v| v.as_str()) {
        object["source"] = json!({
            "content": md,
            "mediaType": "text/markdown",
        });
    }

    object
}

/// Produce a federated representation of a `noombat:ScholarlyArticle` that
/// degrades to a `Note` containing a formatted citation with a
/// clickable DOI link.
pub fn downgrade_scholarly_article(publication: &Value, actor_ap_id: &str) -> Value {
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
        "type": ["Note", vocab::SCHOLARLY_ARTICLE],
        "attributedTo": actor_ap_id,
        "content": content,
        "url": doi_url,
        "noombat:doi": doi,
        "noombat:doiMetadata": publication.get("doi_metadata").cloned().unwrap_or(json!(null)),
    })
}

// ..... Profile downgrade (respecting privacy) .....

/// A profile section with its visibility, used for filtered federation.
///
/// `section_type` uses [`Cow<'static, str>`] so that built-in section
/// types can pass a `&'static str` (zero-cost) while custom section
/// types (whose names are runtime `String` values read from the
/// database) can pass an owned `String` without leaking memory.
pub struct FederatedSection {
    pub section_type: Cow<'static, str>,
    pub visibility: SectionVisibility,
    pub data: Value,
}

/// A domain-verified link to include in the federated actor's
/// `attachment` array as a Mastodon-convention `PropertyValue`.
pub struct VerifiedLinkRef<'a> {
    /// The verified URL (e.g. `https://alice.example.com`).
    pub url: &'a str,
}

/// Build the AP actor document for a local actor, respecting the
/// `federate_profile` and per-section visibility settings.
///
/// This is the only serialiser for a local actor, and must stay so: a
/// peer that fetches the actor and a peer that receives an `Update` have
/// to hold the same document, or which one a given peer holds depends on
/// the order events reached it.
///
/// Identity and key material (`publicKey`, `assertionMethod`, `icon`,
/// `image`, `movedTo`, `alsoKnownAs`, `noombat:ttl`) is emitted for
/// every actor. When `federate_profile` is `false` the document stops
/// there. When `true` it also carries the `attachment` array and the
/// sections whose visibility is [`SectionVisibility::Public`].
pub fn build_federated_actor(
    actor: &Actor,
    domain: &str,
    sections: &[FederatedSection],
    aliases: &[String],
    verified_links: &[VerifiedLinkRef<'_>],
    ttl_secs: Option<u64>,
) -> Value {
    let profile_url = format!("https://{domain}/@{}", actor.username);

    let mut obj = json!({
        "@context": if actor.ed25519_public_key.is_some() {
            actor_context()
        } else {
            default_context()
        },
        "id": actor.ap_id,
        "type": actor.actor_type.ap_type(),
        "preferredUsername": actor.username,
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
    });

    // Omitted when absent, never sent as `null`: a peer can read a null
    // as an instruction to clear what it has cached.
    if let Some(ref display_name) = actor.display_name {
        obj["name"] = json!(display_name);
    }
    if let Some(ref summary) = actor.summary_html {
        obj["summary"] = json!(summary);
    }

    // The Ed25519 key for FEP-8b32 proofs (FEP-521a `assertionMethod`).
    // Key material rather than profile data, so it belongs above the
    // `federate_profile` return: an actor who stops federating a profile
    // must still be verifiable.
    if let Some(ref multibase) = actor.ed25519_public_key {
        obj["assertionMethod"] = json!([{
            "id": format!("{}#ed25519-key", actor.ap_id),
            "type": "Multikey",
            "controller": actor.ap_id,
            "publicKeyMultibase": multibase,
        }]);
    }

    // Profile data TTL hint.
    obj[vocab::TTL] = json!(ttl_secs.unwrap_or(DEFAULT_TTL_SECS));

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

    // Everything below is profile data, so this return must stay above
    // it. Below it sit the ORCID, the Chatmail address and the verified
    // links, and a return placed after them suppresses the sections while
    // pushing the attachments to every peer anyway.
    if !actor.actor_privacy.federate_profile {
        return obj;
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

    // Domain-verified links, following the Mastodon convention.
    for link in verified_links {
        attachments.push(json!({
            "type": "PropertyValue",
            "name": link.url,
            "value": format!(
                "<a href=\"{}\" rel=\"me\">{}</a>",
                escape_html(link.url),
                escape_html(link.url),
            ),
        }));
    }

    if !attachments.is_empty() {
        obj["attachment"] = json!(attachments);
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
    fn job_posting_dual_typed() {
        let posting = json!({
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

        let object = downgrade_job_posting(&posting, "https://acme.example/actor");
        let types = object["type"].as_array().unwrap();
        assert_eq!(types.len(), 2);
        assert_eq!(types[0], "Note");
        assert_eq!(types[1], vocab::JOB_POSTING);
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
    fn scholarly_article_dual_typed() {
        let pub_data = json!({
            "doi": "10.1000/xyz123",
            "title": "Federated Networks",
            "authors": ["Alice", "Bob"],
            "journal": "Journal of Networks",
            "doi_metadata": { "source": "crossref" },
        });

        let object = downgrade_scholarly_article(&pub_data, "https://example.org/users/alice");
        let types = object["type"].as_array().unwrap();
        assert_eq!(types[1], vocab::SCHOLARLY_ARTICLE);
        assert_eq!(object["noombat:doi"], "10.1000/xyz123");
        assert!(object["content"].as_str().unwrap().contains("doi.org"));
    }

    #[test]
    fn federated_actor_omits_sections_when_federate_profile_disabled() {
        let mut actor = test_actor();
        actor.actor_privacy.federate_profile = false;

        let sections = vec![FederatedSection {
            section_type: "experience".into(),
            visibility: SectionVisibility::Public,
            data: json!({"title": "Engineer"}),
        }];

        let obj = build_federated_actor(&actor, "noombat.social", &sections, &[], &[], None);
        assert!(obj.get("noombat:experience").is_none());
        assert!(obj.get(vocab::TTL).is_some());
    }

    #[test]
    fn federated_actor_omits_attachments_when_federate_profile_disabled() {
        // The sections test above passed throughout the period when this
        // did not hold: the attachment array was assigned into the object
        // before the `federate_profile` early return, so turning the
        // setting off suppressed the sections and pushed the ORCID, the
        // Chatmail address and the verified links to every peer anyway.
        let mut actor = test_actor();
        actor.actor_privacy.federate_profile = false;
        actor.orcid = Some("0000-0002-1825-0097".into());
        actor.chatmail_addr = Some("alice@chat.noombat.social".into());
        actor.actor_privacy.chatmail_visible = true;

        let links = vec![VerifiedLinkRef {
            url: "https://example.org/alice",
        }];

        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &links, None);

        let rendered = obj.to_string();
        assert!(
            obj.get("attachment").is_none(),
            "attachment present with federate_profile disabled: {rendered}"
        );
        // Assert on the values, not just the key: a future refactor could
        // rename the key and reintroduce the leak under another name.
        assert!(
            !rendered.contains("0000-0002-1825-0097"),
            "ORCID leaked: {rendered}"
        );
        assert!(
            !rendered.contains("alice@chat.noombat.social"),
            "Chatmail address leaked"
        );
        assert!(
            !rendered.contains("example.org/alice"),
            "verified link leaked"
        );
    }

    #[test]
    fn federated_actor_excludes_non_public_sections() {
        let actor = test_actor();
        let sections = vec![
            FederatedSection {
                section_type: "experience".into(),
                visibility: SectionVisibility::Public,
                data: json!({"title": "Public role"}),
            },
            FederatedSection {
                section_type: "education".into(),
                visibility: SectionVisibility::Private,
                data: json!({"institution": "Secret Uni"}),
            },
            FederatedSection {
                section_type: "experience".into(),
                visibility: SectionVisibility::Followers,
                data: json!({"title": "Followers-only role"}),
            },
        ];

        let obj = build_federated_actor(&actor, "noombat.social", &sections, &[], &[], None);

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
        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &[], Some(3600));
        assert_eq!(obj[vocab::TTL], 3600);
    }

    #[test]
    fn federated_actor_includes_moved_to() {
        let mut actor = test_actor();
        actor.moved_to = Some("https://new.example/users/alice".into());
        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &[], None);
        assert_eq!(obj["movedTo"], "https://new.example/users/alice");
    }

    #[test]
    fn federated_actor_includes_also_known_as() {
        let actor = test_actor();
        let aliases = vec!["https://old.example/users/alice".to_owned()];
        let obj = build_federated_actor(&actor, "noombat.social", &[], &aliases, &[], None);
        let aka = obj["alsoKnownAs"].as_array().unwrap();
        assert_eq!(aka.len(), 1);
        assert_eq!(aka[0], "https://old.example/users/alice");
    }

    #[test]
    fn federated_actor_publishes_the_ed25519_key() {
        let actor = test_actor();
        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &[], None);

        let methods = obj["assertionMethod"].as_array().unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(
            methods[0]["id"],
            "https://noombat.social/users/alice#ed25519-key"
        );
        assert_eq!(methods[0]["type"], "Multikey");
        assert_eq!(
            methods[0]["controller"],
            "https://noombat.social/users/alice"
        );
        assert_eq!(
            methods[0]["publicKeyMultibase"],
            actor.ed25519_public_key.as_deref().unwrap()
        );
    }

    #[test]
    fn federated_actor_publishes_the_key_without_profile_federation() {
        // The push path omitted `assertionMethod` entirely, so a peer
        // that learned this actor from an Update could not verify a
        // FEP-8b32 proof from it. The key is not profile data: turning
        // profile federation off must not withdraw it.
        let mut actor = test_actor();
        actor.actor_privacy.federate_profile = false;

        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &[], None);
        assert!(obj.get("assertionMethod").is_some());
        assert!(obj.get("publicKey").is_some());
    }

    #[test]
    fn federated_actor_context_defines_every_term_it_uses() {
        use noombat_ap::context::MULTIKEY_CONTEXT;
        use std::collections::BTreeSet;

        // Terms a referenced context supplies, grouped by which one.
        // Naming a term here asserts that the named context defines it.
        // Anything neither listed nor declared inline fails, which is the
        // point: the previous version of this test checked one term and so
        // never noticed that `PropertyValue` and `movedTo` were emitted
        // under a context defining neither.
        // Properties.
        const FROM_ACTIVITYSTREAMS: &[&str] = &[
            "id",
            "type",
            "name",
            "summary",
            "url",
            "icon",
            "image",
            "attachment",
            "endpoints",
            "sharedInbox",
            "inbox",
            "outbox",
            "followers",
            "following",
            "preferredUsername",
            "alsoKnownAs",
            // Type names, which appear as the value of `type`.
            "Person",
            "Organization",
            "Group",
            "Application",
            "Service",
            "Image",
            "Collection",
            "OrderedCollection",
        ];
        const FROM_SECURITY_V1: &[&str] = &["publicKey", "publicKeyPem", "owner"];
        const FROM_MULTIKEY_V1: &[&str] = &[
            "assertionMethod",
            "Multikey",
            "publicKeyMultibase",
            "controller",
        ];

        fn used_terms(value: &Value, out: &mut BTreeSet<String>) {
            match value {
                Value::Object(map) => {
                    for (key, child) in map {
                        if key == "@context" {
                            continue;
                        }
                        out.insert(key.clone());
                        if key == "type"
                            && let Value::String(name) = child
                        {
                            out.insert(name.clone());
                        }
                        used_terms(child, out);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        used_terms(item, out);
                    }
                }
                _ => {}
            }
        }

        fn declared_inline(context: &Value) -> BTreeSet<String> {
            let mut out = BTreeSet::new();
            if let Value::Array(entries) = context {
                for entry in entries {
                    if let Value::Object(map) = entry {
                        out.extend(map.keys().cloned());
                    }
                }
            }
            out
        }

        // An actor exercising every conditional branch: a key, a migration
        // pointer, and two attachment sources.
        let mut actor = test_actor();
        actor.orcid = Some("0000-0002-1825-0097".into());
        actor.moved_to = Some("https://elsewhere.example/users/alice".into());
        let links = [VerifiedLinkRef {
            url: "https://alice.example",
        }];
        let doc = build_federated_actor(&actor, "noombat.social", &[], &[], &links, None);

        let mut used = BTreeSet::new();
        used_terms(&doc, &mut used);

        // A fixture that produced none of these would pass vacuously.
        for expected in ["PropertyValue", "movedTo", "Multikey"] {
            assert!(
                used.contains(expected),
                "fixture never emitted {expected}, so this test would prove nothing"
            );
        }

        let declared = declared_inline(&doc["@context"]);
        for term in &used {
            if term.starts_with('@') || term.contains(':') {
                continue;
            }
            let known = declared.contains(term)
                || FROM_ACTIVITYSTREAMS.contains(&term.as_str())
                || FROM_SECURITY_V1.contains(&term.as_str())
                || FROM_MULTIKEY_V1.contains(&term.as_str());
            assert!(
                known,
                "`{term}` is emitted under an @context that does not define it; \
                 declare it or record which referenced context supplies it"
            );
        }

        // The Multikey context is present only when there is a key to
        // describe, which the original test asserted and is still true.
        let declared_urls: Vec<&str> = doc["@context"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.as_str())
            .collect();
        assert!(declared_urls.contains(&MULTIKEY_CONTEXT));

        let mut keyless = test_actor();
        keyless.ed25519_public_key = None;
        let without_key = build_federated_actor(&keyless, "noombat.social", &[], &[], &[], None);
        let declared_urls: Vec<&str> = without_key["@context"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.as_str())
            .collect();
        assert!(!declared_urls.contains(&MULTIKEY_CONTEXT));
    }

    #[test]
    fn federated_actor_omits_absent_members_rather_than_nulling_them() {
        let mut actor = test_actor();
        actor.display_name = None;
        actor.summary_html = None;

        let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &[], None);
        assert!(obj.get("name").is_none(), "name sent as {}", obj["name"]);
        assert!(obj.get("summary").is_none());

        let present = build_federated_actor(&test_actor(), "noombat.social", &[], &[], &[], None);
        assert_eq!(present["name"], "Alice");
        assert_eq!(present["summary"], "<p>Hello</p>");
    }

    #[test]
    fn federated_actor_type_follows_the_actor_type() {
        use noombat_core::actor::ActorType;

        for (actor_type, expected) in [
            (ActorType::Individual, "Person"),
            (ActorType::Organization, "Organization"),
            (ActorType::Group, "Group"),
        ] {
            let mut actor = test_actor();
            actor.actor_type = actor_type;
            let obj = build_federated_actor(&actor, "noombat.social", &[], &[], &[], None);
            assert_eq!(obj["type"], expected);
        }
    }

    /// Construct a minimal [`Actor`] for unit tests.
    fn test_actor() -> Actor {
        use noombat_core::actor::{ActorStatus, ActorType, InstanceRole};
        use noombat_core::privacy::ActorPrivacy;

        Actor {
            id: uuid::Uuid::new_v4(),
            actor_type: ActorType::Individual,
            ap_id: "https://noombat.social/users/alice".into(),
            username: "alice".into(),
            display_name: Some("Alice".into()),
            headline: None,
            location: None,
            avatar_url: None,
            header_url: None,
            summary_md: None,
            summary_html: Some("<p>Hello</p>".into()),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".into(),
            public_key_id: None,
            private_key_pem: None,
            ed25519_public_key: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into()),
            ed25519_private_key: None,
            domain: "noombat.social".into(),
            is_local: true,
            inbox_url: None,
            instance_role: InstanceRole::User,
            actor_status: ActorStatus::Active,
            chat_requires_reprovisioning: false,
            chatmail_addr: None,
            orcid: None,
            moved_to: None,
            actor_privacy: ActorPrivacy::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}
