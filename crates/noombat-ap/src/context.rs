// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! JSON-LD context constants for ActivityPub and Noombat extensions.

use serde_json::{Value, json};

/// The standard ActivityStreams context URI.
pub const AS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";

/// The ActivityStreams Public collection URI.
///
/// When present in the `to` field of an activity, the object is public.
/// When present only in `cc`, the object is unlisted.
/// Absence from both indicates followers-only (or direct) addressing.
pub const AS_PUBLIC: &str = "https://www.w3.org/ns/activitystreams#Public";

/// The W3C Security Vocabulary context URI.
pub const SECURITY_CONTEXT: &str = "https://w3id.org/security/v1";

/// The W3C Data Integrity context URI (for FEP-8b32 integrity proofs).
pub const DATA_INTEGRITY_CONTEXT: &str = "https://w3id.org/security/data-integrity/v1";

/// The W3C Multikey context URI.
///
/// [`SECURITY_CONTEXT`] defines `assertionMethod` but not the `Multikey`
/// type or `publicKeyMultibase` that FEP-521a puts inside it, so an
/// actor publishing an Ed25519 key under the default context alone
/// hands a JSON-LD processor terms it must drop.
pub const MULTIKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";

/// The Noombat extension namespace.
pub const NOOMBAT_NS: &str = "https://noombat.org/ns#";

/// The schema.org namespace.
pub const SCHEMA_NS: &str = "http://schema.org#";

/// GoToSocial's namespace, which defines the interaction policy
/// vocabulary that Mastodon has also adopted.
pub const GTS_NS: &str = "https://gotosocial.org/ns#";

/// A context entry added only when the document uses what it defines.
///
/// Mastodon's serialisers work this way, one extension per feature
/// rather than a fixed union, which keeps a plain `Follow` from carrying
/// the vocabulary of a profile page. The alternative, a single context
/// wide enough for every document, makes every document pay for the
/// widest one and hides which terms a given document actually needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Extension {
    /// `publicKey`, `publicKeyPem` and `owner`.
    Security,
    /// `Multikey`, `publicKeyMultibase`, `assertionMethod`, `controller`.
    Multikey,
    /// `PropertyValue` and `value`, bound unprefixed because that is the
    /// spelling Mastodon reads profile fields from. Anything else
    /// schema.org supplies is written with an explicit `schema:` prefix
    /// rather than growing this map.
    Schema,
    /// `movedTo`. Absent from the ActivityStreams context, so bound the
    /// way Mastodon binds it.
    MovedTo,
    /// `Hashtag`, in a `tag` array.
    Hashtag,
    /// `interactionPolicy` and its sub-policies.
    InteractionPolicy,
}

/// Produces an `@context` carrying ActivityStreams, the `noombat`
/// prefix, and exactly the extensions asked for.
///
/// Order matters: a prefix is only usable by entries after the one that
/// defines it, which is why `as:` bindings sit in the trailing term map
/// rather than before the ActivityStreams entry.
pub fn context_with(extensions: &[Extension]) -> Value {
    let mut entries = vec![json!(AS_CONTEXT)];
    let mut terms = serde_json::Map::new();

    let mut wanted = extensions.to_vec();
    wanted.sort_unstable();
    wanted.dedup();

    for extension in wanted {
        match extension {
            Extension::Security => entries.push(json!(SECURITY_CONTEXT)),
            Extension::Multikey => entries.push(json!(MULTIKEY_CONTEXT)),
            Extension::Schema => {
                terms.insert("schema".into(), json!(SCHEMA_NS));
                terms.insert("PropertyValue".into(), json!("schema:PropertyValue"));
                terms.insert("value".into(), json!("schema:value"));
            }
            Extension::MovedTo => {
                terms.insert(
                    "movedTo".into(),
                    json!({ "@id": "as:movedTo", "@type": "@id" }),
                );
            }
            Extension::Hashtag => {
                terms.insert("Hashtag".into(), json!("as:Hashtag"));
            }
            Extension::InteractionPolicy => {
                terms.insert("gts".into(), json!(GTS_NS));
                terms.insert(
                    "interactionPolicy".into(),
                    json!({ "@id": "gts:interactionPolicy", "@type": "@id" }),
                );
            }
        }
    }

    terms.insert("noombat".into(), json!(NOOMBAT_NS));
    entries.push(Value::Object(terms));
    Value::Array(entries)
}

/// Produces the `@context` for a document needing no extension: the
/// activities that carry only ActivityStreams terms and `noombat:` ones.
pub fn default_context() -> Value {
    context_with(&[])
}

/// Produces a minimal `@context` array for objects that use the
/// `noombat:` namespace prefix but do not carry HTTP Signature key
/// material (e.g. error bodies).
///
/// Omits [`SECURITY_CONTEXT`] because `publicKey` is not present.
pub fn error_context() -> Value {
    json!([
        AS_CONTEXT,
        { "noombat": NOOMBAT_NS }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declares(ctx: &Value, term: &str) -> bool {
        ctx.as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.get(term).is_some())
    }

    fn lists(ctx: &Value, url: &str) -> bool {
        ctx.as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.as_str())
            .any(|entry| entry == url)
    }

    #[test]
    fn the_default_context_carries_nothing_a_plain_activity_does_not_use() {
        let ctx = default_context();
        assert!(lists(&ctx, AS_CONTEXT));
        assert!(declares(&ctx, "noombat"));
        for absent in ["schema", "movedTo", "Hashtag", "interactionPolicy"] {
            assert!(!declares(&ctx, absent), "{absent} should be opt-in");
        }
        assert!(!lists(&ctx, SECURITY_CONTEXT), "security should be opt-in");
    }

    #[test]
    fn each_extension_declares_exactly_what_it_names() {
        let ctx = context_with(&[Extension::Schema]);
        assert!(declares(&ctx, "schema"));
        assert!(declares(&ctx, "PropertyValue"));
        assert!(declares(&ctx, "value"));

        let ctx = context_with(&[Extension::MovedTo]);
        assert!(declares(&ctx, "movedTo"));

        let ctx = context_with(&[Extension::Hashtag]);
        assert_eq!(
            ctx.as_array().unwrap()[1]["Hashtag"],
            "as:Hashtag",
            "bound the way Mastodon and GoToSocial bind it"
        );

        let ctx = context_with(&[Extension::InteractionPolicy]);
        assert_eq!(ctx.as_array().unwrap()[1]["gts"], GTS_NS);
        assert!(declares(&ctx, "interactionPolicy"));

        let ctx = context_with(&[Extension::Security, Extension::Multikey]);
        assert!(lists(&ctx, SECURITY_CONTEXT));
        assert!(lists(&ctx, MULTIKEY_CONTEXT));
    }

    #[test]
    fn asking_twice_declares_once() {
        let ctx = context_with(&[Extension::Schema, Extension::Schema]);
        let urls = ctx.as_array().unwrap().len();
        assert_eq!(urls, 2, "one named context and one term map");
    }

    #[test]
    fn error_context_includes_as_and_noombat_without_security() {
        let ctx = error_context();
        let arr = ctx.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], AS_CONTEXT);
        assert!(arr[1].get("noombat").is_some());
    }
}
