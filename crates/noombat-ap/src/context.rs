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
///
/// Actor documents carry `PropertyValue` attachments by the Mastodon
/// convention, and both that type and its `value` property are
/// schema.org terms that the ActivityStreams context does not define.
/// Emitted undeclared, a JSON-LD processor is free to drop them, and
/// the profile fields go with them.
pub const SCHEMA_NS: &str = "http://schema.org#";

/// Terms this instance emits that none of the contexts it references
/// defines, bound so a processor expanding the document keeps them.
///
/// `PropertyValue` and `value` are schema.org, carried on actor
/// attachments by the Mastodon convention. `movedTo` is the migration
/// pointer: in wide use, absent from the ActivityStreams context, and
/// bound here to `as:movedTo` the way Mastodon binds it. The `as`
/// prefix resolves because the ActivityStreams context precedes this
/// entry in the array, and a JSON-LD context is processed in order.
fn extension_terms() -> Value {
    json!({
        "schema": SCHEMA_NS,
        "PropertyValue": "schema:PropertyValue",
        "value": "schema:value",
        "movedTo": { "@id": "as:movedTo", "@type": "@id" }
    })
}

/// Produces the default `@context` array for outbound objects.
pub fn default_context() -> Value {
    json!([
        AS_CONTEXT,
        SECURITY_CONTEXT,
        extension_terms(),
        { "noombat": NOOMBAT_NS }
    ])
}

/// Produces the `@context` array for an actor that publishes an
/// `assertionMethod`, i.e. [`default_context`] plus the terms that
/// entry's contents need.
pub fn actor_context() -> Value {
    json!([
        AS_CONTEXT,
        SECURITY_CONTEXT,
        MULTIKEY_CONTEXT,
        extension_terms(),
        { "noombat": NOOMBAT_NS }
    ])
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

    #[test]
    fn default_context_declares_every_namespace_it_needs() {
        let ctx = default_context();
        let arr = ctx.as_array().unwrap();

        let urls: Vec<&str> = arr.iter().filter_map(|entry| entry.as_str()).collect();
        assert!(urls.contains(&AS_CONTEXT));
        assert!(urls.contains(&SECURITY_CONTEXT));

        // Looked up rather than indexed: the previous version asserted a
        // length of three and three fixed positions, so it failed the moment
        // a namespace was added rather than telling anyone what was wrong.
        let declares = |term: &str| arr.iter().any(|entry| entry.get(term).is_some());
        assert!(declares("noombat"));
        assert!(
            declares("schema"),
            "PropertyValue and value expand to nothing without the schema.org namespace"
        );
        assert!(
            declares("movedTo"),
            "movedTo is not an ActivityStreams term and must be bound explicitly"
        );
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
