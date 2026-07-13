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

/// The Noombat extension namespace.
pub const NOOMBAT_NS: &str = "https://noombat.org/ns#";

/// Produces the default `@context` array for outbound objects.
pub fn default_context() -> Value {
    json!([
        AS_CONTEXT,
        SECURITY_CONTEXT,
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
    fn default_context_includes_as_security_and_noombat() {
        let ctx = default_context();
        let arr = ctx.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], AS_CONTEXT);
        assert_eq!(arr[1], SECURITY_CONTEXT);
        assert!(arr[2].get("noombat").is_some());
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
