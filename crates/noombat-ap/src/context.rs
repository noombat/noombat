// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! JSON-LD context constants for ActivityPub and Noombat extensions.

use serde_json::{json, Value};

/// The standard ActivityStreams context URI.
pub const AS_CONTEXT: &str = "https://www.w3.org/ns/activitystreams";

/// The Noombat extension namespace.
pub const NOOMBAT_NS: &str = "https://noombat.org/ns#";

/// Produces the default `@context` array for outbound objects.
pub fn default_context() -> Value {
    json!([
        AS_CONTEXT,
        { "noombat": NOOMBAT_NS }
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_context_includes_as_and_noombat() {
        let ctx = default_context();
        let arr = ctx.as_array().unwrap();
        assert_eq!(arr[0], AS_CONTEXT);
        assert!(arr[1].get("noombat").is_some());
    }
}
