// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Deserialiser for `to` and `cc`.
//!
//! ActivityStreams addressing is a single value or an array of them, and
//! each entry is a URI string or an embedded object carrying `id`.
//! GoToSocial sends the single-string form, so a `Vec<String>` field
//! refuses its activities outright.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Read `to`/`cc` in any of the shapes the specification allows.
///
/// Entries that name no URI are dropped rather than failing the parse:
/// addressing is advisory, and one unreadable recipient must not make a
/// signed activity undeliverable.
pub fn one_or_many<'de, D>(deserialiser: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserialiser)?;

    let uris = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(entries)) => entries.iter().filter_map(uri_of).collect(),
        Some(ref single) => uri_of(single).into_iter().collect(),
    };

    Ok(Some(uris))
}

/// The URI an addressing entry denotes: the string itself, or the `id`
/// of an embedded object.
fn uri_of(entry: &Value) -> Option<String> {
    match entry {
        Value::String(uri) => Some(uri.clone()),
        Value::Object(_) => entry.get("id")?.as_str().map(str::to_owned),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Addressed {
        #[serde(default, deserialize_with = "super::one_or_many")]
        to: Option<Vec<String>>,
    }

    fn to_of(json: &str) -> Option<Vec<String>> {
        serde_json::from_str::<Addressed>(json)
            .expect("the addressing shape parses")
            .to
    }

    #[test]
    fn a_single_string_is_one_recipient() {
        assert_eq!(
            to_of(r#"{"to":"https://example.test/users/bob"}"#),
            Some(vec!["https://example.test/users/bob".to_owned()])
        );
    }

    #[test]
    fn an_array_keeps_every_recipient() {
        assert_eq!(
            to_of(r#"{"to":["https://a.test/one","https://b.test/two"]}"#),
            Some(vec![
                "https://a.test/one".to_owned(),
                "https://b.test/two".to_owned()
            ])
        );
    }

    #[test]
    fn an_embedded_object_contributes_its_id() {
        assert_eq!(
            to_of(r#"{"to":[{"type":"Person","id":"https://a.test/one"},"https://b.test/two"]}"#),
            Some(vec![
                "https://a.test/one".to_owned(),
                "https://b.test/two".to_owned()
            ])
        );
    }

    #[test]
    fn an_absent_field_is_none() {
        assert_eq!(to_of(r#"{}"#), None);
        assert_eq!(to_of(r#"{"to":null}"#), None);
    }

    // The shape GoToSocial delivers. Asserted against `Activity` itself,
    // because the helper working proves nothing about the fields using
    // it: a `Vec<String>` field refuses this document at the inbox.
    #[test]
    fn a_follow_addressed_with_a_single_string_parses() {
        let follow: crate::activity::Activity = serde_json::from_str(
            r#"{"@context":"https://www.w3.org/ns/activitystreams",
                "id":"https://a.test/users/bob/follow/1",
                "type":"Follow",
                "actor":"https://a.test/users/bob",
                "object":"https://b.test/users/alice",
                "to":"https://b.test/users/alice"}"#,
        )
        .expect("a Follow addressed with a single string parses");

        assert_eq!(
            follow.to,
            Some(vec!["https://b.test/users/alice".to_owned()])
        );
    }

    #[test]
    fn an_unreadable_entry_is_dropped_rather_than_fatal() {
        assert_eq!(
            to_of(r#"{"to":[42,"https://b.test/two"]}"#),
            Some(vec!["https://b.test/two".to_owned()])
        );
    }
}
