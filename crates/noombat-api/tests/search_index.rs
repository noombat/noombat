// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Meilisearch accepts the documents this codebase generates.
//!
//! This exists because of a bug that was invisible from inside the
//! process for the whole life of the feature. `index_post` used the
//! post's `ap_id`, a URL, as the document id. Meilisearch permits only
//! alphanumerics, hyphens and underscores there, so every insert was
//! rejected, no post was ever indexed, and post search silently
//! returned nothing while being offered in the UI.
//!
//! Nothing in-process could see it. `add_or_replace` returns as soon as
//! the task is *enqueued*, so the call succeeded, `index_post` is
//! fire-and-forget anyway, and the only trace was one `warn!` per post.
//! A test asserting the call returns `Ok` would have passed throughout.
//!
//! So the assertion here is on the **task status** reported by the
//! server, and the test needs a real Meilisearch to make it. Without
//! one it skips loudly; the `integration` CI job provides the service.

use meilisearch_sdk::client::Client;
use noombat_api::search_sync::{IndexedPost, post_document};
use uuid::Uuid;

/// The instance the `integration` job provides, if this run has one.
fn client() -> Option<Client> {
    let url = std::env::var("MEILI_URL").ok()?;
    let key = std::env::var("MEILI_KEY").ok();
    Client::new(url, key).ok()
}

fn sample(id: Uuid, ap_id: &str) -> (String, serde_json::Value) {
    post_document(&IndexedPost {
        id,
        ap_id,
        actor_id: "1c6e5f28-0000-4000-8000-00000000000a",
        content_html: "<p>something they wrote</p>",
        visibility: "public",
        post_type: "note",
        title: None,
    })
}

/// Index a post, confirm the server accepted it, find it, remove it.
///
/// The round trip matters as much as the insert. A document id the
/// server accepts on the way in but cannot be addressed on the way out
/// would leave erasure unable to withdraw it, which is the other half
/// of the same mistake: `DELETE /indexes/posts/documents/<url>` returns
/// 404 because the slashes break the path.
#[ignore = "requires Meilisearch; run with --include-ignored"]
#[tokio::test]
async fn a_post_document_round_trips_through_meilisearch() {
    let Some(client) = client() else {
        eprintln!(
            "SKIPPED a_post_document_round_trips_through_meilisearch: MEILI_URL unset. \
             The integration CI job is where this runs."
        );
        return;
    };

    let index = client.index("posts_roundtrip_test");
    let post_id = Uuid::new_v4();
    let ap_id = format!("https://noombat.example/users/alice/posts/{post_id}");
    let (doc_id, doc) = sample(post_id, &ap_id);

    let task = index
        .add_or_replace(&[doc], Some("id"))
        .await
        .expect("the request itself should be accepted");

    // The assertion the old code could not have failed: enqueued is not
    // succeeded.
    let done = task
        .wait_for_completion(&client, None, None)
        .await
        .expect("task should reach a terminal state");
    assert!(
        matches!(done, meilisearch_sdk::tasks::Task::Succeeded { .. }),
        "Meilisearch rejected the document we generate: {done:?}"
    );

    // Addressable on the way out, which the URL form was not.
    let fetched: serde_json::Value = index
        .get_document(&doc_id)
        .await
        .expect("the document should be retrievable by its id");
    assert_eq!(fetched["ap_id"], ap_id, "the AP id is kept as a field");

    let removed = index
        .delete_document(&doc_id)
        .await
        .expect("delete should be accepted")
        .wait_for_completion(&client, None, None)
        .await
        .expect("delete task should reach a terminal state");
    assert!(
        matches!(removed, meilisearch_sdk::tasks::Task::Succeeded { .. }),
        "the document could not be withdrawn: {removed:?}"
    );

    let _ = index.delete().await;
}

/// The identifier itself, isolated from the rest of the document.
///
/// No Meilisearch needed: this encodes the server's documented rule, so
/// it runs in the ordinary unit suite and catches a regression on every
/// commit rather than only where a service container exists. The round
/// trip above is what confirms the rule is stated correctly.
#[test]
fn the_document_id_is_one_meilisearch_permits() {
    let (doc_id, _) = sample(Uuid::new_v4(), "https://noombat.example/users/a/posts/x");

    assert!(
        doc_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "Meilisearch admits only alphanumerics, hyphens and underscores in a \
         document id, and we generate {doc_id:?}"
    );
    assert!(doc_id.len() <= 511, "ids are capped at 511 bytes");
}
