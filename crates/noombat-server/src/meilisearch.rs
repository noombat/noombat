// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Meilisearch implementation of the [`SearchBackend`] trait.

use meilisearch_sdk::client::Client;
use noombat_core::error::{NoombatError, Result};
use noombat_core::extension::SearchBackend;
use serde_json::Value;
use tracing::debug;

/// Concrete [`SearchBackend`] backed by a Meilisearch instance.
pub struct MeilisearchBackend {
    client: Client,
}

impl MeilisearchBackend {
    /// Create a new backend connected to the given Meilisearch instance.
    ///
    /// # Arguments
    ///
    /// * `url`: Base URL (e.g. `http://localhost:7700`).
    /// * `api_key`: Optional master/admin API key.
    pub fn new(url: &str, api_key: Option<&str>) -> Result<Self> {
        let client = Client::new(url, api_key)
            .map_err(|e| NoombatError::Internal(format!("meilisearch client init: {e}")))?;
        Ok(Self { client })
    }

    /// Ensure the required indices exist with appropriate settings.
    ///
    /// This method is idempotent and should be called once at startup.
    /// It awaits Meilisearch task completion for each index so that the
    /// server does not begin serving requests before indices are ready.
    pub async fn ensure_indices(&self) -> Result<()> {
        use std::time::Duration;

        let indices = [
            ("profiles", vec!["display_name", "summary", "skills"]),
            (
                "jobs",
                vec!["title", "company", "description", "requirements"],
            ),
            ("posts", vec!["content"]),
            ("groups", vec!["name", "description", "tags"]),
            (
                "events",
                vec!["title", "description", "location_name"],
            ),
        ];

        for (name, searchable) in indices {
            // `create_index` is idempotent from Meilisearch 1.0.
            let task = self
                .client
                .create_index(name, Some("id"))
                .await
                .map_err(|e| NoombatError::Internal(format!("meilisearch create_index: {e}")))?;
            debug!(
                index = name,
                task_uid = task.task_uid,
                "index creation enqueued"
            );

            // Wait for index creation before configuring attributes.
            task.wait_for_completion(
                &self.client,
                Some(Duration::from_millis(200)),
                Some(Duration::from_secs(30)),
            )
            .await
            .map_err(|e| NoombatError::Internal(format!("meilisearch create_index wait: {e}")))?;

            let index = self.client.index(name);
            let searchable_task =
                index
                    .set_searchable_attributes(&searchable)
                    .await
                    .map_err(|e| {
                        NoombatError::Internal(format!(
                            "meilisearch set_searchable_attributes: {e}"
                        ))
                    })?;

            // Filterable attributes enable faceted search (e.g. remote-only
            // jobs, visibility-scoped profiles, date-range events).
            let filterable: Vec<&str> = match name {
                "profiles" => vec!["visibility", "actor_type"],
                "jobs" => vec!["status", "actor_id", "remote"],
                "posts" => vec!["actor_id", "visibility"],
                "groups" => vec!["actor_id"],
                "events" => vec!["actor_id", "group_id", "start_time"],
                _ => vec![],
            };

            // Sortable attributes enable `sort` parameters at search time
            // (e.g. `sort=["start_time:asc"]` for upcoming events).
            let sortable: Vec<&str> = match name {
                "events" => vec!["start_time"],
                "jobs" => vec!["created_at"],
                _ => vec![],
            };

            // Enqueue filterable and sortable settings; track the last
            // task so that a single `wait_for_completion` call at the
            // end guarantees all prior tasks have also completed.
            let mut last_task = searchable_task;

            if !filterable.is_empty() {
                last_task = index
                    .set_filterable_attributes(&filterable)
                    .await
                    .map_err(|e| {
                        NoombatError::Internal(format!(
                            "meilisearch set_filterable_attributes: {e}"
                        ))
                    })?;
            }

            if !sortable.is_empty() {
                last_task = index
                    .set_sortable_attributes(&sortable)
                    .await
                    .map_err(|e| {
                        NoombatError::Internal(format!(
                            "meilisearch set_sortable_attributes: {e}"
                        ))
                    })?;
            }

            // Meilisearch processes tasks per index sequentially, so
            // awaiting the last enqueued task guarantees all prior
            // tasks for this index have also completed.
            last_task
                .wait_for_completion(
                    &self.client,
                    Some(Duration::from_millis(200)),
                    Some(Duration::from_secs(30)),
                )
                .await
                .map_err(|e| {
                    NoombatError::Internal(format!("meilisearch index setup wait: {e}"))
                })?;

            debug!(index = name, "index ready");
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl SearchBackend for MeilisearchBackend {
    async fn upsert(&self, index: &str, id: &str, document: Value) -> Result<()> {
        let idx = self.client.index(index);
        let docs = vec![document];
        idx.add_or_replace(&docs, Some("id"))
            .await
            .map_err(|e| NoombatError::Internal(format!("meilisearch upsert: {e}")))?;
        debug!(index, id, "upserted document");
        Ok(())
    }

    async fn delete(&self, index: &str, id: &str) -> Result<()> {
        let idx = self.client.index(index);
        idx.delete_document(id)
            .await
            .map_err(|e| NoombatError::Internal(format!("meilisearch delete: {e}")))?;
        debug!(index, id, "deleted document");
        Ok(())
    }

    async fn search(
        &self,
        index: &str,
        query: &str,
        filters: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Value>> {
        let idx = self.client.index(index);
        let mut search = idx.search();
        search.with_query(query);
        search.with_limit(limit);
        search.with_offset(offset);
        if let Some(f) = filters {
            search.with_filter(f);
        }

        let results = search
            .execute::<Value>()
            .await
            .map_err(|e| NoombatError::Internal(format!("meilisearch search: {e}")))?;

        let hits: Vec<Value> = results.hits.into_iter().map(|h| h.result).collect();
        debug!(
            index,
            query,
            total_hits = results.estimated_total_hits.unwrap_or(0),
            returned = hits.len(),
            "search completed"
        );
        Ok(hits)
    }
}
