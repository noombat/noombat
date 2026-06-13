// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Extension-point traits.
//!
//! These traits define the stable interfaces that instance operators and
//! downstream developers may implement to customise the platform.

use std::future::Future;

use serde_json::Value;

use crate::error::Result;

/// Pluggable search backend (default: Meilisearch).
pub trait SearchBackend: Send + Sync + 'static {
    fn upsert(&self, index: &str, id: &str, document: Value)
        -> impl Future<Output = Result<()>> + Send;

    fn delete(&self, index: &str, id: &str) -> impl Future<Output = Result<()>> + Send;

    fn search(
        &self,
        index: &str,
        query: &str,
        filters: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> impl Future<Output = Result<Vec<Value>>> + Send;
}

/// Pluggable analytics backend (default: PostgreSQL counters).
pub trait AnalyticsBackend: Send + Sync + 'static {
    fn increment(
        &self,
        target_type: &str,
        target_id: &str,
        metric: &str,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Custom profile section provider.
pub trait ProfileSectionProvider: Send + Sync + 'static {
    /// A unique identifier for this section type (e.g. `"certifications"`).
    fn section_type(&self) -> &'static str;

    /// Human-readable label for the section.
    fn label(&self) -> &'static str;

    /// Validate type-specific structured data before persistence.
    fn validate(&self, data: &Value) -> Result<()>;
}
