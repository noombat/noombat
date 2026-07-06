// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Extension-point traits.
//!
//! These traits define the stable interfaces that instance operators and
//! downstream developers may implement to customise the platform.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

use crate::error::Result;

/// Pluggable search backend (default: Meilisearch).
pub trait SearchBackend: Send + Sync + 'static {
    fn upsert(
        &self,
        index: &str,
        id: &str,
        document: Value,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    fn delete(
        &self,
        index: &str,
        id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    fn search(
        &self,
        index: &str,
        query: &str,
        filters: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Value>>> + Send + '_>>;
}

/// Pluggable analytics backend (default: PostgreSQL counters).
pub trait AnalyticsBackend: Send + Sync + 'static {
    fn increment(
        &self,
        target_type: &str,
        target_id: &str,
        metric: &str,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Pluggable ActivityPub vocabulary extension (default: built-in Noombat namespace).
///
/// Implementations register additional JSON-LD namespaces. The federation
/// service includes their properties in outbound objects and parses them
/// on inbound receipt.
pub trait VocabularyExtension: Send + Sync + 'static {
    /// The namespace URI (e.g. `"https://example.org/ns#"`).
    fn namespace_uri(&self) -> &str;

    /// The short prefix used in JSON-LD `@context` (e.g. `"example"`).
    fn prefix(&self) -> &str;

    /// Extend an outbound ActivityPub object with extension-specific
    /// properties. The implementation may mutate `object` in place.
    fn extend_outbound(&self, object: &mut Value);

    /// Extract extension-specific properties from an inbound object.
    /// Returns a JSON value of the extracted data, or `None` if the
    /// extension namespace is not present.
    fn parse_inbound(&self, object: &Value) -> Option<Value>;
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
