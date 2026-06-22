// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared application state passed to all Axum handlers.

use std::sync::Arc;

use noombat_core::auth::AuthorisationBackend;
use sqlx::PgPool;

/// Application-wide state, injected into Axum handlers via [`axum::extract::State`].
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub domain: String,
    pub http_client: reqwest::Client,
    pub open_registrations: bool,
    /// Development-only bearer token for C2S outbox POST!
    /// To be replaced by full authentication!
    pub admin_token: Option<String>,
    /// Authorisation backend (default: Cedar).
    pub auth: Arc<dyn AuthorisationBackend>,
}
