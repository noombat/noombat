// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Engine-agnostic authorisation backend trait.
//!
//! Every access decision is evaluated as
//! `(principal, action, resource, context) → Decision`.
//!
//! This module intentionally contains no concrete backend
//! implementation. The default Cedar backend lives in the
//! `noombat-server` crate.

use std::collections::HashMap;

// ..... Public types .....

/// The result of an authorisation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Permit,
    Deny,
}

/// Contextual key-value pairs passed alongside the authorisation request.
///
/// Values are stringly-typed at the trait boundary so that the trait
/// remains engine-agnostic. Concrete backends convert them to their
/// native context representation internally.
pub type AuthContext = HashMap<String, String>;

/// Engine-agnostic authorisation backend.
///
/// The four-parameter signature maps directly to Cedar's evaluation
/// model and to OpenFGA's `Check` API, enabling backend substitution
/// without changes to calling code.
pub trait AuthorisationBackend: Send + Sync + 'static {
    fn is_authorised(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: &AuthContext,
    ) -> Decision;
}
