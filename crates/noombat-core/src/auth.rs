// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Authorisation backend trait and default Cedar implementation.
//!
//! Every access decision is evaluated as
//! `(principal, action, resource, context) → Decision`.
//! The trait is engine-agnostic; the default implementation
//! delegates to the Cedar policy engine (`cedar-policy` crate).

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, warn};

use crate::error::{NoombatError, Result};

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
/// remains engine-agnostic. The Cedar backend converts them to Cedar
/// `Context` values internally.
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

// ..... Cedar backend .....

/// Default [`AuthorisationBackend`] backed by the Cedar policy engine.
///
/// Loads a [`cedar_policy::PolicySet`] and an optional
/// [`cedar_policy::Schema`] at construction time. Entity data is
/// currently empty; relationship-aware entity sets (follower graph,
/// group memberships) will be populated as federation matures.
pub struct CedarBackend {
    policy_set: Arc<cedar_policy::PolicySet>,
    schema: Option<Arc<cedar_policy::Schema>>,
}

impl CedarBackend {
    /// Construct a new Cedar backend from policy and schema source strings.
    ///
    /// # Errors
    ///
    /// Returns [`NoombatError::Internal`] if the policy or schema source
    /// fails to parse.
    pub fn new(policy_src: &str, schema_src: Option<&str>) -> Result<Self> {
        let policy_set: cedar_policy::PolicySet = policy_src
            .parse()
            .map_err(|e| NoombatError::Internal(format!("failed to parse Cedar policies: {e}")))?;

        let schema = match schema_src {
            Some(src) => {
                let (schema, warnings) =
                    cedar_policy::Schema::from_cedarschema_str(src).map_err(|e| {
                        NoombatError::Internal(format!("failed to parse Cedar schema: {e}"))
                    })?;
                for w in warnings {
                    warn!("Cedar schema warning: {w}");
                }
                Some(Arc::new(schema))
            }
            None => None,
        };

        Ok(Self {
            policy_set: Arc::new(policy_set),
            schema,
        })
    }
}

impl AuthorisationBackend for CedarBackend {
    fn is_authorised(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        context: &AuthContext,
    ) -> Decision {
        let principal_uid = match principal.parse::<cedar_policy::EntityUid>() {
            Ok(uid) => uid,
            Err(e) => {
                warn!(principal, "invalid principal entity UID: {e}");
                return Decision::Deny;
            }
        };
        let action_uid = match action.parse::<cedar_policy::EntityUid>() {
            Ok(uid) => uid,
            Err(e) => {
                warn!(action, "invalid action entity UID: {e}");
                return Decision::Deny;
            }
        };
        let resource_uid = match resource.parse::<cedar_policy::EntityUid>() {
            Ok(uid) => uid,
            Err(e) => {
                warn!(resource, "invalid resource entity UID: {e}");
                return Decision::Deny;
            }
        };

        let cedar_context = cedar_policy::Context::from_pairs(context.iter().map(|(k, v)| {
            (
                k.clone(),
                cedar_policy::RestrictedExpression::new_string(v.clone()),
            )
        }));
        let cedar_context = match cedar_context {
            Ok(ctx) => ctx,
            Err(e) => {
                warn!("failed to build Cedar context: {e}");
                return Decision::Deny;
            }
        };

        let request = match cedar_policy::Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            cedar_context,
            self.schema.as_deref(),
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to build Cedar request: {e}");
                return Decision::Deny;
            }
        };

        let entities = cedar_policy::Entities::empty();
        let authorizer = cedar_policy::Authorizer::new();
        let response = authorizer.is_authorized(&request, &self.policy_set, &entities);

        let decision = match response.decision() {
            cedar_policy::Decision::Allow => Decision::Permit,
            cedar_policy::Decision::Deny => Decision::Deny,
        };

        debug!(
            principal,
            action,
            resource,
            ?decision,
            "authorisation decision"
        );

        decision
    }
}

// ..... Convenience helpers .....

/// Load Cedar policy and schema files from the filesystem.
///
/// # Arguments
///
/// * `policy_path`: path to the `.cedar` policy file.
/// * `schema_path`: optional path to the `.cedarschema` file.
pub fn load_cedar_backend(
    policy_path: &std::path::Path,
    schema_path: Option<&std::path::Path>,
) -> Result<CedarBackend> {
    let policy_src = std::fs::read_to_string(policy_path).map_err(|e| {
        NoombatError::Internal(format!(
            "failed to read Cedar policies from {}: {e}",
            policy_path.display()
        ))
    })?;

    let schema_src = match schema_path {
        Some(path) => Some(std::fs::read_to_string(path).map_err(|e| {
            NoombatError::Internal(format!(
                "failed to read Cedar schema from {}: {e}",
                path.display()
            ))
        })?),
        None => None,
    };

    CedarBackend::new(&policy_src, schema_src.as_deref())
}

// ..... Tests .....

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_POLICIES: &str = r#"
        // Owner may perform any action on their own profile.
        permit(
            principal,
            action,
            resource
        ) when {
            context.is_owner == "true"
        };
    "#;

    fn backend() -> CedarBackend {
        CedarBackend::new(TEST_POLICIES, None).unwrap()
    }

    #[test]
    fn owner_is_permitted() {
        let b = backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "true".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"alice""#,
            r#"Noombat::Action::"edit""#,
            r#"Noombat::Profile::"alice""#,
            &ctx,
        );
        assert_eq!(d, Decision::Permit);
    }

    #[test]
    fn non_owner_is_denied() {
        let b = backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"bob""#,
            r#"Noombat::Action::"edit""#,
            r#"Noombat::Profile::"alice""#,
            &ctx,
        );
        assert_eq!(d, Decision::Deny);
    }
}
