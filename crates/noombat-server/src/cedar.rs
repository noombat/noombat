// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Default [`AuthorisationBackend`] implementation backed by the
//! Cedar policy engine (`cedar-policy` crate).
//!
//! This module lives in `noombat-server` rather than `noombat-core`
//! so that the core domain crate remains decoupled from any specific
//! authorisation engine.

use std::sync::Arc;

use tracing::{debug, warn};

use noombat_core::auth::{AuthContext, AuthorisationBackend, Decision};

/// [`AuthorisationBackend`] backed by the Cedar policy engine.
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
    /// Returns a human-readable error message if the policy or schema
    /// source fails to parse.
    pub fn new(policy_src: &str, schema_src: Option<&str>) -> Result<Self, String> {
        let policy_set: cedar_policy::PolicySet = policy_src
            .parse()
            .map_err(|e| format!("failed to parse Cedar policies: {e}"))?;

        let schema = match schema_src {
            Some(src) => {
                let (schema, warnings) = cedar_policy::Schema::from_cedarschema_str(src)
                    .map_err(|e| format!("failed to parse Cedar schema: {e}"))?;
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
) -> Result<CedarBackend, String> {
    let policy_src = std::fs::read_to_string(policy_path).map_err(|e| {
        format!(
            "failed to read Cedar policies from {}: {e}",
            policy_path.display()
        )
    })?;

    let schema_src = match schema_path {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read Cedar schema from {}: {e}", path.display()))?,
        ),
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

    // ..... Production policy + schema validation .....
    //
    // These tests load the actual Cedar files from the repository and
    // verify that the policies parse against the schema. A typo in an
    // action name, a missing context attribute, or a type mismatch
    // would cause `CedarBackend::new` to fail.

    fn production_backend() -> CedarBackend {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let policies_dir = manifest_dir.join("../../policies");
        load_cedar_backend(
            &policies_dir.join("noombat.cedar"),
            Some(&policies_dir.join("noombat.cedarschema")),
        )
        .expect("production policies must parse against the schema")
    }

    #[test]
    fn production_policies_parse_against_schema() {
        // If this panics, the policy or schema file has a structural
        // error (misspelled action, unknown entity type, context
        // attribute type mismatch, etc.).
        let _b = production_backend();
    }

    #[test]
    fn production_owner_may_edit() {
        let b = production_backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "true".into());
        ctx.insert("is_authenticated".into(), "true".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"alice""#,
            r#"Noombat::Action::"edit""#,
            r#"Noombat::Profile::"alice""#,
            &ctx,
        );
        assert_eq!(d, Decision::Permit);
    }

    #[test]
    fn production_public_view_permitted() {
        let b = production_backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        ctx.insert("is_authenticated".into(), "false".into());
        ctx.insert("visibility".into(), "public".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"anonymous""#,
            r#"Noombat::Action::"view""#,
            r#"Noombat::Profile::"alice""#,
            &ctx,
        );
        assert_eq!(d, Decision::Permit);
    }

    #[test]
    fn production_anonymous_report_denied() {
        let b = production_backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        ctx.insert("is_authenticated".into(), "false".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"anonymous""#,
            r#"Noombat::Action::"report""#,
            r#"Noombat::Post::"post-1""#,
            &ctx,
        );
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn production_authenticated_report_permitted() {
        let b = production_backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        ctx.insert("is_authenticated".into(), "true".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"bob""#,
            r#"Noombat::Action::"report""#,
            r#"Noombat::Post::"post-1""#,
            &ctx,
        );
        assert_eq!(d, Decision::Permit);
    }

    #[test]
    fn production_cv_download_self_only() {
        let b = production_backend();

        // Owner may download their own self-only CV.
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "true".into());
        ctx.insert("is_authenticated".into(), "true".into());
        ctx.insert("cv_download".into(), "self".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"alice""#,
            r#"Noombat::Action::"download_cv""#,
            r#"Noombat::Profile::"alice""#,
            &ctx,
        );
        assert_eq!(d, Decision::Permit);

        // Non-owner is denied even when authenticated.
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        ctx.insert("is_authenticated".into(), "true".into());
        ctx.insert("cv_download".into(), "self".into());
        ctx.insert("is_follower".into(), "true".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"bob""#,
            r#"Noombat::Action::"download_cv""#,
            r#"Noombat::Profile::"alice""#,
            &ctx,
        );
        assert_eq!(d, Decision::Deny);
    }

    #[test]
    fn production_moderator_may_resolve_report() {
        let b = production_backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        ctx.insert("is_authenticated".into(), "true".into());
        ctx.insert("instance_role".into(), "moderator".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"mod1""#,
            r#"Noombat::Action::"resolve_report""#,
            r#"Noombat::Report::"report-1""#,
            &ctx,
        );
        assert_eq!(d, Decision::Permit);
    }

    #[test]
    fn production_user_cannot_resolve_report() {
        let b = production_backend();
        let mut ctx = AuthContext::new();
        ctx.insert("is_owner".into(), "false".into());
        ctx.insert("is_authenticated".into(), "true".into());
        ctx.insert("instance_role".into(), "user".into());
        let d = b.is_authorised(
            r#"Noombat::Actor::"bob""#,
            r#"Noombat::Action::"resolve_report""#,
            r#"Noombat::Report::"report-1""#,
            &ctx,
        );
        assert_eq!(d, Decision::Deny);
    }
}
