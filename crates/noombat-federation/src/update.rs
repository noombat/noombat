// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Shared helper for broadcasting an `Update` activity for an actor's
//! profile to all accepted followers.
//!
//! Used by route handlers (on profile section changes) and by the
//! background link re-verification worker (on verification state
//! changes).

use std::borrow::Cow;

use noombat_core::actor::Actor;
use noombat_core::privacy::SectionVisibility;
use sqlx::PgPool;
use tracing::warn;

use crate::delivery;
use crate::downgrade::{self, FederatedSection};
use crate::move_actor;

/// Construct an `Update` activity for the given actor's full federated
/// profile and enqueue it for delivery to all accepted followers.
///
/// The activity carries the complete federated actor object (built via
/// [`downgrade::build_federated_actor`]), including public profile
/// sections, verified links, ORCID badge, `noombat:ttl`, and
/// `movedTo` and `alsoKnownAs` when applicable. This ensures that
/// remote instances receiving the `Update` refresh their cached copy
/// with the same data they would obtain by re-fetching the actor.
///
/// Errors are logged, not propagated: a federation delivery failure
/// must not block the local mutation that triggered it.
///
/// `domain` builds the human-facing `url` field, `/@{username}`.
pub async fn enqueue_actor_update(pool: &PgPool, actor: &Actor, domain: &str) {
    // Fetch public profile sections for federation.
    let sections = match fetch_public_sections(pool, actor.id).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                actor = %actor.ap_id,
                error = %e,
                "failed to fetch profile sections for Update; \
                 falling back to minimal actor object"
            );
            Vec::new()
        }
    };

    // Fetch actor aliases (alsoKnownAs) for Move support.
    let aliases = move_actor::list_aliases(pool, actor.id)
        .await
        .unwrap_or_default();

    // Fetch verified links for the attachment array.
    let verified_links = noombat_identity::verification::list_links(pool, actor.id)
        .await
        .unwrap_or_default();
    let link_refs: Vec<downgrade::VerifiedLinkRef<'_>> = verified_links
        .iter()
        .filter(|l| l.verified_at.is_some() && l.visibility == "public")
        .map(|l| downgrade::VerifiedLinkRef { url: &l.url })
        .collect();

    // Build the full federated actor object, respecting
    // federate_profile and per-section visibility.
    let object =
        downgrade::build_federated_actor(actor, domain, &sections, &aliases, &link_refs, None);

    let update_id = format!(
        "{}#update-{}",
        actor.ap_id,
        chrono::Utc::now().timestamp_millis()
    );

    let update_activity = serde_json::json!({
        "@context": noombat_ap::context::default_context(),
        "id": update_id,
        "type": "Update",
        "actor": actor.ap_id,
        "object": object,
        "published": chrono::Utc::now().to_rfc3339(),
    });

    let inboxes = match noombat_identity::repo::get_follower_inboxes(pool, actor.id).await {
        Ok(v) => v,
        Err(e) => {
            warn!(
                actor = %actor.ap_id,
                error = %e,
                "failed to fetch follower inboxes for profile Update"
            );
            return;
        }
    };

    for inbox in inboxes {
        if let Err(e) = delivery::enqueue(pool, actor.id, &update_activity, &inbox).await {
            warn!(
                actor = %actor.ap_id,
                target_inbox = %inbox,
                error = %e,
                "failed to enqueue profile Update"
            );
        }
    }
}

/// Fetch all public-visibility profile sections for an actor,
/// formatted as [`FederatedSection`] values suitable for
/// [`downgrade::build_federated_actor`].
///
/// The five independent database queries are executed concurrently
/// via [`tokio::try_join!`] to minimise latency on the Update
/// broadcast path.
async fn fetch_public_sections(
    pool: &PgPool,
    actor_id: uuid::Uuid,
) -> noombat_core::error::Result<Vec<FederatedSection>> {
    let vis = SectionVisibility::Public;

    let (experiences, educations, skills, publications, custom) = tokio::try_join!(
        noombat_identity::profile::list_experiences(pool, actor_id, &vis),
        noombat_identity::profile::list_educations(pool, actor_id, &vis),
        noombat_identity::profile::list_skills(pool, actor_id, false),
        noombat_identity::profile::list_publications(pool, actor_id, &vis),
        noombat_identity::profile::list_custom_sections(pool, actor_id, &vis),
    )?;

    let mut sections = Vec::new();

    for exp in experiences {
        sections.push(FederatedSection {
            section_type: "experience".into(),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({
                "noombat:title": exp.title,
                "noombat:company": exp.company,
                "noombat:startDate": exp.start_date.to_string(),
                "noombat:endDate": exp.end_date.map(|d| d.to_string()),
                "content": exp.description_html,
            }),
        });
    }

    for edu in educations {
        sections.push(FederatedSection {
            section_type: "education".into(),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({
                "noombat:institution": edu.institution,
                "noombat:degree": edu.degree,
                "noombat:fieldOfStudy": edu.field_of_study,
                "noombat:startDate": edu.start_date.to_string(),
                "noombat:endDate": edu.end_date.map(|d| d.to_string()),
                "content": edu.description_html,
            }),
        });
    }

    for skill in skills {
        sections.push(FederatedSection {
            section_type: "skill".into(),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({ "name": skill.name }),
        });
    }

    for pub_ in publications {
        sections.push(FederatedSection {
            section_type: "publication".into(),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({
                "noombat:doi": pub_.doi,
                "name": pub_.title,
                "noombat:authors": pub_.authors,
                "noombat:journal": pub_.journal,
            }),
        });
    }

    for cs in custom {
        sections.push(FederatedSection {
            section_type: Cow::Owned(cs.section_type),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({
                "name": cs.title,
                "content": cs.content_html,
                "noombat:data": cs.data,
            }),
        });
    }

    Ok(sections)
}
