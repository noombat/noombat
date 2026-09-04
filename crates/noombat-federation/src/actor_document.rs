// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! The one place a local actor's ActivityPub document is assembled.
//!
//! Two paths publish an actor: a peer dereferences it, and an `Update`
//! pushes it to followers. Both must go through [`build`], gather
//! included, or a peer ends up holding whichever document reached it
//! last rather than the actor's actual state.

use std::borrow::Cow;

use noombat_core::actor::Actor;
use noombat_core::privacy::{ListVisibility, SectionVisibility};
use serde_json::Value;
use sqlx::PgPool;
use tracing::warn;

use crate::downgrade::{self, FederatedSection, VerifiedLinkRef};
use crate::move_actor;

/// Gather an actor's federated inputs and serialise the document.
///
/// A gather that fails degrades to a smaller document rather than to no
/// document: an actor that cannot be served is worse than one served
/// without its sections, and the dereference path has no way to retry.
pub async fn build(pool: &PgPool, actor: &Actor, domain: &str) -> Value {
    let sections = match fetch_public_sections(pool, actor.id).await {
        Ok(sections) => sections,
        Err(error) => {
            warn!(
                actor = %actor.ap_id,
                %error,
                "failed to fetch profile sections; serving a minimal actor"
            );
            Vec::new()
        }
    };

    let aliases = move_actor::list_aliases(pool, actor.id)
        .await
        .unwrap_or_default();

    let links = noombat_identity::verification::list_links(pool, actor.id)
        .await
        .unwrap_or_default();
    let link_refs: Vec<VerifiedLinkRef<'_>> = links
        .iter()
        .filter(|link| link.verified_at.is_some() && link.visibility == "public")
        .map(|link| VerifiedLinkRef { url: &link.url })
        .collect();

    // Advertised only where the owner has made the list public. The
    // collection endpoint enforces the setting again, so this decides
    // what a peer is told exists, not what it may read.
    let connections = match noombat_identity::connections::list_settings(pool, actor.id).await {
        Ok(settings) => matches!(settings.connections, ListVisibility::Public)
            .then(|| format!("{}/connections", actor.ap_id)),
        Err(error) => {
            warn!(
                actor = %actor.ap_id,
                %error,
                "failed to read the list settings; omitting the connections collection"
            );
            None
        }
    };

    // The avatar's description lives with the upload, not on the actor
    // row, so it is read here rather than carried on `Actor`. A failure
    // omits the property instead of failing the document: a peer would
    // rather have the picture undescribed than not have the actor.
    let avatar_alt: Option<String> = sqlx::query_scalar(
        "SELECT alt_text FROM media_attachments WHERE actor_id = $1 AND purpose = 'avatar'",
    )
    .bind(actor.id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten();

    downgrade::build_federated_actor(
        actor,
        domain,
        &sections,
        &aliases,
        &link_refs,
        None,
        connections.as_deref(),
        avatar_alt.as_deref(),
    )
}

/// Fetch all public-visibility profile sections for an actor,
/// formatted as [`FederatedSection`] values.
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
        noombat_identity::profile::list_work_experiences(pool, actor_id, &vis),
        noombat_identity::profile::list_education_entries(pool, actor_id, &vis),
        noombat_identity::profile::list_skills(pool, actor_id, &vis),
        noombat_identity::profile::list_scholarly_articles(pool, actor_id, &vis),
        noombat_identity::profile::list_custom_sections(pool, actor_id, &vis),
    )?;

    let mut sections = Vec::new();

    for exp in experiences {
        sections.push(FederatedSection {
            section_type: "experience".into(),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({
                "schema:roleName": exp.title,
                "schema:worksFor": exp.organization,
                "schema:startDate": exp.start_date.to_string(),
                "schema:endDate": exp.end_date.map(|d| d.to_string()),
                "content": exp.description_html,
            }),
        });
    }

    for edu in educations {
        sections.push(FederatedSection {
            section_type: "education".into(),
            visibility: SectionVisibility::Public,
            data: serde_json::json!({
                "schema:alumniOf": edu.institution,
                "schema:credentialCategory": edu.degree,
                "noombat:fieldOfStudy": edu.field_of_study,
                "schema:startDate": edu.start_date.to_string(),
                "schema:endDate": edu.end_date.map(|d| d.to_string()),
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
                "schema:identifier": {
                    "type": "PropertyValue",
                    "schema:propertyID": "DOI",
                    "value": pub_.doi,
                },
                "name": pub_.title,
                "schema:author": pub_.authors,
                "schema:isPartOf": pub_.journal,
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
