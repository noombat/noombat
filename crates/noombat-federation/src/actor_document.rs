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
use noombat_core::error::{NoombatError, Result};
use noombat_core::privacy::{ListVisibility, SectionVisibility};
use serde_json::Value;
use sqlx::PgPool;
use tracing::warn;

use crate::downgrade::{self, FederatedSection, VerifiedLinkRef};
use crate::move_actor;

/// Gather an actor's federated inputs and serialise the document.
///
/// A read that fails degrades to a smaller document rather than to no
/// document: an actor that cannot be served is worse than one served
/// without its sections, and the dereference path has no way to retry.
pub async fn build(pool: &PgPool, actor: &Actor, domain: &str) -> Value {
    assemble(pool, actor, domain, Gather::Degrade)
        .await
        .expect("every read degrades, so the build cannot fail")
}

/// [`build`], failing where it degrades. For a push: followers keep the
/// document they are sent, so one a failed read had left smaller would
/// withdraw what nobody withdrew.
pub async fn build_whole(pool: &PgPool, actor: &Actor, domain: &str) -> Result<Value> {
    assemble(pool, actor, domain, Gather::Whole).await
}

/// What a failed read does to the document.
#[derive(Clone, Copy)]
enum Gather {
    Degrade,
    Whole,
}

/// `read`'s value, or for a failed read, `fallback` where `gather`
/// degrades.
fn kept<T>(read: Result<T>, gather: Gather, fallback: T, actor: &Actor, what: &str) -> Result<T> {
    match (read, gather) {
        (Ok(value), _) => Ok(value),
        (Err(error), Gather::Degrade) => {
            warn!(actor = %actor.ap_id, %error, "failed to read {what}; leaving it out");
            Ok(fallback)
        }
        (Err(error), Gather::Whole) => Err(error),
    }
}

async fn assemble(pool: &PgPool, actor: &Actor, domain: &str, gather: Gather) -> Result<Value> {
    // When the document last changed, which a peer compares to keep the
    // newer of two. None before the first push. Read first, so a document
    // carries no stamp newer than what it was built from.
    let updated: Option<chrono::DateTime<chrono::Utc>> = kept(
        sqlx::query_scalar("SELECT document_updated FROM actors WHERE id = $1")
            .bind(actor.id)
            .fetch_optional(pool)
            .await
            .map(Option::flatten)
            .map_err(NoombatError::from),
        gather,
        None,
        actor,
        "the document's stamp",
    )?;

    let sections = kept(
        fetch_public_sections(pool, actor.id).await,
        gather,
        Vec::new(),
        actor,
        "the profile sections",
    )?;
    let aliases = kept(
        move_actor::list_aliases(pool, actor.id).await,
        gather,
        Vec::new(),
        actor,
        "the aliases",
    )?;
    let links = kept(
        noombat_identity::verification::list_links(pool, actor.id).await,
        gather,
        Vec::new(),
        actor,
        "the verified links",
    )?;
    let link_refs: Vec<VerifiedLinkRef<'_>> = links
        .iter()
        .filter(|link| link.verified_at.is_some() && link.visibility == "public")
        .map(|link| VerifiedLinkRef { url: &link.url })
        .collect();

    // Advertised only where the owner has made the list public. The
    // collection endpoint enforces the setting again, so this decides
    // what a peer is told exists, not what it may read.
    let settings = kept(
        noombat_identity::connections::list_settings(pool, actor.id)
            .await
            .map(Some),
        gather,
        None,
        actor,
        "the list settings",
    )?;
    let connections = settings
        .filter(|settings| matches!(settings.connections, ListVisibility::Public))
        .map(|_| format!("{}/connections", actor.ap_id));

    // The avatar's description lives with the upload, not on the actor
    // row, so it is read here rather than carried on `Actor`.
    let avatar_alt: Option<String> = kept(
        sqlx::query_scalar(
            "SELECT alt_text FROM media_attachments WHERE actor_id = $1 AND purpose = 'avatar'",
        )
        .bind(actor.id)
        .fetch_optional(pool)
        .await
        .map(Option::flatten)
        .map_err(NoombatError::from),
        gather,
        None,
        actor,
        "the avatar's description",
    )?;

    // Read here as the avatar's description is: only a key for the
    // member's current address, while their account may sign in and they
    // need not set chat up again, as the local lookup serves it. Whether the
    // address, and with it the key, is published at all is decided in
    // `build_federated_actor`.
    let chat_key: Option<Vec<u8>> = match &actor.chatmail_addr {
        Some(address) if actor.actor_status.is_active() && !actor.chat_requires_reprovisioning => {
            kept(
                sqlx::query_scalar(
                    "SELECT key_data FROM chat_keys WHERE actor_id = $1 AND address = $2",
                )
                .bind(actor.id)
                .bind(address)
                .fetch_optional(pool)
                .await
                .map_err(NoombatError::from),
                gather,
                None,
                actor,
                "the chat key",
            )?
        }
        _ => None,
    };

    let mut document = downgrade::build_federated_actor(
        actor,
        domain,
        &sections,
        &aliases,
        &link_refs,
        None,
        connections.as_deref(),
        avatar_alt.as_deref(),
        chat_key.as_deref(),
    );
    if let Some(updated) = updated {
        document["updated"] = Value::String(stamp(updated));
    }
    Ok(document)
}

/// A document's `updated`, to the millisecond, which is as fine as the
/// stored stamp is kept apart.
pub(crate) fn stamp(updated: chrono::DateTime<chrono::Utc>) -> String {
    updated.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
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
