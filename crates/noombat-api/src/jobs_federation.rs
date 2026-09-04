// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! The Note that publicises a job posting, and its withdrawal.
//!
//! **The listing itself does not federate.** What travels is an ordinary
//! `Note`, which every Fediverse implementation can render, carrying a
//! link back to the listing on this instance. A peer holds a post that
//! says a job exists; it never holds the job.
//!
//! Three properties are load-bearing:
//!
//! - **The organisation is the author, never the member who wrote it.**
//!   A recruiter's name on a peer's timeline is a disclosure the
//!   recruiter did not agree to, and the posting is the organisation's
//!   act.
//! - **`published_at` is the trigger, and it is also the verification
//!   gate.** Creation refuses to set it for an organisation that does
//!   not control its claimed domain, and `demote_lapsed_organizations`
//!   clears it when that lapses, so a non-NULL `published_at` already
//!   means "published by an organisation that controls its claimed
//!   domain". The trigger and the gate are the same fact.
//! - **Withdrawal has to travel too.** A Note left running on a peer
//!   under a badge this instance has withdrawn is exactly the vector the
//!   demotion sweep exists to close, so demotion emits a `Delete` for
//!   every posting it demotes rather than only counting them.

use noombat_core::actor::Actor;
use noombat_jobs::JobPosting;
use serde_json::{Value, json};
use sqlx::PgPool;
use tracing::warn;

/// Build the `Create { Note }` that publicises a posting.
///
/// `canonical_uri` is the listing URL, so a peer that later sees the
/// same job through another route de-duplicates against the listing
/// rather than accumulating copies. The inbound half of that is already
/// built, in `noombat_federation::crosspost`.
pub fn publicising_note(organisation: &Actor, job: &JobPosting, domain: &str) -> Value {
    let listing_url = format!("https://{domain}/jobs/{}", job.id);
    let location = match (&job.location, job.remote) {
        (Some(place), true) => format!("{place} (remote)"),
        (Some(place), false) => place.clone(),
        (None, true) => "Remote".to_owned(),
        (None, false) => String::new(),
    };

    let heading = if location.is_empty() {
        format!("<p><b>{}</b></p>", escape(&job.title))
    } else {
        format!(
            "<p><b>{}</b> ({})</p>",
            escape(&job.title),
            escape(&location)
        )
    };

    let note = json!({
        "id": format!("{}#note", job.ap_id),
        "type": "Note",
        "attributedTo": organisation.ap_id,
        "content": format!(
            "{heading}<p><a href=\"{listing_url}\">{listing_url}</a></p>"
        ),
        "url": listing_url,
        "canonicalUri": listing_url,
        "published": job.created_at.to_rfc3339(),
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "cc": [format!("{}/followers", organisation.ap_id)],
    });

    json!({
        "@context": noombat_ap::context::default_context(),
        "id": format!("{}#create-note", job.ap_id),
        "type": "Create",
        "actor": organisation.ap_id,
        "object": note,
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "cc": [format!("{}/followers", organisation.ap_id)],
    })
}

/// Build the `Delete` that withdraws a Note this instance published.
pub fn withdrawing_delete(organisation_ap_id: &str, job_ap_id: &str) -> Value {
    json!({
        "@context": noombat_ap::context::default_context(),
        "id": format!("{job_ap_id}#delete-note"),
        "type": "Delete",
        "actor": organisation_ap_id,
        "object": format!("{job_ap_id}#note"),
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
    })
}

/// Deliver the publicising Note to the organisation's followers.
///
/// Best effort, and deliberately not fatal: the posting exists whether
/// or not a peer hears about it, and failing the write because a queue
/// insert failed would lose the recruiter's work.
///
/// A posting with no `published_at` publicises nothing. That is the
/// verification gate speaking: an organisation that has not proved its
/// domain never reaches this call with a published posting.
pub async fn announce_published(pool: &PgPool, domain: &str, author: &Actor, job: &JobPosting) {
    if job.published_at.is_none() {
        return;
    }

    let organisation = match resolve_organisation(pool, author, job).await {
        Some(actor) => actor,
        None => return,
    };

    let activity = publicising_note(&organisation, job, domain);
    deliver(pool, &organisation, &activity).await;
}

/// Deliver a `Delete` for each posting a sweep or a withdrawal removed.
///
/// Takes ids rather than a count, which is the point: a bulk `UPDATE`
/// that returns only `rows_affected()` cannot withdraw anything from a
/// peer, so a lapsed organisation's Notes keep running on every instance
/// that received them.
pub async fn announce_withdrawn(pool: &PgPool, job_ids: &[uuid::Uuid]) {
    for job_id in job_ids {
        let job = match noombat_jobs::get_job(pool, *job_id).await {
            Ok(job) => job,
            Err(e) => {
                warn!(%job_id, error = %e, "withdrawn posting could not be read; no Delete sent");
                continue;
            }
        };

        let organisation = match noombat_identity::repo::find_by_id(pool, job.actor_id).await {
            Ok(actor) => actor,
            Err(e) => {
                warn!(%job_id, error = %e, "posting's actor could not be read; no Delete sent");
                continue;
            }
        };

        let activity = withdrawing_delete(&organisation.ap_id, &job.ap_id);
        deliver(pool, &organisation, &activity).await;
    }
}

/// The actor a Note is attributed to.
///
/// The posting's own `actor_id`, which for an organisation's posting is
/// the organisation. `author` is the account that made the request and
/// is used only when the two are the same, so a recruiter's identity
/// never leaves this instance in a Note.
async fn resolve_organisation(pool: &PgPool, author: &Actor, job: &JobPosting) -> Option<Actor> {
    if job.actor_id == author.id {
        return Some(author.clone());
    }
    match noombat_identity::repo::find_by_id(pool, job.actor_id).await {
        Ok(actor) => Some(actor),
        Err(e) => {
            warn!(
                job = %job.id,
                error = %e,
                "posting's actor could not be read; nothing publicised"
            );
            None
        }
    }
}

/// Queue an activity to every follower inbox of .
pub async fn deliver(pool: &PgPool, organisation: &Actor, activity: &Value) {
    let inboxes = match noombat_identity::repo::get_follower_inboxes(pool, organisation.id).await {
        Ok(inboxes) => inboxes,
        Err(e) => {
            warn!(actor = %organisation.ap_id, error = %e, "follower inboxes unreadable");
            return;
        }
    };

    for inbox in inboxes {
        if let Err(e) =
            noombat_federation::delivery::enqueue(pool, organisation.id, activity, &inbox).await
        {
            warn!(actor = %organisation.ap_id, %inbox, error = %e, "delivery could not be queued");
        }
    }
}

/// Escape the characters that would otherwise close a tag in the
/// `content` string. Titles and locations are recruiter input.
fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organisation() -> Actor {
        Actor {
            id: uuid::Uuid::new_v4(),
            actor_type: noombat_core::actor::ActorType::Organization,
            org_kind: Some(noombat_core::actor::OrgKind::Employer),
            ap_id: "https://noombat.example/users/acme".to_owned(),
            username: "acme".to_owned(),
            display_name: Some("Acme".to_owned()),
            headline: None,
            location: None,
            avatar_url: None,
            header_url: None,
            summary_md: None,
            summary_html: None,
            public_key_pem: String::new(),
            public_key_id: None,
            private_key_pem: None,
            ed25519_public_key: None,
            ed25519_private_key: None,
            domain: "noombat.example".to_owned(),
            is_local: true,
            inbox_url: None,
            instance_role: noombat_core::actor::InstanceRole::User,
            actor_status: noombat_core::actor::ActorStatus::Active,
            chat_requires_reprovisioning: false,
            chatmail_addr: None,
            orcid: None,
            moved_to: None,
            actor_privacy: noombat_core::privacy::ActorPrivacy::default(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn posting(actor_id: uuid::Uuid) -> JobPosting {
        JobPosting {
            id: uuid::Uuid::nil(),
            actor_id,
            ap_id: "https://noombat.example/jobs/00000000-0000-0000-0000-000000000000".to_owned(),
            title: "Rust Engineer".to_owned(),
            description_md: String::new(),
            description_html: String::new(),
            location: Some("Berlin".to_owned()),
            remote: true,
            salary_min: None,
            salary_max: None,
            currency: None,
            requirements: None,
            published_at: Some(chrono::Utc::now()),
            expires_at: None,
            created_at: chrono::Utc::now(),
            org_kind: Some(noombat_core::actor::OrgKind::Employer),
        }
    }

    #[test]
    fn the_note_is_attributed_to_the_organisation() {
        let org = organisation();
        let activity = publicising_note(&org, &posting(org.id), "noombat.example");

        assert_eq!(activity["type"], "Create");
        assert_eq!(activity["actor"], org.ap_id);
        assert_eq!(activity["object"]["type"], "Note");
        assert_eq!(activity["object"]["attributedTo"], org.ap_id);
    }

    #[test]
    fn the_note_points_at_the_listing_and_carries_it_as_canonical() {
        let org = organisation();
        let job = posting(org.id);
        let activity = publicising_note(&org, &job, "noombat.example");

        let listing = format!("https://noombat.example/jobs/{}", job.id);
        assert_eq!(activity["object"]["url"], listing);
        // The inbound de-duplication matches on this, so a peer that
        // meets the same job twice keeps one post.
        assert_eq!(activity["object"]["canonicalUri"], listing);
        assert!(
            activity["object"]["content"]
                .as_str()
                .expect("content is a string")
                .contains(&listing),
            "the Note must carry the link a reader follows"
        );
    }

    #[test]
    fn what_travels_is_a_note_and_not_the_listing() {
        // Peers get an ordinary Note they can render, never a
        // `noombat:JobPosting` they cannot.
        let org = organisation();
        let activity = publicising_note(&org, &posting(org.id), "noombat.example");

        let object_type = &activity["object"]["type"];
        assert_eq!(object_type, "Note");
        assert!(
            !object_type.to_string().contains("JobPosting"),
            "the listing type must not federate: {object_type}"
        );
        // None of the structured job fields travel either.
        for absent in ["salary", "schema:baseSalary", "requirements"] {
            assert!(
                activity["object"].get(absent).is_none(),
                "the Note carries {absent}, which belongs to the listing"
            );
        }
    }

    #[test]
    fn recruiter_input_cannot_close_the_tag_it_sits_in() {
        let org = organisation();
        let mut job = posting(org.id);
        job.title = "</b><script>alert(1)</script>".to_owned();

        let activity = publicising_note(&org, &job, "noombat.example");
        let content = activity["object"]["content"]
            .as_str()
            .expect("content is a string");

        assert!(!content.contains("<script>"), "unescaped title: {content}");
        assert!(content.contains("&lt;script&gt;"));
    }

    #[test]
    fn the_delete_names_the_note_and_not_the_listing() {
        let activity = withdrawing_delete(
            "https://noombat.example/users/acme",
            "https://noombat.example/jobs/abc",
        );

        assert_eq!(activity["type"], "Delete");
        // The peer holds the Note. Naming the listing would ask it to
        // delete something it never had.
        assert_eq!(activity["object"], "https://noombat.example/jobs/abc#note");
    }
}
