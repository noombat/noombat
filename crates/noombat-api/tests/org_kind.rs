// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! A job seeker can tell an employer's posting from an agency's.
//!
//! The column existed with no reader, so a posting from a recruiter
//! looked exactly like one from the company hiring. These assertions
//! cover the two halves that have to move together: the declaration
//! reaching the posting a seeker reads, and the filter that narrows a
//! list to one kind.

use noombat_core::actor::OrgKind;
use noombat_jobs::{NewJobPosting, create_job, list_published_jobs};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

/// An organisation, declared or not.
async fn organisation(pool: &PgPool, kind: Option<OrgKind>) -> Uuid {
    let id = Uuid::new_v4();
    let actor = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('organization', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/org-{id}"))
    .bind(format!("org{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert organisation");

    if let Some(kind) = kind {
        sqlx::query("UPDATE actors SET org_kind = $1 WHERE id = $2")
            .bind(kind.as_str())
            .bind(actor)
            .execute(pool)
            .await
            .expect("declare org kind");
    }
    actor
}

fn posting(title: &str) -> NewJobPosting {
    NewJobPosting {
        title: title.to_owned(),
        description_md: "Build things.".to_owned(),
        location: None,
        remote: Some(true),
        salary_min: None,
        salary_max: None,
        currency: None,
        requirements: None,
        expires_at: None,
        publish: true,
    }
}

/// The badge's value. Read from the posting, because that is where the
/// seeker meets it: a declaration that stops at the actor row is the
/// state this feature replaced.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn a_posting_carries_its_poster_declaration(pool: PgPool) {
    let agency = organisation(&pool, Some(OrgKind::Agency)).await;
    let job = create_job(&pool, agency, None, DOMAIN, &posting("Recruiting"))
        .await
        .expect("create posting");

    assert_eq!(job.org_kind, Some(OrgKind::Agency));

    let fetched = noombat_jobs::get_job(&pool, job.id).await.expect("get");
    assert_eq!(fetched.org_kind, Some(OrgKind::Agency));
}

/// Re-declaring changes every posting, including ones already published.
/// The value is read from the actor rather than copied onto the posting
/// precisely so that an agency cannot leave last year's postings
/// claiming to be a direct employer.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn redeclaring_moves_existing_postings(pool: PgPool) {
    let org = organisation(&pool, Some(OrgKind::Employer)).await;
    let job = create_job(&pool, org, None, DOMAIN, &posting("Engineer"))
        .await
        .expect("create posting");
    assert_eq!(job.org_kind, Some(OrgKind::Employer));

    noombat_identity::repo::set_org_kind(&pool, org, OrgKind::Agency)
        .await
        .expect("redeclare");

    let after = noombat_jobs::get_job(&pool, job.id).await.expect("get");
    assert_eq!(after.org_kind, Some(OrgKind::Agency));
}

/// The filter half. A seeker asking for direct employers must not be
/// shown an agency's posting, and asking for nothing must still show
/// both.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn the_filter_narrows_to_one_kind(pool: PgPool) {
    let employer = organisation(&pool, Some(OrgKind::Employer)).await;
    let agency = organisation(&pool, Some(OrgKind::Agency)).await;
    create_job(&pool, employer, None, DOMAIN, &posting("Direct role"))
        .await
        .expect("employer posting");
    create_job(&pool, agency, None, DOMAIN, &posting("Agency role"))
        .await
        .expect("agency posting");

    let employers = list_published_jobs(&pool, Some(OrgKind::Employer), 20, 0)
        .await
        .expect("list employers");
    let titles: Vec<&str> = employers.iter().map(|j| j.title.as_str()).collect();
    assert_eq!(titles, vec!["Direct role"]);

    let agencies = list_published_jobs(&pool, Some(OrgKind::Agency), 20, 0)
        .await
        .expect("list agencies");
    let titles: Vec<&str> = agencies.iter().map(|j| j.title.as_str()).collect();
    assert_eq!(titles, vec!["Agency role"]);

    let everything = list_published_jobs(&pool, None, 20, 0)
        .await
        .expect("list all");
    assert_eq!(everything.len(), 2);
}

/// An individual's posting is in neither filtered list, and is not
/// silently folded into "employer". Nobody asked them, and answering for
/// them is what the nullable column exists to avoid.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_undeclared_poster_is_in_neither_list(pool: PgPool) {
    let id = Uuid::new_v4();
    let person = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/person-{id}"))
    .bind(format!("person{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(&pool)
    .await
    .expect("insert individual");

    create_job(&pool, person, None, DOMAIN, &posting("Freelance"))
        .await
        .expect("create posting");

    assert!(
        list_published_jobs(&pool, Some(OrgKind::Employer), 20, 0)
            .await
            .expect("employers")
            .is_empty()
    );
    assert!(
        list_published_jobs(&pool, Some(OrgKind::Agency), 20, 0)
            .await
            .expect("agencies")
            .is_empty()
    );
    assert_eq!(
        list_published_jobs(&pool, None, 20, 0)
            .await
            .expect("all")
            .len(),
        1
    );
}

/// The constraint that keeps the declaration meaningful: only an
/// organisation carries one, so an individual cannot be labelled an
/// employer by a stray write.
#[ignore = "requires a database; run with --include-ignored"]
#[sqlx::test(migrations = "../../migrations")]
async fn an_individual_cannot_be_declared(pool: PgPool) {
    let id = Uuid::new_v4();
    let person = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/person-{id}"))
    .bind(format!("person{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(&pool)
    .await
    .expect("insert individual");

    let refused = sqlx::query("UPDATE actors SET org_kind = 'employer' WHERE id = $1")
        .bind(person)
        .execute(&pool)
        .await;
    assert!(refused.is_err(), "the constraint should refuse this row");

    // And the route refuses it too, so a caller sees a request error
    // rather than a database one.
    assert!(
        noombat_identity::repo::set_org_kind(&pool, person, OrgKind::Employer)
            .await
            .is_err()
    );
}
