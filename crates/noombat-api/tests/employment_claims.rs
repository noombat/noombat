// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Employment is a two-sided claim.
//!
//! The property worth asserting is not that a badge can be set. It is that
//! the badge cannot outlive the claim it was given for: being confirmed at
//! one employer and then editing the row to name another is the exact
//! impersonation this feature exists to prevent, and it is invisible to a
//! test that only checks the happy path.

use chrono::NaiveDate;
use noombat_identity::profile::{
    ConfirmedVia, NewWorkExperience, UpdateWorkExperience, confirm_employment,
    create_work_experience, update_work_experience, withdraw_employment_confirmation,
};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn actor(pool: &PgPool, kind: &str, label: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ($1, $2, $3, 'PEM', $4, TRUE) RETURNING id",
    )
    .bind(kind)
    .bind(format!("https://{DOMAIN}/users/{label}-{id}"))
    .bind(format!("{label}{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert actor")
}

fn claim(organization: &str, organization_id: Option<Uuid>) -> NewWorkExperience {
    NewWorkExperience {
        title: "Engineer".to_owned(),
        organization: organization.to_owned(),
        organization_id,
        start_date: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
        end_date: None,
        description_md: None,
        sort_order: None,
        visibility: Some("public".to_owned()),
    }
}

fn edit() -> UpdateWorkExperience {
    UpdateWorkExperience {
        title: None,
        organization: None,
        organization_id: None,
        start_date: None,
        end_date: None,
        description_md: None,
        sort_order: None,
        visibility: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_starts_unconfirmed(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;
    let acme = actor(&pool, "organization", "acme").await;

    let row = create_work_experience(&pool, person, &claim("Acme", Some(acme)))
        .await
        .expect("create claim");

    assert!(!row.is_confirmed(), "naming an actor is not confirmation");
    assert_eq!(row.organization_id, Some(acme));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_organisation_confirms_and_can_withdraw(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;
    let acme = actor(&pool, "organization", "acme").await;
    let row = create_work_experience(&pool, person, &claim("Acme", Some(acme)))
        .await
        .unwrap();

    let confirmed = confirm_employment(&pool, row.id, acme, ConfirmedVia::Organisation)
        .await
        .expect("confirm");
    assert!(confirmed.is_confirmed());
    assert_eq!(
        confirmed.organization_confirmed_via.as_deref(),
        Some("organisation")
    );
    let wire: serde_json::Value =
        sqlx::query_scalar("SELECT ap_object FROM work_experiences WHERE id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .expect("read wire form");
    assert_eq!(
        wire["noombat:organizationConfirmed"],
        serde_json::json!(true),
        "the row says confirmed and the document a peer receives does not"
    );

    let withdrawn = withdraw_employment_confirmation(&pool, row.id, acme)
        .await
        .expect("withdraw");
    assert!(!withdrawn.is_confirmed());
    assert_eq!(
        withdrawn.organization, "Acme",
        "withdrawing a confirmation must not edit the claim"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn another_organisation_cannot_confirm_the_claim(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;
    let acme = actor(&pool, "organization", "acme").await;
    let globex = actor(&pool, "organization", "globex").await;
    let row = create_work_experience(&pool, person, &claim("Acme", Some(acme)))
        .await
        .unwrap();

    let refused = confirm_employment(&pool, row.id, globex, ConfirmedVia::Organisation).await;
    assert!(refused.is_err(), "Globex confirmed a claim naming Acme");
}

#[sqlx::test(migrations = "../../migrations")]
async fn rewriting_the_employer_name_drops_the_confirmation(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;
    let acme = actor(&pool, "organization", "acme").await;
    let row = create_work_experience(&pool, person, &claim("Acme", Some(acme)))
        .await
        .unwrap();
    confirm_employment(&pool, row.id, acme, ConfirmedVia::Organisation)
        .await
        .unwrap();

    let edited = update_work_experience(
        &pool,
        person,
        row.id,
        &UpdateWorkExperience {
            organization: Some("Globex".to_owned()),
            ..edit()
        },
    )
    .await
    .expect("edit");

    assert!(
        !edited.is_confirmed(),
        "a badge given for Acme survived being renamed to Globex"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn repointing_the_reference_drops_the_confirmation(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;
    let acme = actor(&pool, "organization", "acme").await;
    let globex = actor(&pool, "organization", "globex").await;
    let row = create_work_experience(&pool, person, &claim("Acme", Some(acme)))
        .await
        .unwrap();
    confirm_employment(&pool, row.id, acme, ConfirmedVia::Organisation)
        .await
        .unwrap();

    let edited = update_work_experience(
        &pool,
        person,
        row.id,
        &UpdateWorkExperience {
            organization_id: Some(Some(globex)),
            ..edit()
        },
    )
    .await
    .expect("edit");

    assert!(
        !edited.is_confirmed(),
        "a badge given by Acme survived being repointed at Globex"
    );
    assert_eq!(edited.organization_id, Some(globex));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unrelated_edit_keeps_the_confirmation(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;
    let acme = actor(&pool, "organization", "acme").await;
    let row = create_work_experience(&pool, person, &claim("Acme", Some(acme)))
        .await
        .unwrap();
    confirm_employment(&pool, row.id, acme, ConfirmedVia::Organisation)
        .await
        .unwrap();

    let edited = update_work_experience(
        &pool,
        person,
        row.id,
        &UpdateWorkExperience {
            title: Some("Senior engineer".to_owned()),
            ..edit()
        },
    )
    .await
    .expect("edit");

    assert!(
        edited.is_confirmed(),
        "a promotion is not a change of employer, and must not cost the badge"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_schema_refuses_a_confirmation_with_nothing_to_point_at(pool: PgPool) {
    let person = actor(&pool, "individual", "alice").await;

    let refused = sqlx::query(
        "INSERT INTO work_experiences \
             (actor_id, title, organization, organization_confirmed_at, start_date, ap_object) \
         VALUES ($1, 'Engineer', 'Acme', now(), '2024-01-01', '{}'::jsonb)",
    )
    .bind(person)
    .execute(&pool)
    .await;

    assert!(
        refused.is_err(),
        "a free-text row was confirmed with no organisation behind it"
    );
}
