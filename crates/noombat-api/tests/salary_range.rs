// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Salary amounts survive the range a 32-bit column could not hold.
//!
//! The amount is stored as entered, in the major unit of its currency, so
//! the ceiling that matters is reached by ordinary postings in currencies
//! with a small unit rather than by extreme ones. These assertions fail
//! against an `INTEGER` column: the first two overflow the bind, and the
//! third is the boundary immediately above it.

use noombat_jobs::{NewJobPosting, create_job};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn employer(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('organization', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/acme-{id}"))
    .bind(format!("acme{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert employer")
}

fn posting(salary_min: i64, salary_max: i64, currency: &str) -> NewJobPosting {
    NewJobPosting {
        title: "Senior engineer".to_owned(),
        description_md: "Build things.".to_owned(),
        location: None,
        remote: Some(true),
        salary_min: Some(salary_min),
        salary_max: Some(salary_max),
        currency: Some(currency.to_owned()),
        requirements: None,
        expires_at: None,
        publish: true,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_vietnamese_senior_salary_round_trips(pool: PgPool) {
    let actor = employer(&pool).await;
    // Roughly USD 85,000 at 2026 rates, which is where INTEGER runs out.
    let job = create_job(
        &pool,
        actor,
        DOMAIN,
        &posting(2_000_000_000, 2_600_000_000, "VND"),
    )
    .await
    .expect("create posting");

    assert_eq!(job.salary_min, Some(2_000_000_000));
    assert_eq!(job.salary_max, Some(2_600_000_000));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_indonesian_senior_salary_round_trips(pool: PgPool) {
    let actor = employer(&pool).await;
    let job = create_job(
        &pool,
        actor,
        DOMAIN,
        &posting(1_800_000_000, 3_500_000_000, "IDR"),
    )
    .await
    .expect("create posting");

    assert_eq!(job.salary_max, Some(3_500_000_000));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_value_one_above_the_old_ceiling_survives(pool: PgPool) {
    let actor = employer(&pool).await;
    // i32::MAX + 1. The boundary is asserted on its own so that a
    // regression to INTEGER fails here even if the figures above were
    // ever revised downwards.
    let just_over = i64::from(i32::MAX) + 1;
    let job = create_job(&pool, actor, DOMAIN, &posting(just_over, just_over, "VND"))
        .await
        .expect("create posting");

    assert_eq!(job.salary_min, Some(2_147_483_648));
}
