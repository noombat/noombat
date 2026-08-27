// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! One moderation spine, for every kind of report.
//!
//! Two tables meant every duty owed to a reporter had to be implemented
//! twice, and the second one is the one that gets forgotten. These
//! assertions pin the shape that makes that impossible: a chat report is a
//! row in `reports`, and the queue is one query.
//!
//! They also pin the bounds on reporter-supplied text, which reaches a
//! moderator's screen and is therefore attacker-controlled input.

use noombat_chat::report::{ChatReportReason, ChatReportRequest, submit_report};
use sqlx::PgPool;
use uuid::Uuid;

const DOMAIN: &str = "noombat.example";

async fn reporter(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO actors (actor_type, ap_id, username, public_key_pem, domain, is_local) \
         VALUES ('individual', $1, $2, 'PEM', $3, TRUE) RETURNING id",
    )
    .bind(format!("https://{DOMAIN}/users/r-{id}"))
    .bind(format!("r{}", &id.simple().to_string()[..8]))
    .bind(DOMAIN)
    .fetch_one(pool)
    .await
    .expect("insert reporter")
}

fn request(addr: &str, message: Option<String>) -> ChatReportRequest {
    ChatReportRequest {
        target_addr: addr.to_owned(),
        message_content: message,
        message_date: None,
        reason: ChatReportReason::Harassment,
        comment: Some("please look at this".to_owned()),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_chat_report_is_a_row_in_reports(pool: PgPool) {
    let who = reporter(&pool).await;

    let submitted = submit_report(&pool, who, &request("spammer@relay.example", None))
        .await
        .expect("submit");

    let (addr, status): (Option<String>, String) =
        sqlx::query_as("SELECT target_chat_addr, status FROM reports WHERE id = $1")
            .bind(submitted.report_id)
            .fetch_one(&pool)
            .await
            .expect("the report is not in the reports table");

    assert_eq!(addr.as_deref(), Some("spammer@relay.example"));
    assert_eq!(status, "open");
}

#[sqlx::test(migrations = "../../migrations")]
async fn one_query_returns_both_kinds_of_report(pool: PgPool) {
    let who = reporter(&pool).await;
    let subject = reporter(&pool).await;

    submit_report(&pool, who, &request("spammer@relay.example", None))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO reports (reporter_id, target_actor_id, reason) VALUES ($1, $2, 'spam')",
    )
    .bind(who)
    .bind(subject)
    .execute(&pool)
    .await
    .unwrap();

    let open: i64 = sqlx::query_scalar("SELECT count(*) FROM reports WHERE status = 'open'")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(open, 2, "the queue needs two reads to see both kinds");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_oversized_quoted_message_is_refused(pool: PgPool) {
    let who = reporter(&pool).await;
    let huge = "a".repeat(8193);

    let refused = submit_report(&pool, who, &request("spammer@relay.example", Some(huge))).await;

    assert!(
        refused.is_err(),
        "unbounded attacker text reached the moderation queue"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn text_that_is_not_an_address_is_refused(pool: PgPool) {
    let who = reporter(&pool).await;

    for bad in [
        "",
        "no-at-sign",
        "two@at@signs",
        "user@nodot",
        "user@.leadingdot",
        "with space@relay.example",
        "control\u{0007}@relay.example",
    ] {
        let refused = submit_report(&pool, who, &request(bad, None)).await;
        assert!(refused.is_err(), "accepted {bad:?} as an address");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_plausible_address_is_accepted(pool: PgPool) {
    let who = reporter(&pool).await;

    // The counterpart to the refusals above: a check that rejects
    // everything would pass that test and be useless.
    submit_report(&pool, who, &request("someone@relay.example", None))
        .await
        .expect("a well-formed address was refused");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_schema_refuses_a_report_about_nothing(pool: PgPool) {
    let who = reporter(&pool).await;

    let refused = sqlx::query("INSERT INTO reports (reporter_id, reason) VALUES ($1, 'spam')")
        .bind(who)
        .execute(&pool)
        .await;

    assert!(refused.is_err(), "a report naming no target was accepted");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_schema_keeps_quoted_evidence_with_the_chat_case(pool: PgPool) {
    let who = reporter(&pool).await;
    let subject = reporter(&pool).await;

    let refused = sqlx::query(
        "INSERT INTO reports (reporter_id, target_actor_id, reason, reported_message) \
         VALUES ($1, $2, 'spam', 'quoted')",
    )
    .bind(who)
    .bind(subject)
    .execute(&pool)
    .await;

    assert!(
        refused.is_err(),
        "a moderator now has two places to look for the quoted message"
    );
}
