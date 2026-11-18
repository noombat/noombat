// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The default CV template, typeset by the real compiler and read back.
//!
//! Its own binary, so its compilations never share the process-wide Typst
//! limits with the unit test that kills a slow compilation, nor, under
//! `cargo test`, which runs one binary at a time, that test's count of
//! running `typst` processes.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use chrono::{NaiveDate, Utc};
use noombat_identity::cv::{CvProfile, typeset_cv};
use noombat_identity::profile::{EducationEntry, ScholarlyArticle, Skill, WorkExperience};
use noombat_identity::verification::VerifiedLink;
use uuid::Uuid;

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).expect("a valid date")
}

fn education(institution: &str, degree: Option<&str>, field: Option<&str>) -> EducationEntry {
    EducationEntry {
        id: Uuid::new_v4(),
        actor_id: Uuid::nil(),
        institution: institution.to_owned(),
        degree: degree.map(str::to_owned),
        field_of_study: field.map(str::to_owned),
        start_date: date(2016, 9, 1),
        end_date: Some(date(2020, 6, 30)),
        description_md: None,
        description_html: None,
        sort_order: 0,
        visibility: "public".to_owned(),
    }
}

/// The CV's text as `pdftotext` reads it from the PDF.
fn text_of(pdf: &[u8]) -> String {
    let mut child = Command::new("pdftotext")
        .args(["-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("pdftotext runs");
    child
        .stdin
        .take()
        .expect("pdftotext's stdin")
        .write_all(pdf)
        .expect("the PDF reaches pdftotext");
    let output = child.wait_with_output().expect("pdftotext finishes");
    assert!(output.status.success(), "pdftotext failed on the CV");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Whether a command is on PATH.
fn present(command: &str, flag: &str) -> bool {
    Command::new(command).arg(flag).output().is_ok()
}

/// Whether the test can run: the tools it names are present. Where
/// NOOMBAT_REQUIRE_TYPST is set, as CI's typst job sets it after
/// installing them, a missing one fails the test rather than skipping it.
fn tools_present(test: &str, tools: &[(&str, &str)]) -> bool {
    let missing: Vec<&str> = tools
        .iter()
        .filter(|(command, flag)| !present(command, flag))
        .map(|(command, _)| *command)
        .collect();
    if missing.is_empty() {
        return true;
    }
    assert!(
        std::env::var_os("NOOMBAT_REQUIRE_TYPST").is_none(),
        "{missing:?} missing, but NOOMBAT_REQUIRE_TYPST is set: {test} did not run. \
         The typst-injection job installs them before running it."
    );
    eprintln!("SKIPPED {test}: {missing:?} missing. The typst-injection CI job runs it.");
    false
}

const TYPST: (&str, &str) = ("typst", "--version");
const PDFTOTEXT: (&str, &str) = ("pdftotext", "-v");

fn no_sections<'a>(name: &'a str) -> CvProfile<'a> {
    CvProfile {
        name,
        headline: None,
        summary_md: None,
        orcid: None,
        experiences: &[],
        educations: &[],
        skills: &[],
        publications: &[],
        links: &[],
    }
}

/// Every section the generator emits is typeset: the CV compiles, heads
/// each section in plain words, names each employer, and shows a field of
/// study with no degree beside it.
#[ignore = "requires the typst binary and pdftotext; run with --include-ignored"]
#[tokio::test]
async fn the_default_template_typesets_every_section() {
    if !tools_present(
        "the_default_template_typesets_every_section",
        &[TYPST, PDFTOTEXT],
    ) {
        return;
    }

    let experiences = [WorkExperience {
        id: Uuid::new_v4(),
        actor_id: Uuid::nil(),
        title: "Research engineer".to_owned(),
        organization: "Example Labs".to_owned(),
        organization_id: None,
        organization_confirmed_at: None,
        organization_confirmed_via: None,
        start_date: date(2021, 1, 4),
        end_date: None,
        description_md: None,
        description_html: None,
        sort_order: 0,
        visibility: "public".to_owned(),
    }];
    let educations = [
        education("University of Example", Some("PhD"), Some("Logic")),
        education("Example College", None, Some("Mathematics")),
    ];
    let skills = [Skill {
        id: Uuid::new_v4(),
        actor_id: Uuid::nil(),
        name: "Type theory".to_owned(),
        visibility: "public".to_owned(),
    }];
    let publications = [ScholarlyArticle {
        id: Uuid::new_v4(),
        actor_id: Uuid::nil(),
        doi: "10.1000/example".to_owned(),
        title: "Proofs as programs".to_owned(),
        authors: serde_json::json!(["Alice Example"]),
        abstract_md: None,
        abstract_html: None,
        journal: Some("Journal of Examples".to_owned()),
        publisher: None,
        published_date: Some(date(2022, 3, 1)),
        visibility: "public".to_owned(),
        fetched_at: Utc::now(),
    }];
    let links = [VerifiedLink {
        id: Uuid::new_v4(),
        actor_id: Uuid::nil(),
        url: "https://alice.example/".to_owned(),
        verified_at: Some(Utc::now()),
        last_checked: Utc::now(),
        visibility: "public".to_owned(),
    }];
    let cv = CvProfile {
        name: "Alice Example",
        headline: Some("Research engineer"),
        summary_md: None,
        orcid: None,
        experiences: &experiences,
        educations: &educations,
        skills: &skills,
        publications: &publications,
        links: &links,
    };
    let templates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../templates");

    let pdf = typeset_cv(&cv, &templates, "default", "apa")
        .await
        .expect("the default template typesets");
    let text = text_of(&pdf);

    for expected in [
        "Work experience",
        "Example Labs",
        "Education",
        "PhD · Logic",
        "Mathematics",
        "Scholarly articles",
        "Proofs as programs",
        "Type theory",
        "https://alice.example/",
    ] {
        assert!(
            text.contains(expected),
            "the CV does not show \"{expected}\": {text}"
        );
    }
    assert!(
        !text.contains("· Mathematics"),
        "a field of study with no degree must not follow a separator: {text}"
    );
    for type_name in ["WorkExperience", "EducationEntry", "ScholarlyArticles"] {
        assert!(
            !text.contains(type_name),
            "a heading must be words, not the type name {type_name}: {text}"
        );
    }
}

/// A template that cannot compile fails with Typst's own diagnostic in the
/// error, which the log then shows: the error and the variable it names.
#[ignore = "requires the typst binary; run with --include-ignored"]
#[tokio::test]
async fn a_failed_compilation_names_its_error() {
    if !tools_present("a_failed_compilation_names_its_error", &[TYPST]) {
        return;
    }
    let templates = tempfile::tempdir().expect("a template directory");
    std::fs::write(
        templates.path().join("broken.typ"),
        "= #name\n#if nonesuch.len() > 0 [never]\n",
    )
    .expect("the broken template is written");

    let result = typeset_cv(
        &no_sections("Alice Example"),
        templates.path(),
        "broken",
        "apa",
    )
    .await;

    match result {
        Err(noombat_core::error::NoombatError::Internal(message)) => assert!(
            message.contains("unknown variable: nonesuch"),
            "the error must carry Typst's diagnostic: {message}"
        ),
        Err(other) => panic!("expected an internal error from typst, got {other:?}"),
        Ok(_) => panic!("a template naming an unknown variable compiled"),
    }
}
