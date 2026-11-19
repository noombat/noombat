// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! The server, started as a process for a domain other than `localhost`,
//! refuses a configuration unfit for production: the checks' wiring, which
//! the unit tests of each check do not reach.

use std::process::Command;

/// The server's output when started for `noombat.example` with ORCID at
/// `orcid`, in an empty folder and an empty environment otherwise. It
/// stops at the checks: no secrets are set, so some always fail.
fn refusals_with_orcid_at(orcid: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "noombat-production-config-{}-{}",
        std::process::id(),
        orcid.len()
    ));
    std::fs::create_dir_all(&dir).expect("an empty folder");
    let output = Command::new(env!("CARGO_BIN_EXE_noombat"))
        .current_dir(&dir)
        .env_clear()
        .env("NOOMBAT_DOMAIN", "noombat.example")
        .env("NOOMBAT_DATABASE_URL", "postgres://u:p@127.0.0.1:1/x")
        .env("NOOMBAT_ORCID_BASE_URI", orcid)
        .output()
        .expect("the server runs");
    std::fs::remove_dir_all(&dir).expect("the folder removed");
    assert!(!output.status.success(), "the server refused to start");
    String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr)
}

#[test]
fn an_orcid_address_that_is_not_https_is_refused_at_startup() {
    let refused = refusals_with_orcid_at("http://orcid.example");
    assert!(
        refused.contains("NOOMBAT_ORCID_BASE_URI is \"http://orcid.example\""),
        "{refused}"
    );
    assert!(refused.contains("aborting"), "{refused}");
    let refused = refusals_with_orcid_at("https://orcid.example");
    assert!(!refused.contains("NOOMBAT_ORCID_BASE_URI"), "{refused}");
    assert!(refused.contains("aborting"), "{refused}");
}
