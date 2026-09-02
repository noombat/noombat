// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The interop suite's sign-in credential still works.
//!
//! `tests/interop/seed.sh` stores an Argon2id hash and `tests/interop/run.sh`
//! sends the key it hashes; neither script can run Argon2, so the hash is
//! committed rather than computed. That leaves one way for it to rot: a
//! change to the hashing that stops the committed string verifying. This
//! catches that here, in seconds, rather than in a Docker-based federation
//! suite that runs rarely and would report it as a sign-in failure three
//! hundred lines from the cause.
//!
//! The constants are read from the shell file rather than repeated, so the
//! thing under test is the pair the harness actually uses.
//!
//! To regenerate after an intentional change, run this with `--nocapture`
//! and copy the printed hash into `fixture-credential.sh`.

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

/// Read a `NAME="value"` or `NAME='value'` assignment from the shell file.
fn shell_const(source: &str, name: &str) -> String {
    let line = source
        .lines()
        .find(|l| l.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} is not assigned in fixture-credential.sh"));
    let value = &line[name.len() + 1..];
    value
        .trim_matches(|c| c == '"' || c == '\'')
        .trim()
        .to_owned()
}

/// Every committed (key, hash) pair, with the file it came from.
///
/// Two harnesses seed a sign-in credential in SQL, for the same reason:
/// neither can run Argon2, and `POST /api/v1/auth/register` refuses
/// without an SMTP relay. Both are pinned here so that one of them
/// cannot rot unnoticed while the other is exercised.
fn fixtures() -> Vec<(&'static str, String, String)> {
    let files = [
        (
            "tests/interop/fixture-credential.sh",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/interop/fixture-credential.sh"
            ),
            "FIXTURE_AUTH_KEY",
            "FIXTURE_AUTH_KEY_HASH",
        ),
        (
            "scripts/e2e-stack.sh",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/e2e-stack.sh"),
            "E2E_AUTH_KEY",
            "E2E_AUTH_KEY_HASH",
        ),
    ];

    files
        .iter()
        .map(|(label, path, key_name, hash_name)| {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("cannot read the fixture at {path}: {e}"));
            (
                *label,
                shell_const(&source, key_name),
                shell_const(&source, hash_name),
            )
        })
        .collect()
}

#[test]
fn every_committed_hash_verifies_against_its_committed_key() {
    for (label, key, hash) in fixtures() {
        // Printed so that a regeneration needs no second command.
        let salt = SaltString::generate(&mut OsRng);
        let fresh = Argon2::default()
            .hash_password(key.as_bytes(), &salt)
            .expect("hashing the fixture key");
        println!("{label}: {fresh}");

        let parsed = PasswordHash::new(&hash)
            .unwrap_or_else(|e| panic!("{label} holds an invalid PHC string: {e}"));
        Argon2::default()
            .verify_password(key.as_bytes(), &parsed)
            .unwrap_or_else(|_| panic!("{label}: the committed hash does not verify its key"));
    }
}

#[test]
fn every_committed_key_is_a_well_formed_auth_key() {
    // The server refuses anything else, so a malformed key would fail at
    // login with a message about the field rather than about the fixture.
    for (label, key, _) in fixtures() {
        assert_eq!(key.len(), 64, "{label}: auth_key is 32 bytes, hex-encoded");
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()), "{label}: {key}");
    }
}

#[test]
fn another_key_does_not_verify() {
    // Guards the guard: a verify that accepted anything would make the
    // test above pass whatever the committed hashes said.
    for (label, _, hash) in fixtures() {
        let parsed = PasswordHash::new(&hash).expect("valid PHC string");
        assert!(
            Argon2::default()
                .verify_password(b"not the fixture key", &parsed)
                .is_err(),
            "{label}"
        );
    }
}

#[test]
fn the_two_fixtures_do_not_share_a_key() {
    // They authenticate different accounts on different stacks. Sharing
    // one would make a change to either silently rebind the other.
    let all = fixtures();
    let (a, b) = (&all[0], &all[1]);
    assert_ne!(a.1, b.1, "{} and {} share a key", a.0, b.0);
}
