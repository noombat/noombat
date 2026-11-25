// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Watch `locales/` so that a changed translation rebuilds this crate.
//!
//! `rust_i18n::i18n!` reads the locale files while it expands, at compile
//! time, and tells Cargo about none of them, so a build that only changed
//! a translation would keep serving, and testing, the old tables. A
//! directory here is scanned whole, so an added file counts too.

fn main() {
    println!("cargo::rerun-if-changed=locales");
}
