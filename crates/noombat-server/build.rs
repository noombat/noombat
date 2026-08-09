// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Watch `migrations/` so that adding a file invalidates this binary.
//!
//! `sqlx::migrate!` embeds the migration set at compile time. It does
//! register a dependency on each file it *found*, through the
//! `include_str!` it emits per migration, but never on the directory
//! that holds them. Directory registration is `proc_macro::tracked::path`,
//! gated behind `#[cfg(any(sqlx_macros_unstable, procmacro2_semver_exempt))]`
//! (`sqlx-macros-core-0.9.0/src/migrate.rs:123`), and this project sets
//! neither cfg. Cargo therefore has no reason to re-expand the macro when
//! a migration is *added*: only when one that already existed changes.
//!
//! Left alone, the first schema change that adds a file rather than
//! amending `0001` produces a binary that silently omits it on every
//! warm-cache build, and a server that creates the tables it embedded,
//! reports success, and fails later in whatever code reads the table it
//! never created.
//!
//! The other way to close this is `RUSTFLAGS=--cfg procmacro2_semver_exempt`,
//! which enables the tracking above. It also changes the fingerprint of
//! every proc-macro crate in the graph and forces a full rebuild, and it
//! leans on an unstable cfg, so this takes the cheap and portable option.
//!
//! Watching the directory is necessary but not sufficient: it fixes new
//! builds and does nothing for a `target` tree that already went stale.
//! The assertion in `main.rs` is what catches that one.

fn main() {
    // Relative to the package root, so this is the `migrations/` at the
    // workspace root: the same directory `sqlx::migrate!` is pointed at
    // from `main.rs`. Cargo walks it, so adding or removing a file
    // counts as a change, which is the case the macro misses.
    println!("cargo::rerun-if-changed=../../migrations");
}
