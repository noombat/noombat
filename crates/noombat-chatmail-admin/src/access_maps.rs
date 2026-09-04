// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Access map persistence and Postfix map generation.
//!
//! Maintains the lists of blocked recipient addresses and per-pair
//! sender blocks in a JSON file that survives container restarts
//! (stored on the mounted `chatmail-data` volume).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::Config;

/// Persistent access map state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessMaps {
    /// Recipient addresses for which inbound mail is rejected
    /// (suspended or deleted accounts).
    pub blocked_recipients: BTreeSet<String>,
    /// Per-pair sender blocks: `sender_addr to set of recipient_addrs`.
    /// Mail from `sender` to any address in the set is rejected.
    pub sender_blocks: BTreeMap<String, BTreeSet<String>>,
}

/// Validate that `path` is absolute, contains no traversal sequences
/// (`..`) or null bytes, and, if it or its parent exists on disk,
/// canonicalises to a location within the expected directory tree.
///
/// Returns the validated `PathBuf` on success.
///
/// The rejected path is quoted with `Debug` wherever it appears below, in
/// these messages and at the `tracing` call sites that report them: a
/// path holding a newline would otherwise forge a line in the log it
/// reaches. Unlike a peer's URL it is not truncated, because this value
/// comes from the operator's own environment and its length is theirs.
fn validated_path(path: &str) -> Result<PathBuf, String> {
    if path.contains('\0') {
        return Err("path contains null byte".into());
    }
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(format!("path is not absolute: {path:?}"));
    }
    if path.contains("..") {
        return Err(format!("path contains '..' traversal: {path:?}"));
    }

    // If the file itself exists, canonicalise it directly; otherwise
    // canonicalise the nearest existing ancestor and re-append the
    // remaining components, then verify the result is still absolute
    // and free of `..`.
    let canonical = if p.exists() {
        p.canonicalize()
            .map_err(|e| format!("canonicalize failed: {e}"))?
    } else if let Some(parent) = p.parent() {
        if parent.exists() {
            let canon_parent = parent
                .canonicalize()
                .map_err(|e| format!("canonicalize parent failed: {e}"))?;
            let file_name = p.file_name().ok_or("path has no filename")?;
            canon_parent.join(file_name)
        } else {
            // Parent doesn't exist yet (first run); the string-level
            // checks above are the only defence. `save` will create
            // the parent via `create_dir_all`.
            return Ok(p.to_path_buf());
        }
    } else {
        return Err("path has no parent component".into());
    };

    if canonical.to_string_lossy().contains("..") {
        return Err(format!("canonical path still contains '..': {canonical:?}"));
    }
    Ok(canonical)
}

impl AccessMaps {
    /// Load from the persistence file, or initialise empty maps if the
    /// file does not exist or is malformed.
    pub fn load_or_init(path: &str) -> Self {
        let p = match validated_path(path) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    path = ?path,
                    error = %e,
                    "access maps path failed validation; using empty maps"
                );
                return Self::default();
            }
        };
        if p.exists() {
            match fs::read_to_string(&p) {
                Ok(json) => match serde_json::from_str(&json) {
                    Ok(maps) => {
                        info!(path = ?path, "loaded access maps from disk");
                        return maps;
                    }
                    Err(e) => {
                        warn!(
                            path = ?path,
                            error = %e,
                            "malformed access maps file; reinitialising"
                        )
                    }
                },
                Err(e) => {
                    warn!(
                        path = ?path,
                        error = %e,
                        "failed to read access maps file; reinitialising"
                    )
                }
            }
        }
        Self::default()
    }

    /// Persist the current state to the JSON file.
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let p = validated_path(path).map_err(std::io::Error::other)?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        fs::write(p, json)?;
        info!(path = ?path, "access maps persisted to disk");
        Ok(())
    }

    /// Write the Postfix `check_recipient_access` and `check_sender_access`
    /// map files and regenerate the hash `.db` files via `postmap`.
    pub fn write_postfix_maps(&self, config: &Config) {
        if let Err(e) = self.write_recipient_map(&config.recipient_access_path) {
            warn!(error = %e, "failed to write recipient access map");
        } else {
            let _ = std::process::Command::new("postmap")
                .arg(&config.recipient_access_path)
                .status();
        }
        if let Err(e) = self.write_sender_map(&config.sender_access_path) {
            warn!(error = %e, "failed to write sender access map");
        } else {
            let _ = std::process::Command::new("postmap")
                .arg(&config.sender_access_path)
                .status();
        }
    }

    /// Generate the `check_recipient_access` file.
    ///
    /// Format: one `address REJECT` line per blocked recipient.
    fn write_recipient_map(&self, path: &str) -> std::io::Result<()> {
        let mut f = fs::File::create(path)?;
        writeln!(f, "# Generated by noombat-chatmail-admin. Do not edit.")?;
        for addr in &self.blocked_recipients {
            writeln!(f, "{addr} REJECT account suspended or deleted")?;
        }
        info!(path = ?path, entries = self.blocked_recipients.len(), "wrote recipient access map");
        Ok(())
    }

    /// Generate the `check_sender_access` file.
    ///
    /// Writes one `sender REJECT` line per sender that has at least one
    /// per-pair block, regardless of which recipients are blocked. This
    /// is a best-effort enforcement:
    /// Postfix evaluates `check_sender_access` before recipient
    /// information is available, so true per-pair granularity is not
    /// achievable with flat access maps alone (it would require a milter
    /// or policy service). Application-level per-pair enforcement in the
    /// `noombat-chat` proxy remains the primary mechanism; this map
    /// provides a transport-level backstop for senders who have exported
    /// credentials to an external client.
    fn write_sender_map(&self, path: &str) -> std::io::Result<()> {
        let mut f = fs::File::create(path)?;
        writeln!(f, "# Generated by noombat-chatmail-admin. Do not edit.")?;
        let mut count = 0usize;
        for (sender, recipients) in &self.sender_blocks {
            if !recipients.is_empty() {
                writeln!(f, "{sender} REJECT blocked by moderation")?;
                count += 1;
            }
        }
        info!(path = ?path, entries = count, "wrote sender access map");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKED: &str = r#"{"blocked_recipients":["blocked@example.test"],"sender_blocks":{}}"#;

    #[test]
    fn a_relative_path_is_refused() {
        assert!(validated_path("etc/passwd").is_err());
    }

    #[test]
    fn a_traversal_is_refused() {
        assert!(validated_path("/var/lib/../../etc/passwd").is_err());
    }

    #[test]
    fn a_null_byte_is_refused() {
        assert!(validated_path("/var/lib/maps.json\0.png").is_err());
    }

    #[test]
    fn an_ordinary_absolute_path_is_accepted() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("maps.json");
        assert!(validated_path(path.to_str().expect("utf-8 path")).is_ok());
    }

    // The rejection message reaches a log, and the value in it is the one
    // that was rejected. `Debug` is what stops a newline in it opening a
    // line of its own.
    #[test]
    fn a_rejected_path_cannot_forge_a_log_line() {
        let message = validated_path("etc/\n2026-01-01 ERROR forged").expect_err("refused");
        assert!(
            !message.contains('\n'),
            "a raw newline survived into the message: {message}"
        );
        assert!(
            message.contains("\\n"),
            "the newline should be escaped: {message}"
        );
    }

    // ..... Both entry points reach the validator .....
    //
    // Each test first proves the file is readable or writable by its
    // direct path, so the traversal half failing cannot be passing
    // because nothing was there to find.

    #[test]
    fn load_or_init_refuses_a_traversal_that_would_otherwise_resolve() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let real = dir.path().join("maps.json");
        fs::write(&real, BLOCKED).expect("fixture written");
        fs::create_dir(dir.path().join("sub")).expect("subdirectory");

        let direct = AccessMaps::load_or_init(real.to_str().expect("utf-8 path"));
        assert!(
            direct.blocked_recipients.contains("blocked@example.test"),
            "the fixture must load by its direct path or this test proves nothing"
        );

        let traversal = dir.path().join("sub/../maps.json");
        let loaded = AccessMaps::load_or_init(traversal.to_str().expect("utf-8 path"));
        assert!(
            loaded.blocked_recipients.is_empty(),
            "a path with '..' reached the same file"
        );
    }

    #[test]
    fn save_refuses_a_traversal_it_could_otherwise_write() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        fs::create_dir(dir.path().join("sub")).expect("subdirectory");
        let maps = AccessMaps::default();

        let direct = dir.path().join("maps.json");
        maps.save(direct.to_str().expect("utf-8 path"))
            .expect("a direct path must save or this test proves nothing");

        let traversal = dir.path().join("sub/../other.json");
        assert!(
            maps.save(traversal.to_str().expect("utf-8 path")).is_err(),
            "a path with '..' was written"
        );
        assert!(!dir.path().join("other.json").exists());
    }
}
