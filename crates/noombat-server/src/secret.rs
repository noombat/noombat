// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Configuration values that must not be printed, and where they come
//! from.
//!
//! Two problems, one for each half of this module.
//!
//! **A secret in a struct that derives `Debug` is one `tracing` call
//! from a log file.** `Secret` has no `Debug` that prints its value and
//! no `Display` at all, so reaching the string takes `expose()`, which
//! is greppable and reviewable. The alternative, remembering never to
//! format the config, is a property of today's code rather than of the
//! type.
//!
//! **A secret in the environment is readable by anything that can see
//! the process.** `docker inspect` prints it, `/proc/<pid>/environ`
//! holds it, and it reaches any crash reporter that captures the
//! environment. `NOOMBAT_X_FILE` names a file to read `NOOMBAT_X` from
//! instead, which is what Docker secrets, Kubernetes projected volumes
//! and systemd's `LoadCredential` all produce.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

/// A configuration value that is never printed.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// The value. Named so that reading one is visible in review.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value, trimmed, or `None` when it is blank.
    ///
    /// A shell that expands an unset variable yields the empty string,
    /// so `NOOMBAT_KEK=` arrives as `Some("")`, which is not a key and
    /// must not be treated as one.
    pub fn non_empty(&self) -> Option<&str> {
        let trimmed = self.0.trim();
        (!trimmed.is_empty()).then_some(trimmed)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Read every `NOOMBAT_*_FILE` variable and return the values they name.
///
/// The keys returned are lowercase and without the prefix, which is the
/// form `figment`'s `Env` provider produces, so the two merge.
///
/// A file that cannot be read is fatal rather than skipped. Continuing
/// would start the instance with the secret unset, which for a
/// credential means silently running without authentication rather than
/// refusing to run at all.
pub fn from_files() -> Result<BTreeMap<String, String>, String> {
    resolve(std::env::vars())
}

/// The part of [`from_files`] that does not read the environment, so it
/// can be tested without mutating global state.
fn resolve<I>(vars: I) -> Result<BTreeMap<String, String>, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut values = BTreeMap::new();
    for (name, path) in vars {
        let Some(key) = name
            .strip_prefix("NOOMBAT_")
            .and_then(|k| k.strip_suffix("_FILE"))
        else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("{name} names {path}, which cannot be read: {e}"))?;
        // Trailing newline, because every editor and every `echo -n`
        // omission puts one there and no secret ends in one.
        values.insert(key.to_ascii_lowercase(), contents.trim_end().to_string());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_does_not_print_itself() {
        let secret = Secret::from("hunter2".to_string());
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:#?}").contains("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
    }

    #[test]
    fn a_secret_inside_another_struct_still_does_not_print() {
        // The case that matters: nothing formats a `Secret` directly,
        // it formats the config that holds one.
        // Read only by the derived `Debug`, which the dead-code lint
        // does not count as a use.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: String,
            key: Option<Secret>,
        }
        let holder = Holder {
            name: "instance".to_string(),
            key: Some(Secret::from("hunter2".to_string())),
        };
        let rendered = format!("{holder:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("instance"));
    }

    #[test]
    fn a_file_named_by_the_environment_becomes_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bucket-key");
        // With the trailing newline every editor adds.
        std::fs::write(&path, "s3cr3t\n").unwrap();

        let resolved = resolve([
            (
                "NOOMBAT_S3_SECRET_KEY_FILE".to_string(),
                path.display().to_string(),
            ),
            ("NOOMBAT_DOMAIN".to_string(), "example.test".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ])
        .unwrap();

        assert_eq!(
            resolved.get("s3_secret_key").map(String::as_str),
            Some("s3cr3t")
        );
        // Only `_FILE` variables are consulted, and the prefix is
        // stripped, because that is the shape figment's Env provider
        // produces and the two have to merge.
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn a_file_that_cannot_be_read_stops_the_boot() {
        let error = resolve([(
            "NOOMBAT_KEK_FILE".to_string(),
            "/nonexistent/kek".to_string(),
        )])
        .unwrap_err();
        // The message has to name both, or an operator cannot tell
        // which setting is wrong.
        assert!(error.contains("NOOMBAT_KEK_FILE"), "{error}");
        assert!(error.contains("/nonexistent/kek"), "{error}");
    }

    #[test]
    fn a_value_from_a_file_beats_the_same_setting_in_the_environment() {
        // `merge` gives the later provider precedence and `join` gives
        // it to the earlier one. Getting that backwards would leave the
        // `_FILE` form silently doing nothing whenever the plain
        // variable was also set, which is exactly when an operator is
        // migrating a secret into a store.
        //
        // Merge order is what decides this, not the kind of provider,
        // so two maps stand in for the environment and the files.
        use figment::Figment;
        use figment::providers::Serialized;

        let mut environment = BTreeMap::new();
        environment.insert("jwt_secret".to_string(), "from-the-environment".to_string());
        let mut from_files = BTreeMap::new();
        from_files.insert("jwt_secret".to_string(), "from-the-file".to_string());

        let value: String = Figment::new()
            .merge(Serialized::defaults(environment))
            .merge(Serialized::defaults(from_files))
            .extract_inner("jwt_secret")
            .unwrap();
        assert_eq!(value, "from-the-file");
    }

    #[test]
    fn a_blank_secret_is_not_a_value() {
        assert_eq!(Secret::from(String::new()).non_empty(), None);
        assert_eq!(Secret::from("   ".to_string()).non_empty(), None);
        assert_eq!(Secret::from("  k  ".to_string()).non_empty(), Some("k"));
    }
}
