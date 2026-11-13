// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The relay's accounts: the passwd-file Dovecot authenticates against.
//!
//! One line per address, `address:{ARGON2ID}<hash>`. The file and its
//! directory are root's, the file readable by the group Dovecot's auth
//! service runs as and by nobody else, so no process that handles mail can
//! add an account or plant a link for this root process to follow. Every
//! change rewrites the whole file into a temporary one renamed over it, so
//! Dovecot never reads half a write, and a lock serialises the rewrites, so
//! two requests cannot each drop the other's line.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use argon2::Argon2;
use argon2::password_hash::PasswordHasher as _;

#[derive(Debug)]
pub enum Error {
    /// The address already has a line.
    Exists,
    /// The address has no line.
    NotFound,
    /// The address cannot be a line Dovecot reads back; see [`usable`].
    Unsafe,
    Hash(String),
    Io(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Exists => f.write_str("the account exists"),
            Error::NotFound => f.write_str("no such account"),
            Error::Unsafe => f.write_str("the address cannot be a passwd-file line"),
            Error::Hash(e) => write!(f, "hashing failed: {e}"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

/// What [`PasswdFile::migrate_plain_files`] did.
pub struct Migration {
    pub moved: usize,
    /// Each address left where it was, with the reason.
    pub skipped: Vec<(String, String)>,
}

pub struct PasswdFile {
    path: PathBuf,
    gid: u32,
    lock: Mutex<()>,
}

impl PasswdFile {
    /// `gid` is the group Dovecot's auth service runs as.
    pub fn new(path: PathBuf, gid: u32) -> Self {
        Self {
            path,
            gid,
            lock: Mutex::new(()),
        }
    }

    pub fn contains(&self, address: &str) -> Result<bool, Error> {
        Ok(self.lines()?.iter().any(|l| user_of(l) == address))
    }

    pub fn add(&self, address: &str, password: &[u8]) -> Result<(), Error> {
        let line = line(address, password)?;
        self.update(|lines| {
            if lines.iter().any(|l| user_of(l) == address) {
                return Err(Error::Exists);
            }
            lines.push(line);
            Ok(())
        })
    }

    pub fn replace(&self, address: &str, password: &[u8]) -> Result<(), Error> {
        let line = line(address, password)?;
        self.update(|lines| {
            let slot = lines
                .iter_mut()
                .find(|l| user_of(l) == address)
                .ok_or(Error::NotFound)?;
            *slot = line;
            Ok(())
        })
    }

    /// Whether there was a line to remove.
    pub fn remove(&self, address: &str) -> Result<bool, Error> {
        let mut removed = false;
        self.update(|lines| {
            let before = lines.len();
            lines.retain(|l| user_of(l) != address);
            removed = lines.len() != before;
            Ok(())
        })?;
        Ok(removed)
    }

    /// Moves accounts kept as `{vmail_home}/{address}/password`, a
    /// plain-text file per address, into this file in one write, then
    /// deletes each plain-text file. A line already here wins over the
    /// file. An entry that cannot be moved is skipped and reported, and the
    /// rest still move.
    pub fn migrate_plain_files(&self, vmail_home: &Path) -> Result<Migration, Error> {
        let mut found = Vec::new();
        let mut skipped = Vec::new();
        for entry in std::fs::read_dir(vmail_home)?.flatten() {
            let plain = entry.path().join("password");
            if !plain.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // Trailing newlines are not part of the password.
            let read = std::fs::read(&plain).map_err(Error::from);
            match read.and_then(|bytes| line(&name, without_trailing_newlines(&bytes))) {
                Ok(line) => found.push((name, line, plain)),
                Err(e) => skipped.push((name, e.to_string())),
            }
        }

        let mut moved = 0;
        self.update(|lines| {
            for (address, line, _) in &found {
                if !lines.iter().any(|l| user_of(l) == address) {
                    lines.push(line.clone());
                    moved += 1;
                }
            }
            Ok(())
        })?;

        for (address, _, plain) in &found {
            if let Err(e) = std::fs::remove_file(plain) {
                skipped.push((address.clone(), format!("the plain-text file stays: {e}")));
            }
        }
        Ok(Migration { moved, skipped })
    }

    /// Reads the lines, lets `change` edit them, and writes them back if it
    /// changed any, all under the lock. Hashing happens before, outside it.
    fn update(
        &self,
        change: impl FnOnce(&mut Vec<String>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let _guard = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut lines = self.lines()?;
        let before = lines.clone();
        change(&mut lines)?;
        if lines != before {
            self.write(&lines)?;
        }
        Ok(())
    }

    fn lines(&self) -> Result<Vec<String>, Error> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, lines: &[String]) -> Result<(), Error> {
        let parent = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension("tmp");
        let mut text = lines.join("\n");
        text.push('\n');

        // A leftover from a failed write. Removing it never follows a link,
        // and `create_new` refuses whatever is at that name by the time it
        // opens; `mode` is set at creation, so the hashes are never briefly
        // readable by others.
        match std::fs::remove_file(&temporary) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&temporary)?;
        file.write_all(text.as_bytes())?;

        // Dovecot reloads the file only when its size or its mtime in whole
        // seconds has changed, and a rotation keeps the size. So the mtime
        // moves at least one second past the old one, even ahead of the
        // clock, or a rotated password would go on logging in.
        let now = SystemTime::now();
        let modified = match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
            Ok(old) => now.max(old + Duration::from_secs(1)),
            Err(_) => now,
        };
        file.set_modified(modified)?;
        file.sync_all()?;
        std::os::unix::fs::fchown(&file, None, Some(self.gid))?;
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

/// Whether `address` can be a line Dovecot reads back: no field
/// separator, whitespace or control character, and no leading `#`, which
/// Dovecot reads as a comment.
pub fn usable(address: &str) -> bool {
    !address.is_empty()
        && !address.starts_with('#')
        && !address
            .bytes()
            .any(|b| b == b':' || b.is_ascii_whitespace() || b.is_ascii_control())
}

fn line(address: &str, password: &[u8]) -> Result<String, Error> {
    if !usable(address) {
        return Err(Error::Unsafe);
    }
    // Argon2's defaults (Argon2id, one lane) are what Dovecot's libsodium
    // verifier accepts; it refuses more than one lane.
    let hash = Argon2::default()
        .hash_password(password)
        .map_err(|e| Error::Hash(e.to_string()))?;
    Ok(format!("{address}:{{ARGON2ID}}{hash}"))
}

fn without_trailing_newlines(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != b'\n').map_or(0, |i| i + 1);
    &bytes[..end]
}

fn user_of(line: &str) -> &str {
    line.split(':').next().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::PasswordVerifier as _;
    use argon2::password_hash::phc::PasswordHash;
    use std::os::unix::fs::MetadataExt as _;

    fn file_in(dir: &Path) -> PasswdFile {
        let gid = std::fs::metadata(dir).expect("the directory exists").gid();
        PasswdFile::new(dir.join(".noombat-admin/passwd"), gid)
    }

    fn text(file: &PasswdFile) -> String {
        std::fs::read_to_string(&file.path).unwrap_or_default()
    }

    fn verifies(file: &PasswdFile, address: &str, password: &[u8]) -> bool {
        let text = text(file);
        let Some(line) = text.lines().find(|l| user_of(l) == address) else {
            return false;
        };
        let hash = line
            .split_once(":{ARGON2ID}")
            .map(|(_, h)| h)
            .expect("the line names its scheme");
        let parsed = PasswordHash::new(hash).expect("a PHC string");
        Argon2::default().verify_password(password, &parsed).is_ok()
    }

    #[test]
    fn an_added_account_is_a_hashed_line() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        file.add("a@b.test", b"secret-one").unwrap();

        assert!(file.contains("a@b.test").unwrap());
        assert!(text(&file).starts_with("a@b.test:{ARGON2ID}$argon2id$"));
        assert!(
            !text(&file).contains("secret-one"),
            "the password is stored in clear"
        );
        assert!(verifies(&file, "a@b.test", b"secret-one"));
        assert!(!verifies(&file, "a@b.test", b"secret-two"));
    }

    #[test]
    fn the_file_is_readable_by_its_group_and_written_by_its_owner_only() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        file.add("a@b.test", b"secret-one").unwrap();

        let meta = std::fs::metadata(&file.path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o640);
        assert_eq!(meta.gid(), file.gid);
        assert!(
            !file.path.with_extension("tmp").exists(),
            "the temporary file is left behind"
        );
    }

    #[test]
    fn every_write_moves_the_mtime_a_whole_second_on() {
        // Dovecot keeps the file it loaded until the size or the mtime in
        // whole seconds changes, and these writes come within one second.
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        let mut seconds = Vec::new();
        for i in 0..3 {
            file.update(|lines| {
                *lines = vec![format!("a@b.test:{i}")];
                Ok(())
            })
            .unwrap();
            seconds.push(std::fs::metadata(&file.path).unwrap().mtime());
        }
        assert!(
            seconds[0] < seconds[1] && seconds[1] < seconds[2],
            "{seconds:?}"
        );
    }

    #[test]
    fn a_link_planted_at_the_temporary_name_is_not_followed() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        let target = home.path().join("target");
        std::fs::write(&target, "untouched").unwrap();
        std::fs::create_dir_all(file.path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, file.path.with_extension("tmp")).unwrap();

        file.add("a@b.test", b"secret-one").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
        assert!(file.contains("a@b.test").unwrap());
    }

    #[test]
    fn adding_an_existing_account_changes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        file.add("a@b.test", b"secret-one").unwrap();
        let before = text(&file);

        assert!(matches!(
            file.add("a@b.test", b"secret-two"),
            Err(Error::Exists)
        ));
        assert_eq!(text(&file), before);
    }

    #[test]
    fn replacing_changes_only_that_password() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        file.add("a@b.test", b"secret-one").unwrap();
        file.add("c@b.test", b"secret-c").unwrap();

        file.replace("a@b.test", b"secret-two").unwrap();
        assert!(verifies(&file, "a@b.test", b"secret-two"));
        assert!(!verifies(&file, "a@b.test", b"secret-one"));
        assert!(verifies(&file, "c@b.test", b"secret-c"));
        assert!(matches!(
            file.replace("x@b.test", b"p"),
            Err(Error::NotFound)
        ));
    }

    #[test]
    fn removing_drops_only_that_line() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        file.add("a@b.test", b"secret-one").unwrap();
        file.add("c@b.test", b"secret-c").unwrap();

        assert!(file.remove("a@b.test").unwrap());
        assert!(!file.contains("a@b.test").unwrap());
        assert!(file.contains("c@b.test").unwrap());
        assert!(!file.remove("a@b.test").unwrap());
    }

    #[test]
    fn an_address_dovecot_would_not_read_back_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        for address in [
            "a:{PLAIN}x@b.test",
            "a@b.test\nc",
            "a b@b.test",
            "#a@b.test",
            "",
        ] {
            assert!(
                matches!(file.add(address, b"p"), Err(Error::Unsafe)),
                "{address:?}"
            );
        }
        assert_eq!(text(&file), "");
    }

    #[test]
    fn concurrent_changes_keep_every_line() {
        // Each change pauses between reading the file and writing it back,
        // where two unserialised writers would each drop the other's line.
        let home = tempfile::tempdir().unwrap();
        let file = std::sync::Arc::new(file_in(home.path()));
        let workers: Vec<_> = (0..4)
            .map(|i| {
                let file = std::sync::Arc::clone(&file);
                std::thread::spawn(move || {
                    file.update(|lines| {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        lines.push(format!("u{i}@b.test:x"));
                        Ok(())
                    })
                    .unwrap()
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        for i in 0..4 {
            assert!(
                file.contains(&format!("u{i}@b.test")).unwrap(),
                "u{i} was lost"
            );
        }
    }

    #[test]
    fn plain_files_move_into_the_file_and_are_deleted() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        std::fs::create_dir_all(home.path().join("a@b.test/Maildir")).unwrap();
        std::fs::write(home.path().join("a@b.test/password"), "old-a").unwrap();
        std::fs::create_dir_all(home.path().join("c@b.test")).unwrap();
        std::fs::write(home.path().join("c@b.test/password"), "old-c\n").unwrap();
        file.add("c@b.test", b"current-c").unwrap();

        let migration = file.migrate_plain_files(home.path()).unwrap();
        assert_eq!(migration.moved, 1);
        assert!(migration.skipped.is_empty());
        assert!(verifies(&file, "a@b.test", b"old-a"));
        assert!(
            verifies(&file, "c@b.test", b"current-c"),
            "a line already here wins"
        );
        assert!(!home.path().join("a@b.test/password").exists());
        assert!(!home.path().join("c@b.test/password").exists());
        assert!(
            home.path().join("a@b.test/Maildir").is_dir(),
            "mail is kept"
        );
        assert_eq!(file.migrate_plain_files(home.path()).unwrap().moved, 0);
    }

    #[test]
    fn a_bad_entry_is_skipped_and_the_rest_still_move() {
        let home = tempfile::tempdir().unwrap();
        let file = file_in(home.path());
        // A name Dovecot could not read back, and a password that is not
        // UTF-8, which was stored exactly as a client sent it.
        std::fs::create_dir_all(home.path().join("x:y@b.test")).unwrap();
        std::fs::write(home.path().join("x:y@b.test/password"), "p").unwrap();
        std::fs::create_dir_all(home.path().join("a@b.test")).unwrap();
        std::fs::write(home.path().join("a@b.test/password"), b"\xffold").unwrap();
        std::fs::create_dir_all(home.path().join("c@b.test")).unwrap();
        std::fs::write(home.path().join("c@b.test/password"), "old-c").unwrap();

        let migration = file.migrate_plain_files(home.path()).unwrap();
        assert_eq!(migration.moved, 2);
        assert_eq!(migration.skipped.len(), 1, "{:?}", migration.skipped);
        assert_eq!(migration.skipped[0].0, "x:y@b.test");
        assert!(verifies(&file, "a@b.test", b"\xffold"));
        assert!(verifies(&file, "c@b.test", b"old-c"));
        assert!(
            home.path().join("x:y@b.test/password").exists(),
            "a skipped entry keeps its file"
        );
    }
}
