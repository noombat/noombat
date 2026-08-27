// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Whether a string is shaped like an email address.
//!
//! Two places need this and they needed it for different reasons: a chat
//! report names an address the server cannot reach, and a recovery address
//! is one it must. Neither can establish deliverability, and neither needs
//! to. What both need is to refuse text that is not an address at all,
//! before it reaches a moderator's screen or a mail queue.
//!
//! Deliberately not a full RFC 5322 parser. That grammar admits quoted
//! local parts, comments and address literals, and accepting them here
//! would widen what reaches the renderer for no gain: nobody signs up with
//! one, and a false refusal is a message a person can act on.

use crate::error::{NoombatError, Result};

/// RFC 5321's maximum reverse-path length.
pub const MAX_LENGTH: usize = 320;

/// Check that `addr` is shaped like an address.
///
/// The field name is passed in so the refusal names what the caller called
/// it, rather than a term the person filling in the form has never seen.
pub fn qualify(addr: &str, field: &str) -> Result<()> {
    if addr.is_empty() || addr.len() > MAX_LENGTH {
        return Err(NoombatError::BadRequest(format!(
            "{field} must be 1 to {MAX_LENGTH} characters"
        )));
    }
    if addr.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(NoombatError::BadRequest(format!(
            "{field} must not contain whitespace or control characters"
        )));
    }

    let mut parts = addr.split('@');
    let (local, domain, extra) = (parts.next(), parts.next(), parts.next());
    match (local, domain, extra) {
        (Some(l), Some(d), None)
            if !l.is_empty()
                && d.contains('.')
                && !d.starts_with('.')
                && !d.ends_with('.')
                && !d.contains("..") =>
        {
            Ok(())
        }
        _ => Err(NoombatError::BadRequest(format!(
            "{field} must be an address of the form user@host"
        ))),
    }
}

/// The comparison form: lowercase.
///
/// Uniqueness and every lookup fold case, through `lower(email)` in the
/// database. A query written against the raw column finds nothing and
/// reports no error, so the folding is done here rather than remembered at
/// each call site.
pub fn fold(addr: &str) -> String {
    addr.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_addresses_are_accepted() {
        // The counterpart to the refusals below: a check that rejected
        // everything would pass those and be useless.
        for good in [
            "alice@example.com",
            "alice+tag@sub.example.co.uk",
            "a@b.co",
            "first.last@example.org",
        ] {
            assert!(qualify(good, "email").is_ok(), "refused {good:?}");
        }
    }

    #[test]
    fn text_that_is_not_an_address_is_refused() {
        for bad in [
            "",
            "no-at-sign",
            "two@at@signs",
            "user@nodot",
            "user@.leading",
            "user@trailing.",
            "user@double..dot",
            "@nolocal.com",
            "with space@example.com",
            "control\u{0007}@example.com",
        ] {
            assert!(qualify(bad, "email").is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn an_over_long_address_is_refused() {
        let long = format!("{}@example.com", "a".repeat(MAX_LENGTH));
        assert!(qualify(&long, "email").is_err());
    }

    #[test]
    fn folding_is_case_insensitive() {
        assert_eq!(fold("Alice@Example.COM"), "alice@example.com");
    }
}
