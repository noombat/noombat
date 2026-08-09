// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Postfix content filter enforcing the Chatmail encryption-only policy.
//!
//! Installed as a Postfix after-queue content filter via `master.cf`.
//! Postfix invokes the binary as:
//!
//! ```text
//! noombat-filtermail -f <sender> -- <recipient> [<recipient> ...]
//! ```
//!
//! The message is read from standard input. If the message body is
//! PGP-encrypted (PGP/MIME `multipart/encrypted` with the OpenPGP
//! protocol parameter, or inline PGP beginning with the
//! `-----BEGIN PGP MESSAGE-----` marker), the message is re-injected
//! into Postfix via `sendmail` with `content_filter=` cleared to
//! prevent a loop. Otherwise, the process exits with code 69
//! (`EX_UNAVAILABLE`), causing Postfix to bounce the message with a
//! permanent delivery failure.
//!
//! ## Exit codes
//!
//! | Code | Meaning (sysexits.h) | Postfix interpretation                 |
//! |------|----------------------|----------------------------------------|
//! | 0    | `EX_OK`              | Message accepted (re-injected).        |
//! | 69   | `EX_UNAVAILABLE`     | Permanent failure; message is bounced. |
//! | 75   | `EX_TEMPFAIL`        | Temporary failure; Postfix retries.    |

use std::io::Read;
use std::process::{Command, ExitCode, Stdio};

/// sysexits.h: service unavailable (permanent failure).
const EX_UNAVAILABLE: u8 = 69;
/// sysexits.h: temporary failure.
const EX_TEMPFAIL: u8 = 75;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // Expected invocation:
    //   noombat-filtermail -f <sender> -- <recipient> [<recipient> ...]
    // Postfix substitutes ${sender} and ${recipient} from the pipe
    // transport definition in master.cf.
    let (sender, recipients) = match parse_args(&args) {
        Some(parsed) => parsed,
        None => {
            eprintln!("usage: noombat-filtermail -f <sender> -- <recipient> [<recipient> ...]");
            return ExitCode::from(EX_TEMPFAIL);
        }
    };

    // Read the entire message from stdin.
    let mut raw = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut raw) {
        eprintln!("filtermail: failed to read message from stdin: {e}");
        return ExitCode::from(EX_TEMPFAIL);
    }

    if !is_encrypted(&raw) {
        eprintln!("filtermail: rejecting unencrypted message from {sender}");
        return ExitCode::from(EX_UNAVAILABLE);
    }

    // Re-inject the message into Postfix via sendmail(1), clearing
    // content_filter to avoid a loop.
    if let Err(e) = reinject(&sender, &recipients, &raw) {
        eprintln!("filtermail: re-injection failed: {e}");
        return ExitCode::from(EX_TEMPFAIL);
    }

    ExitCode::SUCCESS
}

/// Parse the command-line arguments into (sender, recipients).
///
/// Expected form: `[prog, "-f", sender, "--", recipient, ...]`.
fn parse_args(args: &[String]) -> Option<(String, Vec<String>)> {
    let f_pos = args.iter().position(|a| a == "-f")?;
    let sender = args.get(f_pos + 1)?.clone();

    let sep_pos = args.iter().position(|a| a == "--")?;
    let recipients: Vec<String> = args[sep_pos + 1..].to_vec();

    if recipients.is_empty() {
        return None;
    }

    Some((sender, recipients))
}

/// Determine whether the raw message is PGP-encrypted.
///
/// Checks for:
/// 1. PGP/MIME: `Content-Type: multipart/encrypted` with
///    `protocol="application/pgp-encrypted"`.
/// 2. Inline PGP: the body contains `-----BEGIN PGP MESSAGE-----`.
/// 3. Autocrypt Setup Message: a `multipart/mixed` containing an
///    `application/autocrypt-setup` part (key transfer; acceptable).
///
/// The function uses a two-tier strategy: a fast raw-byte scan
/// handles the common cases (PGP/MIME header signature and inline
/// PGP marker) without allocating. Only if the fast path does not
/// match does the function fall through to a full MIME parse for
/// edge cases (Autocrypt Setup Messages, inline PGP inside nested
/// multipart subparts).
/// Whether a PGP armour block opens and closes here.
///
/// Both markers must start a line, which RFC 4880 requires of armour
/// headers. That is what separates a real armoured message from the
/// same characters quoted inside running text, and requiring the
/// closing marker too rules out a fragment of a forwarded mail.
fn has_pgp_armour(body: &[u8]) -> bool {
    fn at_line_start(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .enumerate()
            .any(|(i, w)| w == needle && (i == 0 || haystack[i - 1] == b'\n'))
    }

    at_line_start(body, b"-----BEGIN PGP MESSAGE-----")
        && at_line_start(body, b"-----END PGP MESSAGE-----")
}

fn is_encrypted(raw: &[u8]) -> bool {
    // No fast path. There used to be two, and both decided the
    // question by searching the whole message for byte sequences with
    // no regard to structure: `multipart/encrypted` together with
    // `application/pgp-encrypted` anywhere, or the PGP marker
    // anywhere. The comment defending that said the sequences "do not
    // occur in encrypted ciphertext", which is true and beside the
    // point. The question is whether they occur in *plaintext*, and
    // they do: in a quoted reply, an attachment filename, or a body a
    // sender composes on purpose. Either one turned this boundary into
    // an opt-in, letting plaintext through the relay by asking.
    //
    // Parsing costs a few microseconds on a message that is about to
    // cross a network. The boundary is worth more than that.

    // Slow path: fall through to full MIME parse for Autocrypt
    // Setup Messages and other edge cases.
    let parsed = match mailparse::parse_mail(raw) {
        Ok(p) => p,
        Err(_) => return false,
    };

    is_encrypted_part(&parsed)
}

/// Recursively check whether a MIME part (or any of its subparts)
/// is PGP-encrypted.
fn is_encrypted_part(part: &mailparse::ParsedMail<'_>) -> bool {
    let content_type = part
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("content-type"))
        .map(|h| h.get_value())
        .unwrap_or_default()
        .to_ascii_lowercase();

    // PGP/MIME: multipart/encrypted with the OpenPGP protocol.
    if content_type.contains("multipart/encrypted")
        && content_type.contains("application/pgp-encrypted")
    {
        return true;
    }

    // Inline PGP: an armour block in this part's own body.
    if let Ok(body) = part.get_body_raw()
        && has_pgp_armour(&body)
    {
        return true;
    }

    // Autocrypt Setup Message: application/autocrypt-setup part.
    if content_type.contains("application/autocrypt-setup") {
        return true;
    }

    // Recurse into subparts (handles multipart/mixed with an
    // inline-PGP text/plain subpart, among other structures).
    for subpart in &part.subparts {
        if is_encrypted_part(subpart) {
            return true;
        }
    }

    false
}

/// Re-inject the message into Postfix via sendmail(1).
fn reinject(sender: &str, recipients: &[String], raw: &[u8]) -> Result<(), String> {
    let mut cmd = Command::new("/usr/sbin/sendmail");
    cmd.arg("-G") // relay (gateway) mode
        .arg("-i") // do not treat a line with only '.' as EOF
        .arg("-f")
        .arg(sender)
        .arg("-o")
        .arg("content_filter=") // disable content filter for re-injection
        .args(recipients)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| format!("spawn sendmail: {e}"))?;

    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        stdin
            .write_all(raw)
            .map_err(|e| format!("write to sendmail stdin: {e}"))?;
    }
    drop(child.stdin.take());

    let status = child.wait().map_err(|e| format!("wait on sendmail: {e}"))?;

    if !status.success() {
        return Err(format!("sendmail exited with status {status}"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pgp_mime_is_encrypted() {
        let raw = b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=abc\r\n\
                     \r\n\
                     --abc\r\n\
                     Content-Type: application/pgp-encrypted\r\n\
                     \r\n\
                     Version: 1\r\n\
                     --abc\r\n\
                     Content-Type: application/octet-stream\r\n\
                     \r\n\
                     -----BEGIN PGP MESSAGE-----\r\nciphertext\r\n-----END PGP MESSAGE-----\r\n\
                     --abc--\r\n";
        assert!(is_encrypted(raw));
    }

    #[test]
    fn inline_pgp_is_encrypted() {
        let raw = b"Content-Type: text/plain\r\n\
                     \r\n\
                     -----BEGIN PGP MESSAGE-----\r\nciphertext\r\n-----END PGP MESSAGE-----\r\n";
        assert!(is_encrypted(raw));
    }

    #[test]
    fn plaintext_is_not_encrypted() {
        let raw = b"Content-Type: text/plain\r\n\r\nHello, world!\r\n";
        assert!(!is_encrypted(raw));
    }

    #[test]
    fn html_is_not_encrypted() {
        let raw = b"Content-Type: text/html\r\n\r\n<p>Hello</p>\r\n";
        assert!(!is_encrypted(raw));
    }

    #[test]
    fn autocrypt_setup_is_accepted() {
        let raw = b"Content-Type: multipart/mixed; boundary=xyz\r\n\
                     \r\n\
                     --xyz\r\n\
                     Content-Type: application/autocrypt-setup\r\n\
                     \r\n\
                     key data\r\n\
                     --xyz--\r\n";
        assert!(is_encrypted(raw));
    }

    #[test]
    fn parse_args_valid() {
        let args = vec![
            "prog".into(),
            "-f".into(),
            "alice@example.com".into(),
            "--".into(),
            "bob@example.com".into(),
        ];
        let (sender, recipients) = parse_args(&args).unwrap();
        assert_eq!(sender, "alice@example.com");
        assert_eq!(recipients, vec!["bob@example.com"]);
    }

    #[test]
    fn parse_args_multiple_recipients() {
        let args = vec![
            "prog".into(),
            "-f".into(),
            "alice@example.com".into(),
            "--".into(),
            "bob@example.com".into(),
            "carol@example.com".into(),
        ];
        let (_, recipients) = parse_args(&args).unwrap();
        assert_eq!(recipients.len(), 2);
    }

    #[test]
    fn parse_args_missing_recipient() {
        let args = vec![
            "prog".into(),
            "-f".into(),
            "alice@example.com".into(),
            "--".into(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn parse_args_missing_separator() {
        let args = vec![
            "prog".into(),
            "-f".into(),
            "alice@example.com".into(),
            "bob@example.com".into(),
        ];
        assert!(parse_args(&args).is_none());
    }

    #[test]
    fn inline_pgp_in_multipart_mixed_subpart() {
        let raw = b"Content-Type: multipart/mixed; boundary=outer\r\n\
                     \r\n\
                     --outer\r\n\
                     Content-Type: text/plain\r\n\
                     \r\n\
                     -----BEGIN PGP MESSAGE-----\r\nciphertext\r\n-----END PGP MESSAGE-----\r\n\
                     --outer--\r\n";
        assert!(is_encrypted(raw));
    }

    /// Plaintext that merely mentions the PGP/MIME content types.
    ///
    /// The old fast path searched the whole message for
    /// `multipart/encrypted` and `application/pgp-encrypted` and
    /// accepted on finding both, wherever they were. A sender who put
    /// them in the body, deliberately or by quoting a previous mail,
    /// walked the relay's one invariant. This is the regression test
    /// for that.
    #[test]
    fn plaintext_naming_the_pgp_content_types_is_not_encrypted() {
        let raw = b"From: a@example.org\r\n\
                    To: b@example.org\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    Here is how PGP/MIME works: the outer part is\r\n\
                    multipart/encrypted and the first subpart is\r\n\
                    application/pgp-encrypted. Hope that helps!\r\n";
        assert!(
            !is_encrypted(raw),
            "a plaintext explanation of PGP must not pass as encrypted"
        );
    }

    /// The armour marker quoted mid-line, as in a forwarded mail.
    #[test]
    fn a_quoted_armour_marker_is_not_encrypted() {
        let raw = b"From: a@example.org\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    He wrote: \"-----BEGIN PGP MESSAGE-----\" and then gave up.\r\n";
        assert!(
            !is_encrypted(raw),
            "a marker inside running text is not an armour block"
        );
    }

    /// An opening marker with no close, as in a truncated quote.
    #[test]
    fn an_unclosed_armour_block_is_not_encrypted() {
        let raw = b"From: a@example.org\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    -----BEGIN PGP MESSAGE-----\r\n\
                    hQEMA0k1
                    [truncated]\r\n";
        assert!(!is_encrypted(raw), "an unterminated block is not a message");
    }

    /// A real inline-PGP message still passes.
    #[test]
    fn a_complete_armour_block_is_encrypted() {
        let raw = b"From: a@example.org\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n\
                    -----BEGIN PGP MESSAGE-----\r\n\
                    \r\n\
                    hQEMA0k1PLACEHOLDERCIPHERTEXT\r\n\
                    -----END PGP MESSAGE-----\r\n";
        assert!(is_encrypted(raw), "inline PGP must still be accepted");
    }

    /// And so does real PGP/MIME, whose two content types live in
    /// different parts: the outer header and the first subpart's.
    #[test]
    fn real_pgp_mime_is_encrypted() {
        let raw = b"From: a@example.org\r\n\
                    Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\
                    \r\n\
                    --b\r\n\
                    Content-Type: application/pgp-encrypted\r\n\
                    \r\n\
                    Version: 1\r\n\
                    --b\r\n\
                    Content-Type: application/octet-stream\r\n\
                    \r\n\
                    hQEMA0k1PLACEHOLDER\r\n\
                    --b--\r\n";
        assert!(is_encrypted(raw), "PGP/MIME must still be accepted");
    }
}
