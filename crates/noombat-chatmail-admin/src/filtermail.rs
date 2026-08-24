// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Before-queue SMTP proxy enforcing the Chatmail encryption-only policy.
//!
//! Postfix's smtpd connects here for every message, before anything is
//! written to the queue, because the public listeners carry
//! `smtpd_proxy_filter`. This process answers that smtpd and drives the
//! re-injection smtpd behind it:
//!
//! ```text
//! client -- smtpd :25/:465 -- filtermail :10026 -- smtpd :10025 -- queue
//! ```
//!
//! Refusing at end-of-DATA is what makes the policy enforceable: the
//! reply reaches the sending client on its own connection, nothing is
//! spooled, and no bounce carries the plaintext back out.
//!
//! Postfix sends its own `EHLO`, `XFORWARD`, `DATA` and `QUIT` plus
//! unmodified `MAIL FROM` and `RCPT TO`, speaks ESMTP without command
//! pipelining, and opens one connection per message. Everything but
//! `EHLO` and `DATA` is relayed unchanged in both directions, so the
//! final `250` carries the queue id the re-injection listener assigned.
//!
//! `DATA` is answered locally and forwarded only once the message is
//! known to be encrypted, so a refused message never reaches the second
//! smtpd. Signing happens there, past this filter, and never here.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Where Postfix's smtpd connects, one listener per direction.
///
/// Two, because the checks differ. A submission from one of this
/// instance's own users must be rate limited and must not claim someone
/// else's `From`; a message from a peer relay must be aligned with the
/// signature it carries. Upstream runs a separate process per mode; one
/// process with a listener per mode keeps the supervision simpler and
/// makes the same distinction.
const DEFAULT_OUTGOING_LISTEN: &str = "127.0.0.1:10026";
const DEFAULT_INCOMING_LISTEN: &str = "127.0.0.1:10027";
/// The re-injection smtpd each direction hands accepted mail to.
///
/// Two, so each can carry a different milter: the outgoing listener
/// signs, the incoming one verifies. OpenDKIM chooses between signing
/// and verifying from the client address, and both see 127.0.0.1
/// because this filter is what connects, so the listener has to carry
/// the distinction instead.
const DEFAULT_FORWARD_OUTGOING: &str = "127.0.0.1:10025";
const DEFAULT_FORWARD_INCOMING: &str = "127.0.0.1:10028";

/// Longest single SMTP line accepted. RFC 5321 caps commands at 1000
/// octets; message lines are allowed to be longer in practice, and a
/// generous ceiling here only exists to stop a peer that never sends a
/// newline from growing the buffer without bound.
const MAX_LINE_BYTES: usize = 65536;

/// Largest message this filter will buffer. Postfix's own
/// `message_size_limit` is smaller and is enforced by the listener in
/// front, so this is a backstop rather than the operative limit.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Point at which a session is abandoned rather than drained. Reached
/// only by something writing to the loopback port directly, since the
/// listener in front stops long before this.
const ABORT_MESSAGE_BYTES: usize = 256 * 1024 * 1024;

/// Concurrent sessions across both listeners.
const MAX_SESSIONS: usize = 256;

/// Socket timeout. Postfix gives up on a proxy filter after
/// `smtpd_proxy_timeout`, 100 seconds by default; being a little under
/// that means a stall is reported from here, with a reason, rather than
/// as a timeout with none.
const IO_TIMEOUT: Duration = Duration::from_secs(90);

/// Messages one sender may submit per minute, and how many may arrive
/// at once. The same defaults upstream uses.
const DEFAULT_RATE_PER_MINUTE: u32 = 60;
const DEFAULT_RATE_BURST: u32 = 10;

/// Senders tracked before the rate limiter prunes what has expired.
const RATE_KEYS_BEFORE_PRUNE: usize = 10_000;

/// The refusal.
///
/// `550` rather than a basic code outside RFC 5321's set, which only
/// helps a client that recognises it and is a confusingly numbered
/// permanent failure to every other.
const REJECT_REPLY: &str = "550 5.7.1 this relay carries only end-to-end encrypted mail, \
                            and this message is not encrypted";

/// Which side of the relay a session arrived on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Submission from one of this instance's own users.
    Outgoing,
    /// A message from a peer relay.
    Incoming,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Outgoing => "outgoing",
            Self::Incoming => "incoming",
        }
    }
}

/// Per-sender submission limit, as a GCRA bucket.
///
/// Checked at `MAIL FROM`, before the body is read, so a sender who is
/// over quota is refused without this process accepting a megabyte from
/// them first.
struct RateLimiter {
    /// Minimum spacing between two accepted messages from one sender.
    interval: Duration,
    /// How far ahead of that spacing a burst may run.
    tolerance: Duration,
    /// Sender to theoretical arrival time.
    state: Mutex<HashMap<String, Instant>>,
}

impl RateLimiter {
    fn new(per_minute: u32, burst: u32) -> Self {
        let per_minute = per_minute.max(1);
        let interval = Duration::from_secs(60) / per_minute;
        Self {
            interval,
            // `burst - 1`, not `burst`. The first message costs nothing
            // because the bucket starts at the current time, so a
            // tolerance of one whole interval per burst slot admits one
            // message more than asked for. The test below caught this.
            tolerance: interval * (burst.max(1) - 1),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `key` may send now, recording the send if so.
    ///
    /// `now` is a parameter so the behaviour can be tested without
    /// sleeping through a minute.
    fn allow(&self, key: &str, now: Instant) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            // A panic in another thread poisoned the lock. Failing open
            // here is deliberate: a rate limiter is not the boundary
            // this relay exists to enforce, and refusing all mail
            // because of it would be the larger fault.
            Err(poisoned) => poisoned.into_inner(),
        };

        if state.len() > RATE_KEYS_BEFORE_PRUNE {
            state.retain(|_, tat| *tat > now);
        }

        let tat = state.get(key).copied().unwrap_or(now);
        // Compared as an addition rather than a subtraction: `Instant`
        // arithmetic before the process started panics.
        if tat > now + self.tolerance {
            return false;
        }
        state.insert(key.to_string(), tat.max(now) + self.interval);
        true
    }
}

fn main() -> ExitCode {
    let outgoing = std::env::var("FILTERMAIL_OUTGOING_LISTEN")
        .unwrap_or_else(|_| DEFAULT_OUTGOING_LISTEN.to_string());
    let incoming = std::env::var("FILTERMAIL_INCOMING_LISTEN")
        .unwrap_or_else(|_| DEFAULT_INCOMING_LISTEN.to_string());
    let forward_outgoing = std::env::var("FILTERMAIL_FORWARD")
        .unwrap_or_else(|_| DEFAULT_FORWARD_OUTGOING.to_string());
    let forward_incoming = std::env::var("FILTERMAIL_FORWARD_INCOMING")
        .unwrap_or_else(|_| DEFAULT_FORWARD_INCOMING.to_string());

    let limiter = Arc::new(RateLimiter::new(
        env_number("FILTERMAIL_RATE_PER_MINUTE", DEFAULT_RATE_PER_MINUTE),
        env_number("FILTERMAIL_RATE_BURST", DEFAULT_RATE_BURST),
    ));
    let live = Arc::new(AtomicUsize::new(0));

    let mut listeners = Vec::new();
    for (mode, addr, forward) in [
        (Mode::Outgoing, outgoing, forward_outgoing),
        (Mode::Incoming, incoming, forward_incoming),
    ] {
        match TcpListener::bind(&addr) {
            Ok(listener) => {
                eprintln!(
                    "filtermail: {} on {addr}, re-injecting to {forward}",
                    mode.label()
                );
                listeners.push((mode, listener, Arc::new(forward)));
            }
            Err(e) => {
                eprintln!("filtermail: cannot bind {addr} for {}: {e}", mode.label());
                return ExitCode::FAILURE;
            }
        }
    }

    let mut threads = Vec::new();
    for (mode, listener, forward) in listeners {
        let limiter = Arc::clone(&limiter);
        let live = Arc::clone(&live);
        threads.push(thread::spawn(move || {
            accept_loop(mode, listener, forward, limiter, live)
        }));
    }
    for handle in threads {
        let _ = handle.join();
    }

    ExitCode::SUCCESS
}

fn env_number(name: &str, fallback: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn accept_loop(
    mode: Mode,
    listener: TcpListener,
    forward: Arc<String>,
    limiter: Arc<RateLimiter>,
    live: Arc<AtomicUsize>,
) {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(e) => {
                eprintln!("filtermail: accept failed: {e}");
                continue;
            }
        };

        // Refuse rather than queue. A 421 tells the smtpd in front to
        // give the client a temporary failure, which it will retry;
        // silently accepting the connection and letting it wait would
        // instead be reported to the client as a timeout.
        if live.load(Ordering::Relaxed) >= MAX_SESSIONS {
            eprintln!("filtermail: at the {MAX_SESSIONS} session limit, refusing a connection");
            if let Ok(mut w) = stream.try_clone() {
                let _ = w.write_all(b"421 4.3.2 filter is at capacity\r\n");
            }
            continue;
        }

        let forward = Arc::clone(&forward);
        let limiter = Arc::clone(&limiter);
        let counter = Arc::clone(&live);
        live.fetch_add(1, Ordering::Relaxed);
        let spawned = thread::Builder::new()
            .name(format!("filtermail-{}", mode.label()))
            .spawn(move || {
                serve(mode, stream, &forward, &limiter);
                counter.fetch_sub(1, Ordering::Relaxed);
            });
        if let Err(e) = spawned {
            eprintln!("filtermail: cannot spawn a session thread: {e}");
            live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// One end of an SMTP conversation.
struct Wire {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl Wire {
    fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let writer = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
        })
    }

    /// Read one line. `Ok(None)` at end of stream.
    fn line(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = Vec::new();
        if read_line_capped(&mut self.reader, &mut buf, MAX_LINE_BYTES)? == 0 {
            return Ok(None);
        }
        Ok(Some(buf))
    }

    /// Read a complete reply, continuation lines included.
    fn reply(&mut self) -> io::Result<Reply> {
        let mut raw = Vec::new();
        loop {
            let mut line = Vec::new();
            if read_line_capped(&mut self.reader, &mut line, MAX_LINE_BYTES)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the peer closed the connection mid-reply",
                ));
            }
            raw.extend_from_slice(&line);
            let trimmed = trim_eol(&line);
            // A hyphen in the fourth column marks a continuation.
            if trimmed.len() >= 4 && trimmed[3] == b'-' {
                continue;
            }
            let code = std::str::from_utf8(trimmed.get(..3).unwrap_or(b""))
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(0);
            return Ok(Reply { code, raw });
        }
    }

    fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\r\n")?;
        self.writer.flush()
    }

    fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes)?;
        self.writer.flush()
    }

    /// Write a buffered message as SMTP payload: dot-stuffed, and
    /// terminated by a lone dot.
    fn send_message(&mut self, message: &[u8]) -> io::Result<()> {
        for line in message.split_inclusive(|&b| b == b'\n') {
            let line = trim_eol(line);
            if line.first() == Some(&b'.') {
                self.writer.write_all(b".")?;
            }
            self.writer.write_all(line)?;
            self.writer.write_all(b"\r\n")?;
        }
        self.writer.write_all(b".\r\n")?;
        self.writer.flush()
    }
}

/// An SMTP reply, kept whole so it can be relayed byte for byte.
struct Reply {
    code: u16,
    raw: Vec<u8>,
}

impl Reply {
    /// The capability lines of an EHLO reply, i.e. everything after the
    /// greeting line.
    fn capabilities(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.raw)
            .lines()
            .skip(1)
            .filter_map(|l| l.get(4..).map(str::to_string))
            .filter(|l| !l.is_empty())
            .collect()
    }
}

/// What came back from the client after `354`.
enum Body {
    Message(Vec<u8>),
    TooLarge,
    Eof,
}

/// The envelope, held back until the headers have been seen.
///
/// `MAIL FROM` and `RCPT TO` are answered here rather than forwarded,
/// and replayed downstream once the message is known. That is what
/// allows an incoming message whose `From` disagrees with its envelope
/// to be re-injected with the sender stripped instead of refused: the
/// decision needs the headers, which arrive after the envelope.
#[derive(Default)]
struct Envelope {
    xforward: Vec<String>,
    mail_from: Option<String>,
    recipients: Vec<String>,
}

impl Envelope {
    fn clear(&mut self) {
        self.xforward.clear();
        self.mail_from = None;
        self.recipients.clear();
    }
}

fn serve(mode: Mode, stream: TcpStream, forward: &str, limiter: &RateLimiter) {
    let mut up = match Wire::new(stream) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("filtermail: cannot set up the client side: {e}");
            return;
        }
    };

    // Downstream first, so a queue that cannot be reached is reported as
    // a temporary failure instead of being discovered at end-of-DATA,
    // after the client has sent the whole message.
    let mut down = match TcpStream::connect(forward).and_then(Wire::new) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("filtermail: cannot reach the re-injection listener at {forward}: {e}");
            let _ = up.send_line("421 4.3.2 the filter cannot reach the queue");
            return;
        }
    };

    match down.as_mut().map(Wire::reply) {
        Some(Ok(r)) if r.code == 220 => {}
        _ => {
            eprintln!("filtermail: the re-injection listener at {forward} did not greet");
            let _ = up.send_line("421 4.3.2 the queue did not answer");
            return;
        }
    }

    if up.send_line("220 noombat-filtermail ready").is_err() {
        return;
    }

    // A peer that goes away is ordinary SMTP. Logging it as a fault,
    // once per message, trains the reader to skip the lines that are.
    if let Err(e) = converse(mode, &mut up, &mut down, limiter)
        && !is_disconnect(&e)
    {
        eprintln!("filtermail: session ended: {e}");
    }

    if let Some(down) = down.as_mut() {
        let _ = down.send_line("QUIT");
    }
}

fn converse(
    mode: Mode,
    up: &mut Wire,
    down: &mut Option<Wire>,
    limiter: &RateLimiter,
) -> io::Result<()> {
    let mut envelope = Envelope::default();

    loop {
        let Some(line) = up.line()? else {
            return Ok(());
        };
        let text = String::from_utf8_lossy(trim_eol(&line)).to_string();
        let verb = text
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();

        match verb.as_str() {
            "EHLO" | "HELO" => {
                let Some(down) = down.as_mut() else {
                    up.send_line("421 4.3.2 the queue connection is gone")?;
                    return Ok(());
                };
                down.send_line(&text)?;
                let reply = down.reply()?;
                if reply.code != 250 {
                    up.send_raw(&reply.raw)?;
                    continue;
                }
                up.send_raw(announce(&reply).as_bytes())?;
            }

            "XFORWARD" => {
                envelope.xforward.push(text);
                up.send_line("250 2.0.0 Ok")?;
            }

            "MAIL" => {
                let sender = address_of(&text);
                // Before the body, which is the point: a sender over
                // quota costs this process one line rather than a
                // message.
                if mode == Mode::Outgoing
                    && !sender.is_empty()
                    && !limiter.allow(&sender.to_ascii_lowercase(), Instant::now())
                {
                    eprintln!("filtermail: rate limit reached for {sender}");
                    up.send_line("450 4.7.1 too many messages, please slow down")?;
                    continue;
                }
                envelope.mail_from = Some(sender);
                envelope.recipients.clear();
                up.send_line("250 2.1.0 Ok")?;
            }

            "RCPT" => {
                if envelope.mail_from.is_none() {
                    up.send_line("503 5.5.1 need MAIL before RCPT")?;
                    continue;
                }
                envelope.recipients.push(address_of(&text));
                up.send_line("250 2.1.5 Ok")?;
            }

            "DATA" => {
                if envelope.mail_from.is_none() || envelope.recipients.is_empty() {
                    up.send_line("503 5.5.1 need MAIL and RCPT before DATA")?;
                    continue;
                }
                up.send_line("354 End data with <CR><LF>.<CR><LF>")?;
                let raw = match read_message(up)? {
                    Body::Eof => return Ok(()),
                    Body::TooLarge => {
                        eprintln!("filtermail: refusing an oversized message");
                        up.send_line("552 5.3.4 message exceeds the filter's size limit")?;
                        envelope.clear();
                        continue;
                    }
                    Body::Message(raw) => raw,
                };

                match inspect(mode, &raw, envelope.mail_from.as_deref().unwrap_or("")) {
                    Verdict::Refuse(reply) => {
                        eprintln!(
                            "filtermail: {} refusing a message from {}: {reply}",
                            mode.label(),
                            envelope.mail_from.as_deref().unwrap_or("<>")
                        );
                        up.send_line(&reply)?;
                        // Nothing was ever sent to the queue: the
                        // envelope was answered here and never
                        // forwarded, so there is no transaction to
                        // abandon.
                        close_downstream(down);
                        envelope.clear();
                    }
                    Verdict::Accept { strip_sender } => {
                        if strip_sender {
                            eprintln!(
                                "filtermail: stripping a sender that disagrees with From: {}",
                                envelope.mail_from.as_deref().unwrap_or("<>")
                            );
                            envelope.mail_from = Some(String::new());
                        }
                        let Some(d) = down.as_mut() else {
                            up.send_line("421 4.3.2 the queue connection is gone")?;
                            return Ok(());
                        };
                        match deliver(d, &envelope, &raw) {
                            Ok(reply) => up.send_raw(&reply.raw)?,
                            Err(e) if is_disconnect(&e) => return Err(e),
                            Err(e) => {
                                eprintln!("filtermail: re-injection failed: {e}");
                                up.send_line("451 4.3.0 the queue would not take the message")?;
                            }
                        }
                        envelope.clear();
                    }
                }
            }

            "RSET" => {
                envelope.clear();
                up.send_line("250 2.0.0 Ok")?;
            }

            "QUIT" => {
                close_downstream(down);
                // Best effort. Postfix sends QUIT and closes without
                // waiting for the answer, so the write losing its race
                // with the close is the normal case, not a fault.
                let _ = up.send_line("221 2.0.0 Bye");
                return Ok(());
            }

            _ => {
                let Some(down) = down.as_mut() else {
                    up.send_line("421 4.3.2 the queue connection is gone")?;
                    return Ok(());
                };
                down.send_line(&text)?;
                let reply = down.reply()?;
                up.send_raw(&reply.raw)?;
            }
        }
    }
}

/// Replay the held envelope downstream and send the message.
fn deliver(down: &mut Wire, envelope: &Envelope, raw: &[u8]) -> io::Result<Reply> {
    for command in &envelope.xforward {
        down.send_line(command)?;
        expect(down, 250, "XFORWARD")?;
    }
    down.send_line(&format!(
        "MAIL FROM:<{}>",
        envelope.mail_from.as_deref().unwrap_or("")
    ))?;
    expect(down, 250, "MAIL FROM")?;
    for recipient in &envelope.recipients {
        down.send_line(&format!("RCPT TO:<{recipient}>"))?;
        expect(down, 250, "RCPT TO")?;
    }
    down.send_line("DATA")?;
    expect(down, 354, "DATA")?;
    down.send_message(raw)?;
    down.reply()
}

fn expect(down: &mut Wire, code: u16, what: &str) -> io::Result<()> {
    let reply = down.reply()?;
    if reply.code != code {
        return Err(io::Error::other(format!(
            "{what} was answered {}",
            String::from_utf8_lossy(trim_eol(&reply.raw))
        )));
    }
    Ok(())
}

/// What to do with a message, once its headers can be read.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept { strip_sender: bool },
    Refuse(String),
}

/// Every content check, in one place, so the order is visible.
fn inspect(mode: Mode, raw: &[u8], mail_from: &str) -> Verdict {
    let parsed = match mailparse::parse_mail(raw) {
        Ok(p) => p,
        // Unparseable is refused rather than passed on: the encryption
        // decision cannot be made without the structure, and this relay
        // carries nothing it has not checked.
        Err(_) => return Verdict::Refuse(REJECT_REPLY.to_string()),
    };

    if !is_encrypted_part(&parsed) {
        return Verdict::Refuse(REJECT_REPLY.to_string());
    }

    let from = header_address(&parsed, "from");
    let envelope = mail_from.to_ascii_lowercase();
    // A null sender is a bounce and has no `From` to agree with.
    let mismatch = !envelope.is_empty()
        && from
            .as_deref()
            .is_some_and(|f| f.to_ascii_lowercase() != envelope);

    match mode {
        Mode::Outgoing => {
            if mismatch {
                return Verdict::Refuse(
                    "550 5.7.1 the From header must match the envelope sender".to_string(),
                );
            }
            Verdict::Accept {
                strip_sender: false,
            }
        }
        Mode::Incoming => {
            // Alignment only, and only when a signature is present.
            //
            // This filter cannot verify a signature: that needs the
            // signing domain's public key from DNS, which OpenDKIM
            // already fetches on the listener behind this one. So the
            // division is by what each component can see. OpenDKIM
            // decides whether a signature is valid and whether an
            // unsigned message is acceptable; this decides whether the
            // signature claims the domain the reader will be shown.
            //
            // Alignment alone proves nothing, because anyone can write
            // a `DKIM-Signature` header with any `d=`. It is worth
            // having only once OpenDKIM is set to reject what does not
            // verify, and that is not yet configured.
            if let (Some(from_domain), Some(signing_domain)) =
                (from.as_deref().and_then(domain_of), dkim_domain(&parsed))
                && from_domain != signing_domain
            {
                return Verdict::Refuse(
                    "550 5.7.1 the DKIM signature does not match the From domain".to_string(),
                );
            }
            // Not refused: a mismatch here would make this relay bounce
            // to an address the sender may have forged. Dropping the
            // envelope sender keeps the message and removes the bounce
            // path with it.
            Verdict::Accept {
                strip_sender: mismatch,
            }
        }
    }
}

/// The addr-spec of a header, lowercased, or `None` when absent.
fn header_address(parsed: &mailparse::ParsedMail<'_>, name: &str) -> Option<String> {
    let value = parsed
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case(name))
        .map(|h| h.get_value())?;
    let address = match (value.find('<'), value.rfind('>')) {
        (Some(open), Some(close)) if close > open => value[open + 1..close].to_string(),
        _ => value.trim().to_string(),
    };
    let address = address.trim().to_ascii_lowercase();
    (!address.is_empty()).then_some(address)
}

fn domain_of(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
}

/// The `d=` tag of the message's DKIM signature.
fn dkim_domain(parsed: &mailparse::ParsedMail<'_>) -> Option<String> {
    let value = parsed
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("dkim-signature"))
        .map(|h| h.get_value())?;
    value.split(';').find_map(|tag| {
        let (key, val) = tag.split_once('=')?;
        (key.trim() == "d").then(|| val.trim().to_ascii_lowercase())
    })
}

/// Whether an error is just the other end having gone away.
fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}

fn close_downstream(down: &mut Option<Wire>) {
    if let Some(mut d) = down.take() {
        let _ = d.send_line("QUIT");
    }
}

/// Build the EHLO reply for the smtpd in front, from what the
/// re-injection listener offers.
///
/// An allowlist, so this filter never advertises something it does not
/// implement. `PIPELINING` in particular is absent on purpose: Postfix
/// does not pipeline to a proxy filter, and the strictly sequential
/// loop here would misread a client that did. `STARTTLS` and `AUTH` are
/// absent because this hop is loopback and the listener in front has
/// already done both.
fn announce(downstream: &Reply) -> String {
    const RELAYABLE: [&str; 6] = [
        "XFORWARD",
        "8BITMIME",
        "SIZE",
        "SMTPUTF8",
        "DSN",
        "ENHANCEDSTATUSCODES",
    ];

    let kept: Vec<String> = downstream
        .capabilities()
        .into_iter()
        .filter(|cap| {
            let head = cap
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            RELAYABLE.contains(&head.as_str())
        })
        .collect();

    let mut out = String::new();
    if kept.is_empty() {
        out.push_str("250 noombat-filtermail\r\n");
        return out;
    }
    out.push_str("250-noombat-filtermail\r\n");
    for (i, cap) in kept.iter().enumerate() {
        let sep = if i + 1 == kept.len() { ' ' } else { '-' };
        out.push_str(&format!("250{sep}{cap}\r\n"));
    }
    out
}

/// Read the message that follows `354`, undoing dot-stuffing and
/// normalising line endings to CRLF.
fn read_message(up: &mut Wire) -> io::Result<Body> {
    let mut message = Vec::new();
    let mut seen = 0usize;
    let mut oversize = false;

    loop {
        let mut line = Vec::new();
        if read_line_capped(&mut up.reader, &mut line, MAX_LINE_BYTES)? == 0 {
            return Ok(Body::Eof);
        }
        let trimmed = trim_eol(&line);
        if trimmed == b"." {
            break;
        }

        seen += line.len();
        if seen > ABORT_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message exceeded the abort threshold",
            ));
        }
        if seen > MAX_MESSAGE_BYTES {
            // Keep reading to the terminating dot so the refusal is a
            // reply rather than a dropped connection, but stop growing
            // the buffer.
            oversize = true;
            continue;
        }

        let payload = if trimmed.first() == Some(&b'.') {
            &trimmed[1..]
        } else {
            trimmed
        };
        message.extend_from_slice(payload);
        message.extend_from_slice(b"\r\n");
    }

    if oversize {
        Ok(Body::TooLarge)
    } else {
        Ok(Body::Message(message))
    }
}

/// Read one line into `out`, including its terminator, returning the
/// number of bytes read and 0 at end of stream.
///
/// `BufRead::read_until` has no ceiling, so a peer that never sends a
/// newline grows the buffer until the process dies.
fn read_line_capped(reader: &mut impl BufRead, out: &mut Vec<u8>, cap: usize) -> io::Result<usize> {
    out.clear();
    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            return Ok(out.len());
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                out.extend_from_slice(&available[..=i]);
                reader.consume(i + 1);
                return Ok(out.len());
            }
            None => {
                let taken = available.len();
                out.extend_from_slice(available);
                reader.consume(taken);
                if out.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SMTP line exceeded the length limit",
                    ));
                }
            }
        }
    }
}

fn trim_eol(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

/// Pull the address out of `MAIL FROM:<a@b>` or `RCPT TO:<a@b>`, for
/// the log line on refusal. Best effort: nothing depends on it.
fn address_of(command: &str) -> String {
    match (command.find('<'), command.rfind('>')) {
        (Some(open), Some(close)) if close > open => command[open + 1..close].to_string(),
        _ => command
            .split_once(':')
            .map(|(_, rest)| rest.trim().to_string())
            .unwrap_or_default(),
    }
}

/// Whether an armoured PGP block starts and ends at a line boundary.
///
/// RFC 4880 puts both markers on lines of their own, so requiring a
/// line start is what separates a real armoured message from the same
/// characters quoted inside running text, and requiring the closing
/// marker too rules out a fragment of a forwarded mail.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole-message form of the encryption decision. Production
    /// parses once in `inspect` and calls `is_encrypted_part`; these
    /// tests are about the decision rather than the parse.
    fn is_encrypted(raw: &[u8]) -> bool {
        mailparse::parse_mail(raw)
            .map(|parsed| is_encrypted_part(&parsed))
            .unwrap_or(false)
    }
    use std::io::Cursor;
    use std::net::{Shutdown, TcpListener};
    use std::sync::mpsc;

    // ..... THE ENCRYPTION DECISION .....

    #[test]
    fn pgp_mime_is_encrypted() {
        let raw = b"Content-Type: multipart/encrypted; \
                     protocol=\"application/pgp-encrypted\"; boundary=abc\r\n\
                     \r\n\
                     --abc\r\n\
                     Content-Type: application/pgp-encrypted\r\n\
                     \r\n\
                     Version: 1\r\n\
                     \r\n\
                     --abc--\r\n";
        assert!(is_encrypted(raw));
    }

    #[test]
    fn inline_pgp_is_encrypted() {
        let raw = b"Content-Type: text/plain\r\n\
                     \r\n\
                     -----BEGIN PGP MESSAGE-----\r\n\
                     abcdef\r\n\
                     -----END PGP MESSAGE-----\r\n";
        assert!(is_encrypted(raw));
    }

    #[test]
    fn autocrypt_setup_is_accepted() {
        let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\
                     \r\n\
                     --b\r\n\
                     Content-Type: application/autocrypt-setup\r\n\
                     \r\n\
                     data\r\n\
                     --b--\r\n";
        assert!(is_encrypted(raw));
    }

    #[test]
    fn plaintext_is_not_encrypted() {
        let raw = b"Content-Type: text/plain\r\n\r\nhello\r\n";
        assert!(!is_encrypted(raw));
    }

    #[test]
    fn plaintext_naming_the_pgp_content_types_is_not_encrypted() {
        // The strings appear; the MIME structure does not.
        let raw = b"Content-Type: text/plain\r\n\
                     \r\n\
                     I tried multipart/encrypted with application/pgp-encrypted and it failed.\r\n\
                     Someone wrote -----BEGIN PGP MESSAGE----- in a reply once.\r\n";
        assert!(!is_encrypted(raw));
    }

    #[test]
    fn a_truncated_armour_block_is_not_encrypted() {
        let raw = b"Content-Type: text/plain\r\n\
                     \r\n\
                     -----BEGIN PGP MESSAGE-----\r\n\
                     abcdef\r\n";
        assert!(!is_encrypted(raw));
    }

    // ..... LINE HANDLING .....

    #[test]
    fn a_line_without_a_newline_is_capped() {
        let long = vec![b'x'; 64];
        let mut reader = Cursor::new(long);
        let mut out = Vec::new();
        let err = read_line_capped(&mut reader, &mut out, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn lines_are_split_on_the_newline_and_keep_it() {
        let mut reader = Cursor::new(b"one\r\ntwo\r\n".to_vec());
        let mut out = Vec::new();
        assert_eq!(read_line_capped(&mut reader, &mut out, 64).unwrap(), 5);
        assert_eq!(out, b"one\r\n");
        assert_eq!(read_line_capped(&mut reader, &mut out, 64).unwrap(), 5);
        assert_eq!(out, b"two\r\n");
        assert_eq!(read_line_capped(&mut reader, &mut out, 64).unwrap(), 0);
    }

    #[test]
    fn an_address_is_pulled_out_of_a_command() {
        assert_eq!(address_of("MAIL FROM:<a@b.example>"), "a@b.example");
        assert_eq!(
            address_of("RCPT TO:<c@d.example> ORCPT=rfc822;c@d.example"),
            "c@d.example"
        );
        assert_eq!(address_of("MAIL FROM:<>"), "");
    }

    // ..... CAPABILITY FILTERING .....

    fn reply_from(text: &str) -> Reply {
        Reply {
            code: 250,
            raw: text.replace('\n', "\r\n").into_bytes(),
        }
    }

    #[test]
    fn only_relayable_capabilities_are_announced() {
        let downstream = reply_from(
            "250-relay.example\n\
             250-PIPELINING\n\
             250-SIZE 10240000\n\
             250-STARTTLS\n\
             250-AUTH PLAIN LOGIN\n\
             250-XFORWARD NAME ADDR PROTO HELO PORT\n\
             250 8BITMIME\n",
        );
        let announced = announce(&downstream);
        assert!(announced.contains("XFORWARD NAME ADDR PROTO HELO PORT"));
        assert!(announced.contains("SIZE 10240000"));
        assert!(announced.contains("8BITMIME"));
        assert!(!announced.contains("PIPELINING"));
        assert!(!announced.contains("STARTTLS"));
        assert!(!announced.contains("AUTH"));
        // Exactly one terminating line, and it is the last.
        let lines: Vec<&str> = announced.trim_end().split("\r\n").collect();
        assert!(lines.last().unwrap().starts_with("250 "));
        assert!(
            lines[..lines.len() - 1]
                .iter()
                .all(|l| l.starts_with("250-"))
        );
    }

    #[test]
    fn a_downstream_with_nothing_relayable_still_gets_a_valid_reply() {
        let announced = announce(&reply_from("250-relay.example\n250 PIPELINING\n"));
        assert_eq!(announced, "250 noombat-filtermail\r\n");
    }

    // ..... THE RATE LIMITER .....

    #[test]
    fn a_burst_is_allowed_and_then_the_sender_waits() {
        // One per second, ten at once.
        let limiter = RateLimiter::new(60, 10);
        let start = Instant::now();

        for i in 0..10 {
            assert!(
                limiter.allow("a@example.invalid", start),
                "message {i} of the burst was refused"
            );
        }
        assert!(
            !limiter.allow("a@example.invalid", start),
            "the eleventh message in the same instant was allowed"
        );

        // A second later, one more has been earned.
        let later = start + Duration::from_secs(1);
        assert!(limiter.allow("a@example.invalid", later));
        assert!(!limiter.allow("a@example.invalid", later));
    }

    #[test]
    fn one_sender_does_not_spend_another_senders_quota() {
        let limiter = RateLimiter::new(60, 1);
        let now = Instant::now();
        assert!(limiter.allow("a@example.invalid", now));
        assert!(!limiter.allow("a@example.invalid", now));
        assert!(
            limiter.allow("b@example.invalid", now),
            "a second sender was refused because the first was over quota"
        );
    }

    // ..... THE CONTENT CHECKS .....

    fn message(headers: &str, encrypted: bool) -> Vec<u8> {
        let body = if encrypted {
            "Content-Type: multipart/encrypted; \
             protocol=\"application/pgp-encrypted\"; boundary=b\r\n\
             \r\n--b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--b--\r\n"
        } else {
            "Content-Type: text/plain\r\n\r\nhello\r\n"
        };
        format!("{headers}{body}").into_bytes()
    }

    #[test]
    fn outgoing_refuses_a_from_that_is_not_the_envelope_sender() {
        let raw = message("From: <someone.else@chat.example>\r\n", true);
        assert_eq!(
            inspect(Mode::Outgoing, &raw, "user@chat.example"),
            Verdict::Refuse("550 5.7.1 the From header must match the envelope sender".to_string())
        );
    }

    #[test]
    fn outgoing_accepts_a_matching_from() {
        let raw = message("From: \"A User\" <user@chat.example>\r\n", true);
        assert_eq!(
            inspect(Mode::Outgoing, &raw, "user@chat.example"),
            Verdict::Accept {
                strip_sender: false
            }
        );
    }

    #[test]
    fn incoming_strips_the_sender_rather_than_refusing_a_mismatch() {
        // Refusing would make this relay bounce to an envelope sender
        // the peer may have forged. Keeping the message and dropping
        // the sender removes the bounce path instead.
        let raw = message(
            "From: <someone@peer.example>\r\n\
             DKIM-Signature: v=1; a=rsa-sha256; d=peer.example; s=sel; b=xx\r\n",
            true,
        );
        assert_eq!(
            inspect(Mode::Incoming, &raw, "bounce@peer.example"),
            Verdict::Accept { strip_sender: true }
        );
    }

    #[test]
    fn incoming_refuses_a_signature_that_does_not_align_with_from() {
        let raw = message(
            "From: <someone@victim.example>\r\n\
             DKIM-Signature: v=1; a=rsa-sha256; d=attacker.example; s=sel; b=xx\r\n",
            true,
        );
        assert!(matches!(
            inspect(Mode::Incoming, &raw, "someone@victim.example"),
            Verdict::Refuse(reply) if reply.contains("does not match the From domain")
        ));
    }

    #[test]
    fn incoming_leaves_an_unsigned_message_to_opendkim() {
        // Absence is not this filter's decision: it cannot verify a
        // signature, so it cannot sensibly demand one. OpenDKIM, which
        // can, decides whether unsigned mail is acceptable.
        let raw = message("From: <someone@peer.example>\r\n", true);
        assert_eq!(
            inspect(Mode::Incoming, &raw, "someone@peer.example"),
            Verdict::Accept {
                strip_sender: false
            }
        );
    }

    #[test]
    fn incoming_accepts_an_aligned_signature() {
        let raw = message(
            "From: <someone@peer.example>\r\n\
             DKIM-Signature: v=1; a=rsa-sha256; d=peer.example; s=sel; b=xx\r\n",
            true,
        );
        assert_eq!(
            inspect(Mode::Incoming, &raw, "someone@peer.example"),
            Verdict::Accept {
                strip_sender: false
            }
        );
    }

    #[test]
    fn a_null_sender_is_not_a_mismatch() {
        // A bounce carries no envelope sender and a mailer-daemon From.
        let raw = message(
            "From: <MAILER-DAEMON@peer.example>\r\n\
             DKIM-Signature: v=1; a=rsa-sha256; d=peer.example; s=sel; b=xx\r\n",
            true,
        );
        assert_eq!(
            inspect(Mode::Incoming, &raw, ""),
            Verdict::Accept {
                strip_sender: false
            }
        );
    }

    #[test]
    fn plaintext_is_refused_whichever_side_it_arrives_on() {
        let raw = message(
            "From: <user@chat.example>\r\n\
             DKIM-Signature: v=1; a=rsa-sha256; d=chat.example; s=sel; b=xx\r\n",
            false,
        );
        for mode in [Mode::Outgoing, Mode::Incoming] {
            assert!(
                matches!(inspect(mode, &raw, "user@chat.example"), Verdict::Refuse(_)),
                "{mode:?} accepted plaintext"
            );
        }
    }

    #[test]
    fn an_address_is_read_out_of_a_header() {
        let parsed = mailparse::parse_mail(b"From: \"N\" <a@B.example>\r\n\r\nx").unwrap();
        assert_eq!(
            header_address(&parsed, "from").as_deref(),
            Some("a@b.example")
        );
        assert_eq!(domain_of("a@b.example").as_deref(), Some("b.example"));
    }

    // ..... THE PROXY, END TO END .....

    /// A stand-in for the re-injection smtpd. Answers the handshake,
    /// accepts the envelope, and reports what it was given.
    fn fake_reinjection_listener() -> (String, mpsc::Receiver<Option<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut wire = Wire::new(stream).unwrap();
                    wire.send_line("220 fake ESMTP").unwrap();
                    let mut delivered = None;
                    while let Ok(Some(line)) = wire.line() {
                        let text = String::from_utf8_lossy(trim_eol(&line)).to_string();
                        let verb = text
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_ascii_uppercase();
                        match verb.as_str() {
                            "EHLO" => wire
                                .send_raw(b"250-fake\r\n250-XFORWARD NAME ADDR\r\n250 8BITMIME\r\n")
                                .unwrap(),
                            "DATA" => {
                                wire.send_line("354 go ahead").unwrap();
                                match read_message(&mut wire).unwrap() {
                                    Body::Message(m) => {
                                        delivered = Some(m);
                                        wire.send_line("250 2.0.0 Ok: queued as FAKE1").unwrap();
                                    }
                                    _ => wire.send_line("451 4.3.0 error").unwrap(),
                                }
                            }
                            "QUIT" => {
                                let _ = wire.send_line("221 2.0.0 Bye");
                                break;
                            }
                            _ => wire.send_line("250 2.0.0 Ok").unwrap(),
                        }
                    }
                    let _ = tx.send(delivered);
                });
            }
        });

        (addr, rx)
    }

    /// Drive the proxy the way Postfix does, and return the reply to
    /// the terminating dot.
    fn submit_through_proxy(proxy: &str, body: &str) -> (String, TcpStream) {
        let stream = TcpStream::connect(proxy).unwrap();
        let mut wire = Wire::new(stream.try_clone().unwrap()).unwrap();
        assert_eq!(wire.reply().unwrap().code, 220);

        wire.send_line("EHLO front.example").unwrap();
        assert_eq!(wire.reply().unwrap().code, 250);
        wire.send_line("XFORWARD NAME=client.example ADDR=192.0.2.1")
            .unwrap();
        assert_eq!(wire.reply().unwrap().code, 250);
        wire.send_line("MAIL FROM:<sender@chat.example>").unwrap();
        assert_eq!(wire.reply().unwrap().code, 250);
        wire.send_line("RCPT TO:<rcpt@chat.example>").unwrap();
        assert_eq!(wire.reply().unwrap().code, 250);
        wire.send_line("DATA").unwrap();
        assert_eq!(wire.reply().unwrap().code, 354);

        wire.send_raw(body.replace('\n', "\r\n").as_bytes())
            .unwrap();
        wire.send_raw(b".\r\n").unwrap();
        let verdict = wire.reply().unwrap();
        (String::from_utf8_lossy(&verdict.raw).to_string(), stream)
    }

    fn start_proxy(forward: String) -> String {
        start_proxy_in(Mode::Outgoing, forward)
    }

    fn start_proxy_in(mode: Mode, forward: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Effectively no limit: these tests are about the proxy, and a
        // rate limit that fired would look like a proxy fault.
        let limiter = Arc::new(RateLimiter::new(100_000, 100_000));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let forward = forward.clone();
                let limiter = Arc::clone(&limiter);
                thread::spawn(move || serve(mode, stream, &forward, &limiter));
            }
        });
        addr
    }

    #[test]
    fn an_encrypted_message_reaches_the_queue() {
        let (fake, delivered) = fake_reinjection_listener();
        let proxy = start_proxy(fake);

        let (verdict, stream) = submit_through_proxy(
            &proxy,
            "Content-Type: multipart/encrypted; \
             protocol=\"application/pgp-encrypted\"; boundary=b\n\
             \n\
             --b\n\
             Content-Type: application/pgp-encrypted\n\
             \n\
             Version: 1\n\
             --b--\n",
        );

        assert!(verdict.starts_with("250"), "verdict was {verdict}");
        // The queue id from the listener behind the filter, not one
        // invented here.
        assert!(verdict.contains("FAKE1"), "verdict was {verdict}");
        let _ = stream.shutdown(Shutdown::Both);

        let got = delivered.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(got.is_some(), "nothing was delivered");
    }

    #[test]
    fn a_plaintext_message_is_refused_and_never_reaches_the_queue() {
        let (fake, delivered) = fake_reinjection_listener();
        let proxy = start_proxy(fake);

        let (verdict, stream) =
            submit_through_proxy(&proxy, "Content-Type: text/plain\n\nhello in the clear\n");

        assert!(verdict.starts_with("550"), "verdict was {verdict}");
        let _ = stream.shutdown(Shutdown::Both);

        // The refusal is the whole point: the listener behind the filter
        // must have been handed nothing at all.
        let got = delivered.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(got.is_none(), "a refused message still reached the queue");
    }

    #[test]
    fn dot_stuffing_survives_the_round_trip() {
        let (fake, delivered) = fake_reinjection_listener();
        let proxy = start_proxy(fake);

        // A body line starting with a dot, which SMTP stuffs on the
        // wire and which must arrive unstuffed and unchanged.
        let (verdict, stream) = submit_through_proxy(
            &proxy,
            "Content-Type: text/plain\n\
             \n\
             -----BEGIN PGP MESSAGE-----\n\
             ..dotted line\n\
             -----END PGP MESSAGE-----\n",
        );
        assert!(verdict.starts_with("250"), "verdict was {verdict}");
        let _ = stream.shutdown(Shutdown::Both);

        let got = delivered
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .expect("nothing was delivered");
        let text = String::from_utf8_lossy(&got);
        assert!(
            text.contains("\r\n.dotted line\r\n"),
            "dot-stuffing was not undone exactly once: {text:?}"
        );
    }

    #[test]
    fn an_unreachable_queue_is_a_temporary_failure() {
        // Bind and drop, so the port is almost certainly closed.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().to_string()
        };
        let proxy = start_proxy(dead);

        let stream = TcpStream::connect(&proxy).unwrap();
        let mut wire = Wire::new(stream).unwrap();
        let greeting = wire.reply().unwrap();
        assert_eq!(
            greeting.code,
            421,
            "expected a temporary failure, got {}",
            String::from_utf8_lossy(&greeting.raw)
        );
    }
}
