// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! The one outbound HTTP client federation is allowed to use.
//!
//! Every federation fetch starts from a URI somebody else chose. The
//! signer's `keyId` on an inbound request is the sharpest case: the inbox
//! must resolve it to check the signature, so an unauthenticated stranger
//! picks a URL and the server fetches it, before anything about the
//! request has been verified. `http://169.254.169.254/`, `http://redis:6379`
//! and every other service on the deployment's network are one POST away
//! unless the client itself refuses.
//!
//! Three layers, because each defeats an attack the others do not:
//!
//! 1. **A resolver that rejects private and reserved addresses.** This is
//!    also what closes DNS rebinding: reqwest connects to the addresses
//!    this resolver returned, so there is no second lookup between the
//!    check and the connection for an attacker to race.
//! 2. **A redirect policy that re-checks every hop** and stops after two.
//!    A public host answering `302 Location: http://127.0.0.1/` defeats
//!    any check made only against the URL that was submitted.
//! 3. **A byte budget on the response.** A URL that streams forever is a
//!    denial of service even when the address is legitimate.
//!
//! # What the client does *not* do by itself
//!
//! It does not stop an address literal. hyper's connector short-circuits
//! when the host already parses as an IP: "skip resolving the dns and
//! start connecting right away". [`GuardedResolver`] is never consulted
//! for `https://169.254.169.254/`, which is the exact request this module
//! exists to refuse, and a connector layer cannot substitute because
//! reqwest's `Unnameable` keeps its `Uri` private.
//!
//! Literals, scheme and embedded credentials are therefore checked in
//! [`check_url`], which runs on the URL a caller supplies and again on
//! every redirect hop. To keep that from being a rule someone has to
//! remember, federation fetches go through [`guarded_get`] rather than
//! touching the client directly, and the one path that cannot ([`crate::delivery`],
//! which POSTs) calls [`check_url`] itself. A future call site that
//! reaches for the raw client gets the resolver and the redirect policy
//! but not the literal check, so: do not reach for the raw client.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use noombat_core::error::{NoombatError, Result};
use noombat_core::net::is_private_ip;
use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::de::DeserializeOwned;
use tracing::warn;

/// Largest response body any federation fetch will read.
///
/// The same bound as [`crate::integrity_proof::MAX_PROOF_DOCUMENT_BYTES`],
/// and deliberately so: a fetched document goes on to be canonicalised for
/// proof verification, and a limit here that exceeded that one would just
/// move the refusal later, after the work had been done.
pub const MAX_FETCH_BYTES: usize = crate::integrity_proof::MAX_PROOF_DOCUMENT_BYTES;

/// Redirect hops a federation fetch may follow.
///
/// Not zero, because instances legitimately redirect actor URIs, commonly
/// to normalise a trailing slash or letter case. Small, because each hop
/// is another URL the original request did not name.
const MAX_REDIRECTS: usize = 2;

/// Whether loopback and private addresses, and plain `http`, are reachable.
///
/// Follows [`crate::signed_fetch::set_allow_unsigned_fetch`]: set once at
/// startup, defaulting to the safe value so that a caller that forgets
/// gets the production posture rather than the permissive one.
static ALLOW_LOCAL_TARGETS: OnceLock<bool> = OnceLock::new();

/// Permit fetches to loopback and private addresses over plain `http`.
///
/// Intended solely for an instance whose own domain is a loopback name,
/// which is how the development and interop harnesses run. Enabling it on
/// a public instance re-opens the whole of this module.
pub fn set_allow_local_targets(allow: bool) {
    let _ = ALLOW_LOCAL_TARGETS.set(allow);
    if allow {
        warn!(
            "federation fetches to private and loopback addresses are ENABLED; \
             this is a development posture and must not be used in production"
        );
    }
}

fn allow_local_targets() -> bool {
    ALLOW_LOCAL_TARGETS.get().copied().unwrap_or(false)
}

/// Whether an instance domain is a loopback name.
///
/// Derived from the configured domain rather than exposed as its own
/// operator setting: an option that disables an SSRF guard is an option
/// somebody eventually sets in production for an afternoon.
pub fn domain_is_local(domain: &str) -> bool {
    let host = domain.split(':').next().unwrap_or(domain);
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

/// Reject a URL a federation fetch must not follow.
///
/// Applied to the URL a caller supplies and again to every redirect hop.
/// Address filtering is the resolver's job; this covers what a hostname
/// alone can carry.
pub fn check_url(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" => {}
        "http" if allow_local_targets() => {}
        other => {
            return Err(NoombatError::BadRequest(format!(
                "refusing a federation fetch over {other}: only https is permitted"
            )));
        }
    }

    let Some(host) = url.host_str().filter(|h| !h.is_empty()) else {
        return Err(NoombatError::BadRequest(
            "refusing a federation fetch to a URL with no host".into(),
        ));
    };

    // An address written as a literal never reaches the resolver.
    //
    // hyper's connector short-circuits when the host parses as an IP:
    // "If the host is already an IP addr (v4 or v6), skip resolving the
    // dns and start connecting right away." So `GuardedResolver` never
    // sees `http://169.254.169.254/`, which is precisely the request this
    // whole module exists to refuse. The literal has to be checked here.
    //
    // Alternative encodings are already handled: the URL parser
    // normalises `2130706433` and `0x7f.1` to `127.0.0.1` before this
    // point, so there is one spelling left to test.
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>()
        && !allow_local_targets()
        && is_private_ip(ip)
    {
        return Err(NoombatError::BadRequest(format!(
            "refusing a federation fetch to the private or reserved address {ip}"
        )));
    }

    // Credentials in the authority are never legitimate here, and they are
    // the classic way to make a URL read as one host and resolve as
    // another to anything parsing it by eye or by regex.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(NoombatError::BadRequest(
            "refusing a federation fetch to a URL carrying credentials".into(),
        ));
    }

    Ok(())
}

/// A resolver that refuses to hand back an address federation must not
/// reach.
///
/// Rejects the name outright when *any* resolved address is private,
/// rather than filtering to the public ones. A name answering with both is
/// not a host that happens to have an internal interface, it is a rebinding
/// attempt, and there is no reading of it that makes the fetch safe.
struct GuardedResolver;

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str().to_owned();

            // Port zero: reqwest substitutes the real one, and the
            // resolver has no business caring which.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("DNS resolution failed for {host}: {e}").into()
                })?
                .collect();

            if addrs.is_empty() {
                return Err(format!("DNS resolution returned no addresses for {host}").into());
            }

            if !allow_local_targets()
                && let Some(blocked) = addrs.iter().find(|a| is_private_ip(a.ip()))
            {
                warn!(
                    host,
                    address = %blocked.ip(),
                    "refusing a federation fetch to a private or reserved address"
                );
                return Err(format!(
                    "{host} resolves to a private or reserved address; refusing to fetch"
                )
                .into());
            }

            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// The redirect policy: bounded, and every hop re-checked.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error(format!(
                "federation fetch exceeded {MAX_REDIRECTS} redirects"
            ));
        }
        match check_url(attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e.to_string()),
        }
    })
}

/// Build the client every federation fetch and delivery goes through.
///
/// # Errors
///
/// Returns an error if the underlying TLS or connection pool cannot be
/// constructed.
pub fn client(user_agent: String, timeout: Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeout)
        .redirect(redirect_policy())
        .dns_resolver(Arc::new(GuardedResolver))
        .build()
}

/// Fetch an ActivityPub document, refusing the URLs federation must not
/// follow.
///
/// The single entry point for federation GETs. It exists so that
/// [`check_url`] cannot be forgotten: the address-literal case is not
/// covered by the client's resolver, so a call site that builds its own
/// request is a call site with a hole in it.
///
/// Returns the response without inspecting its status, because callers
/// treat statuses differently (`resolve_actor` records a tombstone on
/// 410) and because the final URL after redirects is load-bearing for the
/// document-origin check in `ap_actor_to_remote`.
///
/// # Errors
///
/// Returns an error if the URL is one this instance must not fetch, or if
/// the request fails.
pub async fn guarded_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    let parsed = Url::parse(url)
        .map_err(|e| NoombatError::BadRequest(format!("unusable URI {url}: {e}")))?;
    check_url(&parsed)?;

    client
        .get(parsed)
        .header("Accept", "application/activity+json")
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("fetch of {url} failed: {e}")))
}

/// Read a JSON body, refusing to buffer more than [`MAX_FETCH_BYTES`].
///
/// `Response::json` buffers whatever arrives, so a peer that streams
/// without end exhausts memory on a request it did not have to
/// authenticate. `what` names the document in the error, since by this
/// point the URL is several layers up.
///
/// # Errors
///
/// Returns an error if the body exceeds the budget, if the transfer fails,
/// or if what arrived is not the expected JSON.
pub async fn json_within_limit<T: DeserializeOwned>(
    mut response: reqwest::Response,
    what: &str,
) -> Result<T> {
    let mut body: Vec<u8> = Vec::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| NoombatError::Federation(format!("reading {what} failed: {e}")))?
    {
        if body.len() + chunk.len() > MAX_FETCH_BYTES {
            return Err(NoombatError::Federation(format!(
                "{what} exceeds the {MAX_FETCH_BYTES} byte limit; refusing to buffer it"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body)
        .map_err(|e| NoombatError::Federation(format!("invalid JSON in {what}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_is_fetchable_and_credentials_are_refused() {
        assert!(check_url(&Url::parse("https://remote.example/users/a").unwrap()).is_ok());
        assert!(check_url(&Url::parse("http://remote.example/users/a").unwrap()).is_err());
        assert!(check_url(&Url::parse("file:///etc/passwd").unwrap()).is_err());
        assert!(check_url(&Url::parse("gopher://remote.example/1").unwrap()).is_err());
        assert!(
            check_url(&Url::parse("https://user:pw@remote.example/users/a").unwrap()).is_err(),
            "credentials in the authority disguise the real host"
        );
        assert!(
            check_url(&Url::parse("https://remote.example:8443/users/a").unwrap()).is_ok(),
            "a non-default port is ordinary for a self-hosted instance"
        );
    }

    /// The attack the entry names, in the form it names it.
    #[test]
    fn an_address_literal_is_refused_even_though_it_never_reaches_the_resolver() {
        for target in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/inbox",
            "https://[::1]/inbox",
            "https://[::ffff:127.0.0.1]/inbox",
            "https://10.0.0.5/inbox",
            "https://192.168.1.1/inbox",
            // Decimal and hex spellings of 127.0.0.1: the URL parser
            // normalises these before we see them, which is why one
            // check covers all of them.
            "https://2130706433/inbox",
            "https://0x7f.0.0.1/inbox",
        ] {
            let url = Url::parse(target).expect("parses");
            assert!(
                check_url(&url).is_err(),
                "{target} (host {:?}) must be refused",
                url.host_str()
            );
        }

        assert!(check_url(&Url::parse("https://93.184.216.34/inbox").unwrap()).is_ok());
    }

    #[tokio::test]
    async fn the_resolver_refuses_a_name_that_points_at_loopback() {
        use std::str::FromStr as _;

        // `localhost` resolves to 127.0.0.1 and ::1 on every platform this
        // runs on, which is the named-host form of the same attack.
        let refused = GuardedResolver
            .resolve(Name::from_str("localhost").expect("valid name"))
            .await;
        assert!(
            refused.is_err(),
            "a name resolving to loopback must not yield an address"
        );
    }

    /// The whole point, end to end: the built client must not open a
    /// socket to a private address. Asserting on the error alone would
    /// pass even if the connection were made and then discarded, so this
    /// watches the listener instead.
    #[tokio::test]
    async fn the_client_opens_no_socket_to_a_loopback_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener binds");
        let port = listener.local_addr().unwrap().port();

        let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = accepted.clone();
        tokio::spawn(async move {
            if listener.accept().await.is_ok() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let client = client("test".to_owned(), Duration::from_secs(5)).expect("client builds");

        // The literal goes through `guarded_get`, which is how every
        // federation fetch reaches the network; the named host is refused
        // by the client's own resolver, with no help from `check_url`.
        assert!(
            guarded_get(&client, &format!("https://127.0.0.1:{port}/inbox"))
                .await
                .is_err(),
            "an address literal must not be fetchable"
        );
        assert!(
            client
                .get(format!("https://localhost:{port}/inbox"))
                .send()
                .await
                .is_err(),
            "a name resolving to loopback must not be fetchable even without check_url"
        );

        // Give a connection that should not exist a chance to land.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !accepted.load(std::sync::atomic::Ordering::SeqCst),
            "a socket was opened to the target; the guard is decorative"
        );
    }

    /// A peer that answers with an unbounded body must be refused rather
    /// than buffered. Exercised just over the limit rather than at the
    /// 100 MB the audit names: the branch is the same, and the fixture
    /// stays cheap.
    #[tokio::test]
    async fn an_oversized_body_is_refused_rather_than_buffered() {
        fn response_of(len: usize) -> reqwest::Response {
            let body = vec![b'x'; len];
            reqwest::Response::from(http::Response::new(body))
        }

        // Just under: a well-formed document still parses.
        let under = format!("\"{}\"", "x".repeat(1024));
        let ok: serde_json::Value = json_within_limit(
            reqwest::Response::from(http::Response::new(under.into_bytes())),
            "test document",
        )
        .await
        .expect("a small body parses");
        assert!(ok.is_string());

        // Just over: refused, and the error says why.
        let err = json_within_limit::<serde_json::Value>(
            response_of(MAX_FETCH_BYTES + 1),
            "actor document",
        )
        .await
        .expect_err("an oversized body must be refused");
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_loopback_instance_domain_is_recognised() {
        for domain in [
            "localhost",
            "localhost:8080",
            "noombat.localhost",
            "127.0.0.1",
        ] {
            assert!(domain_is_local(domain), "{domain} is a development domain");
        }
        for domain in ["noombat.social", "localhost.evil.example"] {
            assert!(!domain_is_local(domain), "{domain} is not");
        }
    }
}
