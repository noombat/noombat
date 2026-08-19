// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Chatmail closed-federation allowlist synchronisation.
//!
//! Polls the published allowlist JSON document at a configurable URL
//! (default: `https://noombat.org/chatmail-allowlist.json`) and
//! regenerates the Postfix `transport_maps` file on change.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tracing::{info, warn};

use crate::AppState;

/// Shape of the published allowlist JSON document.
///
/// Expected at `https://noombat.org/chatmail-allowlist.json`:
///
/// ```json
/// {
///   "domains": [
///     "chat.noombat.social",
///     "chat.careers.acme.com"
///   ]
/// }
/// ```
#[derive(Debug, Deserialize)]
struct AllowlistDocument {
    domains: Vec<String>,
}

/// Start the allowlist polling loop in a background thread.
///
/// The loop runs indefinitely, polling the allowlist URL at the
/// configured interval. On each successful fetch, if the domain set
/// has changed, the `transport_maps` file is regenerated and Postfix
/// is reloaded.
pub fn start_polling(state: Arc<AppState>) {
    let url = state.config.allowlist_url.clone();
    let interval = Duration::from_secs(state.config.allowlist_poll_interval_secs);
    let transport_maps_path = state.config.transport_maps_path.clone();
    let sender_domains_path = state.config.sender_domains_path.clone();

    if url.is_empty() {
        info!("allowlist URL not configured; synchronisation disabled");
        return;
    }

    std::thread::spawn(move || {
        info!(
            url = %url,
            interval_secs = interval.as_secs(),
            "allowlist polling started"
        );

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        let mut last_domains: BTreeSet<String> = BTreeSet::new();
        let mut etag: Option<String> = None;

        loop {
            match fetch_allowlist(&agent, &url, etag.as_deref()) {
                Ok(FetchOutcome::Unchanged) => {}
                Ok(FetchOutcome::Fetched { domains, etag: new }) => {
                    etag = new;
                    if domains != last_domains {
                        info!(
                            count = domains.len(),
                            "allowlist changed; regenerating transport_maps"
                        );
                        let outbound = write_transport_maps(&transport_maps_path, &domains);
                        let inbound = write_sender_domains(&sender_domains_path, &domains);

                        // Both or neither. Regenerating only the outbound map
                        // would leave the relay accepting from domains it
                        // refuses to answer, which is the asymmetry this pair
                        // exists to remove.
                        match (outbound, inbound) {
                            (Ok(()), Ok(())) => {
                                for path in [&transport_maps_path, &sender_domains_path] {
                                    let _ =
                                        std::process::Command::new("postmap").arg(path).status();
                                }
                                let _ =
                                    std::process::Command::new("postfix").arg("reload").status();
                                info!("allowlist maps regenerated and postfix reloaded");
                            }
                            (a, b) => {
                                if let Err(e) = a {
                                    warn!(error = %e, "failed to write transport_maps");
                                }
                                if let Err(e) = b {
                                    warn!(error = %e, "failed to write sender domains");
                                }
                            }
                        }
                        last_domains = domains;
                    }
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "allowlist fetch failed");
                }
            }

            // Jitter up to a tenth of the interval, so that relays
            // started from the same image do not poll in lockstep and
            // the sequence reveals a little less about this one's uptime.
            let jitter = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64 % (interval.as_secs() / 10 + 1))
                .unwrap_or(0);
            std::thread::sleep(interval + Duration::from_secs(jitter));
        }
    });
}

/// The result of one allowlist poll.
enum FetchOutcome {
    /// The server answered `304 Not Modified`; the cached set stands.
    Unchanged,
    /// A body was returned, with its `ETag` if the server supplied one.
    Fetched {
        domains: BTreeSet<String>,
        etag: Option<String>,
    },
}

/// Fetch the allowlist JSON document from the given URL.
///
/// Uses a blocking HTTP GET via `ureq`. The caller provides
/// a pre-configured [`ureq::Agent`] with the desired timeout.
///
/// When `etag` is supplied it is sent as `If-None-Match`, so an
/// unchanged list costs a `304` and no body. Note what this does and
/// does not buy: it saves bandwidth for whoever hosts the list, and it
/// does **not** reduce disclosure, because the request is still made and
/// still reveals this relay's address and the time it was made.
fn fetch_allowlist(
    agent: &ureq::Agent,
    url: &str,
    etag: Option<&str>,
) -> Result<FetchOutcome, Box<dyn std::error::Error>> {
    let mut request = agent.get(url);
    if let Some(tag) = etag {
        request = request.header("If-None-Match", tag);
    }

    let mut response = request.call()?;
    if response.status() == 304 {
        return Ok(FetchOutcome::Unchanged);
    }

    let new_etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body: String = response.body_mut().read_to_string()?;
    let doc: AllowlistDocument = serde_json::from_str(&body)?;
    Ok(FetchOutcome::Fetched {
        domains: doc.domains.into_iter().collect(),
        etag: new_etag,
    })
}

/// Write the Postfix `transport_maps` file.
///
/// Each allowlisted domain gets a line `domain smtp:[domain]`,
/// directing Postfix to deliver to that domain via SMTP. Domains
/// not in the map receive no transport entry, causing Postfix to
/// reject delivery attempts (the default transport is not configured
/// for external delivery).
fn write_transport_maps(path: &str, domains: &BTreeSet<String>) -> std::io::Result<()> {
    let mut f = fs::File::create(path)?;
    writeln!(
        f,
        "# Generated by noombat-chatmail-admin allowlist sync. Do not edit."
    )?;
    for domain in domains {
        writeln!(f, "{domain} smtp:[{domain}]")?;
    }
    info!(path = %path, entries = domains.len(), "wrote transport_maps");
    Ok(())
}

/// Write the inbound sender-domain allowlist.
///
/// `transport_maps` decides where this relay will send; this decides who it
/// will accept from. Without it the policy is outbound-only: a message from
/// an unlisted domain is delivered and the reply is refused.
///
/// The null sender is permitted explicitly, or delivery status notifications
/// from allowlisted peers are rejected along with everything else.
fn write_sender_domains(path: &str, domains: &BTreeSet<String>) -> std::io::Result<()> {
    let mut f = fs::File::create(path)?;
    writeln!(
        f,
        "# Generated by noombat-chatmail-admin allowlist sync. Do not edit."
    )?;
    writeln!(f, "<> OK")?;
    for domain in domains {
        writeln!(f, "{domain} OK")?;
    }
    info!(path = %path, entries = domains.len(), "wrote sender domains");
    Ok(())
}
