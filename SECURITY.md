# Security

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability reporting on this repository (Security --> Report a vulnerability).
This opens a channel visible only to the maintainers.

Please do not open a public issue for a suspected vulnerability, and please do not disclose publicly until a fix is available or 90 days have passed, whichever comes first.

A useful report states what an attacker gains, the position they must already occupy to attempt it, and the steps to reproduce.

## What the encrypted chat does and does not protect

Noombat's chat is end-to-end encrypted using OpenPGP with Autocrypt Level 1 key exchange.
Message bodies are encrypted in the browser, and the private key is held in a credential blob encrypted under a key derived from the account password, which is never transmitted.
The server stores ciphertext it cannot read.

That describes the cryptography.
It does not describe the trust model, because **the browser executes JavaScript that the instance operator serves**.
The distinction matters more than the cipher choice:

- **Confidentiality against a passive server holds.**
  An operator who records everything they store and everything that crosses the wire learns ciphertext.
  Message bodies, the OpenPGP private key, and the Chatmail password are all encrypted before they reach the server.

- **Integrity against an active server does not hold.**
  An operator who modifies the served JavaScript defeats the entire scheme without attacking any cipher.
  One altered script, delivered to one user, on one page load, can exfiltrate the decrypted plaintext or the private key.
  It leaves no trace in the transport, in the database, or in this repository, because the published source and the served bytes are different artefacts and only the second one runs.

This is a property of browser-delivered cryptography in general, not of Noombat's implementation.
No amount of care inside the application removes it, because the application is the thing being substituted.
Any project claiming otherwise about a plain web client is overstating its guarantees.

### What can be done about it

Three responses are possible, in increasing order of strength.

**1. Detection through attestation.**
Each release publishes signed manifests:
the SHA-256 of every browser asset, and the SHA-256 of every file and the version of every Debian package in both published images.
They are extracted from the images that are then published, in one build, so the hashes describe what an operator actually runs rather than a separate build made only to be signed.
See [`docs/verifying-builds.md`](docs/verifying-builds.md).

*It detects* **substitution**: a listed file whose bytes have changed, served broadly and persistently enough for somebody to observe.

*It does not detect* **addition** on its own.
The manifest is a set of hashes for files that exist; it says nothing about which files a page loads.
An operator can add a same-origin script the manifest never names, load it from a modified template, and leave every manifest entry verifying.
`script-src 'self'` permits it.
The end-to-end suite closes this for the pages it covers by checking the complement, i.e. that nothing outside the manifest is loaded, and [`docs/verifying-builds.md`](docs/verifying-builds.md) gives readers a similar check.
The readers' check sees what the instance sends to curl, and curl is easy to tell from a browser, so in the pages it checks it catches a change sent to everyone, but not an operator who sends the check something else.
Neither is a substitute for enforcement at load time.

*It does not detect* **targeting**: correct assets to whoever checks, modified assets to one session.
Detection is per-observation, and nobody observes every load.

*Attestation and reproducibility.*
The browser assets and the Rust binaries are both attested and rebuilt to the same bytes from source:
CI checks the assets on every change, and every release compares each file its image manifests list, the binaries included, with a second build of the same commit before it signs.
[`docs/verifying-builds.md`](docs/verifying-builds.md) step 4 rebuilds both.

**2. Enforcement in the browser.**
Verification on every page load, before any script executes, requires a component the operator does not control.
WEBCAT, developed by the Freedom of the Press Foundation, does exactly this:
a browser extension checks an enrolled site's assets against a signed, transparency-logged manifest and blocks the load on mismatch.
It is in alpha; see [`docs/webcat.md`](docs/webcat.md) for the evaluation and its current status here.
A browser standard covering the same ground, WAICT, is under discussion.

**3. A client the operator did not deliver.**
The strongest option in this list, and the one that needs the operator to have finished a deployment step.
Delta Chat validates the relay's certificate chain and refuses to connect to a relay presenting one it cannot verify, which is a relay whose operator has not yet obtained a publicly trusted certificate for `chat.`.
Noombat's Chatmail account is a standard IMAP/SMTP account with a standard OpenPGP key.
The chat credentials page at `/settings/chat` offers those credentials and a `DCACCOUNT` QR code that configures [Delta Chat](https://delta.chat) against the same account.

Delta Chat is reproducibly built and distributed through app stores, so its code does not come from the Noombat operator at all.
Reading the same conversations through it removes the operator from the code-supply path entirely.
**If you have a threat model in which the instance operator is an adversary, use Delta Chat and treat the web client as a convenience.**

## Key substitution and Autocrypt

Autocrypt learns a peer's key from headers on incoming messages.
A server that rewrites those headers can substitute its own key, and the client cannot distinguish that from a legitimate key rotation.

The client reports what it can observe:
when a key already held for a peer is replaced by different key material, a notice appears in that conversation and the event is recorded in the encrypted blob, so it survives the session and synchronises across devices.
The chat interface also shows the user's own fingerprint alongside the selected peer's, for comparison over a channel the server does not control.

Before a peer has written, the web client can write to them with the key published for them: each member's client publishes its public key to their instance, which serves it to members allowed to see their chat address and, beside the address, in the actor document other noombat instances read.
That first contact trusts the instance.
An instance that substitutes a member's key at that point can read what is sent to them, and since the same server relays the peer's later mail, it can go on substituting their Autocrypt headers too; a header whose key differs from the one used raises the key-change notice above, but a server that never lets one through raises nothing.
Comparing fingerprints is what settles it: the verification panel shows the fingerprint of the key a message would go to, the one a first message then uses, and marks a key the instance provided until a header relayed from the peer carries a key; the conversation also shows a notice with that fingerprint when the client first takes a published key, on that device.
The server checks a published key's structure only; the client verifies its signatures before encrypting to it.
A key published by another noombat instance is used only when its address is on the chat domain that instance names in its NodeInfo, that domain is the instance's own host or under it, and this instance's relay delivers there.

Comparing fingerprints out of band is currently the only way to establish that a key belongs to the person you think it does.
SecureJoin, which performs this verification through a QR code exchange rather than manual comparison, is planned but not yet implemented.

## Transport and browser-level hardening

The application emits its own security headers rather than relying on a reverse proxy, so a deployment that terminates TLS elsewhere, or runs
without a proxy, is protected identically.
These are set in `crates/noombat-api/src/middleware.rs`:

| Header                    | Value                                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------------- |
| `Content-Security-Policy` | `default-src 'none'`, with `script-src 'self'` and the WebSocket origin pinned in `connect-src` |
| `X-Content-Type-Options`  | `nosniff`                                                                                       |
| `X-Frame-Options`         | `DENY`                                                                                          |
| `Referrer-Policy`         | `strict-origin-when-cross-origin`                                                               |
| `Permissions-Policy`      | every unused feature denied                                                                     |

`Strict-Transport-Security` is the deliberate exception and remains at the TLS terminator, since browsers honour it only over TLS.

The policy contains neither `'unsafe-inline'` nor `'unsafe-eval'`.
Templates carry no inline script, no inline event handlers, and no inline styles;
`scripts/check-inline-scripts.sh` fails CI if any is reintroduced, and the end-to-end suite fails on any `securitypolicyviolation` event during the login, compose, and chat flows.
This is not only defence in depth:
enforcement mechanisms in category 2 above rely on the CSP to constrain what enrolled pages may execute, so a policy weakened by `'unsafe-inline'` would forfeit that route.

htmx, which swaps HTML from the server into a page after it loads, gets that HTML only through the release's own script, as does the editor's preview.
It parses each answer itself, without declarative shadow roots, and keeps only the elements, attributes and values the honest answers use, an `id` or an `hx-target` only in the honest patterns, without serialising it again: no script, frame, template, stylesheet, refresh, form or title in an answer reaches the page, whichever way htmx inserts it.
htmx's configuration is the release's, frozen where the server cannot change it, and htmx never sees an `HX-*` response header, so an answer cannot move the page, push an address or redirect a swap.
What an answer can still do is what an honest one does: arrange the release's own styles, which could imitate the page, and carry items whose `hx-get` or `hx-delete` asks for any path on the instance, to replace that item or the row or box it sits in.

## Supply chain

- Container base images are pinned by digest, not by tag.
- Archives fetched during an image build are verified against a SHA-256 recorded in the Dockerfile and cross-checked against the digest upstream publishes.
- `pnpm install --frozen-lockfile` is used everywhere, so a `package.json` that has drifted from the lockfile fails the build.
- GitHub Actions are pinned to commit SHAs.
- `cargo-deny` checks advisories and licences on every change.
- Dependabot proposes review-gated updates across Cargo, npm, Docker, Docker Compose, and GitHub Actions.
- All first-party crates declare `#![forbid(unsafe_code)]`, verified in CI.

## Static analysis

CodeQL runs on every push and pull request to `main`, and weekly, over Rust, Python, TypeScript, and the workflow definitions themselves.
The configuration lives in the repository rather than in a repository setting, so what is analysed and what is excluded are both reviewable in a diff:
see [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) and [`.github/codeql/codeql-config.yml`](.github/codeql/codeql-config.yml).
The `security-extended` suite is used rather than the default one, which omits the path-injection and log-injection queries.
`scripts/check-codeql-config.py` fails the build when an exclusion pattern empties a language, which CodeQL treats as a fatal error rather than as nothing to do, or when it reaches a directory not already recorded in `.github/codeql/excluded-dirs.txt`.
Narrowing what is scanned is therefore a reviewed change rather than a silent one.

**The alerts themselves are not public.**
The Security tab returns 404 to a visitor who is not signed in with access to this repository, so neither the finding set nor its triage can be audited from outside.
What can be audited is the code:
the analyser is a public tool over public sources, and anyone may run it against a clone and compare.

**A dismissal has to be enforced by something other than itself.**
A meaningful share of alerts here are dismissed as false positives, and the reason is structural rather than convenient.
CodeQL's taint tracking follows values, and several defences in this codebase validate a value without replacing it:
the check refuses the input and returns early, the value reaching the sink is unchanged, and the analysis reports the flow as though nothing had intervened.
The rule applied is that a dismissal on those grounds names a test that fails if the validator stops being called, so that the claim behind the dismissal keeps being checked after the alert has been closed and forgotten.
Where no such test is practical, that is recorded as an absence rather than left implicit.

This is still a judgement, made by the maintainers and not visible to you.
A reader who wants to check it should run the analysis against the source rather than take the dismissals on trust.

## What leaves the instance

An operator should be able to answer "what does this box report, and to whom" without reading the
source, so it is stated here.

**Third-party telemetry is off.**
Meilisearch reports to `telemetry.meilisearch.com` by default, in every mode.
The reporting is gated solely on `MEILI_NO_ANALYTICS`; `MEILI_ENV` is one of the fields reported, not a condition on the reporting.
The payload is a per-instance UUID persisted in its data directory, the host's OS name, kernel version, CPU core count, total RAM and largest disk size, days since first start, the document count of every index, its configuration flags, and whether TLS options such as client-certificate requirement and OCSP are configured.
Its master key is not sent.
`compose.yml` sets `MEILI_NO_ANALYTICS`, so a Compose deployment reports none of it.
The per-index document counts are the reason: for a federated instance they are a periodic report of the size of one community, tied to an identifier that survives restarts.

**What the instance publishes on purpose is a different matter.**
NodeInfo and the served asset manifest at `/.well-known/noombat/assets.json` are public endpoints, and Fediverse crawlers aggregate the former across instances.
That is by design and is how a federated network is discoverable, but it is disclosure, and an operator should know it is happening rather than infer it.

**Federation, DOI resolution, ORCID and Mastodon sign-in contact third parties by design.**
They are requests the feature cannot work without, not reporting.

## Additional notes

Two limits, stated rather than left to be "discovered".

**The Rust binaries are reproducible within the build image, and only there.**
The `noombat`, `noombat-chatmail-admin`, and `noombat-filtermail` binaries come out byte for byte the same from the same commit, so you can confirm both that the image you run is the image that was released and that its binaries correspond to the source.
That holds because every build runs in the same digest-pinned Rust image, under the same paths (`/build`, and Cargo's home at `/usr/local/cargo`), with the release `rust-toolchain.toml` names, which the build checks, and exactly the dependencies `Cargo.lock` records (`--locked`).
Paths reach the binaries through panic locations, and nothing remaps them, so a build outside that image, such as a plain `cargo build`, will not match.
The binaries are for x86-64 (`linux/amd64`); a build on an arm64 machine produces other ones.
Builds have matched on GitHub's runners and on one machine outside GitHub, a different Docker version and image store included.
Each release builds once, compares every file its manifests list with `verify.yml`'s build of the same commit on another runner, and refuses to sign on any difference but the asset manifest's version label; the maintainer rebuilds the binaries on their own machine before publishing it.
The manifests cover the roots `docs/verifying-builds.md` lists, not every file in the images.
The `typst` binary is a separate case:
it is not built here at all, but taken from the `ghcr.io/typst/typst` image, pinned by digest in the Dockerfile, which makes it immutable rather than reproducible.
Debian packages are installed from the archive at build time, so their files can differ between builds made on different days, and the manifests list them by name and version.

**Signing trusts the build platform.**
GitHub Actions, Fulcio, and Rekor are in the trusted set.
Anyone able to push to `release.yml`, or who compromises the runner, can obtain valid signatures over arbitrary bytes.
There is no threshold scheme or two-party control.
