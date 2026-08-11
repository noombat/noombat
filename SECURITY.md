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
The end-to-end suite closes this for the pages it covers by checking the complement, i.e. that nothing outside the manifest is loaded, and [`docs/verifying-builds.md`](docs/verifying-builds.md) gives the same check to readers.
Neither is a substitute for enforcement at load time.

*It does not detect* **targeting**: correct assets to whoever checks, modified assets to one session.
Detection is per-observation, and nobody observes every load.

*Attestation is not reproducibility.*
The browser assets are known to be byte-reproducible from source and CI enforces that on every change.
The Rust and Typst binaries are attested but have no reproducibility provisions, so an independent rebuild will not match their hashes;
the manifests record what was shipped, not something you can recreate.

**2. Enforcement in the browser.**
Verification on every page load, before any script executes, requires a component the operator does not control.
WEBCAT, developed by the Freedom of the Press Foundation, does exactly this:
a browser extension checks an enrolled site's assets against a signed, transparency-logged manifest and blocks the load on mismatch.
It is in alpha; see [`docs/webcat.md`](docs/webcat.md) for the evaluation and its current status here.
A browser standard covering the same ground, WAICT, is under discussion.

**3. A client the operator did not deliver.**
The strongest option available today, and it already works.
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

## Supply chain

- Container base images are pinned by digest, not by tag.
- Archives fetched during an image build are verified against a SHA-256 recorded in the Dockerfile and cross-checked against the digest upstream publishes.
- `pnpm install --frozen-lockfile` is used everywhere, so a `package.json` that has drifted from the lockfile fails the build.
- GitHub Actions are pinned to commit SHAs.
- `cargo-deny` checks advisories and licences on every change.
- Dependabot proposes review-gated updates across Cargo, npm, Docker, Docker Compose, and GitHub Actions.
- All first-party crates declare `#![forbid(unsafe_code)]`, verified in CI.

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

Two known gaps, stated rather than left to be "discovered".

**Reproducible Rust builds are not implemented yet.**
The manifests attest to the `noombat`, `noombat-chatmail-admin`, `noombat-filtermail`, and `noombat-doveauth` binaries, i.e. you can confirm that the image you run is the image that was released, but nothing yet lets you confirm that the image corresponds to the source.
Nothing sets `SOURCE_DATE_EPOCH` or `--remap-path-prefix`, and dependency paths under `$CARGO_HOME` reach the binary through panic location metadata, so an independent rebuild in a different environment will not match.
Closing this needs those flags, a pinned toolchain version rather than `channel = "stable"`, and a CI gate that builds twice in different directories and compares.
It is planned;
until it lands, treat the binary hashes as a record of what shipped rather than something you can recreate.
The `typst` binary is a separate case:
it is not built here at all, but taken from the `ghcr.io/typst/typst` image, pinned by digest in the Dockerfile, which makes it immutable rather than reproducible.

**Signing trusts the build platform.**
GitHub Actions, Fulcio, and Rekor are in the trusted set.
Anyone able to push to `release.yml`, or who compromises the runner, can obtain valid signatures over arbitrary bytes.
There is no threshold scheme or two-party control.
