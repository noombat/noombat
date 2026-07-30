# WEBCAT evaluation

**Status: exploratory.**
**Not a supported configuration.**
**No release depends on this.**

This document records what WEBCAT is, why it is relevant to Noombat, what remains unresolved, and what would have to be true before it is promoted.

## What it is

WEBCAT (Web-based Code Assurance and Transparency) is a framework from the Freedom of the Press Foundation providing blocking code signing and transparency verification for browser-based applications.
When a user visits an enrolled site, a browser extension verifies the served assets against a signed manifest *before any content executes*, and aborts the load with a warning on mismatch.

- Repository: <https://github.com/freedomofpress/webcat>
- Alpha announcement: <https://securedrop.org/news/webcat-alpha/>
- Introduction: <https://securedrop.org/news/introducing-webcat-web-based-code-assurance-and-transparency/>

The alpha was announced in March 2026.
The extension is Firefox-only and distributed through Mozilla Add-ons.
The project describes it as experimental software that may interfere with pages and may not yet provide the intended guarantees.

## Why it matters here

[`SECURITY.md`](../SECURITY.md) sets out the limit of the signed asset manifest:
it detects a substitution served broadly, but not one served to a single user at a single moment, because nobody checks every load.

WEBCAT closes precisely that gap, by moving verification into a component the operator does not control and running it on every load.
It is the only mechanism currently available that turns detection into prevention without abandoning the browser client.

Two properties make the fit unusually close:

1. **Signing already matches.**
   WEBCAT supports Sigstore signing,    including via automated workflows, alongside Sigsum.
   The release workflow already produces a keyless Sigstore signature over an asset manifest, which is the same shape of artefact WEBCAT consumes.
2. **The CSP already matches.**
   WEBCAT relies on the browser's Content Security Policy for runtime policy enforcement on enrolled domains.
   The policy served is `default-src 'none'` with `script-src 'self'` and no `'unsafe-inline'` or `'unsafe-eval'`, which is the shape such enforcement requires.

## Open questions

These are the reasons this is exploratory rather than planned.

**Application shape.**
WEBCAT is described as targeting single-page browser applications, and the proof-of-concept deployments (Element, Jitsi, Standard Notes, Bitwarden, CryptPad, GlobaLeaks) are all of that kind.
Noombat is not:
it is server-rendered Askama HTML with JavaScript islands mounted per page, and the HTML varies per request and per user.
Whether WEBCAT's manifest model covers server-rendered markup, or only the static assets it references, is the first thing to establish.
If it requires the whole document to be static, Noombat does not qualify without substantial restructuring.

**Enrolment.**
Only clearnet TLS domains can currently enrol.
Enrolment is decentralised across community-run infrastructure.
What enrolment demands of a self-hosting operator is unclear, and matters because Noombat is designed to be self-hosted:
a mechanism only a large instance can operate helps few of its users.

**Maturity.**
Alpha, Firefox only, self-described as possibly not yet delivering its intended guarantees.
Recommending it to users now would misrepresent what they are getting.

## Promotion criteria

Promote to a supported configuration only when **all** of the following hold:

- WEBCAT has left alpha.
- The server-rendered document model is compatible without restructuring the application into a single-page application, or that restructuring has been separately justified on its own merits.
- A self-hosting operator can enrol without infrastructure Noombat does not otherwise require.
- The full end-to-end suite passes with the extension enforcing.

Until then this stays exploratory, and `SECURITY.md` continues to name Delta Chat as the operator-independent option that works today.

## Related work

- **WAICT**: an emerging browser standards effort covering the same problem.
  A standard shipped by browser vendors would remove the extension requirement entirely and is the better long-term outcome.
  Reported points of difference from WEBCAT include preventing dynamic code execution, scrutiny of HTTP headers, and particular attention to the CSP header.
- **Meta's Code Verify**: prior work for extension-based verification of a web application's assets.
