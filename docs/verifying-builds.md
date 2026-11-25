# Verifying a Noombat build

This document describes how to check that the JavaScript a Noombat instance serves you is the JavaScript this project released.

## Why this matters

Noombat encrypts and decrypts messages in your browser.
The code that does so is delivered by the instance operator on every page load.
An operator who wants to read your messages does not need to break any cipher:
they can serve one modified script, to one user, on one page load, and have it send the plaintext or the private key somewhere else.
The message is still encrypted in transit and still stored encrypted on the server, and none of that helps.

This is a property of browser-delivered cryptography in general, not of Noombat specifically.
It is why "the source code is public" is not by itself an answer:
the published source and the served bytes are different artefacts, and only the second one runs.

What follows lets you detect a discrepancy between the two.
It does not prevent one.
See [`SECURITY.md`](../SECURITY.md) for what that distinction does and does not buy you, and for the stronger options.

## What is attested

Each release carries four files:

| File                           | Contents                                    |
|--------------------------------|---------------------------------------------|
| `assets-manifest.json`         | SHA-256 of every browser asset              |
| `server-image-manifest.json`   | SHA-256 of every file in the server image   |
| `chatmail-image-manifest.json` | SHA-256 of every file in the chatmail image |
| `*.sigstore.json`              | A Sigstore bundle for each of the above     |

The server image manifest covers everything under `/opt/noombat` and `/usr/local/bin`: the
`noombat` and `typst` binaries, the migrations, templates, locales and built assets, plus every
installed Debian package and its version.

The chatmail image manifest covers the same ground for that image: `noombat-chatmail-admin`,
`noombat-filtermail`, the Postfix and Dovecot configuration, the entrypoint,
and the package list.

Each Sigstore bundle carries a signature, a certificate, and a Rekor inclusion proof.

Each manifest also records the version and commit it was built from.

**Attestation is not reproducibility.**
The browser assets are both:
attested, and known to rebuild byte-identically from source.
The Rust binaries are attested only.
Reproducible Rust builds are planned but not implemented yet, so an independent rebuild will *not* produce matching hashes;
step 4 below therefore covers the assets and nothing else.
The binary entries let you confirm that the image you are running is the image that was released, not that it corresponds to the source.
See the gaps section of [`SECURITY.md`](../SECURITY.md) for what closing this requires.

The `typst` binary is a different case:
it is not built here, but taken from the `ghcr.io/typst/typst` image, pinned by digest in the Dockerfile.
That makes it immutable rather than reproducible, which for these purposes is stronger, i.e. there is one artefact and its identity is fixed.

Package entries are names and versions, not content hashes:
they pin what the Debian archive was asked for, not what it returned.

The manifest is **extracted from the container image that is then published**, not generated beside it.
One build produces both, so the image an operator runs and the hashes that are signed cannot disagree.
That distinction matters:
the image builds the frontend inside a digest-pinned Node base, whereas a build on the CI runner uses whatever that runner provides.
Attesting to the second would sign bytes no operator serves, and any divergence between the two would appear as a mismatch on instances that are in fact honest.
The release workflow asserts that a host build reproduces the image build, which is what keeps step 3 below meaningful.

Signing is keyless.
The certificate binds the signature to the release workflow's identity rather than to a long-lived private key, so a signature produced anywhere other than that workflow fails the identity check below.
The signature is recorded in the Rekor transparency log at signing time, which means a signature cannot be created retroactively without leaving a public record.

## Prerequisites

- [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/) v3 or later
- `sha256sum`, `curl` 7.83 or later with HTTP/2 (`curl -V` lists `HTTP2`), and `jq`

## 1. Verify the signature on the manifest

Download both files from the release, then:

```sh
TAG=v0.1.0  # the release you are checking

cosign verify-blob \
  --bundle assets-manifest.sigstore.json \
  --certificate-identity \
    "https://github.com/noombat/noombat/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  assets-manifest.json
```

`--certificate-identity` is the part that carries the weight.
Without it, `cosign` accepts a signature from *any* Sigstore identity, and the check degenerates into "somebody signed this".
The value must name this repository, this workflow, and the tag you are verifying.

Expect `Verified OK`.
Anything else means stop.

## 2. Compare against the assets an instance serves

The manifest lists each asset by its path under `/assets/`.
Fetch them from the instance and hash them:

```sh
INSTANCE=https://noombat.example.com

jq -r '.assets | to_entries[] | "\(.key) \(.value)"' assets-manifest.json |
  while read -r path expected; do
      actual=$(curl -fsSL "${INSTANCE}/assets/${path}" | sha256sum | cut -d' ' -f1)
      if [ "$actual" = "$expected" ]; then
          printf '  ok        %s\n' "$path"
      else
          printf '  MISMATCH  %s\n    expected %s\n    actual   %s\n' \
              "$path" "$expected" "$actual"
      fi
  done
```

Every asset should report `ok`.
A mismatch means the instance is serving something other than the released build.
That is not proof of an attack, i.e. the operator may be running a fork, an older release, or a patched build, but it does mean the released signature says nothing about what you are executing, and you should find out why before trusting the instance with anything.

The release workflow's run summary (its `publish` job) records the digest of each published image, so an operator can confirm that the image they are running is the one the manifest was taken from.

An instance may also expose its own copy of the manifest at `/.well-known/noombat/assets.json`.
That copy is a convenience for monitoring tools, **not** evidence:
a server prepared to serve modified assets is equally prepared to serve a manifest describing them.
Only the signed release artefact is authoritative.

If that copy reports `"version": "unknown"`, the image was built without `NOOMBAT_VERSION` and `NOOMBAT_COMMIT`, i.e. the defaults a bare `docker build` leaves in place.
Such a manifest names no release, so there is nothing to compare it against.
Images published by `release.yml` always carry real values, and the same values appear as the `org.opencontainers.image.version` and `.revision` labels, so `docker inspect` can be used to cross-check them.

## 3. Check that nothing *else* is loaded

Step 2 verifies the files the manifest names.
It cannot see a file the manifest does not name.
An operator can add a same-origin script, reference it from a modified template, and leave every hash in step 2 matching; `script-src 'self'` permits it.
A stylesheet matters too: it can change what a page shows, and leak parts of the page to the server through the images and fonts it requests.

So **check the complement**:
every script and stylesheet a page loads must be one the manifest names, the page's Content-Security-Policy must still allow scripts and styles only from the instance's own files, with no inline code, and the page must arrive in the form the check reads, without sending you on to another page.

**The check sees what the instance sends to curl.**
curl is easy to tell from a browser, so an operator who knows this procedure can send curl the release and browsers something else.
A clean result therefore rules out a change sent to everyone, such as by a compromised or careless server, not an operator set on deceiving the check.

Most of these pages need you to be logged in.
Set `COOKIE` to `__Host-noombat_session=` followed by that cookie's value, which your browser's developer tools show under Storage or Application, then Cookies.
The cookie lasts as long as the instance's sessions, 15 minutes unless its operator changed that, so copy it just before running the check.
It is a credential: anyone who has it is logged in as you.

```sh
COOKIE=''  # __Host-noombat_session=..., for the pages behind a login
TMP=$(mktemp -d)

# The tags, besides the release's scripts and stylesheets, that load nothing.
cat > "$TMP/inert" <<'FORMS'
<link rel="(canonical|alternate)"( type="[^"<>]*")? href="[^"<>]*">
<meta charset="utf-8">
<meta name="(viewport|robots|csrf-token)" content="[^"<>]*">
<meta name="htmx-config" content='[^'<>]*'>
FORMS

# Everything printed passes through `tr` at the end as printable ASCII, so
# that a page cannot rewrite what you see.
for path in / /auth/login /auth/register /auth/upgrade /chat /compose /settings/profile /settings/chat; do
  echo "$path"
  # Not following redirects, so the page is the address's own; the headers
  # are the final response's alone, as curl reads them.
  if ! curl -fsS --cookie "$COOKIE" -o "$TMP/page" \
      -w '%{http_code} %{redirect_url}\n%{http_version}\n%{header_json}' \
      "${INSTANCE}${path}" > "$TMP/answer"; then
    echo "  FAILED    could not fetch it"
    continue
  fi
  answer=$(sed -n 1p "$TMP/answer")
  case "$answer" in
    "200 "*) ;;
    *) echo "  NOTE      answered $answer"; continue ;;
  esac
  sed 1,2d "$TMP/answer" > "$TMP/headers"

  # The form the rest assumes: HTTP/2 or 3, where curl and a browser cannot
  # read a header or the body's length differently; UTF-8 HTML, with no
  # byte order mark and no compression; and no header that loads a
  # stylesheet or moves to another page.
  version=$(sed -n 2p "$TMP/answer")
  case "$version" in
    2 | 3) ;;
    *) echo "  RESPONSE  HTTP/$version" ;;
  esac
  jq -r 'def report(name): .[name] // empty | "  RESPONSE  \(name): \(join(", "))";
         if ."content-type" == ["text/html; charset=utf-8"] then empty
         else report("content-type") // "  RESPONSE  no content-type" end,
         report("content-encoding"), report("transfer-encoding"), report("link"),
         report("refresh"), report("speculation-rules")' "$TMP/headers" ||
    echo "  RESPONSE  headers unreadable"
  case $(head -c 2 "$TMP/page" | od -An -tx1 | LC_ALL=C tr -d ' \n') in
    efbb | feff | fffe) echo "  RESPONSE  starts with a byte order mark" ;;
  esac

  # The policy one directive per line, its name lower-cased, read as bytes
  # (LC_ALL=C). Only printable ASCII is expected: a browser also splits a
  # directive at a form feed or a carriage return, which awk does not.
  jq -r '."content-security-policy" // [] | .[]' "$TMP/headers" > "$TMP/csp"
  LC_ALL=C grep -q '[^ -~]' "$TMP/csp" &&
    echo "  POLICY    holds a character other than printable ASCII"
  LC_ALL=C awk -F '[,;]' '{ for (i = 1; i <= NF; i++) print $i }' "$TMP/csp" |
    LC_ALL=C awk 'NF { $1 = tolower($1); print }' > "$TMP/policy"
  for rule in "default-src 'none'" "script-src 'self'" "style-src 'self'"; do
    LC_ALL=C grep -qxF "$rule" "$TMP/policy" || printf '  POLICY    no %s\n' "$rule"
  done
  LC_ALL=C grep -E '^(default|script|style)-src(-elem|-attr)?( |$)' "$TMP/policy" |
    while read -r rule; do
      case "$rule" in
        "default-src 'none'" | "script-src 'self'" | "style-src 'self'") ;;
        *) printf '  POLICY    %s\n' "$rule" ;;
      esac
    done

  # Every script, link, style, base, frame, object, embed or meta tag, with
  # the page joined onto one line and its spaces squeezed, so that a tag
  # split across lines is still found, and any NUL made visible: GNU grep
  # prints nothing for a page holding one, and where a grep prints it,
  # `read` drops it from inside a tag.
  LC_ALL=C tr '\000\n\r\t' '?   ' < "$TMP/page" | LC_ALL=C tr -s ' ' |
    LC_ALL=C grep -oiE '<(script|link|style|base|i?frame|object|embed|meta)[^>]*>' |
    while read -r tag; do
      name=$(printf '%s\n' "$tag" | LC_ALL=C sed -nE \
        -e 's#^<script type="module" src="/assets/([A-Za-z0-9_.-]+\.js)">$#\1#p' \
        -e 's#^<script src="/assets/([A-Za-z0-9_.-]+\.js)" type="module">$#\1#p' \
        -e 's#^<link rel="stylesheet" href="/assets/([A-Za-z0-9_.-]+\.css)">$#\1#p')
      if [ -n "$name" ] && jq -e --arg a "$name" '.assets | has($a)' \
           assets-manifest.json > /dev/null; then
        printf '  ok        %s\n' "$name"
      elif ! printf '%s\n' "$tag" | LC_ALL=C grep -qxEf "$TMP/inert"; then
        printf '  UNKNOWN   %s\n' "$tag"
      fi
    done > "$TMP/tags"
  cat "$TMP/tags"
  grep -q '^  ok ' "$TMP/tags" || echo "  UNKNOWN   no script or stylesheet the manifest names"
done 2>&1 | LC_ALL=C tr -c ' -~\n' '?'
rm -r "$TMP"
```

On an instance running the release, every line under each page reads `ok`.
`UNKNOWN` shows a tag the release does not write, or a file the manifest does not name: code or styles the release never attested to.
`UNKNOWN   no script or stylesheet the manifest names` means the page showed none in a form the release writes, which every page of the release does.
The check accepts only the exact forms the release writes, so it also reports a harmless variation; read the tag before concluding anything.
`POLICY` shows a rule for scripts or styles that differs from the release's three, such as one allowing inline code or another origin, or one of the three missing, or a policy holding characters the release's does not.
`RESPONSE` shows a page sent in another form than the release sends it, which a browser could read differently from the check, or with a header that loads a stylesheet or moves you to another page: an HTTP version other than 2 or 3, another content type or character set, a byte order mark, compression or a transfer coding, or a `Link`, `Refresh` or `Speculation-Rules` header.
An instance whose proxy speaks only HTTP/1.1 cannot be checked this way.
`NOTE` means the address answered with something other than its page, usually a redirect to the login page, so the page went unchecked: set `COOKIE` and run it again.
Any character other than printable ASCII is shown as `?`.
The list holds every page that loads a script or stylesheet of its own, plus `/`.
A modified instance can change any page, so the result covers only the pages checked; add any other page you use.

This is still a check you perform once, on markup you fetched once.
It reads that markup as text, not as a browser does, and accepts only the release's exact forms so that a difference shows; it cannot prove a page safe.
It does not run on every page load, and it cannot see scripts injected by already-running JavaScript.
Only enforcement inside the browser can do that;
see the WEBCAT note in [`SECURITY.md`](../SECURITY.md).

Nor does it read the answers htmx fetches from a page's attributes, whether on loading or on a click; a page's own markup can fetch one as it opens.
htmx runs a script in such an answer that names a same-origin file, and the browser applies a same-origin stylesheet the answer links.
A meta refresh in the answer, or an `HX-Redirect`, `HX-Location` or `HX-Refresh` header, moves you to another page.

## 4. Reproduce the build yourself

The signature attests that the release workflow produced those hashes.
To check that the *source* produces them, build it:

```sh
git clone https://github.com/noombat/noombat
cd noombat
git checkout "$TAG"

cd frontend
../scripts/install-pnpm.sh package.json
pnpm install --frozen-lockfile
pnpm build
cd ..

scripts/asset-manifest.sh > local-manifest.json
diff <(jq -S .assets assets-manifest.json) <(jq -S .assets local-manifest.json)
```

The `assets` objects should be identical.
Only `assets` is compared, because `version` and `commit` are labels rather than build outputs.

The build is deterministic and CI enforces that on every change to the frontend (`scripts/check-reproducible.sh`), so a difference here is meaningful:
either the release did not come from this source, or the build has acquired a dependency on its environment.
Both are worth reporting.

Only the browser assets can be checked this way;
see the note on attestation versus reproducibility above.
This step compares a build on your machine against a manifest taken from the release image, so it also exercises reproducibility across environments.
The release workflow performs the same comparison before signing and refuses to publish if the two disagree;
a difference you observe locally therefore points at your toolchain or at the source, not at a known gap.

## 5. Limits of this procedure

Checking once tells you what the instance served, to curl, *once*.
An operator can serve correct assets to everyone who looks and modified assets to a single targeted user, or to every browser while curl gets the release, and a manual check will not catch that.
Steps 2 and 3 together cover substitution and addition at the moment you look, within the limits step 3 states;
neither covers targeting, nor the next page load.
Closing that gap requires the browser itself to enforce the check on every load, which is what the WEBCAT work described in [`SECURITY.md`](../SECURITY.md) aims at.

If you need integrity today rather than detection, use a Delta Chat client with the credentials from `/settings/chat`.
Delta Chat is reproducibly built and distributed through app stores, so its code does not come from the Noombat operator at all.
