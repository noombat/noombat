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
`noombat-filtermail`, `noombat-doveauth`, the Postfix and Dovecot configuration, the entrypoint,
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
- `sha256sum`, `curl`, and `jq`

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

jq -r '.assets | to_entries[] | "\(.key) \(.value)"' assets-manifest.json \
  | while read -r path expected; do
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

The release job summary records the digest of the published image, so an operator can confirm that the image they are running is the one the manifest was taken from.

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

So **check the complement**:
every script a page loads must appear in the manifest.

```sh
for path in / /auth/login /auth/register /chat /settings/chat /compose; do
  curl -fsSL "${INSTANCE}${path}" \
    | grep -o 'src="/assets/[^"]*"' \
    | sed 's|src="/assets/||; s|"$||' \
    | while read -r asset; do
        if jq -e --arg a "$asset" '.assets | has($a)' \
             assets-manifest.json > /dev/null; then
          printf '  ok        %s -> %s\n' "$path" "$asset"
        else
          printf '  UNKNOWN   %s -> %s (not in the manifest)\n' "$path" "$asset"
        fi
      done
done
```

Anything reported `UNKNOWN`, or any `<script src=...>` pointing outside `/assets/`, is code the release never attested to.

This is still a check you perform once, on markup you fetched once.
It does not run on every page load, and it cannot see scripts injected by already-running JavaScript.
Only enforcement inside the browser can do that;
see the WEBCAT note in [`SECURITY.md`](../SECURITY.md).

## 4. Reproduce the build yourself

The signature attests that the release workflow produced those hashes.
To check that the *source* produces them, build it:

```sh
git clone https://github.com/noombat/noombat
cd noombat
git checkout "$TAG"

cd frontend
corepack enable
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

Checking once tells you what the instance served *once*.
An operator can serve correct assets to everyone who looks and modified assets to a single targeted user, and a manual check will not catch that.
Steps 2 and 3 together cover substitution and addition at the moment you look;
neither covers targeting, nor the next page load.
Closing that gap requires the browser itself to enforce the check on every load, which is what the WEBCAT work described in [`SECURITY.md`](../SECURITY.md) aims at.

If you need integrity today rather than detection, use a Delta Chat client with the credentials from `/settings/chat`.
Delta Chat is reproducibly built and distributed through app stores, so its code does not come from the Noombat operator at all.
