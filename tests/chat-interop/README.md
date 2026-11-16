# Chat Interoperability Tests

This directory contains the test environment and runner for verifying Noombat's Chatmail integration.

## Components

| File                   | Purpose                                              |
|------------------------|------------------------------------------------------|
| `compose.yml`          | Compose stack: Noombat, the relay, PostgreSQL, Redis |
| `run.sh`               | Test runner: 31 assertions (see below)               |
| `build-local.sh`       | Build the binary for the local loop                  |
| `compose.localbin.yml` | Overlay for the local loop                           |
| `fixtures/`            | Bob's throwaway key and one message encrypted to it  |

## Running

```sh
# Build and start the test environment.
docker compose -p chat-interop -f tests/chat-interop/compose.yml up -d --build --wait

# Seed the accounts the suite signs in as.
tests/chat-interop/seed.sh tests/chat-interop/compose.yml

# Check 17 runs the frontend's modules, so install its packages.
(cd frontend && pnpm install --frozen-lockfile)

# Run the tests.
tests/chat-interop/run.sh http://localhost:8443

# Tear down.
docker compose -p chat-interop -f tests/chat-interop/compose.yml down -v
```

CI runs the same steps, installing the frontend's packages before `run.sh` for check 17, in the `chat-interop` job of `.github/workflows/ci-e2e.yml`. Pin `-p chat-interop` as above: the project name decides the network and volume names, and the job depends on them.

## Local loop

`build-local.sh` and `compose.localbin.yml` exist so that changing Rust source or a Chatmail script does not cost an image build. The binary is compiled in the same builder image the Dockerfile uses, then mounted over the image's copy along with the relay's entrypoint and its Postfix, Dovecot and OpenDKIM configuration.

```sh
tests/chat-interop/build-local.sh
docker compose -p chat-interop \
    -f tests/chat-interop/compose.yml \
    -f tests/chat-interop/compose.localbin.yml up -d --wait
```

Its limits are worth knowing before trusting a result. Templates, migrations and the built frontend still come from the image, so a change to any of those makes the loop invalid. Nothing in either Dockerfile is exercised, `.dockerignore` included. CI builds the Dockerfile, so confirm a fix with a real build before shipping it.

## Configuration

The instance domain is `test.local`, which is not `localhost`, so the server's production guard rails run in full and abort the process on any documented default. `compose.yml` therefore has to supply four values: a JWT secret of at least 32 bytes, a database credential that is not `noombat:noombat`, a KEK, and a Chatmail admin secret that is not the documented one. Miss any of them and the container exits before it binds a listener, which reads as a readiness timeout rather than as a configuration error. They are fixtures for a stack that lives for the length of one `docker compose up`, not secrets.

## Chatmail Relay Container

The `chatmail` service builds `Dockerfile.chatmail`, the same image the release workflow publishes, so the relay under test is the shipped one rather than a substitute. It runs on a test mail domain with allowlist polling disabled.

Its entrypoint generates a local certificate authority and a leaf signed by it, rather than one self-signed certificate. A self-signed certificate produced by `openssl req -x509` is marked `CA:TRUE`, and a CA certificate offered as a server's own leaf is refused whatever the client trusts. The CA travels to Noombat through the `chatmail-ca` volume and is trusted through `SSL_CERT_FILE`, which is the same arrangement `tests/interop/compose.yml` uses for Caddy. Noombat waits for the relay to report healthy before starting, because `SSL_CERT_FILE` is read once when the HTTP client is built and a path that does not exist yet aborts the process.

The admin sidecar's port is published because `run.sh` runs on the host. Its liveness is asserted directly: every admin route requires the shared secret and there is no health route, so an unauthenticated 401 is the signal that the process is up. The container healthcheck cannot substitute for this, being an IMAP NOOP that Dovecot answers whether or not the sidecar is running.

## Coverage

Provisioning is exercised end to end: the runner asks Noombat to provision a Chatmail account, which reaches the relay over IMAP with implicit TLS, so the assertion passes only if the certificate the relay serves verifies against the CA Noombat was given.

Message delivery between a Delta Chat client and a Noombat account is not covered. That needs `deltachat-rpc-server` and real accounts on the relay, which this stack does not provide.

A skipped assertion exits non-zero when `CI` is set. Locally a skip is a convenience; under CI a suite that skips everything would report success while asserting nothing.

## Test Cases

Sections 10, 11, 13, 16 and 18 carry several assertions each, so nineteen sections produce thirty-one assertions. Check 17 runs the web client's own modules under Node (`frontend/interop/`), so it needs the frontend's packages installed.

| #  | Section           | Assertion                                       |
|----|-------------------|-------------------------------------------------|
| 0  | Chatmail admin    | Sidecar is serving (401 without the secret)     |
| 1  | Registration      | Password sign-up refused without a mailer (503) |
| 2  | Login             | alice signs in                                  |
| 3  | Login             | bob signs in                                    |
| 4  | Login             | Wrong credentials refused (401 or 403)          |
| 5  | Chat WebSocket    | WebSocket route exists (non-404 response)       |
| 6  | Chat reports      | Report endpoint exists                          |
| 7  | Auth pages        | Login page renders (200)                        |
| 8  | Auth pages        | Register page renders (200)                     |
| 9  | Closed federation | Chat page loads for a signed-in member          |
| 10 | NodeInfo          | Chatmail advertised as available                |
| 10 | NodeInfo          | Configured Chatmail domain named                |
| 11 | Provisioning      | Chat provisioned against the relay (200)        |
| 11 | Provisioning      | Credential page names the domain afterwards     |
| 11 | Provisioning      | An IMAP login for an unknown address is refused |
| 11 | Provisioning      | An IMAP login does not create an address        |
| 11 | Provisioning      | A squat attempt does not stop provisioning      |
| 12 | Sending           | alice's message to bob leaves over SMTP         |
| 13 | Delivery          | The message reaches bob's mailbox               |
| 13 | Delivery          | It is OpenPGP that bob's key opens              |
| 14 | Plain text        | A plain-text body is refused before sending     |
| 15 | Sender binding    | alice cannot send as bob                        |
| 16 | First contact     | bob publishes his key (204)                     |
| 16 | First contact     | bob's handle answers with his chat address      |
| 16 | First contact     | alice reads it by address, byte for byte        |
| 16 | First contact     | alice reads it by handle, byte for byte         |
| 16 | First contact     | bob's actor document carries the same key       |
| 16 | First contact     | alice cannot publish bob's key as hers (400)    |
| 17 | Web client        | carol writes first on dave's key; he reads it   |
| 18 | Set up again      | alice's mailbox gets a new password             |
| 18 | Set up again      | The relay takes the new one, refuses the old    |
