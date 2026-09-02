# Chat Interoperability Tests

This directory contains the test environment and runner for verifying Noombat's Chatmail integration.

## Components

| File                   | Purpose                                              |
|------------------------|------------------------------------------------------|
| `compose.yml`          | Compose stack: Noombat, the relay, PostgreSQL, Redis |
| `run.sh`               | Test runner: 15 assertions over HTTP and the sidecar |
| `build-local.sh`       | Build the binary for the local loop                  |
| `compose.localbin.yml` | Overlay for the local loop                           |

## Running

```sh
# Build and start the test environment.
docker compose -p chat-interop -f tests/chat-interop/compose.yml up -d --build --wait

# Run the tests.
tests/chat-interop/run.sh http://localhost:8443

# Tear down.
docker compose -p chat-interop -f tests/chat-interop/compose.yml down -v
```

CI runs the same three steps in the `chat-interop` job of `.github/workflows/ci-e2e.yml`. Pin `-p chat-interop` as above: the project name decides the network and volume names, and the job depends on them.

## Local loop

`build-local.sh` and `compose.localbin.yml` exist so that changing Rust source or a Chatmail script does not cost an image build. The binary is compiled in the same builder image the Dockerfile uses, then mounted over the image's copy along with the relay's entrypoint, Dovecot configuration and checkpassword helper.

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

Sections 11 and 12 carry two assertions each, so thirteen sections produce fifteen assertions.

| #  | Section           | Assertion                                   |
|----|-------------------|---------------------------------------------|
| 0  | Chatmail admin    | Sidecar is serving (401 without the secret) |
| 1  | Registration      | Register alice                              |
| 2  | Registration      | Register bob                                |
| 3  | Registration      | Duplicate registration rejected             |
| 4  | Login             | Login with correct credentials              |
| 5  | Login             | Login with wrong credentials (401 or 403)   |
| 6  | Chat WebSocket    | WebSocket route exists (non-404 response)   |
| 7  | Chat WebSocket    | Chat report endpoint exists                 |
| 8  | Auth pages        | Login page renders (200)                    |
| 9  | Auth pages        | Register page renders (200)                 |
| 10 | Closed federation | Chat page loads for authenticated user      |
| 11 | NodeInfo          | Chatmail advertised as available            |
| 11 | NodeInfo          | Configured Chatmail domain named            |
| 12 | Provisioning      | Chat provisioned against the relay (200)    |
| 12 | Provisioning      | Credential page names the domain afterwards |
