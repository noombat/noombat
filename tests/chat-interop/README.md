# Chat Interoperability Tests

This directory contains the test environment and runner for verifying Noombat's Chatmail integration.

## Components

| File          | Purpose                                                             |
|---------------|---------------------------------------------------------------------|
| `compose.yml` | Compose stack: Noombat, the Chatmail relay, PostgreSQL, Redis.      |
| `run.sh`      | Test runner: 12 assertions over the HTTP API and the admin sidecar. |

## Running

```sh
# Build and start the test environment.
docker compose -f tests/chat-interop/compose.yml up -d --build

# Run the tests.
tests/chat-interop/run.sh http://localhost:8443

# Tear down.
docker compose -f tests/chat-interop/compose.yml down -v
```

CI runs the same three steps in the `chat-interop` job of `.github/workflows/ci-e2e.yml`.

## Configuration

The instance domain is `test.local`, which is not `localhost`, so the server's production guard rails run in full and abort the process on any documented default. `compose.yml` therefore has to supply five values: an admin token, a JWT secret of at least 32 bytes, a database credential that is not `noombat:noombat`, a KEK, and a Chatmail admin secret that is not the documented one. Miss any of them and the container exits before it binds a listener, which reads as a readiness timeout rather than as a configuration error. They are fixtures for a stack that lives for the length of one `docker compose up`, not secrets.

## Chatmail Relay Container

The `chatmail` service builds `Dockerfile.chatmail`, the same image the release workflow publishes, so the relay under test is the shipped one rather than a substitute. It runs on a test mail domain with allowlist polling disabled; `compose.yml` holds the values, and `run.sh` asserts the domain reaches the server's credential page.

The admin sidecar's port is published because `run.sh` runs on the host. Its liveness is asserted directly: every admin route requires the shared secret and there is no health route, so an unauthenticated 401 is the signal that the process is up. The container healthcheck cannot substitute for this, being an IMAP NOOP that Dovecot answers whether or not the sidecar is running.

## Coverage

The assertions are HTTP-level. Message delivery between a Delta Chat client and a Noombat account is not covered: that needs `deltachat-rpc-server` and real accounts on the relay, which this stack does not provide.

A skipped assertion exits non-zero when `CI` is set. Locally a skip is a convenience; under CI a suite that skips everything would report success while asserting nothing.

## Test Cases

| #  | Section           | Description                                 |
|----|-------------------|---------------------------------------------|
| 0  | Chatmail admin    | Sidecar is serving (401 without the secret) |
| 1  | Registration      | Register alice                              |
| 2  | Registration      | Register bob                                |
| 3  | Registration      | Duplicate registration rejected             |
| 4  | Login             | Login with correct credentials              |
| 5  | Login             | Login with wrong credentials (401 or 403)   |
| 6  | Chat WebSocket    | WebSocket route exists (non-404 response)   |
| 7  | Chat WebSocket    | Chat report endpoint exists                 |
| 8  | Auth Pages        | Login page renders (200)                    |
| 9  | Auth Pages        | Register page renders (200)                 |
| 10 | Closed Federation | Chat page loads for authenticated user      |
| 11 | Closed Federation | Chatmail domain configured on instance      |
