# Chat Interoperability Tests

This directory contains the test environment and runner for verifying Noombat's Chatmail integration and Delta Chat interoperability.

## Components

| File          | Purpose                                                                                                             |
|---------------|---------------------------------------------------------------------------------------------------------------------|
| `compose.yml` | Compose stack: Noombat, Chatmail relay (stub), PostgreSQL, Redis                                                    |
| `run.sh`      | Test runner: 11 test cases covering registration, login, WebSocket, chat reports, auth pages, and closed federation |

## Running

```sh
# Build and start the test environment.
docker compose -f tests/chat-interop/compose.yml up -d --build

# Run the tests.
tests/chat-interop/run.sh http://localhost:8443

# Tear down.
docker compose -f tests/chat-interop/compose.yml down -v
```

## Chatmail Relay Container

The `compose.yml` uses an Alpine stub as a placeholder for the Chatmail relay container.
In CI, replace the `chatmail` service image with the actual `noombat-chatmail` container image (e.g. `ghcr.io/noombat/noombat-chatmail`) to enable end-to-end IMAP/SMTP tests.
The stub is sufficient for the HTTP-level tests (registration, login, page rendering, configuration checks).

## Delta Chat Interoperability

To test against Delta Chat, set the `DELTACHAT_RPC` environment variable to the address of a running `deltachat-rpc-server` instance before invoking `run.sh`.
When set, the runner executes additional tests that send and receive messages via the Delta Chat RPC API.

```sh
DELTACHAT_RPC=http://localhost:20808 tests/chat-interop/run.sh
```

## Test Cases

| #   | Section           | Description                               |
|-----|-------------------|-------------------------------------------|
| 1   | Registration      | Register alice                            |
| 2   | Registration      | Register bob                              |
| 3   | Registration      | Duplicate registration rejected           |
| 4   | Login             | Login with correct credentials            |
| 5   | Login             | Login with wrong credentials (401 or 403) |
| 6   | Chat WebSocket    | WebSocket route exists (non-404 response) |
| 7   | Chat WebSocket    | Chat report endpoint exists               |
| 8   | Auth Pages        | Login page renders (200)                  |
| 9   | Auth Pages        | Register page renders (200)               |
| 10  | Closed Federation | Chat page loads for authenticated user    |
| 11  | Closed Federation | Chatmail domain configured on instance    |
| 12+ | Delta Chat        | Interop tests (when DELTACHAT_RPC is set) |
