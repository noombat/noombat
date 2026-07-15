# Interoperability Tests

This directory contains the infrastructure for testing Noombat's ActivityPub federation against other Fediverse server implementations.

## Architecture

### CI (services mode)
 
```
┌────────────────────────────────────────────────┐
│           Forgejo Actions runner container     │
│                                                │
│  ┌──────────────────────────────────────────┐  │
│  │  Job container                           │  │
│  │    cargo build → ./noombat (background)  │  │
│  │    tests/interop/run.sh                  │  │
│  │      http://localhost:8443 ──► Noombat   │  │
│  │      http://gotosocial:8080 ─┐           │  │
│  └──────────────────────────────┼───────────┘  │
│                                 │              │
│  ┌────────────┐ ┌────────────┐ ┌▼───────────┐  │
│  │ PostgreSQL │ │      Redis │ │ GotoSocial │  │
│  │  (service) │ │  (service) │ │  (service) │  │
│  └────────────┘ └────────────┘ └────────────┘  │
└────────────────────────────────────────────────┘
```

### Local (Compose + Caddy mode)

The test environment uses Docker Compose to run multiple Fediverse servers on a shared network:

```
┌─────────────────────────────────────────────────┐
│                Docker Network: interop          │
│                                                 │
│  ┌──────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Noombat  │  │  GotoSocial  │  │  Caddy    │  │
│  │ :8443    │  │  :8080       │  │  :443     │  │
│  └──────────┘  └──────────────┘  └───────────┘  │
│        ▲               ▲              │         │
│        │               │              │         │
│        └───────────────┴──────────────┘         │
│              TLS reverse proxy                  │
│         noombat.local / gotosocial.local        │
└─────────────────────────────────────────────────┘
```

Caddy provides TLS termination using an internal CA, so that both servers can use `https://` AP IDs without publicly trusted certificates.

## Test Runner
 
`run.sh` accepts two positional arguments: the Noombat base URL and the GotoSocial base URL.
 
```bash
# CI (HTTP, services on the runner network):
tests/interop/run.sh http://localhost:8443 http://gotosocial:8080
 
# Local (HTTPS via Caddy, after starting the Compose stack):
tests/interop/run.sh https://noombat.local:8443 https://gotosocial.local:8443
```
 
## CI
 
The Forgejo Actions workflow (`.forgejo/workflows/ci.yml`) runs the interop job using the same pattern as the end-to-end tests:
Noombat is built from source and started as a background process;
GotoSocial, PostgreSQL, and Redis run as `services:` containers managed by the runner.
 
No Docker CLI, Caddy TLS proxy, or port-mapping is involved.
The test runner connects to both servers over plain HTTP on the runner's internal network.
 
## Local Testing
 
For local testing with HTTPS (closer to production), use the Compose stack:
 
``bash
docker compose -f tests/interop/compose.yml up -d --build
 
# Seed a test actor (wait for Noombat to run migrations first):
sleep 10
docker compose -f tests/interop/compose.yml exec -T db \
  psql -U noombat -d noombat -c "
    INSERT INTO actors
      (actor_type, ap_id, username, domain, public_key_pem, is_local)
    VALUES
      ('individual', 'https://noombat.local/users/alice',
       'alice', 'noombat.local',
       '-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAngu+UeqfsU3AJHhVHk2k
    MEjaIOzbOWRPu1TsqUpGq0IX/mhQUC6/mkF9+H27ziERaM+77JB7MQ9q1ITLnukj
    TlmQhgUrsstMV1ZiU+9WqJ+NmlpdoQ4zVFXEf7IJHmZ+mYxei/qhVrnBDvV4e1KR
    iOTxUYyqWrI7BFGrA3eR22zb9K5/CwOuTw0uYGGhkxfMalBXd4k1AyYGsHo/riQY
    xOCucw31jlUavoajo3CPXWXgCi+F6mumsIm7snaFNiCG8d8jqXZ8aSC8JcGImf95
    Gg3J3oGE9ZiAue0WmYC+oMDzLBJtqN0V/c1OsU7PsP8+8fllvlfBluhuTfR/O19J
    RQIDAQAB
    -----END PUBLIC KEY-----',
       TRUE)
    ON CONFLICT (ap_id) DO NOTHING;"
 
# Run the tests (use CURL_OPTS for Caddy's self-signed cert):
CURL_OPTS="--insecure" tests/interop/run.sh \
  https://noombat.local:8443 https://gotosocial.local:8443
 
docker compose -f tests/interop/compose.yml down -v
```
 
This stack includes a Caddy reverse proxy that provides TLS with an internal CA.
When using HTTPS locally, skip certificate verification for `curl` (`CURL_OPTS="--insecure"`), or extract Caddy's root CA (see `Caddyfile`).

## Test Coverage

The current suite verifies:

| Test                       | Protocol        | Scope          |
|----------------------------|-----------------|----------------|
| WebFinger discovery        | RFC 7033        | Noombat        |
| NodeInfo 2.1               | NodeInfo        | Noombat        |
| Actor AP JSON              | ActivityPub S2S | Noombat        |
| `endpoints.sharedInbox`    | ActivityPub S2S | Noombat        |
| `publicKey` presence       | HTTP Signatures | Noombat        |
| AP ID canonical format     | ActivityPub S2S | Noombat        |
| Outbox `OrderedCollection` | ActivityPub S2S | Noombat        |
| Shared inbox route         | ActivityPub S2S | Noombat        |
| GotoSocial NodeInfo        | NodeInfo        | Cross-instance |
| GotoSocial WebFinger       | RFC 7033        | Cross-instance |
| GotoSocial actor fetch     | ActivityPub S2S | Cross-instance |

## Extending

### Adding a new platform

1. Add the service to `compose.yml` (for local testing)
2. Add a reverse-proxy entry to `Caddyfile`.
3. Add the service to the `services:` block in `ci.yml` (for CI).
4. Add seeding logic and test cases to `run.sh`.

### Target platforms

- [x] GotoSocial
- [ ] Mastodon
- [ ] Ghost
- [ ] Lemmy
- [ ] PieFed
- [ ] Pixelfed
- [ ] PeerTube
- [ ] Friendica
- [ ] Bonfire

Each additional platform requires its own service definition in `compose.yml` (with any necessary database sidecars) and a corresponding section in `run.sh`.
