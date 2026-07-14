# Interoperability Tests

This directory contains the infrastructure for testing Noombat's ActivityPub federation against other Fediverse server implementations.

## Architecture

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

## Usage

```bash
# Start the environment (builds Noombat from source):
docker compose -f tests/interop/compose.yml up -d --build

# Run the test suite:
tests/interop/run.sh

# Tear down:
docker compose -f tests/interop/compose.yml down -v
```

## Test Coverage

The current suite verifies:

| Test                       | Protocol        | Scope          |
|----------------------------|-----------------|----------------|
| WebFinger discovery        | RFC 7033        | Noombat        |
| NodeInfo 2.1               | NodeInfo        | Noombat        |
| Actor AP JSON              | ActivityPub S2S | Noombat        |
| `endpoints.sharedInbox`    | ActivityPub S2S | Noombat        |
| `publicKey` presence       | HTTP Signatures | Noombat        |
| Outbox `OrderedCollection` | ActivityPub S2S | Noombat        |
| Shared inbox route         | ActivityPub S2S | Noombat        |
| GotoSocial NodeInfo        | NodeInfo        | Cross-instance |
| GotoSocial WebFinger       | RFC 7033        | Cross-instance |
| AP ID canonical format     | ActivityPub S2S | Cross-instance |
| GotoSocial actor fetch     | ActivityPub S2S | Cross-instance |

## Extending

### Adding a new platform

1. Add the service to `compose.yml` with an alias on the `interop` network.
2. Add a reverse-proxy entry to `Caddyfile`.
3. Add seeding logic and test cases to `run.sh`.

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
