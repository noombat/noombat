# Interoperability Tests

This directory contains the infrastructure for testing Noombat's ActivityPub federation against other Fediverse server implementations.

## What this suite is for

Reading Noombat's own endpoints proves that it serves the right shapes. It does not prove that it federates: WebFinger, NodeInfo and an actor document can all be correct on an instance that has never successfully sent or received an activity.

So the suite is in two halves. The first reads Noombat's endpoints. The second drives one round trip and then asserts against **GoToSocial's** state, through GoToSocial's own API, as the account that was followed. Only the second half can fail for a reason internal to federation.

## Architecture

One topology, used by CI and locally alike:

```
┌─────────────────────────────────────────────────────┐
│                Docker network: interop              │
│                                                     │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Noombat  │  │  GoToSocial  │  │  Caddy        │  │
│  │ :8443    │  │  :8080       │  │  :8443 (TLS)  │  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
│        ▲               ▲                 │          │
│        └───────────────┴─────────────────┘          │
│         noombat.localhost / gotosocial.localhost    │
└─────────────────────────────────────────────────────┘
                          │
                   published :8443
```

Three properties of it are load-bearing, and each of them cost a working round trip to get right.

**The names end in `.localhost`.** Every address on this network is private, and `noombat-federation::http` refuses private and reserved addresses. It derives the permissive posture from the instance's own domain rather than offering it as a setting, and `domain_is_local` accepts `localhost`, `*.localhost`, `127.0.0.1` and `[::1]`. Under a `.local` name the resolver rejects the peer before a request is made, and nothing federates.

**The port is part of the domain.** Noombat builds every id it generates from `NOOMBAT_DOMAIN` alone, and matches WebFinger resources against it exactly. GoToSocial does the same with `GTS_HOST`. AP ids are absolute, so an id generated behind one authority and fetched through another is a different resource. Caddy therefore listens on 8443 inside the network as well as on the published port, and both instances carry `:8443` in their domain, so one id works from the runner and from either container.

**Both sides have to trust Caddy's CA.** GoToSocial is told not to verify (`GTS_HTTP_CLIENT_TLS_INSECURE_SKIP_VERIFY`). Noombat has no such setting, which is the right shape for a server that fetches URLs strangers chose, so it is pointed at Caddy's root certificate with `SSL_CERT_FILE` instead. Caddy writes that file mode 0600 under directories mode 0700, which is why the Noombat container runs as root here.

## Running it

The hostnames have to resolve to the machine running the stack:

```bash
echo "127.0.0.1 noombat.localhost gotosocial.localhost" | sudo tee -a /etc/hosts
```

Then:

```bash
docker compose -f tests/interop/compose.yml up -d --build --wait

# Both accounts, on both instances. Neither is created by its server:
# Noombat has no open registration route and GoToSocial runs with
# registration closed.
tests/interop/seed.sh tests/interop/compose.yml

# Caddy issues its own certificate for these names.
CURL_OPTS="--insecure" tests/interop/run.sh \
  https://noombat.localhost:8443 https://gotosocial.localhost:8443

docker compose -f tests/interop/compose.yml down -v
```

`run.sh` takes the two base URLs and nothing else. They have to be the URLs the instances know themselves by, for the reason given under "the port is part of the domain" above.

Environment:

| Variable                | Effect                                                                        |
|-------------------------|-------------------------------------------------------------------------------|
| `CURL_OPTS`             | Extra curl flags. `--insecure` for Caddy's internal CA.                    |
| `INTEROP_CROSS_TIMEOUT` | Seconds to wait for an activity to cross. Default 60.                     |
| `CI`                    | When set, a skipped assertion fails the run, an unreachable peer included. |

The accounts themselves are declared once, in `fixtures.sh`, because `seed.sh` creates them and `run.sh` signs in as one of them.

Noombat's authenticated routes act for whoever the session says they are, so there is no
instance-wide bearer to configure. `seed.sh` stores an Argon2id hash of a fixture key, `run.sh`
exchanges that key for an access token at `POST /api/v1/auth/login`, and both read the key from
`fixture-credential.sh` so the two cannot drift apart. That file explains the choice of key and
gives the command that regenerates the hash.

## What is asserted, and where

| Assertion                            | Protocol        | Asserted in           |
|--------------------------------------|-----------------|-----------------------|
| WebFinger discovery                  | RFC 7033        | Noombat               |
| NodeInfo 2.1                         | NodeInfo        | Noombat               |
| Actor AP JSON                        | ActivityPub S2S | Noombat               |
| `endpoints.sharedInbox`              | ActivityPub S2S | Noombat               |
| `publicKey` presence                 | HTTP Signatures | Noombat               |
| AP ID canonical format               | ActivityPub S2S | Noombat               |
| Outbox `OrderedCollection`           | ActivityPub S2S | Noombat               |
| Shared inbox route                   | ActivityPub S2S | Noombat               |
| GoToSocial NodeInfo                  | NodeInfo        | GoToSocial (liveness) |
| Sign-in as the seeded account        | OAuth 2         | GoToSocial            |
| Follow policy: no approval needed    | Mastodon API    | GoToSocial (setup)    |
| Follow accepted for delivery (202)   | ActivityPub S2S | Noombat               |
| Follow appears in the followers list | ActivityPub S2S | **GoToSocial**        |
| Accept appears in `following`        | ActivityPub S2S | **Noombat**           |
| GoToSocial resolved `alice`          | WebFinger       | GoToSocial (setup)    |
| Follow back accepted for delivery    | ActivityPub S2S | GoToSocial (setup)    |
| Follow back appears in `followers`   | ActivityPub S2S | **Noombat**           |
| Accept back appears in `following`   | ActivityPub S2S | **GoToSocial**        |
| Noombat published a Note             | ActivityPub S2S | Noombat               |
| Note appears in the home timeline    | ActivityPub S2S | **GoToSocial**        |
| GoToSocial published a status        | Mastodon API    | GoToSocial (setup)    |
| Note reaches Noombat's feed          | ActivityPub S2S | **Noombat**           |

The bolded rows are the suite: each is a peer reporting a state it could only reach by verifying something the other end signed. The unbolded rows are Noombat's own endpoints, which would pass identically against any ActivityPub implementation or against none, and the preconditions each round trip needs before its assertion can mean anything.

The two `accepted for delivery` rows are deliberately separate from the collection assertions that follow them. A 202 or a 200 says only that the sender queued the activity; the collection says the peer received it, verified the signature and stored it. A regression in signing shows up as the first passing and the second failing, which is the pair that localises it.

The follower assertion is reached only if GoToSocial received a signed `Follow`, resolved `alice` through WebFinger, fetched the actor document over TLS and verified the signature against the key in it. `following` lists accepted follows only, so an entry there is Noombat having received GoToSocial's `Accept` and verified *its* signature, the same exchange in reverse. The timeline assertion is the strongest single check here: the status is in the follower's timeline only if GoToSocial verified the HTTP Signature on a POST Noombat made, parsed the activity and stored the object. The inbound content assertion is its mirror: GoToSocial composes a status of its own, and it is Noombat that has to verify the signature, resolve the actor and store the object for the Note to appear in `alice`'s feed. Without it the suite showed that Noombat could send a Note and never that it could receive one.

**Both follows are needed, and they are not the same test.** `alice` following `bob` is the outbound half: Noombat signs the `Follow` and verifies the `Accept`. `bob` following `alice`, driven through GoToSocial's own API, is the inbound half: Noombat verifies a `Follow` somebody else signed and signs the `Accept` itself. It is also what makes the timeline assertion reachable at all. Delivery targets are the *followers* of the posting actor, so with only the first follow in place nothing is enqueued and the `Create` never leaves Noombat; and a home timeline holds statuses from the accounts its owner follows, so `bob` has to be the follower for the status to land there. Neither end of that assertion is satisfied by a follow pointing the other way.

Reading GoToSocial's state means signing in to it. Its ActivityPub endpoints require a signature and its client API requires a user token, so `run.sh` registers an application, posts the sign-in form, posts the consent form and exchanges the code. GoToSocial supports the `authorization_code` grant only; `password` is rejected and a `client_credentials` token is not attached to a user, so neither is a shortcut.

## CI

`.github/workflows/ci-e2e.yml` runs this compose stack, digest-pinned, on pull requests. `.github/workflows/ci-interop-latest.yml` runs the same harness with the pin lifted, on a schedule, so that a peer changing under us is reported against the calendar rather than against whoever pushed next.

Both set `CI`, so a skip fails the run.

## Extending

### Adding a new platform

1. Add the service to `compose.yml`.
2. Add a reverse-proxy entry to `Caddyfile` on port 8443.
3. Seed its account in `seed.sh`, next to the other two.
4. Add a round trip to `run.sh`, asserted in the new platform's own state.

### Target platforms

- [x] GoToSocial
- [ ] Mastodon
- [ ] Ghost
- [ ] Lemmy
- [ ] PieFed
- [ ] Pixelfed
- [ ] PeerTube
- [ ] Friendica
- [ ] Bonfire

Each additional platform requires its own service definition in `compose.yml` (with any necessary database sidecars) and a corresponding section in `run.sh`.
