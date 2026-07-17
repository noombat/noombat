-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

-- Foundation schema for Noombat.

-- ..... ACTORS .....

CREATE TABLE actors (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_type          TEXT NOT NULL CHECK (actor_type IN ('individual', 'company', 'group')),
    ap_id               TEXT NOT NULL UNIQUE,
    username            TEXT NOT NULL,
    display_name        TEXT,
    avatar_url          TEXT,
    header_url          TEXT,
    summary_md          TEXT,
    summary_html        TEXT,
    public_key_pem      TEXT NOT NULL,
    private_key_pem     TEXT,
    ed25519_public_key  TEXT, -- multibase-encoded Ed25519 public key; NOT NULL for local actors (generated at creation); nullable for remote actors
    ed25519_private_key TEXT, -- Ed25519 private key; NOT NULL for local actors; NULL for remote actors
    auth_key_hash       TEXT, -- Argon2id hash of the authentication key (split key derivation); NULL for OAuth-only users
    domain              TEXT NOT NULL,
    is_local            BOOLEAN NOT NULL DEFAULT TRUE,
    inbox_url           TEXT, -- remote actors only: their declared AP inbox URI
    shared_inbox_url    TEXT, -- remote actors only: their endpoints.sharedInbox URI (delivery deduplication)
    instance_role       TEXT NOT NULL DEFAULT 'user' CHECK (instance_role IN ('user', 'moderator', 'admin')),
    actor_status        TEXT NOT NULL DEFAULT 'active' CHECK (actor_status IN ('active', 'silenced', 'suspended')),
    chatmail_addr       TEXT,
    chatmail_cred       BYTEA,
    orcid               TEXT,
    moved_to            TEXT, -- target actor URI if migrated via Move activity
    headline            TEXT,
    actor_privacy       JSONB NOT NULL DEFAULT '{"discoverable":true,"indexable":true,"require_follow_approval":false,"federate_profile":true,"chatmail_visible":true,"show_followers_count":true,"cv_download":"public"}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_actors_username_domain ON actors (username, domain);
CREATE UNIQUE INDEX idx_actors_local_username_domain ON actors (username, domain) WHERE is_local = TRUE;
CREATE INDEX idx_actors_domain ON actors (domain);
CREATE INDEX idx_actors_shared_inbox ON actors (shared_inbox_url) WHERE shared_inbox_url IS NOT NULL;

-- Actor aliases: URIs that this actor has declared as prior identities.
-- Required by the Move protocol: the target actor must list the source
-- actor as an alias before the Move is accepted (Mastodon convention).
CREATE TABLE actor_aliases (
    id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    alias    TEXT NOT NULL,
    UNIQUE (actor_id, alias)
);

-- ..... SESSIONS .....

-- Server-side session metadata. The access token itself is a short-lived
-- JWT verified statelessly; this table records the refresh token and
-- provides an audit trail of active sessions.
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    refresh_token   TEXT NOT NULL UNIQUE,
    user_agent      TEXT,
    ip_addr         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ -- non-NULL = revoked
);

CREATE INDEX idx_sessions_actor ON sessions (actor_id);
CREATE INDEX idx_sessions_active_actor ON sessions (actor_id) WHERE revoked_at IS NULL;

-- ..... TOTP 2FA .....

-- Each actor may enrol at most one TOTP secret. The secret is stored
-- as a base32-encoded string.
-- TO-DO: Application-level encryption of `secret` column.
CREATE TABLE totp_secrets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    UUID NOT NULL UNIQUE REFERENCES actors(id) ON DELETE CASCADE,
    secret      TEXT NOT NULL, -- base32-encoded TOTP secret
    verified    BOOLEAN NOT NULL DEFAULT FALSE, -- TRUE after first successful verification
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... OAUTH CLIENT CACHE .....

-- Caches OAuth 2.0 dynamic client registrations per remote Mastodon
-- instance, avoiding repeated POST /api/v1/apps calls.
CREATE TABLE oauth_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_domain TEXT NOT NULL UNIQUE,
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... OAUTH STATE .....

-- Stores the transient OAuth 2.0 authorisation state parameter,
-- binding it to the flow that initiated it (Mastodon or ORCID).
-- NOTE: expired rows should be purged periodically (e.g. via a
-- background sweeper or pg_cron job).
CREATE TABLE oauth_states (
    state       TEXT PRIMARY KEY,
    provider    TEXT NOT NULL CHECK (provider IN ('mastodon', 'orcid')),
    -- For Mastodon: the remote instance domain.
    -- For ORCID: NULL (single provider).
    instance_domain TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

-- ..... OAUTH IDENTITIES .....

-- Links a local actor to an external OAuth identity (Mastodon account
-- or ORCID iD).
CREATE TABLE oauth_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL CHECK (provider IN ('mastodon', 'orcid')),
    -- For Mastodon: "alice@mastodon.social".
    -- For ORCID: "0000-0002-1825-0097".
    external_id     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, external_id)
);

CREATE INDEX idx_oauth_identities_actor ON oauth_identities (actor_id);

-- ..... PROFILE SECTIONS .....

CREATE TABLE experiences (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id         UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    title            TEXT NOT NULL,
    company          TEXT NOT NULL,
    start_date       DATE NOT NULL,
    end_date         DATE,
    description_md   TEXT,
    description_html TEXT,
    sort_order       SMALLINT NOT NULL DEFAULT 0,
    visibility       TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'private')),
    ap_object        JSONB NOT NULL
);

CREATE TABLE educations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id         UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    institution      TEXT NOT NULL,
    degree           TEXT,
    field_of_study   TEXT,
    start_date       DATE NOT NULL,
    end_date         DATE,
    description_md   TEXT,
    description_html TEXT,
    sort_order       SMALLINT NOT NULL DEFAULT 0,
    visibility       TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'private')),
    ap_object        JSONB NOT NULL
);

CREATE TABLE skills (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'private')),
    UNIQUE (actor_id, name)
);

-- ..... DOMAIN-VERIFIED LINKS .....

CREATE TABLE verified_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    verified_at  TIMESTAMPTZ,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT now(),
    visibility   TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'private')),
    UNIQUE (actor_id, url)
);

-- ..... PUBLICATIONS .....

CREATE TABLE publications (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id       UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    doi            TEXT NOT NULL,
    title          TEXT NOT NULL,
    authors        JSONB NOT NULL,
    abstract_md    TEXT,
    abstract_html  TEXT,
    journal        TEXT,
    publisher      TEXT,
    published_date DATE,
    doi_metadata   JSONB NOT NULL,
    fetched_at     TIMESTAMPTZ NOT NULL,
    visibility     TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'private')),
    ap_object      JSONB NOT NULL,
    UNIQUE (actor_id, doi)
);

-- ..... JOB LISTINGS .....

CREATE TABLE job_listings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id         UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id            TEXT NOT NULL UNIQUE,
    title            TEXT NOT NULL,
    description_md   TEXT NOT NULL,
    description_html TEXT NOT NULL,
    location         TEXT,
    remote           BOOLEAN NOT NULL DEFAULT FALSE,
    salary_min       INTEGER,
    salary_max       INTEGER,
    currency         TEXT,
    requirements     JSONB,
    published_at     TIMESTAMPTZ,
    expires_at       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... POSTS .....

CREATE TABLE posts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id           UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id              TEXT NOT NULL UNIQUE,
    post_type          TEXT NOT NULL DEFAULT 'note' CHECK (post_type IN ('note', 'article')),
    title              TEXT,
    featured_image_url TEXT,
    content_md         TEXT NOT NULL,
    content_html       TEXT NOT NULL,
    in_reply_to        TEXT,
    canonical_uri      TEXT,
    visibility         TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'unlisted', 'followers')),
    ap_object          JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_posts_actor ON posts (actor_id, created_at DESC);
CREATE INDEX idx_posts_canonical ON posts (canonical_uri) WHERE canonical_uri IS NOT NULL;

-- ..... MEDIA ATTACHMENTS .....

CREATE TABLE media_attachments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    post_id    UUID REFERENCES posts(id) ON DELETE CASCADE,
    media_type TEXT NOT NULL,
    url        TEXT NOT NULL,
    alt_text   TEXT,
    blurhash   TEXT,
    byte_size  BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... SOCIAL GRAPH .....

CREATE TABLE follows (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    follower_id  UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    following_id UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id        TEXT,
    accepted     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (follower_id, following_id)
);

CREATE TABLE boosts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    ap_id      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (actor_id, post_id)
);

CREATE TABLE likes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    ap_id      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (actor_id, post_id)
);

-- ..... JOB APPLICATIONS .....

CREATE TABLE applications (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    applicant_id      UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    job_listing_id    UUID NOT NULL REFERENCES job_listings(id) ON DELETE CASCADE,
    ap_id             TEXT NOT NULL UNIQUE,
    cover_letter_md   TEXT,
    cover_letter_html TEXT,
    include_cv        BOOLEAN NOT NULL DEFAULT TRUE,
    cv_snapshot       BYTEA,
    status            TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'reviewed', 'shortlisted', 'rejected', 'withdrawn')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (applicant_id, job_listing_id)
);

-- ..... GROUPS .....

CREATE TABLE group_memberships (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    member_id  UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'moderator', 'admin')),
    accepted   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (group_id, member_id)
);

-- ..... EVENTS .....

CREATE TABLE events (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id         UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id            TEXT NOT NULL UNIQUE,
    title            TEXT NOT NULL,
    description_md   TEXT NOT NULL,
    description_html TEXT NOT NULL,
    start_time       TIMESTAMPTZ NOT NULL,
    end_time         TIMESTAMPTZ,
    location_name    TEXT,
    location_address TEXT,
    location_lat     DOUBLE PRECISION,
    location_lon     DOUBLE PRECISION,
    virtual_url      TEXT,
    organiser_id     UUID NOT NULL REFERENCES actors(id),
    group_id         UUID REFERENCES actors(id),
    ap_object        JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_rsvps (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id   UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    status     TEXT NOT NULL CHECK (status IN ('attending', 'maybe', 'declined')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, actor_id)
);

-- ..... HASHTAGS .....

CREATE TABLE hashtags (
    id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE post_hashtags (
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    hashtag_id UUID NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, hashtag_id)
);

CREATE TABLE hashtag_follows (
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    hashtag_id UUID NOT NULL REFERENCES hashtags(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor_id, hashtag_id)
);

-- ..... ANALYTICS .....

CREATE TABLE analytics_counters (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_type TEXT NOT NULL CHECK (target_type IN ('job_listing', 'profile', 'article', 'event')),
    target_id   UUID NOT NULL,
    metric      TEXT NOT NULL CHECK (metric IN ('view', 'application', 'rsvp')),
    period      DATE NOT NULL,
    count       BIGINT NOT NULL DEFAULT 0,
    UNIQUE (target_type, target_id, metric, period)
);

-- ..... CUSTOM PROFILE SECTIONS .....

CREATE TABLE custom_profile_sections (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    section_type TEXT NOT NULL,
    title        TEXT NOT NULL,
    content_md   TEXT,
    content_html TEXT,
    data         JSONB,
    sort_order   SMALLINT NOT NULL DEFAULT 0,
    visibility   TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'private')),
    ap_object    JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... BLOCKS AND MUTES .....

CREATE TABLE blocks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    target_id  UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (actor_id, target_id)
);

CREATE TABLE mutes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    target_id  UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (actor_id, target_id)
);

CREATE TABLE domain_restrictions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain      TEXT NOT NULL UNIQUE,
    restriction TEXT NOT NULL CHECK (restriction IN ('block', 'silence')),
    reason      TEXT,
    created_by  UUID REFERENCES actors(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... USER REPORTS .....

CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    target_actor_id UUID REFERENCES actors(id) ON DELETE CASCADE,
    target_post_id  UUID REFERENCES posts(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL CHECK (reason IN ('spam', 'harassment', 'illegal', 'impersonation', 'other')),
    comment         TEXT,
    forwarded       BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed')),
    resolved_by     UUID REFERENCES actors(id),
    resolution_note TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    CHECK (target_actor_id IS NOT NULL OR target_post_id IS NOT NULL)
);

-- ..... RELAY SUBSCRIPTIONS .....

-- Tracks ActivityPub relays to which this instance is subscribed.
-- A relay receives all public activities and rebroadcasts them to
-- subscribers, widening content discovery.
CREATE TABLE relay_subscriptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inbox_url   TEXT NOT NULL UNIQUE,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... TOMBSTONED ACTORS .....

-- When a remote actor returns 410 Gone, the federation service records
-- the tombstone so that future resolution attempts short-circuit
-- without an HTTP round-trip.
--
-- Tombstones should be pruned periodically (e.g. after 30 days) by a
-- background worker so that actors who re-create their account on the
-- same URI become resolvable again.
CREATE TABLE tombstoned_actors (
    ap_id         TEXT PRIMARY KEY,
    tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... DELIVERY QUEUE .....

CREATE TABLE delivery_queue (
    id           BIGSERIAL PRIMARY KEY,
    actor_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    payload      JSONB NOT NULL,
    target_inbox TEXT NOT NULL,
    attempts     SMALLINT NOT NULL DEFAULT 0,
    next_retry   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_delivery_queue_next_retry ON delivery_queue (next_retry) WHERE attempts < 10;

-- NOTIFY trigger: wakes the delivery worker immediately when new
-- activities are enqueued, eliminating polling latency.
CREATE OR REPLACE FUNCTION notify_delivery_queue_insert()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('delivery_queue_insert', '');
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_delivery_queue_notify AFTER INSERT ON delivery_queue FOR EACH STATEMENT EXECUTE FUNCTION notify_delivery_queue_insert();

-- ..... FOREIGN-KEY INDICES .....

CREATE INDEX idx_experiences_actor ON experiences (actor_id);
CREATE INDEX idx_educations_actor ON educations (actor_id);
CREATE INDEX idx_skills_actor ON skills (actor_id);
CREATE INDEX idx_publications_actor ON publications (actor_id);
CREATE INDEX idx_verified_links_actor ON verified_links (actor_id);
CREATE INDEX idx_custom_sections_actor ON custom_profile_sections (actor_id);
CREATE INDEX idx_media_attachments_post ON media_attachments (post_id);
CREATE INDEX idx_job_listings_actor ON job_listings (actor_id);
CREATE INDEX idx_applications_job ON applications (job_listing_id);
CREATE INDEX idx_group_memberships_group ON group_memberships (group_id);
CREATE INDEX idx_event_rsvps_event ON event_rsvps (event_id);
CREATE INDEX idx_events_group ON events (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_reports_reporter ON reports (reporter_id);
CREATE INDEX idx_reports_target_actor ON reports (target_actor_id) WHERE target_actor_id IS NOT NULL;
CREATE INDEX idx_reports_target_post ON reports (target_post_id) WHERE target_post_id IS NOT NULL;
CREATE INDEX idx_reports_status ON reports (status) WHERE status = 'open';

-- ..... UPDATED_AT TRIGGER .....

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_actors_updated_at BEFORE UPDATE ON actors FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_applications_updated_at BEFORE UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_relay_subscriptions_updated_at BEFORE UPDATE ON relay_subscriptions FOR EACH ROW EXECUTE FUNCTION set_updated_at();
