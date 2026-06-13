-- Foundation schema for Noombat.

-- ..... ACTORS .....

CREATE TABLE actors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('individual', 'company', 'group')),
    ap_id           TEXT NOT NULL UNIQUE,
    username        TEXT NOT NULL,
    display_name    TEXT,
    avatar_url      TEXT,
    header_url      TEXT,
    summary_md      TEXT,
    summary_html    TEXT,
    public_key_pem  TEXT NOT NULL,
    private_key_pem TEXT,
    domain          TEXT NOT NULL,
    is_local        BOOLEAN NOT NULL DEFAULT TRUE,
    chatmail_addr   TEXT,
    chatmail_cred   BYTEA,
    orcid           TEXT,
    actor_privacy   JSONB NOT NULL DEFAULT '{"discoverable":true,"indexable":true,"require_follow_approval":false,"federate_profile":true,"chatmail_visible":true,"show_followers_count":true,"cv_download":"public"}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_actors_username_domain ON actors (username, domain);
CREATE INDEX idx_actors_domain ON actors (domain);

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
    visibility       TEXT NOT NULL DEFAULT 'public'
                     CHECK (visibility IN ('public', 'followers', 'private')),
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
    visibility       TEXT NOT NULL DEFAULT 'public'
                     CHECK (visibility IN ('public', 'followers', 'private')),
    ap_object        JSONB NOT NULL
);

CREATE TABLE skills (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'public'
               CHECK (visibility IN ('public', 'private')),
    UNIQUE (actor_id, name)
);

-- ..... DOMAIN-VERIFIED LINKS .....

CREATE TABLE verified_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    verified_at  TIMESTAMPTZ,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT now(),
    visibility   TEXT NOT NULL DEFAULT 'public'
                 CHECK (visibility IN ('public', 'followers', 'private')),
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
    visibility     TEXT NOT NULL DEFAULT 'public'
                   CHECK (visibility IN ('public', 'followers', 'private')),
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
    post_type          TEXT NOT NULL DEFAULT 'note'
                       CHECK (post_type IN ('note', 'article')),
    title              TEXT,
    featured_image_url TEXT,
    content_md         TEXT NOT NULL,
    content_html       TEXT NOT NULL,
    in_reply_to        TEXT,
    canonical_uri      TEXT,
    visibility         TEXT NOT NULL DEFAULT 'public'
                       CHECK (visibility IN ('public', 'unlisted', 'followers')),
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
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    applicant_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    job_listing_id   UUID NOT NULL REFERENCES job_listings(id) ON DELETE CASCADE,
    ap_id            TEXT NOT NULL UNIQUE,
    cover_letter_md  TEXT,
    cover_letter_html TEXT,
    include_cv       BOOLEAN NOT NULL DEFAULT TRUE,
    cv_snapshot      BYTEA,
    status           TEXT NOT NULL DEFAULT 'submitted'
                     CHECK (status IN ('submitted', 'reviewed', 'shortlisted', 'rejected', 'withdrawn')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (applicant_id, job_listing_id)
);

-- ..... GROUPS .....

CREATE TABLE group_memberships (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    member_id  UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member'
               CHECK (role IN ('member', 'moderator', 'admin')),
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
    visibility   TEXT NOT NULL DEFAULT 'public'
                 CHECK (visibility IN ('public', 'followers', 'private')),
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

-- ..... DELIVERY QUEUE .....

CREATE TABLE delivery_queue (
    id           BIGSERIAL PRIMARY KEY,
    payload      JSONB NOT NULL,
    target_inbox TEXT NOT NULL,
    attempts     SMALLINT NOT NULL DEFAULT 0,
    next_retry   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_delivery_queue_next_retry
    ON delivery_queue (next_retry)
    WHERE attempts < 10;
