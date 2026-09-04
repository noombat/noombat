-- SPDX-License-Identifier: AGPL-3.0-or-later
-- SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

-- Foundation schema for Noombat.

-- Stored HTML is a derived, versioned projection of the wire record.
--
-- Remote HTML arriving over ActivityPub is passed through
-- `noombat_markup::sanitise::clean_strict` at ingestion and never persisted
-- verbatim, because it is rendered with Askama's `|safe`.
--
-- `sanitiser_version` records which policy produced a stored value.
-- Sanitising is not a one-off: when the allowlist changes, or a bypass is
-- found, the fix is to re-derive every row whose version is behind
-- `noombat_markup::sanitise::STRICT_VERSION`. Storing the version turns that
-- from a hand-written script into a routine, resumable, idempotent operation
-- (`noombat_federation::backfill`, which sweeps on every boot). Raising the
-- constant and deploying is therefore the whole operator procedure.
--
-- Version 0 means "not produced by the ingestion sanitiser". That is true of
-- every locally authored row, permanently: local HTML comes from
-- `noombat_markup::render` under the lenient profile, and re-cleaning it
-- strictly would strip the `style` attributes the maths renderer emits. The backfill
-- scopes itself to remote rows by joining `actors` on `is_local = FALSE`, so
-- the partial indexes below settle at the local row count rather than
-- draining to empty.
--
-- `posts.ap_object` is deliberately excluded. It is the wire record, and
-- FEP-8b32 Object Integrity Proofs are computed over it, so rewriting it
-- would destroy the ability to audit a stored verification result.
-- Sanitisation belongs to the projection, not to the record.
--
-- Note the limit of that guarantee: the column is `JSONB`, which stores a
-- parsed tree, not bytes. Key order, insignificant whitespace and duplicate
-- keys do not survive. JCS re-sorts keys, so the common case round-trips,
-- but a document relying on anything JSONB normalises away cannot be
-- re-verified from storage. Verification therefore happens at ingestion,
-- against the document as received, and the stored value is evidence of
-- that check rather than a substrate for repeating it.

-- ..... ACTORS .....

CREATE TABLE actors (
    id                           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 'application' is the instance speaking as itself, not a kind of user.
    -- Server-to-server fetches are signed as it, so that asking a peer for a
    -- document does not hand them the name of an administrator. There is at
    -- most one per instance, nobody signs into it, and it is excluded from
    -- the directory and from candidate search by actor_type.
    actor_type                   TEXT NOT NULL CHECK (actor_type IN ('individual', 'organization', 'group', 'application')),
    ap_id                        TEXT NOT NULL UNIQUE,
    username                     TEXT NOT NULL,
    display_name                 TEXT,
    avatar_url                   TEXT,
    header_url                   TEXT,
    summary_md                   TEXT,
    summary_html                 TEXT,
    sanitiser_version            SMALLINT NOT NULL DEFAULT 0, -- policy that produced summary_html; 0 = not the ingestion sanitiser
    public_key_pem               TEXT NOT NULL,
    public_key_id                TEXT, -- the `publicKey.id` a REMOTE actor publishes, used to resolve an inbound signer whose keyId is a URL of its own rather than a fragment; NULL for local actors, whose key id is always `{ap_id}#main-key` and is derived, never looked up
    private_key_pem              TEXT,
    ed25519_public_key           TEXT, -- multibase-encoded Ed25519 public key; NOT NULL for local actors (generated at creation); nullable for remote actors
    ed25519_private_key          TEXT, -- Ed25519 private key; NOT NULL for local actors; NULL for remote actors
    auth_key_hash                TEXT, -- Argon2id hash of the authentication key (split key derivation); NULL for OAuth-only users
    domain                       TEXT NOT NULL,
    is_local                     BOOLEAN NOT NULL DEFAULT TRUE,
    inbox_url                    TEXT, -- remote actors only: their declared AP inbox URI
    shared_inbox_url             TEXT, -- remote actors only: their endpoints.sharedInbox URI (delivery deduplication)
    instance_role                TEXT NOT NULL DEFAULT 'user' CHECK (instance_role IN ('user', 'moderator', 'admin')),
    -- 'pending' is an admission state, not a moderation outcome: the account
    -- exists, holds its username, and has never been signed into. It is not a
    -- fourth degree of 'silenced'.
    --
    -- The DEFAULT stays 'active' deliberately. Neither insert path names this
    -- column (create_actor_on writes local actors, upsert_remote_actor writes
    -- remote ones, and both rely on the default), so a default of 'pending'
    -- would hold every federated actor for approval.
    actor_status                 TEXT NOT NULL DEFAULT 'active' CHECK (actor_status IN ('pending', 'active', 'silenced', 'suspended')),
    chatmail_addr                TEXT,
    chatmail_cred                BYTEA,
    -- The user's own address, requested at registration for verification and
    -- account recovery. Never federated: build_federated_actor names its fields
    -- one at a time, so a column cannot reach a peer by being added here, and
    -- this one must not be added there.
    --
    -- Nullable, permanently. The OAuth sign-up paths mint an account with no
    -- password and no address, and remote actors never have one.
    --
    -- Stored as entered, compared folded: uniqueness and every lookup go
    -- through lower(email), via the index below. A query written against the
    -- raw column finds nothing and reports no error.
    email                        TEXT,
    email_verified_at            TIMESTAMPTZ, -- non-NULL = control of the address proved
    chat_requires_reprovisioning BOOLEAN NOT NULL DEFAULT FALSE,
    orcid                        TEXT,
    moved_to                     TEXT, -- target actor URI if migrated via Move activity
    headline                     TEXT,
    location                     TEXT, -- free-text location (e.g. "Berlin, Germany")
    -- Organisations only: the corporate domain claimed. Publishing is gated
    -- on a verified rel="me" link whose registrable domain matches it, so
    -- without the claim the gate would admit any domain the actor happens
    -- to control, including a personal blog.
    claimed_domain               TEXT,
    -- Organisations only: whether this actor recruits for itself or for third
    -- parties. Declared at enrolment, never inferred, because rel="me" proves
    -- the wrong thing for an agency: it establishes control of a domain, and a
    -- reader takes it as a relationship to the roles advertised, which for an
    -- agency it is not.
    --
    -- Nullable rather than defaulted. NULL means nobody was asked, which is
    -- true of every individual, every group and every remote actor, and an
    -- agency that never declared itself has to stay distinguishable from one
    -- that declared itself a direct employer.
    org_kind                     TEXT CHECK (org_kind IN ('employer', 'agency')),
    -- Whether a sensitive image is shown as a blur or as a plain
    -- placeholder. The reader's choice, not the author's.
    --
    -- Deliberately separate from whether sensitive media is hidden at all:
    -- Mastodon carries the two as `display_media` and `use_blurhash`, and
    -- keeping them apart is what lets somebody who wants such media hidden
    -- still refuse the blur, which can itself be unpleasant to look at.
    --
    -- Defaults to TRUE, matching Mastodon: a blur says something is there
    -- and roughly what it looks like, which is more use than a grey box.
    blur_sensitive_media         BOOLEAN NOT NULL DEFAULT TRUE,
    -- The default a new post takes when the request states no visibility.
    -- Deliberately not inside actor_privacy: that blob holds access-control
    -- predicates, each with a read-enforcement site, and this has none. It is a
    -- default for new objects, so the only thing that reads it is the compose
    -- path.
    --
    -- The same four values as posts.visibility, which are NOT the four the
    -- profile-section tables use: 'unlisted' here, 'private' there.
    default_post_visibility      TEXT NOT NULL DEFAULT 'public' CHECK (default_post_visibility IN ('public', 'unlisted', 'followers', 'connections')),
    -- Who may read the connection, following and follower lists. Private by
    -- default: the graph is the one thing a professional network holds that a
    -- competitor most wants, and a default that leaks it cannot be recalled.
    connections_visibility       TEXT NOT NULL DEFAULT 'private' CHECK (connections_visibility IN ('public', 'followers', 'connections', 'private')),
    following_visibility         TEXT NOT NULL DEFAULT 'private' CHECK (following_visibility IN ('public', 'followers', 'connections', 'private')),
    followers_visibility         TEXT NOT NULL DEFAULT 'private' CHECK (followers_visibility IN ('public', 'followers', 'connections', 'private')),
    actor_privacy                JSONB NOT NULL DEFAULT '{"discoverable":true,"indexable":true,"require_follow_approval":false,"federate_profile":true,"chatmail_visible":true,"show_followers_count":true,"cv_download":"public"}',
    deletion_requested_at        TIMESTAMPTZ, -- non-NULL = grace-period deletion pending
    -- When the tombstone was written, which starts the retention window before
    -- the row itself is hard-deleted. A second clock, after the grace period
    -- deletion_requested_at starts, not the same one.
    --
    -- Not updated_at: trg_actors_updated_at is BEFORE UPDATE ... FOR EACH ROW,
    -- so it moves on every later write to the row and cannot carry a window.
    -- Not tombstoned_actors.tombstoned_at either: that is keyed on ap_id and
    -- its INSERT is ON CONFLICT DO NOTHING, so a second erasure inherits the
    -- first one's timestamp.
    erased_at                    TIMESTAMPTZ, -- non-NULL = tombstoned; the purge clock
    last_sign_in_at              TIMESTAMPTZ, -- last accepted credential presentation; NULL = never signed in. NOT updated_at, see below
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT org_kind_is_for_organisations CHECK (
        org_kind IS NULL
        OR actor_type = 'organization'
    )
);

CREATE INDEX idx_actors_username_domain ON actors (username, domain);
CREATE UNIQUE INDEX idx_actors_local_username_domain ON actors (username, domain) WHERE is_local = TRUE;
-- Unique, because it decides which actor a signature is verified against:
-- two rows claiming one key id would make that ambiguous. Partial, so the
-- local rows that leave it NULL do not collide with one another.
CREATE UNIQUE INDEX idx_actors_public_key_id ON actors (public_key_id) WHERE public_key_id IS NOT NULL;
-- Uniqueness and every lookup fold case, so both go through lower(email).
-- lower() is IMMUTABLE, so this needs no extension.
CREATE UNIQUE INDEX idx_actors_local_email ON actors (lower(email)) WHERE is_local AND email IS NOT NULL;
-- At most one instance actor. The signing path selects it by type, so a
-- second one would make which key signs an outbound fetch depend on row
-- order. Unique on actor_type within the filtered set, which holds only
-- the one value, is how "at most one row" is spelled.
CREATE UNIQUE INDEX idx_actors_instance_actor ON actors (actor_type)
    WHERE actor_type = 'application' AND is_local;
-- The admission queue's work list, oldest first. Unlike
-- idx_actors_sanitiser_version this one is intended to drain to empty.
CREATE INDEX idx_actors_pending ON actors (created_at) WHERE actor_status = 'pending' AND is_local;
-- The purge worker's work list: tombstoned rows past their retention window.
CREATE INDEX idx_actors_erased ON actors (erased_at) WHERE erased_at IS NOT NULL;
CREATE INDEX idx_actors_domain ON actors (domain);
CREATE INDEX idx_actors_shared_inbox ON actors (shared_inbox_url) WHERE shared_inbox_url IS NOT NULL;
CREATE INDEX idx_actors_orcid ON actors (orcid) WHERE orcid IS NOT NULL;
CREATE INDEX idx_actors_chatmail ON actors (chatmail_addr) WHERE chatmail_addr IS NOT NULL;

-- The backfill's work list. Partial because the rows behind the current
-- policy are the minority; see the note at the head of this file for why it
-- does not drain to empty.
CREATE INDEX idx_actors_sanitiser_version ON actors (sanitiser_version) WHERE sanitiser_version = 0;

-- NodeInfo's usage.users.activeMonth and activeHalfyear, which the schema
-- defines as users who SIGNED IN during the window. Both queries filter on
-- is_local and a lower bound on last_sign_in_at, so the index carries only
-- the rows they can return.
--
-- last_sign_in_at exists because updated_at cannot answer the question.
-- trg_actors_updated_at below is BEFORE UPDATE ... FOR EACH ROW, so it moves
-- on every write to the row whether or not the statement mentions it. Reading
-- activity from it counted profile edits, moderation actions, deletion
-- requests and account migrations as sign-ins, and missed anyone who signed
-- in without changing their row, because posting does not write to actors.
-- The two columns must not be conflated again: writing a sign-in also bumps
-- updated_at, which is harmless only because nothing derives activity from it.
CREATE INDEX idx_actors_last_sign_in ON actors (last_sign_in_at)
    WHERE is_local AND last_sign_in_at IS NOT NULL;

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
    -- Set when the flow is linking a provider to an account that already
    -- exists, rather than signing in. It is recorded when the flow starts,
    -- from the session that started it, so the callback cannot be talked
    -- into attaching an identity to somebody else's account by anything in
    -- the redirect it receives.
    link_actor_id UUID REFERENCES actors(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

-- ..... EMAIL VERIFICATION .....

-- A challenge proving control of an address.
--
-- The address under test lives here and not on `actors` until it is proven.
-- Writing it there first would let anyone claim any address by starting a
-- verification they never finish, and the unique index would then hold that
-- name against the person who actually owns it.
--
-- The token is stored as a SHA-256 hash, never in the clear. A read of this
-- table would otherwise be a read of every live credential in flight, and
-- these carry the same force as a password reset.
CREATE TABLE email_verifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Non-NULL once redeemed. Kept rather than deleted so that a token
    -- presented twice is refused as used instead of as unknown, which is
    -- also what makes the rate limit below countable.
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The rate limit's window, and the sweep for expired challenges.
CREATE INDEX idx_email_verifications_actor ON email_verifications (actor_id, created_at DESC);
CREATE INDEX idx_email_verifications_expiry ON email_verifications (expires_at)
    WHERE consumed_at IS NULL;

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

-- Employment is a two-sided claim. `organization` is what the person typed
-- and is kept for employers that are not actors anywhere; `organization_id`
-- is the actor they mean, where one exists, and is what makes the claim
-- checkable at all. A row with the text and no reference is an ordinary
-- self-assertion, which is most rows and is fine.
CREATE TABLE work_experiences (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id         UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    title            TEXT NOT NULL,
    organization     TEXT NOT NULL,
    -- ON DELETE SET NULL, not CASCADE: an organisation leaving the instance
    -- must not delete a person's work history. The claim reverts to the free
    -- text it always carried, and loses its confirmation with the reference.
    organization_id  UUID REFERENCES actors(id) ON DELETE SET NULL,
    -- When the employer side was established, and by which of the two routes
    -- that carry equal force: the organisation confirming the person, or the
    -- person proving an address at a domain the organisation has already
    -- verified through rel="me", which is a standing pre-authorisation.
    --
    -- NULL is the honest default and is rendered as unconfirmed rather than
    -- hidden. Absence of a badge is the signal, so there is deliberately no
    -- DEFAULT that could make an unchecked row read as checked.
    organization_confirmed_at  TIMESTAMPTZ,
    organization_confirmed_via TEXT CHECK (organization_confirmed_via IN ('organisation', 'domain-email')),
    start_date       DATE NOT NULL,
    end_date         DATE,
    description_md   TEXT,
    description_html TEXT,
    sort_order       SMALLINT NOT NULL DEFAULT 0,
    visibility       TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'connections', 'private')),
    ap_object        JSONB NOT NULL,
    -- A confirmation with nothing to point at is not a confirmation. This
    -- stops a route setting the timestamp on a free-text row, which would
    -- render a badge no organisation ever stood behind.
    CONSTRAINT confirmation_names_an_organisation CHECK (
        organization_confirmed_at IS NULL
        OR (organization_id IS NOT NULL AND organization_confirmed_via IS NOT NULL)
    )
);

-- The employer's work list: claims naming this organisation, unconfirmed first.
CREATE INDEX idx_work_experiences_organization ON work_experiences (organization_id)
    WHERE organization_id IS NOT NULL;

CREATE TABLE education_entries (
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
    visibility       TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'connections', 'private')),
    ap_object        JSONB NOT NULL
);

CREATE TABLE skills (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'connections', 'private')),
    UNIQUE (actor_id, name)
);

-- ..... DOMAIN-VERIFIED LINKS .....

CREATE TABLE verified_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    verified_at  TIMESTAMPTZ,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT now(),
    visibility   TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'connections', 'private')),
    UNIQUE (actor_id, url)
);

-- ..... PUBLICATIONS .....

CREATE TABLE scholarly_articles (
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
    visibility     TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'connections', 'private')),
    ap_object      JSONB NOT NULL,
    UNIQUE (actor_id, doi)
);

-- ..... JOB POSTINGS .....

CREATE TABLE job_postings (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id                 UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id                    TEXT NOT NULL UNIQUE,
    title                    TEXT NOT NULL,
    description_md           TEXT NOT NULL,
    description_html         TEXT NOT NULL,
    location                 TEXT,
    remote                   BOOLEAN NOT NULL DEFAULT FALSE,
    -- BIGINT, not INTEGER. The amount is stored as entered, in the major
    -- unit of `currency`, and INTEGER caps at 2,147,483,647. In a currency
    -- with a small unit that ceiling is an ordinary senior salary rather
    -- than an absurd one: it is roughly USD 85,000 in VND and roughly USD
    -- 130,000 in IDR. A refused insert is the good outcome there, and a
    -- value quietly stored wrong is the bad one.
    salary_min               BIGINT,
    salary_max               BIGINT,
    currency                 TEXT,
    requirements             JSONB,
    published_at             TIMESTAMPTZ,
    expires_at               TIMESTAMPTZ,
    -- Moderation approval, which is not publication. published_at distinguishes
    -- draft from published; this distinguishes reviewed from not.
    --
    -- Nullable so "never reviewed" and "refused" stay distinguishable: a boolean
    -- collapses them, and the refusal is the one a moderator has to be able to
    -- find again. No DEFAULT: fail closed. A DEFAULT now() means any future
    -- INSERT that forgets the column silently publishes an unreviewed posting.
    approved_at              TIMESTAMPTZ,
    -- Who approved it. Mirrors reports.resolved_by: approving is a moderation
    -- decision, and an audit trail with no actor is half an audit trail.
    approved_by              UUID REFERENCES actors(id) ON DELETE SET NULL,
    integrity_proof_verified BOOLEAN, -- NULL = nothing checkable; TRUE = verified. FALSE is unreachable: ingestion discards a document whose proof fails
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The member who created it, where `actor_id` is the organisation
    -- that publishes it. Null when that actor posted as itself.
    created_by               UUID REFERENCES actors(id) ON DELETE SET NULL,
    -- Who, besides the owners and the creator, may read its job_applications.
    -- Defaults to neither: a recruiter's posting is not every recruiter's
    -- business until somebody says so.
    job_application_readers      TEXT NOT NULL DEFAULT 'creator_only'
                             CHECK (job_application_readers IN ('creator_only', 'all_recruiters', 'listed'))
);

-- Who acts for an organisation. It is an actor, not a person, so
-- "whoever published the posting" strands the pipeline when that person
-- goes on leave, and the workaround is a shared login.
CREATE TABLE organization_members (
    organization_id UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    member_id       UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('owner', 'recruiter')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, member_id)
);

CREATE INDEX idx_organization_members_member ON organization_members (member_id);

-- Recruiters named by `job_application_readers = 'listed'`. Owners and the
-- posting's creator do not appear here; they are always admitted.
CREATE TABLE job_posting_readers (
    job_posting_id UUID NOT NULL REFERENCES job_postings(id) ON DELETE CASCADE,
    member_id      UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_posting_id, member_id)
);


-- ..... POSTS .....

CREATE TABLE posts (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id                 UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id                    TEXT NOT NULL UNIQUE,
    post_type                TEXT NOT NULL DEFAULT 'note' CHECK (post_type IN ('note', 'article')),
    title                    TEXT,
    featured_image_url       TEXT,
    -- What a screen reader announces in place of the featured image.
    --
    -- Nullable, and the null is meaningful: it says the author was asked
    -- and declined, which renders as alt="" and marks the image
    -- decorative. A required field produces "image" and "photo", which
    -- is worse for a reader than announcing nothing at all.
    --
    -- Carried on the post rather than in media_attachments because the
    -- featured image is a URL the author supplies, which may point at
    -- another instance and so has no row of its own here.
    featured_image_alt       TEXT,
    content_md               TEXT, -- NULL for a remote post whose author sent no `source`; a local post always has one
    content_html             TEXT NOT NULL,
    sanitiser_version        SMALLINT NOT NULL DEFAULT 0, -- policy that produced content_html; 0 = not the ingestion sanitiser
    in_reply_to              TEXT,
    canonical_uri            TEXT,
    visibility               TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'unlisted', 'followers', 'connections')),
    integrity_proof_verified BOOLEAN, -- NULL = nothing checkable; TRUE = verified. FALSE is unreachable: ingestion discards a document whose proof fails
    -- Accepted on a relay's word alone, under the `trust-relay` policy.
    --
    -- A separate column from integrity_proof_verified because that one
    -- cannot express this: a directly delivered post with no proof is
    -- also NULL there, and it is not the same thing at all. Direct
    -- delivery is authenticated by an HTTP Signature bound to the actor;
    -- a relayed post under trust-relay is authenticated by the relay
    -- saying so, and the relay is not the author.
    --
    -- Read by the surfaces where that difference decides something:
    -- trending, search, and the badge on the post itself.
    relayed_unverified       BOOLEAN NOT NULL DEFAULT FALSE,
    -- Whether the images on this post are shown blurred until the reader
    -- asks to see them.
    --
    -- On the post, not on the attachment, which is where Mastodon puts it
    -- and what peers therefore send: a post is sensitive as a whole, and a
    -- reader deciding whether to look is deciding about the post.
    --
    -- Defaults to FALSE. A default that hid everything would train readers
    -- to click through without reading the warning, which is the failure
    -- mode the flag exists to avoid.
    sensitive                BOOLEAN NOT NULL DEFAULT FALSE,
    ap_object                JSONB NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A featured image is what alt text describes, so text without one
    -- is a description of nothing: either the write path dropped the
    -- URL, or the column was set on a post that never had an image.
    CONSTRAINT featured_alt_needs_an_image CHECK (
        featured_image_alt IS NULL
        OR featured_image_url IS NOT NULL
    )
);

CREATE INDEX idx_posts_actor ON posts (actor_id, created_at DESC);
CREATE INDEX idx_posts_canonical ON posts (canonical_uri) WHERE canonical_uri IS NOT NULL;
CREATE INDEX idx_posts_sanitiser_version ON posts (sanitiser_version) WHERE sanitiser_version = 0;

-- ..... MEDIA ATTACHMENTS .....

CREATE TABLE media_attachments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id   UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    post_id    UUID REFERENCES posts(id) ON DELETE CASCADE,
    -- A closed list. Content sniffing decides which of these a file is;
    -- this constraint is what stops a third value ever being stored.
    media_type TEXT NOT NULL CHECK (media_type IN ('image/jpeg', 'image/png')),
    -- The opaque object key. Random, and never derived from the actor,
    -- the filename or the content: a key anyone can guess or enumerate
    -- lets them walk the instance's users, and a content hash lets them
    -- test whether a given photograph is in use here.
    object_key TEXT NOT NULL UNIQUE,
    -- Where the bytes rest. Per row, not per instance: an operator who
    -- enables object storage later must not orphan everything written
    -- while storage was local.
    backend    TEXT NOT NULL DEFAULT 'local' CHECK (backend IN ('local', 's3')),
    -- What the object is for. `post_id` alone cannot distinguish an
    -- avatar from a header, and the read paths need one deterministic
    -- row per purpose.
    purpose    TEXT NOT NULL DEFAULT 'post' CHECK (purpose IN ('avatar', 'header', 'post')),
    url        TEXT NOT NULL,
    alt_text   TEXT,
    blurhash   TEXT,
    byte_size  BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- An avatar or header belongs to the actor and never to a post. A
    -- post attachment may be either: NULL while it is uploaded and not yet
    -- attached, and set once the post that claims it exists.
    CONSTRAINT media_purpose_matches_owner CHECK (
        purpose = 'post'
        OR post_id IS NULL
    )
);

-- The upload-and-then-attach window. An attachment uploaded and never
-- used leaves a row with no post, and this is what the sweep that
-- removes them reads.
CREATE INDEX idx_media_unattached
    ON media_attachments (created_at)
    WHERE purpose = 'post' AND post_id IS NULL;

-- One current avatar and one current header per actor. The upload path
-- replaces rather than accumulates, and this is what makes "replaces"
-- true rather than a convention the next writer can break.
CREATE UNIQUE INDEX idx_media_one_per_purpose
    ON media_attachments (actor_id, purpose)
    WHERE purpose IN ('avatar', 'header');

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

-- A mutual, accepted relationship, and the second axis of the social graph.
-- Independent of follows on purpose: a connection is granted by an act and
-- revoked by an act, so access it carries cannot drift with follow churn.
--
-- Directed columns for an undirected fact. requester_id is who invited, which
-- has to be kept because only they may withdraw before acceptance, but the
-- relationship itself has no direction once accepted. The unique index below
-- is on the ordered pair (least, greatest), so A inviting B and B inviting A
-- collide rather than producing two rows that disagree.
--
-- Local-only in v1: the AS2 Relationship travels, but nothing accepts one from
-- a peer yet, so both sides are local actors.
CREATE TABLE connections (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    addressee_id UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    ap_id        TEXT UNIQUE,
    -- NULL until accepted. A row is the invitation; the timestamp is the
    -- acceptance. Rejection and withdrawal both delete the row, because a
    -- refused invitation that lingers is a record of who asked, which is
    -- exactly what the addressee declined to enter into.
    accepted_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (requester_id <> addressee_id)
);

CREATE UNIQUE INDEX idx_connections_pair ON connections (
    least(requester_id, addressee_id),
    greatest(requester_id, addressee_id)
);

CREATE INDEX idx_connections_addressee_pending
    ON connections (addressee_id)
    WHERE accepted_at IS NULL;

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

CREATE TABLE job_applications (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    applicant_id      UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    -- Nullable, and SET NULL rather than CASCADE, because erasing the
    -- recruiter deletes their postings and must not take the
    -- applicants' records with them: the posting is the recruiter's
    -- content, the application is the applicant's.
    job_posting_id    UUID REFERENCES job_postings(id) ON DELETE SET NULL,
    -- Denormalised at insert, never at erasure. These are what keeps an
    -- application meaningful once the posting is gone ("I applied to X
    -- at Y on Z"), and NOT NULL so a future insert cannot forget them:
    -- copying at erasure would mean reading a row that is about to be
    -- deleted, which races anything else deleting it.
    posting_title     TEXT NOT NULL,
    posting_organization TEXT NOT NULL,
    applied_on        DATE NOT NULL DEFAULT CURRENT_DATE,
    ap_id             TEXT NOT NULL UNIQUE,
    cover_letter_md   TEXT,
    cover_letter_html TEXT,
    include_cv        BOOLEAN NOT NULL DEFAULT TRUE,
    cv_snapshot       BYTEA,
    status            TEXT NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'reviewed', 'shortlisted', 'rejected', 'withdrawn')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (applicant_id, job_posting_id)
);

-- The bearer capability an employer dereferences to read an application.
-- Minting is not built yet; the revocation path is, because what happens
-- to a grant when its applicant migrates is cheaper to settle before the
-- first grant exists than after.
CREATE TABLE job_application_grants (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_application_id          UUID NOT NULL REFERENCES job_applications(id) ON DELETE CASCADE,
    -- Hashed: a database read must not yield a working capability.
    token_hash              TEXT NOT NULL UNIQUE,
    -- Immutable after mint. A capability that can be re-pointed can be walked.
    audience_ap_id          TEXT NOT NULL,
    audience_origin         TEXT NOT NULL,
    -- Reporting only. Authorisation reads expires_at directly, or a lagging
    -- expiry job could extend a grant.
    state                   TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked', 'expired')),
    expires_at              TIMESTAMPTZ NOT NULL,
    document_uses_remaining INTEGER NOT NULL,
    cv_uses_remaining       INTEGER NOT NULL,
    revoked_at              TIMESTAMPTZ,
    revoked_reason          TEXT CHECK (revoked_reason IN ('applicant_withdrew', 'applicant_revoked', 'rejected_by_employer', 'posting_removed', 'posting_fraud_takedown', 'account_deleted', 'account_migrated', 'superseded', 'expired')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A time without a reason is a revocation nobody can explain.
    CONSTRAINT revocation_is_complete CHECK (
        (revoked_at IS NULL AND revoked_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)
    )
);

CREATE INDEX idx_job_application_grants ON job_application_grants (job_application_id);

-- Every disclosure of an application, and the applicant's own record of
-- it. A moderator read is a disclosure like any other, so it lands here
-- rather than in a log the applicant never sees. `grant_id` is null for a
-- local read; an employer's dereference carries one once minting exists.
CREATE TABLE job_application_accesses (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_application_id UUID NOT NULL REFERENCES job_applications(id) ON DELETE CASCADE,
    grant_id       UUID REFERENCES job_application_grants(id) ON DELETE CASCADE,
    reader_id      UUID REFERENCES actors(id) ON DELETE SET NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('grant_dereference', 'moderator_review')),
    outcome        TEXT NOT NULL CHECK (outcome IN ('disclosed', 'denied')),
    -- Required for a moderator review, and shown to the applicant.
    reason         TEXT,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT moderator_review_states_a_reason CHECK (
        kind <> 'moderator_review'
        OR (reader_id IS NOT NULL AND reason IS NOT NULL AND length(btrim(reason)) > 0)
    )
);

CREATE INDEX idx_job_application_accesses ON job_application_accesses (job_application_id);

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
    group_id         UUID REFERENCES actors(id) ON DELETE SET NULL,
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
    target_type TEXT NOT NULL CHECK (target_type IN ('job_posting', 'profile', 'article', 'event')),
    target_id   UUID NOT NULL,
    metric      TEXT NOT NULL CHECK (metric IN ('view', 'application', 'rsvp', 'download')),
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
    visibility   TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'followers', 'connections', 'private')),
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
    created_by  UUID REFERENCES actors(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... USER REPORTS .....

-- One moderation spine, for every kind of report.
--
-- Chat reports were a second table with the same columns under different
-- names. Two spines meant every duty owed to a reporter was owed twice and
-- implemented once: a statement of reasons, a complaints route, a retention
-- rule and a point of contact each had to be built, and then built again
-- somewhere easy to forget. What a report is about is a column here, not a
-- table of its own.
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id     UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    target_actor_id UUID REFERENCES actors(id) ON DELETE CASCADE,
    target_post_id  UUID REFERENCES posts(id) ON DELETE CASCADE,
    -- A Chatmail address, which is not an actor here and often not an actor
    -- anywhere: the sender may be a stranger on another server, which is
    -- exactly the case worth being able to report.
    target_chat_addr TEXT,
    -- The message complained of, quoted by the reporter as evidence. This
    -- is attacker-supplied text on its way to a moderator's screen, so it
    -- is bounded in the schema rather than trusted to a caller.
    reported_message    TEXT,
    reported_message_at TIMESTAMPTZ,
    reason          TEXT NOT NULL CHECK (reason IN ('spam', 'harassment', 'illegal', 'impersonation', 'other')),
    comment         TEXT,
    forwarded       BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed')),
    resolved_by     UUID REFERENCES actors(id) ON DELETE SET NULL,
    resolution_note TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ,
    -- A report about nothing cannot be actioned. Deliberately not "exactly
    -- one": reporting a post also names its author, and both columns being
    -- set is that report, not a malformed one.
    CONSTRAINT report_names_a_target CHECK (
        target_actor_id IS NOT NULL
        OR target_post_id IS NOT NULL
        OR target_chat_addr IS NOT NULL
    ),
    -- Quoted evidence belongs to the chat case. Allowing it everywhere
    -- would give a moderator two places to look for the same thing.
    CONSTRAINT quoted_message_belongs_to_a_chat_report CHECK (
        (reported_message IS NULL AND reported_message_at IS NULL)
        OR target_chat_addr IS NOT NULL
    ),
    -- 8 KiB is far more than any message a person quotes and far less than
    -- what an attacker would send if nothing said otherwise.
    CONSTRAINT quoted_message_is_bounded CHECK (
        reported_message IS NULL OR length(reported_message) <= 8192
    )
);

-- The moderation queue's work list: open reports, oldest first.
CREATE INDEX idx_reports_open ON reports (created_at) WHERE status = 'open';

-- ..... CHATMAIL BLOCKS .....

-- Chatmail address block list (application-level, enforced by the
-- noombat-chat proxy before relaying messages to the browser).
-- Chatmail work this instance owes the sidecar, and could not complete.
--
-- Erasure is the case that matters: a maildir left behind after an
-- account is erased is the erasure failing silently, and the sidecar is
-- a separate process that can be down while this one is up. So the
-- intent is written here first and drained by a worker with backoff,
-- rather than attempted once and lost.
--
-- This is also the outage record. An administrator asking "is Chatmail
-- deletion working" reads this table, which is why a failure keeps its
-- error text rather than only a state.
CREATE TABLE chatmail_operations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SET NULL rather than CASCADE: the actor row is hard-deleted at the
    -- end of the retention window, and the maildir may still be owed
    -- deletion after it. The address below is what the work needs.
    actor_id        UUID REFERENCES actors(id) ON DELETE SET NULL,
    address         TEXT NOT NULL,
    operation       TEXT NOT NULL CHECK (operation IN ('delete_account')),
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'succeeded', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    -- Kept on a failure, because "it is not working" without "why" is
    -- not an outage record.
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    -- One outstanding operation per address and kind. A second erasure
    -- of the same address is the same work, not more of it.
    UNIQUE (address, operation)
);

CREATE INDEX idx_chatmail_operations_due
    ON chatmail_operations (next_attempt_at)
    WHERE state = 'pending';

-- Search-index work this instance owes, and could not complete.
--
-- Removals are the case that matters, and the reason this table exists.
-- A search document outlives the row it was built from: erasure deletes
-- the post and the index keeps the full text, so a removal that fails
-- silently is an erasure that leaves the writing searchable by its
-- contents. Fire-and-forget with a log line cannot express that, because
-- nobody reads a log line for something that already returned success.
--
-- Additions are queued too, but only for content this instance did not
-- author. A local post that fails to index is missing from search and
-- its author will notice; a remote post that fails to index is missing
-- from search and nobody will.
--
-- This is also the outage record: an administrator asking "is anything
-- stuck out of the index" reads this table, which is why a failure keeps
-- its error text as well as its state.
CREATE TABLE search_index_operations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The Meilisearch index, and the document id within it. Deliberately
    -- text rather than a foreign key: the whole point of a removal is
    -- that it outlives the row, so it cannot reference one.
    index_name      TEXT NOT NULL CHECK (index_name IN ('profiles', 'posts', 'jobs')),
    document_id     TEXT NOT NULL,
    operation       TEXT NOT NULL CHECK (operation IN ('upsert', 'remove')),
    -- The document body for an upsert, NULL for a removal.
    document        JSONB,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'succeeded', 'failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    -- One outstanding operation per document. A second removal of the
    -- same document is the same work; an upsert superseding a pending
    -- upsert is the newer body, and the writer replaces it.
    UNIQUE (index_name, document_id)
);

CREATE INDEX idx_search_index_operations_due
    ON search_index_operations (next_attempt_at)
    WHERE state = 'pending';

CREATE TABLE chatmail_blocks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    blocked_addr TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (actor_id, blocked_addr)
);

-- ..... RELAY SUBSCRIPTIONS .....

-- Tracks ActivityPub relays to which this instance is subscribed.
-- A relay receives all public activities and rebroadcasts them to
-- subscribers, widening content discovery.
CREATE TABLE relay_subscriptions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inbox_url           TEXT NOT NULL UNIQUE,
    status              TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    verification_policy TEXT CHECK (verification_policy IN ('verify', 'verify-or-fetch', 'trust-relay')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... TOMBSTONED ACTORS .....

-- When a remote actor returns 410 Gone, the federation service records
-- the tombstone so that future resolution attempts short-circuit
-- without an HTTP round-trip.
--
-- Two kinds of row live here and they have opposite lifetimes.
--
-- A row written for a REMOTE 410 (by resolve_actor or deliver_one) may be
-- pruned periodically, so that an actor who re-creates their account on the
-- same URI becomes resolvable again.
--
-- A row written by a LOCAL erasure (by tombstone_actor) is permanent. It is
-- the sole record that the ap_id ever existed, and it is what keeps the
-- username locked: freeing it would let a stranger re-register the name and
-- inherit the erased user's mentions and inbound follows. A pruner written
-- from the first paragraph alone would delete these, so it must scope itself
-- to the remote rows.
CREATE TABLE tombstoned_actors (
    ap_id         TEXT PRIMARY KEY,
    tombstoned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ..... INSTANCE SETTINGS .....

-- Single-row configuration table for instance-wide settings
-- managed via the admin UI.
CREATE TABLE instance_settings (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    registration_mode        TEXT NOT NULL DEFAULT 'open' CHECK (registration_mode IN ('open', 'approval', 'closed')),
    default_job_approval     BOOLEAN NOT NULL DEFAULT TRUE,
    analytics_retention_days INTEGER NOT NULL DEFAULT 90,
    -- Whether posts from other instances enter this instance's search
    -- index and trending counts.
    --
    -- Off by default, and the default is the decision. Indexing a peer's
    -- content makes this instance a second publisher of it: the index
    -- outlives the row, so it takes on the duty to withdraw a document
    -- when the author's instance says to, and it gives a relay a way to
    -- put text in front of every local reader. An operator who wants the
    -- wider corpus can have it; nobody gets it by not choosing.
    --
    -- Independently of this, a remote author's own `indexable` is
    -- honoured: turning this on does not index anybody who said no.
    index_remote_posts       BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed a single default row.
INSERT INTO instance_settings (id) VALUES (gen_random_uuid());

-- ..... ANNOUNCEMENTS .....

-- Instance-wide banner announcements displayed to all local users.
CREATE TABLE announcements (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content     TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID REFERENCES actors(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
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

CREATE INDEX idx_work_experiences_actor ON work_experiences (actor_id);
CREATE INDEX idx_education_entries_actor ON education_entries (actor_id);
CREATE INDEX idx_skills_actor ON skills (actor_id);
CREATE INDEX idx_scholarly_articles_actor ON scholarly_articles (actor_id);
CREATE INDEX idx_verified_links_actor ON verified_links (actor_id);
CREATE INDEX idx_custom_sections_actor ON custom_profile_sections (actor_id);
CREATE INDEX idx_media_attachments_actor ON media_attachments (actor_id);
CREATE INDEX idx_media_attachments_post ON media_attachments (post_id);
CREATE INDEX idx_job_postings_actor ON job_postings (actor_id);
-- The approval queue's work list, oldest first.
CREATE INDEX idx_job_postings_pending_approval ON job_postings (created_at) WHERE approved_at IS NULL;
CREATE INDEX idx_job_applications_posting ON job_applications (job_posting_id);
CREATE INDEX idx_group_memberships_group ON group_memberships (group_id);
CREATE INDEX idx_event_rsvps_event ON event_rsvps (event_id);
CREATE INDEX idx_events_group ON events (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX idx_reports_reporter ON reports (reporter_id);
CREATE INDEX idx_reports_target_actor ON reports (target_actor_id) WHERE target_actor_id IS NOT NULL;
CREATE INDEX idx_reports_target_post ON reports (target_post_id) WHERE target_post_id IS NOT NULL;
-- The chat-filtered view of the queue, which is the same work list narrowed
-- to the reports that carry an address.
CREATE INDEX idx_reports_open_chat ON reports (created_at)
    WHERE status = 'open' AND target_chat_addr IS NOT NULL;

-- ..... UPDATED_AT TRIGGER .....

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_actors_updated_at BEFORE UPDATE ON actors FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_job_applications_updated_at BEFORE UPDATE ON job_applications FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_relay_subscriptions_updated_at BEFORE UPDATE ON relay_subscriptions FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_instance_settings_updated_at BEFORE UPDATE ON instance_settings FOR EACH ROW EXECUTE FUNCTION set_updated_at();
