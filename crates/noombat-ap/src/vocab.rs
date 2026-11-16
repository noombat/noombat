// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Noombat-specific ActivityPub vocabulary extension constants.

/// Custom object type: a structured job posting.
pub const JOB_POSTING: &str = "noombat:JobPosting";
/// Custom object type: a work-experience entry.
pub const WORK_EXPERIENCE: &str = "noombat:WorkExperience";
/// Custom object type: an educational-history entry.
pub const EDUCATION_ENTRY: &str = "noombat:EducationEntry";
/// Custom object type: a declared professional skill.
pub const SKILL: &str = "noombat:Skill";
/// Custom object type: a scholarly publication linked via DOI.
pub const SCHOLARLY_ARTICLE: &str = "noombat:ScholarlyArticle";
/// Custom object type: a job application (private, C2S only).
pub const JOB_APPLICATION: &str = "noombat:JobApplication";
/// Extension namespace for Event-specific fields (virtual URL, organiser,
/// RSVP status) not covered by the base ActivityStreams `Event` type.
pub const EVENT_EXTENSIONS: &str = "noombat:eventExtensions";
/// Custom property: canonical URI for cross-post de-duplication.
pub const CANONICAL_URI: &str = "noombat:canonicalUri";
/// Custom property: profile data TTL hint (seconds) for remote caching.
pub const TTL: &str = "noombat:ttl";
/// Custom property: a member's OpenPGP public key for chat, published
/// beside their chat address so that others can write to them first.
pub const CHAT_KEY: &str = "noombat:chatKey";
/// Within [`CHAT_KEY`]: the chat address the key belongs to.
pub const CHAT_KEY_ADDRESS: &str = "noombat:address";
/// Within [`CHAT_KEY`]: the binary transferable public key, in base64.
pub const CHAT_KEY_DATA: &str = "noombat:keyData";
