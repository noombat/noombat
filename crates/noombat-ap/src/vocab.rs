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
