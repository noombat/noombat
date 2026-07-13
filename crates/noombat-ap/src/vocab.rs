// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Noombat-specific ActivityPub vocabulary extension constants.

/// Custom object type: a structured job posting.
pub const JOB_LISTING: &str = "noombat:JobListing";
/// Custom object type: a work-experience entry.
pub const EXPERIENCE: &str = "noombat:Experience";
/// Custom object type: an educational-history entry.
pub const EDUCATION: &str = "noombat:Education";
/// Custom object type: a declared professional skill.
pub const SKILL: &str = "noombat:Skill";
/// Custom object type: a scholarly publication linked via DOI.
pub const PUBLICATION: &str = "noombat:Publication";
/// Custom object type: a job application (private, C2S only).
pub const APPLICATION: &str = "noombat:Application";
/// Extension namespace for Event-specific fields (virtual URL, organiser,
/// RSVP status) not covered by the base ActivityStreams `Event` type.
pub const EVENT_EXTENSIONS: &str = "noombat:EventExtensions";
/// Custom property: canonical URI for cross-post de-duplication.
pub const CANONICAL_URI: &str = "noombat:canonicalUri";
