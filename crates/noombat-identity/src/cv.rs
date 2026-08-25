// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! CV generation: assembles Typst source from profile data and compiles
//! to PDF via the `typst` CLI.

use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use noombat_core::error::{NoombatError, Result};
use noombat_core::privacy::SectionVisibility;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::warn;
use uuid::Uuid;

use crate::profile;

/// Generate a CV as a PDF byte vector for the given actor.
///
/// `max_vis` caps which sections are included. `template` is a filename
/// stem within `template_dir`, e.g. `"default"`, and `citation_style` is
/// one of `"apa"`, `"ieee"` or `"vancouver"`.
pub async fn generate_cv_pdf(
    pool: &PgPool,
    actor_id: Uuid,
    max_vis: &SectionVisibility,
    template_dir: &Path,
    template: &str,
    citation_style: &str,
) -> Result<Vec<u8>> {
    // ..... Fetch profile data .....
    let actor = crate::repo::find_by_id(pool, actor_id).await?;

    let experiences = profile::list_experiences(pool, actor_id, max_vis).await?;
    let educations = profile::list_educations(pool, actor_id, max_vis).await?;
    let skills = profile::list_skills(
        pool,
        actor_id,
        matches!(max_vis, SectionVisibility::Private),
    )
    .await?;
    let publications = profile::list_publications(pool, actor_id, max_vis).await?;
    let links = crate::verification::list_links(pool, actor_id).await?;

    // ..... Load template .....
    let template_path = template_dir.join(format!("{template}.typ"));
    let template_src = tokio::fs::read_to_string(&template_path)
        .await
        .map_err(|e| {
            NoombatError::Internal(format!(
                "failed to read template {}: {e}",
                template_path.display()
            ))
        })?;

    // ..... Assemble Typst source .....
    let mut src = String::with_capacity(4096);

    // The prelude first, because every binding below is an expression
    // built from its functions. It lives here rather than in a template
    // file so that it precedes those bindings and covers every
    // template, including any added later.
    src.push_str(noombat_markup::TYPST_PRELUDE);
    src.push('\n');

    // Inject all #let bindings expected by the template. The template
    // file contains no #let declarations of its own (doing so would
    // shadow these values).
    src.push_str(&format!(
        "#let name = \"{}\"\n",
        escape_typst_string(actor.display_name.as_deref().unwrap_or(&actor.username))
    ));

    // Professional headline (injected as Typst `title`).
    let headline = actor.headline.as_deref().unwrap_or("");
    src.push_str(&format!(
        "#let title = \"{}\"\n",
        escape_typst_string(headline)
    ));

    // Summary (Markdown to Typst). Inject `none` when absent so the
    // template guard `#if summary != none` works correctly (an empty
    // content block `[]` is truthy and not equal to `""` or `none`).
    match actor.summary_md.as_deref() {
        Some(md) if !md.trim().is_empty() => {
            // Bound to the expression directly. Wrapping it in `[...]`
            // would put it back in markup context, which is the whole
            // thing this avoids.
            let typst = noombat_markup::md_to_typst_expr(md);
            src.push_str(&format!("#let summary = {typst}\n"));
        }
        _ => {
            src.push_str("#let summary = none\n");
        }
    }

    // ORCID iD (empty string when absent).
    match actor.orcid.as_deref() {
        Some(orcid) => src.push_str(&format!(
            "#let orcid = \"{}\"\n",
            escape_typst_string(orcid)
        )),
        None => src.push_str("#let orcid = \"\"\n"),
    }

    // Experiences.
    src.push_str("#let experiences = (\n");
    for exp in &experiences {
        let dates = format_date_range(exp.start_date, exp.end_date);
        let desc = exp
            .description_md
            .as_deref()
            .map(noombat_markup::md_to_typst_expr)
            .unwrap_or_else(|| "none".to_owned());
        src.push_str(&format!(
            "  (title: \"{}\", organization: \"{}\", dates: \"{dates}\", description: {desc}),\n",
            escape_typst_string(&exp.title),
            escape_typst_string(&exp.organization),
        ));
    }
    src.push_str(")\n");

    // Educations.
    src.push_str("#let educations = (\n");
    for edu in &educations {
        let dates = format_date_range(edu.start_date, edu.end_date);
        let desc = edu
            .description_md
            .as_deref()
            .map(noombat_markup::md_to_typst_expr)
            .unwrap_or_else(|| "none".to_owned());
        let degree = edu.degree.as_deref().unwrap_or("");
        let field = edu.field_of_study.as_deref().unwrap_or("");
        src.push_str(&format!(
            "  (institution: \"{}\", degree: \"{}\", field: \"{}\", dates: \"{dates}\", description: {desc}),\n",
            escape_typst_string(&edu.institution),
            escape_typst_string(degree),
            escape_typst_string(field),
        ));
    }
    src.push_str(")\n");

    // Skills.
    src.push_str("#let skills = (\n");
    for skill in &skills {
        src.push_str(&format!("  \"{}\",\n", escape_typst_string(&skill.name)));
    }
    src.push_str(")\n");

    // Publications (formatted per the requested citation style).
    src.push_str(&format!(
        "#let citation_style = \"{}\"\n",
        escape_typst_string(citation_style)
    ));
    src.push_str("#let publications = (\n");
    for pub_ in &publications {
        let authors_str = if let Some(arr) = pub_.authors.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            String::new()
        };
        let date = pub_
            .published_date
            .map(|d| d.format("%Y").to_string())
            .unwrap_or_default();
        let formatted = format_citation(
            citation_style,
            &authors_str,
            &pub_.title,
            pub_.journal.as_deref().unwrap_or(""),
            &date,
            &pub_.doi,
        );
        src.push_str(&format!(
            "  (formatted: \"{}\", doi: \"{}\"),\n",
            escape_typst_string(&formatted),
            escape_typst_string(&pub_.doi),
        ));
    }
    src.push_str(")\n");

    // Verified links.
    src.push_str("#let verified_links = (\n");
    for link in &links {
        if link.verified_at.is_some() {
            src.push_str(&format!("  \"{}\",\n", escape_typst_string(&link.url)));
        }
    }
    src.push_str(")\n\n");

    // Append the template body (which references the variables above).
    src.push_str(&template_src);

    // ..... Compile via Typst CLI .....
    compile_typst_source(&src).await
}

/// Limits applied to every Typst compilation.
///
/// Set once at startup from configuration. Compiling is the most
/// expensive thing a request can ask this process to do, and until
/// these existed a single profile could occupy a core indefinitely.
#[derive(Debug, Clone, Copy)]
pub struct TypstLimits {
    /// Compilations allowed to run at once, process-wide.
    pub max_concurrent: usize,
    /// How long one compilation may run before its process is killed.
    pub timeout: Duration,
    /// How long a request waits for a permit before giving up.
    pub queue_timeout: Duration,
}

impl Default for TypstLimits {
    fn default() -> Self {
        Self {
            // Compiling is CPU-bound, so the ceiling is about leaving
            // the runtime somewhere to run. Four is the same figure the
            // federation origin-fetch pool uses.
            max_concurrent: 4,
            timeout: Duration::from_secs(10),
            queue_timeout: Duration::from_secs(5),
        }
    }
}

static LIMITS: OnceLock<TypstLimits> = OnceLock::new();
static PERMITS: OnceLock<Semaphore> = OnceLock::new();

/// Install the process-global Typst limits.
///
/// Called once from `main`. Callers that never call it (tests, and any
/// binary that only generates a CV incidentally) get [`TypstLimits::default`],
/// which is bounded rather than unbounded: forgetting to configure this
/// must not be the same as switching it off.
pub fn init_limits(limits: TypstLimits) {
    if LIMITS.set(limits).is_err() {
        warn!("Typst limits already initialised; ignoring the second call");
    }
}

fn limits() -> TypstLimits {
    *LIMITS.get_or_init(TypstLimits::default)
}

fn permits() -> &'static Semaphore {
    PERMITS.get_or_init(|| Semaphore::new(limits().max_concurrent))
}

/// Compile a Typst source string to PDF bytes using the `typst` CLI.
///
/// Four things bound this, and the first two are the ones that matter:
///
/// - A **permit** from a process-wide semaphore, so the number of
///   concurrent compilations is capped no matter how many requests
///   arrive. Waiting for one is itself bounded, because an unbounded
///   queue is the same exhaustion one layer down.
/// - A **timeout**, after which the child is killed. This works because
///   Typst is a separate process: killing it genuinely reclaims the CPU,
///   unlike an in-process interpreter, which cannot be interrupted from
///   the outside.
/// - `--root` pinned to the temporary directory. Typst already resolves
///   paths relative to the input's parent and refuses `..`, so this is a
///   guard against that default changing or against a future caller
///   compiling somewhere less isolated, not a live hole.
/// - Package paths pointed inside the tempdir. This does **not** stop a
///   fetch: `@preview` still reaches `packages.typst.org` with these set,
///   confirmed against typst 0.15. What it buys is that anything fetched
///   lands in a directory that is deleted with the request instead of
///   accumulating in a shared cache. The reason no fetch happens today is
///   that user content cannot emit `#import` at all since the markup
///   emitter switched to string literals; only an operator's own template
///   can. Closing the network path properly needs process isolation this
///   does not have.
///
/// `--ignore-system-fonts` needs no accompanying `--font-path`: Typst
/// embeds Libertinus Serif, which is what the default template asks for,
/// and a compile with the flag and no font path succeeds.
async fn compile_typst_source(source: &str) -> Result<Vec<u8>> {
    let limits = limits();

    let _permit = tokio::time::timeout(limits.queue_timeout, permits().acquire())
        .await
        .map_err(|_| {
            warn!("Typst compilation queue is saturated; shedding the request");
            NoombatError::ServiceUnavailable("CV generation is busy; try again shortly".into())
        })?
        .map_err(|e| NoombatError::Internal(format!("Typst permit pool closed: {e}")))?;

    let tmp_dir = tempfile::tempdir()
        .map_err(|e| NoombatError::Internal(format!("failed to create temp dir: {e}")))?;
    let input_path = tmp_dir.path().join("cv.typ");
    let output_path = tmp_dir.path().join("cv.pdf");
    // Empty and inside the tempdir, so package resolution finds nothing
    // locally and is not permitted to look anywhere else.
    let package_dir = tmp_dir.path().join("packages");
    tokio::fs::create_dir(&package_dir)
        .await
        .map_err(|e| NoombatError::Internal(format!("failed to create package dir: {e}")))?;

    tokio::fs::write(&input_path, source)
        .await
        .map_err(|e| NoombatError::Internal(format!("failed to write temp Typst source: {e}")))?;

    let child = tokio::process::Command::new("typst")
        .arg("compile")
        .arg("--root")
        .arg(tmp_dir.path())
        // System fonts vary by host, which makes output unreproducible
        // and leaks something about the machine into the PDF.
        .arg("--ignore-system-fonts")
        .arg(&input_path)
        .arg(&output_path)
        .env("TYPST_PACKAGE_PATH", &package_dir)
        .env("TYPST_PACKAGE_CACHE_PATH", &package_dir)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            NoombatError::Internal(format!("failed to invoke typst (is it installed?): {e}"))
        })?;

    let output = match tokio::time::timeout(limits.timeout, child.wait_with_output()).await {
        Ok(result) => {
            result.map_err(|e| NoombatError::Internal(format!("typst process failed: {e}")))?
        }
        Err(_) => {
            // `kill_on_drop` reaps the child as `child` goes out of
            // scope here. Reported as unavailable rather than as an
            // internal error: the document is the cause, and the
            // operator's log line is the actionable part.
            warn!(
                timeout_secs = limits.timeout.as_secs(),
                "Typst compilation exceeded its deadline and was killed"
            );
            return Err(NoombatError::ServiceUnavailable(
                "CV generation timed out".into(),
            ));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NoombatError::Internal(format!(
            "typst compilation failed: {stderr}"
        )));
    }

    tokio::fs::read(&output_path)
        .await
        .map_err(|e| NoombatError::Internal(format!("failed to read compiled PDF: {e}")))
}

/// Escape a string for embedding in a Typst string literal.
fn escape_typst_string(s: &str) -> String {
    // Backslash and quote only. `\#` is *not* a Typst string escape:
    // the compiler keeps both characters, so escaping a hash here put a
    // stray backslash in front of every one, and a headline of "C#"
    // typeset as "C\#". Verified against typst 0.15:
    // `assert.eq("a\#b".len(), 4)` passes.
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Format a date range as `"Jan 2020 - Dec 2023"` or `"Jan 2020 - present"`.
fn format_date_range(start: chrono::NaiveDate, end: Option<chrono::NaiveDate>) -> String {
    let start_str = start.format("%b %Y").to_string();
    match end {
        Some(e) => format!("{start_str} - {}", e.format("%b %Y")),
        None => format!("{start_str} - present"),
    }
}

/// Format a single publication citation in the requested style.
///
/// Supported styles: `apa` (default), `ieee`, `vancouver`.
fn format_citation(
    style: &str,
    authors: &str,
    title: &str,
    journal: &str,
    year: &str,
    doi: &str,
) -> String {
    match style {
        "ieee" => {
            // IEEE: A. Author, "Title," Journal, year. doi:DOI.
            let mut s = format!("{authors}, \"{title},\"");
            if !journal.is_empty() {
                s.push_str(&format!(" {journal},"));
            }
            if !year.is_empty() {
                s.push_str(&format!(" {year}."));
            }
            if !doi.is_empty() {
                s.push_str(&format!(" doi:{doi}."));
            }
            s
        }
        "vancouver" => {
            // Vancouver: Author. Title. Journal. Year. doi:DOI.
            let mut s = format!("{authors}. {title}.");
            if !journal.is_empty() {
                s.push_str(&format!(" {journal}."));
            }
            if !year.is_empty() {
                s.push_str(&format!(" {year}."));
            }
            if !doi.is_empty() {
                s.push_str(&format!(" doi:{doi}."));
            }
            s
        }
        _ => {
            // APA (default): Author (Year). Title. Journal. doi:DOI
            let year_part = if year.is_empty() {
                "(n.d.)".to_owned()
            } else {
                format!("({year})")
            };
            let mut s = format!("{authors} {year_part}. {title}.");
            if !journal.is_empty() {
                s.push_str(&format!(" {journal}."));
            }
            if !doi.is_empty() {
                s.push_str(&format!(" https://doi.org/{doi}"));
            }
            s
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defaults are bounded, because forgetting to configure the limits
    /// must not be the same as switching them off.
    #[test]
    fn default_limits_are_finite() {
        let d = TypstLimits::default();
        assert!(d.max_concurrent > 0 && d.max_concurrent <= 16);
        assert!(d.timeout > Duration::ZERO);
        assert!(d.queue_timeout > Duration::ZERO);
    }

    /// A compilation that outlives the deadline is killed, and the
    /// process really does go away.
    ///
    /// Ignored by default because it needs the `typst` binary, which is
    /// absent from CI and from the build image;
    /// `scripts/check-typst-injection.sh` is where the compiler-backed
    /// checks run. Kept here rather than there because it is about this
    /// function's behaviour, not about generated markup.
    ///
    /// The assertion is deliberately not "the call returned quickly". A
    /// timeout that abandons its work would satisfy that while leaving the
    /// compiler running, so this counts `typst` processes afterwards.
    #[ignore = "requires the typst binary; run with --include-ignored"]
    #[tokio::test]
    async fn a_slow_compile_is_killed_not_merely_abandoned() {
        // `--include-ignored` runs this everywhere, including the
        // integration job and the build image, neither of which has
        // typst. Skipping is the only alternative to failing there, so
        // it is skipped loudly and the `typst-injection` CI job installs
        // the binary and runs it for real. If that job is ever dropped,
        // this test stops running anywhere and nothing will say so.
        if std::process::Command::new("typst")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!(
                "SKIPPED a_slow_compile_is_killed_not_merely_abandoned: no typst on PATH. \
                 The typst-injection CI job is where this runs."
            );
            return;
        }

        init_limits(TypstLimits {
            max_concurrent: 2,
            timeout: Duration::from_secs(1),
            queue_timeout: Duration::from_secs(1),
        });

        // Sixty thousand paragraphs. Nothing here is malformed or
        // hostile, which is the point: this is the pathological but
        // entirely legitimate document that the old code would have
        // compiled for as long as it took. Measured at over 20 seconds
        // against typst 0.15, against a deadline of one.
        let source = "#for i in range(0, 60000) [Lorem ipsum dolor sit amet #i \\ ]\n";

        let started = std::time::Instant::now();
        let result = compile_typst_source(source).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(NoombatError::ServiceUnavailable(_))),
            "expected a timeout, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the deadline did not fire: {elapsed:?}"
        );

        // The child is reaped as the `Child` drops, so give the kill a
        // moment and then confirm nothing is left running.
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Panics rather than defaulting when pgrep is missing: a check
        // that silently reports "nothing running" because it could not
        // look is worse than no check.
        let probe = std::process::Command::new("pgrep")
            .args(["-c", "-x", "typst"])
            .output()
            .expect("pgrep is needed to tell a kill from an abandonment");
        let survivors = String::from_utf8_lossy(&probe.stdout).trim().to_owned();
        assert_eq!(
            survivors, "0",
            "a killed compilation left {survivors} typst process(es) running"
        );
    }

    /// Backslash and quote are escaped. A hash is not.
    ///
    /// The tempting assertion, that `C#` becomes `C\#`, is wrong: `\#`
    /// is not a string escape, so the compiler keeps both characters
    /// and the PDF reads `C\#`. Confirmed against typst 0.15, where
    /// `assert.eq("a\#b".len(), 4)` passes and `"C\#".len()` is 3.
    #[test]
    fn escape_special_chars() {
        assert_eq!(escape_typst_string(r#"C# "dev""#), r#"C# \"dev\""#);
        assert_eq!(escape_typst_string(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn date_range_with_end() {
        let start = chrono::NaiveDate::from_ymd_opt(2020, 1, 15).unwrap();
        let end = chrono::NaiveDate::from_ymd_opt(2023, 12, 1);
        assert_eq!(format_date_range(start, end), "Jan 2020 - Dec 2023");
    }

    #[test]
    fn date_range_present() {
        let start = chrono::NaiveDate::from_ymd_opt(2022, 6, 1).unwrap();
        assert_eq!(format_date_range(start, None), "Jun 2022 - present");
    }
}
