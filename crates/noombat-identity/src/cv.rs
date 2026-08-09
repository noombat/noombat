// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! CV generation: assembles Typst source from profile data and compiles
//! to PDF via the `typst` CLI.

use std::path::Path;

use noombat_core::error::{NoombatError, Result};
use noombat_core::privacy::SectionVisibility;
use sqlx::PgPool;
use uuid::Uuid;

use crate::profile;

/// Generate a CV as a PDF byte vector for the given actor.
///
/// # Arguments
///
/// * `pool`: Database connection pool.
/// * `actor_id`: The actor whose CV is being generated.
/// * `max_vis`: Maximum section visibility to include.
/// * `template_dir`: Path to the directory containing `.typ` templates.
/// * `template`: Template filename stem (e.g. `"default"`).
/// * `citation_style`: Citation format for publications (e.g. `"apa"`, `"ieee"`, or `"vancouver"`).
///
/// # Errors
///
/// Returns [`NoombatError::Internal`] if template loading, Typst source
/// assembly, or Typst compilation fails.
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
            "  (title: \"{}\", company: \"{}\", dates: \"{dates}\", description: {desc}),\n",
            escape_typst_string(&exp.title),
            escape_typst_string(&exp.company),
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

/// Compile a Typst source string to PDF bytes using the `typst` CLI.
async fn compile_typst_source(source: &str) -> Result<Vec<u8>> {
    let tmp_dir = tempfile::tempdir()
        .map_err(|e| NoombatError::Internal(format!("failed to create temp dir: {e}")))?;
    let input_path = tmp_dir.path().join("cv.typ");
    let output_path = tmp_dir.path().join("cv.pdf");

    tokio::fs::write(&input_path, source)
        .await
        .map_err(|e| NoombatError::Internal(format!("failed to write temp Typst source: {e}")))?;

    let output = tokio::process::Command::new("typst")
        .arg("compile")
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .await
        .map_err(|e| {
            NoombatError::Internal(format!("failed to invoke typst (is it installed?): {e}"))
        })?;

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

    /// Backslash and quote are escaped. A hash is not.
    ///
    /// This assertion used to require `C#` to become `C\#`, which is
    /// what the function did and what typst does not want: `\#` is not
    /// a string escape, so the compiler keeps both characters and the
    /// PDF read `C\#`. Confirmed against typst 0.15, where
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
