// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! The built frontend's files, by entry name.
//!
//! Every file under `/assets` is named by a hash of its content and cached
//! for a year, so a page must name the current build's file. Vite's
//! manifest maps each entry (`main`, `htmx`, `chat` and so on) to its file
//! and to the stylesheets it and the chunks it imports need, which the page
//! links itself: a script entry does not load them. The server checks the
//! manifest at startup and reads it again whenever a build replaces it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{LazyLock, PoisonError, RwLock};
use std::time::SystemTime;

use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use serde::Deserialize;

/// The entries Vite builds (`input` in `frontend/vite.config.ts`), each of
/// which a page may name.
pub const ENTRIES: [&str; 8] = [
    "main",
    "htmx",
    "auth",
    "editor",
    "chat",
    "chat-cred",
    "compose",
    "upgrade",
];

/// A year, never revalidated: a changed file gets a new name.
const IMMUTABLE: &str = "public, max-age=31536000, immutable";

#[derive(Deserialize)]
struct Chunk {
    file: String,
    name: Option<String>,
    #[serde(rename = "isEntry", default)]
    is_entry: bool,
    #[serde(default)]
    imports: Vec<String>,
    #[serde(default)]
    css: Vec<String>,
    #[serde(default)]
    assets: Vec<String>,
}

/// One entry's file and the stylesheets it needs, as URLs.
#[derive(Debug, PartialEq)]
struct Entry {
    file: String,
    css: Vec<String>,
}

/// A manifest's chunks, by key.
fn chunks(manifest: &str) -> Result<HashMap<String, Chunk>, String> {
    serde_json::from_str(manifest)
        .map_err(|error| format!("the frontend's manifest cannot be read: {error}"))
}

/// The entries the chunks name, or why they cannot serve the pages.
fn entries(chunks: &HashMap<String, Chunk>) -> Result<HashMap<String, Entry>, String> {
    let mut entries = HashMap::new();
    for (key, chunk) in chunks.iter().filter(|(_, chunk)| chunk.is_entry) {
        let Some(name) = &chunk.name else { continue };
        let mut css = Vec::new();
        stylesheets_of(chunks, key, &mut HashSet::new(), &mut css);
        let entry = Entry {
            file: format!("/{}", chunk.file),
            css,
        };
        entries.insert(name.clone(), entry);
    }
    let missing: Vec<&str> = ENTRIES
        .into_iter()
        .filter(|name| !entries.contains_key(*name))
        .collect();
    if missing.is_empty() {
        Ok(entries)
    } else {
        Err(format!(
            "the frontend's manifest lacks the entries {}",
            missing.join(", ")
        ))
    }
}

/// The stylesheets the chunk at `key` needs: those of the chunks it
/// imports, depth first, then its own, each once.
fn stylesheets_of<'a>(
    chunks: &'a HashMap<String, Chunk>,
    key: &'a str,
    seen: &mut HashSet<&'a str>,
    css: &mut Vec<String>,
) {
    let Some(chunk) = chunks.get(key) else { return };
    if !seen.insert(key) {
        return;
    }
    for import in &chunk.imports {
        stylesheets_of(chunks, import, seen, css);
    }
    for sheet in &chunk.css {
        let url = format!("/{sheet}");
        if !css.contains(&url) {
            css.push(url);
        }
    }
}

/// Every file the chunks name, as URLs: each chunk's own, its stylesheets
/// and the other files it uses, such as fonts.
fn files(chunks: &HashMap<String, Chunk>) -> BTreeSet<String> {
    chunks
        .values()
        .flat_map(|chunk| {
            std::iter::once(&chunk.file)
                .chain(&chunk.css)
                .chain(&chunk.assets)
        })
        .map(|file| format!("/{file}"))
        .collect()
}

/// A file's modification time, length and, on Unix, device and inode: a
/// rewrite changes the length even within one tick of the clock, and a
/// file renamed into place, as a build is, changes the inode.
type Stamp = Option<(SystemTime, u64, (u64, u64))>;

/// The entries of the last manifest that could serve the pages, and the
/// stamp of the last one read, whether it could or not.
struct Built {
    seen: Stamp,
    entries: HashMap<String, Entry>,
}

/// Vite's manifest at `path`, read again whenever its file changes.
struct Manifest {
    path: PathBuf,
    built: RwLock<Option<Built>>,
}

impl Manifest {
    fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            built: RwLock::new(None),
        }
    }

    fn stamp(&self) -> Stamp {
        let meta = std::fs::metadata(&self.path).ok()?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        };
        #[cfg(not(unix))]
        let identity = (0, 0);
        Some((meta.modified().ok()?, meta.len(), identity))
    }

    fn read(&self) -> Result<HashMap<String, Chunk>, String> {
        let manifest = std::fs::read_to_string(&self.path)
            .map_err(|error| format!("no frontend build at {}: {error}", self.path.display()))?;
        chunks(&manifest)
    }

    /// Read and check the manifest now, and that every file it names is
    /// there, so an interrupted build is refused at startup.
    fn check(&self) -> Result<(), String> {
        let seen = self.stamp();
        let chunks = self.read()?;
        let entries = entries(&chunks)?;
        let dist = self
            .path
            .parent()
            .and_then(std::path::Path::parent)
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Some(url) = files(&chunks)
            .into_iter()
            .find(|url| !dist.join(url.trim_start_matches('/')).is_file())
        {
            return Err(format!("the frontend build lacks {url}"));
        }
        *self.built.write().unwrap_or_else(PoisonError::into_inner) = Some(Built { seen, entries });
        Ok(())
    }

    /// `f` of the current build's entry `name`. A manifest that changed is
    /// read again; one that cannot serve the pages, as in the middle of a
    /// build, leaves the last build's entries in place until it changes.
    fn with_entry<T>(&self, name: &str, f: impl FnOnce(Option<&Entry>) -> T) -> T {
        let seen = self.stamp();
        {
            let built = self.built.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(built) = built.as_ref().filter(|built| built.seen == seen) {
                return f(built.entries.get(name));
            }
        }
        let mut built = self.built.write().unwrap_or_else(PoisonError::into_inner);
        let kept = built.take().map(|built| built.entries).unwrap_or_default();
        let entries = match self.read().and_then(|chunks| entries(&chunks)) {
            Ok(entries) => entries,
            Err(problem) if kept.is_empty() => {
                tracing::warn!(%problem, "no frontend build to name files from");
                kept
            }
            Err(problem) => {
                tracing::warn!(%problem, "keeping the frontend build already known");
                kept
            }
        };
        let current = built.insert(Built { seen, entries });
        f(current.entries.get(name))
    }
}

static FRONTEND: LazyLock<Manifest> =
    LazyLock::new(|| Manifest::new("frontend/dist/.vite/manifest.json"));

/// Check, at startup, that the frontend's build can serve the pages.
pub fn check() -> Result<(), String> {
    FRONTEND.check()
}

/// The URL of entry `name`'s file; one that answers 404 if no build names it.
pub fn url(name: &str) -> String {
    FRONTEND.with_entry(name, |entry| match entry {
        Some(entry) => entry.file.clone(),
        None => {
            tracing::warn!(name, "no frontend entry by that name");
            format!("/assets/{name}")
        }
    })
}

/// The URLs of the stylesheets entry `name` needs.
pub fn stylesheets(name: &str) -> Vec<String> {
    FRONTEND.with_entry(name, |entry| match entry {
        Some(entry) => entry.css.clone(),
        None => {
            tracing::warn!(name, "no frontend entry by that name");
            Vec::new()
        }
    })
}

/// Cache a file `/assets` serves for a year, and nothing else it answers,
/// so a file missing for a moment is not remembered as missing.
pub async fn caching(mut response: Response) -> Response {
    let status = response.status();
    let value = if status.is_success() || status == StatusCode::NOT_MODIFIED {
        IMMUTABLE
    } else {
        "no-store"
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(value));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A manifest in the shape Vite writes, with all eight entries: `chat`
    /// imports a chunk with a stylesheet of its own and uses a font, and
    /// `csrf` is a chunk no page names. `tag` marks the build.
    fn manifest(tag: &str) -> String {
        let mut chunks = vec![
            format!(
                r#""src/chat/index.tsx": {{"file": "assets/chat-{tag}.js", "name": "chat",
                    "isEntry": true, "imports": ["_ui.js", "_csrf.js"],
                    "css": ["assets/chat-{tag}.css"], "assets": ["assets/font-{tag}.woff2"]}}"#
            ),
            format!(
                r#""_ui.js": {{"file": "assets/ui-{tag}.js", "imports": ["_csrf.js"],
                    "css": ["assets/ui-{tag}.css"]}}"#
            ),
            format!(r#""_csrf.js": {{"file": "assets/csrf-{tag}.js", "name": "csrf"}}"#),
        ];
        for name in ENTRIES.into_iter().filter(|name| *name != "chat") {
            chunks.push(format!(
                r#""src/{name}": {{"file": "assets/{name}-{tag}.js", "name": "{name}",
                    "isEntry": true}}"#
            ));
        }
        format!("{{{}}}", chunks.join(","))
    }

    #[test]
    fn an_entry_resolves_to_its_file_and_every_stylesheet_it_needs() {
        let found = entries(&chunks(&manifest("a")).expect("a manifest")).expect("a whole one");
        assert_eq!(
            found.get("chat"),
            Some(&Entry {
                file: "/assets/chat-a.js".to_owned(),
                css: vec![
                    "/assets/ui-a.css".to_owned(),
                    "/assets/chat-a.css".to_owned()
                ],
            }),
            "an imported chunk's stylesheet first, each once"
        );
        assert_eq!(found.get("csrf"), None, "a chunk that is no entry");
    }

    #[test]
    fn a_manifest_that_cannot_serve_the_pages_is_refused() {
        let partial =
            r#"{"src/htmx.ts": {"file": "assets/htmx-a.js", "name": "htmx", "isEntry": true}}"#;
        let problem =
            entries(&chunks(partial).expect("a manifest")).expect_err("seven entries missing");
        assert!(
            problem.contains("main") && problem.contains("upgrade"),
            "{problem}"
        );
        assert!(chunks("not json").is_err());
    }

    /// A build at `dir`: its manifest under `.vite/` and, for `tag`'s build,
    /// every file it names, read here apart from [`files`].
    fn build_at(dir: &std::path::Path, tag: &str) {
        std::fs::create_dir_all(dir.join(".vite")).expect("a scratch build");
        std::fs::create_dir_all(dir.join("assets")).expect("a scratch build");
        let chunks: HashMap<String, serde_json::Value> =
            serde_json::from_str(&manifest(tag)).expect("a manifest");
        for chunk in chunks.values() {
            let named = std::iter::once(&chunk["file"])
                .chain(chunk["css"].as_array().into_iter().flatten())
                .chain(chunk["assets"].as_array().into_iter().flatten());
            for file in named.filter_map(serde_json::Value::as_str) {
                std::fs::write(dir.join(file), "").expect("a built file");
            }
        }
    }

    #[test]
    fn a_build_missing_a_file_it_names_is_refused_at_startup() {
        let dir = std::env::temp_dir().join(format!("noombat-assets-check-{}", std::process::id()));
        build_at(&dir, "a");
        let path = dir.join(".vite/manifest.json");
        std::fs::write(&path, manifest("a")).expect("manifest written");
        let frontend = Manifest::new(&path);
        assert!(frontend.check().is_ok(), "a whole build");
        for file in [
            "assets/chat-a.css",
            "assets/csrf-a.js",
            "assets/font-a.woff2",
        ] {
            std::fs::rename(dir.join(file), dir.join("aside")).expect("a file moved aside");
            let problem = frontend.check().expect_err("a file missing");
            assert!(problem.contains(file), "{problem}");
            std::fs::rename(dir.join("aside"), dir.join(file)).expect("a file put back");
        }
        std::fs::remove_dir_all(&dir).expect("scratch folder removed");
    }

    #[test]
    fn a_rebuilt_manifest_is_read_again_and_a_broken_one_is_not_taken() {
        let dir = std::env::temp_dir().join(format!("noombat-assets-{}", std::process::id()));
        build_at(&dir, "a");
        let path = dir.join(".vite/manifest.json");
        let write_at = |at: &std::path::Path, text: &str, age: u64| {
            std::fs::write(at, text).expect("manifest written");
            let file = std::fs::File::options()
                .write(true)
                .open(at)
                .expect("manifest open");
            file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(age))
                .expect("modification time set");
        };
        let write = |text: &str, age: u64| write_at(&path, text, age);
        let file_of = |manifest: &Manifest| {
            manifest.with_entry("htmx", |entry| entry.map(|e| e.file.clone()))
        };

        write(&manifest("a"), 1_000);
        let frontend = Manifest::new(&path);
        frontend.check().expect("a whole manifest");
        assert_eq!(file_of(&frontend).as_deref(), Some("/assets/htmx-a.js"));

        write(&manifest("b"), 2_000);
        assert_eq!(
            file_of(&frontend).as_deref(),
            Some("/assets/htmx-b.js"),
            "a rebuild"
        );

        write("{", 3_000);
        assert_eq!(
            file_of(&frontend).as_deref(),
            Some("/assets/htmx-b.js"),
            "a half-written manifest keeps the last build"
        );

        write(&manifest("c"), 3_000);
        assert_eq!(
            file_of(&frontend).as_deref(),
            Some("/assets/htmx-c.js"),
            "finished within the same tick as its half-written state"
        );

        // Broken, then whole at the same time and length: what was found
        // broken is not read again until it changes.
        let whole = manifest("d");
        write(&whole.replacen('{', " ", 1), 4_000);
        assert_eq!(file_of(&frontend).as_deref(), Some("/assets/htmx-c.js"));
        write(&whole, 4_000);
        assert_eq!(
            file_of(&frontend).as_deref(),
            Some("/assets/htmx-c.js"),
            "a broken manifest read once, not on every page"
        );
        write(&whole, 5_000);
        assert_eq!(file_of(&frontend).as_deref(), Some("/assets/htmx-d.js"));

        // Another file renamed into place, at the same time and length.
        #[cfg(unix)]
        {
            let next = dir.join(".vite/manifest.next");
            write_at(&next, &manifest("e"), 5_000);
            std::fs::rename(&next, &path).expect("new manifest in place");
            assert_eq!(
                file_of(&frontend).as_deref(),
                Some("/assets/htmx-e.js"),
                "a build renamed into place"
            );
        }
        std::fs::remove_dir_all(&dir).expect("scratch folder removed");
    }

    #[tokio::test]
    async fn only_a_file_served_is_cached_for_a_year() {
        for (status, cached) in [
            (StatusCode::OK, IMMUTABLE),
            (StatusCode::NOT_MODIFIED, IMMUTABLE),
            (StatusCode::NOT_FOUND, "no-store"),
        ] {
            let mut response = Response::default();
            *response.status_mut() = status;
            let response = caching(response).await;
            assert_eq!(
                response
                    .headers()
                    .get(CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some(cached),
                "{status}"
            );
        }
    }

    /// `text` without what lies between each `open` and its `close`.
    fn without(text: &str, open: &str, close: &str) -> String {
        let mut kept = String::new();
        let mut rest = text;
        while let Some(start) = rest.find(open) {
            kept.push_str(&rest[..start]);
            rest = rest[start..]
                .find(close)
                .map_or("", |end| &rest[start + end + close.len()..]);
        }
        kept + rest
    }

    /// Every template's text as its page carries it: without the template
    /// comments, which render to nothing, but with the HTML ones.
    fn served_templates() -> Vec<(PathBuf, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
        let found: Vec<(PathBuf, String)> = std::fs::read_dir(&dir)
            .expect("templates readable")
            .map(|file| {
                let path = file.expect("a template").path();
                let text = std::fs::read_to_string(&path).expect("a template's text");
                (path, without(&text, "{#", "#}"))
            })
            .collect();
        assert!(found.len() > 30, "the templates were read");
        found
    }

    /// Every template's text without its comments, where a call loads
    /// nothing.
    fn templates() -> Vec<(PathBuf, String)> {
        served_templates()
            .into_iter()
            .map(|(path, text)| (path, without(&text, "<!--", "-->")))
            .collect()
    }

    /// Every tag a page carries that could load code or styles is in a
    /// form the check in docs/verifying-builds.md accepts, so that check
    /// reports nothing on an honest instance. An HTML comment reaches the
    /// page too, so a tag named in one counts. Like the check, this reads
    /// each tag with its line breaks and tabs as spaces, and runs of spaces
    /// as one.
    #[test]
    fn every_loading_tag_is_in_a_form_the_verification_guide_accepts() {
        // The check accepts a script only as a `.js` file: every entry Vite
        // builds is a script but `main`, whose file is a stylesheet.
        let script_entry = |name: &str| ENTRIES.contains(&name) && name != "main";
        let script = |tag: &str, head: &str, tail: &str| {
            tag.strip_prefix(head)
                .and_then(|rest| rest.strip_suffix(tail))
                .is_some_and(script_entry)
        };
        // A link or meta tag the check skips, in the forms it lists: no value
        // holds an angle bracket or the quote around it.
        let plain = |value: &str| !value.contains(['"', '<', '>']);
        let inert_meta = |tag: &str| {
            let content = |name: &str, quote: char| {
                tag.strip_prefix(&format!(r#"<meta name="{name}" content={quote}"#))
                    .and_then(|rest| rest.strip_suffix(&format!("{quote}>")))
                    .is_some_and(|value| !value.contains([quote, '<', '>']))
            };
            tag == r#"<meta charset="utf-8">"#
                || ["viewport", "robots", "csrf-token"]
                    .iter()
                    .any(|name| content(name, '"'))
                || content("htmx-config", '\'')
        };
        let loads_nothing = |tag: &str| {
            let Some(rest) = tag
                .strip_prefix(r#"<link rel="canonical" "#)
                .or_else(|| tag.strip_prefix(r#"<link rel="alternate" "#))
            else {
                return false;
            };
            let rest = match rest.strip_prefix(r#"type=""#) {
                Some(typed) => match typed.split_once(r#"" "#) {
                    Some((kind, rest)) if plain(kind) => rest,
                    _ => return false,
                },
                None => rest,
            };
            rest.strip_prefix(r#"href=""#)
                .and_then(|href| href.strip_suffix(r#"">"#))
                .is_some_and(plain)
        };
        let accepted = |tag: &str| {
            script(
                tag,
                r#"<script type="module" src="{{ crate::assets::url(""#,
                r#"") }}">"#,
            ) || script(
                tag,
                r#"<script src="{{ crate::assets::url(""#,
                r#"") }}" type="module">"#,
            ) || [
                r#"<link rel="stylesheet" href="{{ href }}">"#,
                r#"<link rel="stylesheet" href="{{ crate::assets::url("main") }}">"#,
            ]
            .contains(&tag)
                || loads_nothing(tag)
                || inert_meta(tag)
        };
        let mut tags = 0;
        for (path, text) in served_templates() {
            let lower = text.to_ascii_lowercase();
            for open in [
                "<script", "<link", "<style", "<base", "<iframe", "<frame", "<object", "<embed",
                "<meta",
            ] {
                for (start, _) in lower.match_indices(open) {
                    let end = text[start..]
                        .find('>')
                        .map_or(text.len(), |i| start + i + 1);
                    let tag = text[start..end]
                        .split([' ', '\t', '\n', '\r'])
                        .filter(|word| !word.is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    tags += 1;
                    // The OAuth hand-off page sends the browser on by design; the
                    // guide checks no such page.
                    if path.ends_with("oauth_continue.html")
                        && tag == r#"<meta http-equiv="refresh" content="0;url={{ url }}">"#
                    {
                        continue;
                    }
                    assert!(
                        accepted(&tag),
                        "{} carries {tag}, which the guide's check would report",
                        path.display()
                    );
                }
            }
        }
        assert!(tags >= 20, "the pages' tags were found: {tags}");
    }

    /// Every page names its files through [`url`] and [`stylesheets`]: a
    /// path written by hand would name no build's file.
    #[test]
    fn no_template_names_an_asset_by_hand() {
        for (path, text) in templates() {
            assert!(
                !text.contains("/assets/"),
                "{} names an asset by hand",
                path.display()
            );
        }
    }

    /// Every page that loads an entry's script links that entry's
    /// stylesheets too, so one an entry gains later is not left out.
    #[test]
    fn every_script_a_page_loads_comes_with_its_stylesheets() {
        let mut loaded = 0;
        for (path, text) in templates() {
            for call in ["assets::url(", "assets::stylesheets("] {
                assert_eq!(
                    text.matches(call).count(),
                    text.matches(&format!("crate::{call}\"")).count(),
                    "{} calls {call} in a form this test cannot read",
                    path.display()
                );
            }
            for rest in text.split("crate::assets::url(\"").skip(1) {
                let name = rest.split('"').next().unwrap_or_default();
                loaded += 1;
                if name == "main" {
                    continue;
                }
                let head = format!("{{% for href in crate::assets::stylesheets(\"{name}\") %}}");
                let linked = text.split(&head).skip(1).any(|body| {
                    body.trim_start()
                        .strip_prefix(r#"<link rel="stylesheet" href="{{ href }}">"#)
                        .is_some_and(|rest| rest.trim_start().starts_with("{% endfor %}"))
                });
                assert!(
                    linked,
                    "{} loads {name} without linking its stylesheets",
                    path.display()
                );
            }
        }
        assert!(loaded >= 10, "the pages' scripts were found: {loaded}");
    }

    /// Every entry a page names is one Vite builds, and the list here is
    /// the list Vite's configuration builds.
    #[test]
    fn every_entry_named_is_one_vite_builds() {
        for (path, text) in templates() {
            for call in ["crate::assets::url(\"", "crate::assets::stylesheets(\""] {
                for rest in text.split(call).skip(1) {
                    let name = rest.split('"').next().unwrap_or_default();
                    assert!(
                        ENTRIES.contains(&name),
                        "{} names an entry Vite does not build: {name}",
                        path.display()
                    );
                }
            }
        }
        let config =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../frontend/vite.config.ts");
        let config = std::fs::read_to_string(config).expect("the Vite configuration");
        let input = config
            .split("input: {")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .expect("the configuration's inputs");
        let mut built: Vec<String> = input
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .map(|(name, _)| name.trim().trim_matches('"').to_owned())
            .collect();
        built.sort();
        let mut listed: Vec<String> = ENTRIES.iter().map(|name| (*name).to_owned()).collect();
        listed.sort();
        assert_eq!(built, listed);
    }
}
