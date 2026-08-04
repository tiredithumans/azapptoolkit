//! Renders an updater changelog as formatted HTML instead of a raw-text dump.
//! The source is the updater manifest's `notes` field — the raw CHANGELOG.md
//! section for the release (`release.yml` slices it out) — so it arrives as
//! Markdown. This handles the small subset our changelog actually uses: `###`
//! headings, `-` bullet lists (one level of nesting + wrapped continuation
//! lines), and inline `**bold**`, `` `code` ``, and `[text](url)` links. The
//! notes are our own release content, never user input, so there's no untrusted
//! HTML to sanitise — we build elements, never inject raw markup.
//!
//! # Summary first, detail on request
//!
//! `CHANGELOG.md` is written for operators *and* contributors: each entry leads
//! with one sentence of what changed for the person running the app, then
//! several paragraphs of why, which function was wrong, and how it was fixed —
//! plus whole `### Internal` sections about tests and refactors. Dumping that
//! verbatim into an update splash buries the answer to the only question being
//! asked there ("what changes for me?") under implementation detail.
//!
//! So the default render is condensed: repo-internal sections are dropped, and
//! every bullet is cut to its lede sentence (see [`first_sentence`]). Nothing is
//! lost — a "Show technical details" toggle renders the section verbatim, and
//! it only appears when the two actually differ. Doing this at render time (not
//! in `release.yml`'s extraction) keeps the manifest complete and means already
//! published releases summarise correctly too.

use leptos::prelude::*;

/// Headings whose sections describe repo-internal work — tests, refactors,
/// build plumbing — with no observable effect for the operator. Matched
/// case-insensitively against the heading text; the section is dropped from the
/// summary and shown by the toggle. Keep this list to headings that are *never*
/// user-facing: "Fixed"/"Changed"/"Added"/"Security" all are.
const INTERNAL_SECTIONS: &[&str] = &["internal", "development", "chore", "build", "ci"];

/// Shown when every section in a release was internal (e.g. a dependency-and-CI
/// maintenance release), so the summary would otherwise render blank.
const NO_USER_FACING_CHANGES: &str = "This release contains internal maintenance changes only — nothing changes in how the app \
     works for you.";

#[component]
pub fn ChangelogNotes(notes: String) -> impl IntoView {
    let full_blocks = parse_blocks(&notes);
    let summary_blocks = summarize(&full_blocks);
    // No toggle when condensing changed nothing — an inert control that swaps a
    // block for an identical one reads as broken.
    let has_detail = summary_blocks != full_blocks;
    let show_full = RwSignal::new(false);

    view! {
        <div class="changelog">
            {move || {
                let blocks = if show_full.get() { &full_blocks } else { &summary_blocks };
                render_blocks(blocks)
            }}
        </div>
        {has_detail
            .then(|| {
                view! {
                    <button
                        class="link-btn changelog__toggle"
                        type="button"
                        aria-expanded=move || if show_full.get() { "true" } else { "false" }
                        on:click=move |_| show_full.update(|f| *f = !*f)
                    >
                        {move || {
                            if show_full.get() {
                                "Hide technical details"
                            } else {
                                "Show technical details"
                            }
                        }}
                    </button>
                }
            })}
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Block {
    Heading(String),
    Paragraph(String),
    List(Vec<Item>),
}

#[derive(Debug, Clone, PartialEq)]
struct Item {
    text: String,
    children: Vec<Item>,
}

/// Condense parsed notes to what changed for the user: drop
/// [`INTERNAL_SECTIONS`] wholesale, cut every bullet to its lede sentence, and
/// drop nested bullets (always elaboration on their parent). A heading left
/// with nothing under it is dropped too, and a release that condenses to
/// nothing at all becomes the [`NO_USER_FACING_CHANGES`] line rather than an
/// empty box.
fn summarize(blocks: &[Block]) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    let mut in_internal = false;
    for block in blocks {
        match block {
            Block::Heading(title) => {
                in_internal = INTERNAL_SECTIONS
                    .iter()
                    .any(|s| title.trim().eq_ignore_ascii_case(s));
                if !in_internal {
                    out.push(Block::Heading(title.clone()));
                }
            }
            _ if in_internal => {}
            Block::Paragraph(text) => out.push(Block::Paragraph(first_sentence(text))),
            Block::List(items) => out.push(Block::List(
                items
                    .iter()
                    .map(|i| Item {
                        text: first_sentence(&i.text),
                        children: Vec::new(),
                    })
                    .collect(),
            )),
        }
    }
    out.retain(|b| !matches!(b, Block::List(items) if items.is_empty()));
    // Drop a heading with no surviving content under it (last, or followed
    // straight by the next heading).
    let mut kept = Vec::with_capacity(out.len());
    for (i, block) in out.iter().enumerate() {
        let dangling = matches!(block, Block::Heading(_))
            && !matches!(out.get(i + 1), Some(Block::Paragraph(_) | Block::List(_)));
        if !dangling {
            kept.push(block.clone());
        }
    }
    if kept.is_empty() {
        kept.push(Block::Paragraph(NO_USER_FACING_CHANGES.to_string()));
    }
    kept
}

/// The lede of a changelog entry: its first sentence.
///
/// Entries are authored lede-first — one sentence of what changed for the
/// operator, then the rationale ("`run_audit` collapsed every per-app failure
/// to a log warning, so a session whose refresh token died mid-run…"). Cutting
/// at the first sentence boundary keeps the former and drops the latter, so
/// summary mode needs no change to how the changelog is written.
///
/// A `.`/`!`/`?` only ends a sentence when what follows can start one: end of
/// text, or whitespace then an uppercase letter or an opening `**`/`` ` ``/
/// quote/`[`. That leaves `e.g.`, `i.e.`, `v0.22.4` and `1.2.1 → 1.2.2` intact.
/// Periods inside a `` `code` `` span never end a sentence, and a closing `**`
/// is carried along so a bolded lede still renders bold.
fn first_sentence(text: &str) -> String {
    let mut in_code = false;
    for (i, byte) in text.bytes().enumerate() {
        match byte {
            b'`' => in_code = !in_code,
            b'.' | b'!' | b'?' if !in_code => {
                // Byte indices land on char boundaries: ASCII punctuation and
                // `**` are never part of a multi-byte sequence.
                let mut end = i + 1;
                if text[end..].starts_with("**") {
                    end += 2;
                }
                let rest = &text[end..];
                if rest.is_empty() {
                    return text.to_string();
                }
                let after = rest.trim_start();
                if rest.len() != after.len() && starts_sentence(after) {
                    return text[..end].to_string();
                }
                if after.is_empty() {
                    return text[..end].to_string();
                }
            }
            _ => {}
        }
    }
    text.to_string()
}

fn starts_sentence(rest: &str) -> bool {
    rest.chars()
        .next()
        .is_some_and(|c| c.is_uppercase() || matches!(c, '*' | '`' | '"' | '\'' | '['))
}

/// Block-level parse of a changelog section. Each line is classified as a
/// heading (`#…`), a bullet (`- …`, leading indent = nesting depth), or loose
/// text; a non-bullet, non-heading line continues the open bullet or paragraph
/// (CHANGELOG.md wraps long entries across physical lines). Blank lines and
/// headings flush the open list/paragraph.
fn parse_blocks(notes: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut flat: Vec<(usize, String)> = Vec::new();
    let mut para: Vec<String> = Vec::new();

    for raw in notes.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if trimmed.is_empty() {
            flush_para(&mut blocks, &mut para);
            flush_list(&mut blocks, &mut flat);
        } else if trimmed.starts_with('#') {
            flush_para(&mut blocks, &mut para);
            flush_list(&mut blocks, &mut flat);
            blocks.push(Block::Heading(
                trimmed.trim_start_matches('#').trim().to_string(),
            ));
        } else if let Some(item) = trimmed.strip_prefix("- ") {
            flush_para(&mut blocks, &mut para);
            flat.push((indent, item.trim().to_string()));
        } else if let Some(last) = flat.last_mut() {
            // Wrapped continuation of the open bullet.
            last.1.push(' ');
            last.1.push_str(trimmed);
        } else {
            para.push(trimmed.to_string());
        }
    }
    flush_para(&mut blocks, &mut para);
    flush_list(&mut blocks, &mut flat);
    blocks
}

fn flush_para(blocks: &mut Vec<Block>, para: &mut Vec<String>) {
    if !para.is_empty() {
        blocks.push(Block::Paragraph(para.join(" ")));
        para.clear();
    }
}

fn flush_list(blocks: &mut Vec<Block>, flat: &mut Vec<(usize, String)>) {
    if !flat.is_empty() {
        let mut pos = 0;
        let base = flat[0].0;
        blocks.push(Block::List(build_level(flat, &mut pos, base)));
        flat.clear();
    }
}

/// Build a (possibly nested) list tree from indentation-tagged items. Items at
/// `level` become siblings; a run of deeper-indented items immediately after one
/// becomes its children (recursively).
fn build_level(items: &[(usize, String)], pos: &mut usize, level: usize) -> Vec<Item> {
    let mut out = Vec::new();
    while let Some((indent, text)) = items.get(*pos) {
        if *indent < level {
            break;
        }
        if *indent > level {
            // Defensive: a deeper item with no sibling at this level to own it.
            // Adopt it here rather than dropping it.
            *pos += 1;
            out.push(Item {
                text: text.clone(),
                children: Vec::new(),
            });
            continue;
        }
        *pos += 1;
        let children = match items.get(*pos) {
            Some((next, _)) if *next > level => build_level(items, pos, *next),
            _ => Vec::new(),
        };
        out.push(Item {
            text: text.clone(),
            children,
        });
    }
    out
}

fn render_blocks(blocks: &[Block]) -> AnyView {
    blocks
        .iter()
        .map(|block| match block {
            Block::Heading(t) => {
                view! { <h4 class="changelog__heading">{render_inline(t)}</h4> }.into_any()
            }
            Block::Paragraph(t) => view! { <p>{render_inline(t)}</p> }.into_any(),
            Block::List(items) => view! { <ul>{render_items(items)}</ul> }.into_any(),
        })
        .collect_view()
        .into_any()
}

fn render_items(items: &[Item]) -> AnyView {
    items
        .iter()
        .map(|item| {
            let children = (!item.children.is_empty())
                .then(|| view! { <ul>{render_items(&item.children)}</ul> });
            view! { <li>{render_inline(&item.text)}{children}</li> }.into_any()
        })
        .collect_view()
        .into_any()
}

#[derive(Debug, PartialEq)]
enum Inline {
    Text(String),
    Bold(String),
    Code(String),
    Link { text: String, href: String },
}

/// Inline parse of the changelog subset: `**bold**`, `` `code` ``, and
/// `[text](url)`. Earliest marker wins; an unterminated or malformed marker
/// degrades to literal text. Bold/code spans are taken as plain text inside (no
/// nesting) — enough for our changelog and keeps the scanner simple.
fn parse_inline(s: &str) -> Vec<Inline> {
    let mut out: Vec<Inline> = Vec::new();
    let mut text = String::new();
    let mut rest = s;

    while !rest.is_empty() {
        let next = ["`", "**", "["]
            .iter()
            .filter_map(|m| rest.find(m).map(|i| (i, *m)))
            .min_by_key(|(i, _)| *i);

        let Some((idx, marker)) = next else {
            text.push_str(rest);
            break;
        };

        let (before, from) = rest.split_at(idx);
        text.push_str(before);

        match marker {
            "`" => {
                let inner = &from[1..];
                if let Some(end) = inner.find('`') {
                    flush_text(&mut out, &mut text);
                    out.push(Inline::Code(inner[..end].to_string()));
                    rest = &inner[end + 1..];
                } else {
                    text.push('`');
                    rest = inner;
                }
            }
            "**" => {
                let inner = &from[2..];
                if let Some(end) = inner.find("**") {
                    flush_text(&mut out, &mut text);
                    out.push(Inline::Bold(inner[..end].to_string()));
                    rest = &inner[end + 2..];
                } else {
                    text.push_str("**");
                    rest = inner;
                }
            }
            _ => match parse_link(from) {
                Some((link, consumed)) => {
                    flush_text(&mut out, &mut text);
                    out.push(link);
                    rest = &from[consumed..];
                }
                None => {
                    text.push('[');
                    rest = &from[1..];
                }
            },
        }
    }
    flush_text(&mut out, &mut text);
    out
}

/// Parse a `[text](url)` link at the start of `s`, returning the node and the
/// number of bytes it consumed. `None` if it isn't a well-formed link.
fn parse_link(s: &str) -> Option<(Inline, usize)> {
    let close = s.find(']')?;
    let url = s[close + 1..].strip_prefix('(')?;
    let paren = url.find(')')?;
    let link = Inline::Link {
        text: s[1..close].to_string(),
        href: url[..paren].to_string(),
    };
    // '[' text ']' '(' url ')'  =>  close + paren + 3 bytes past the start.
    Some((link, close + paren + 3))
}

fn flush_text(out: &mut Vec<Inline>, text: &mut String) {
    if !text.is_empty() {
        out.push(Inline::Text(std::mem::take(text)));
    }
}

fn render_inline(s: &str) -> AnyView {
    parse_inline(s)
        .into_iter()
        .map(|node| match node {
            Inline::Text(t) => view! { {t} }.into_any(),
            Inline::Bold(t) => view! { <strong>{t}</strong> }.into_any(),
            Inline::Code(t) => view! { <code>{t}</code> }.into_any(),
            Inline::Link { text, href } => {
                view! { <a href=href target="_blank" rel="noopener noreferrer">{text}</a> }
                    .into_any()
            }
        })
        .collect_view()
        .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_parses_bold_code_links_and_text() {
        assert_eq!(
            parse_inline("plain text"),
            vec![Inline::Text("plain text".into())]
        );
        assert_eq!(
            parse_inline("a **bold** and `code` end"),
            vec![
                Inline::Text("a ".into()),
                Inline::Bold("bold".into()),
                Inline::Text(" and ".into()),
                Inline::Code("code".into()),
                Inline::Text(" end".into()),
            ]
        );
        assert_eq!(
            parse_inline("see [Keep a Changelog](https://keepachangelog.com) now"),
            vec![
                Inline::Text("see ".into()),
                Inline::Link {
                    text: "Keep a Changelog".into(),
                    href: "https://keepachangelog.com".into(),
                },
                Inline::Text(" now".into()),
            ]
        );
    }

    #[test]
    fn inline_degrades_unterminated_markers_to_literal_text() {
        // A lone `**`, an open backtick, and a non-link `[` must not eat the
        // rest of the line — they render as the literal characters.
        assert_eq!(parse_inline("2 ** 3"), vec![Inline::Text("2 ** 3".into())]);
        assert_eq!(parse_inline("a `b c"), vec![Inline::Text("a `b c".into())]);
        assert_eq!(
            parse_inline("[not a link"),
            vec![Inline::Text("[not a link".into())]
        );
    }

    #[test]
    fn blocks_split_headings_lists_and_wrapped_continuations() {
        let notes = "### Added\n\n- **Thing.** first line\n  continues here\n- second item\n";
        assert_eq!(
            parse_blocks(notes),
            vec![
                Block::Heading("Added".into()),
                Block::List(vec![
                    Item {
                        text: "**Thing.** first line continues here".into(),
                        children: vec![]
                    },
                    Item {
                        text: "second item".into(),
                        children: vec![]
                    },
                ]),
            ]
        );
    }

    #[test]
    fn blocks_nest_indented_bullets_under_their_parent() {
        let notes = "- parent\n  - child a\n  - child b\n- sibling\n";
        assert_eq!(
            parse_blocks(notes),
            vec![Block::List(vec![
                Item {
                    text: "parent".into(),
                    children: vec![
                        Item {
                            text: "child a".into(),
                            children: vec![]
                        },
                        Item {
                            text: "child b".into(),
                            children: vec![]
                        },
                    ],
                },
                Item {
                    text: "sibling".into(),
                    children: vec![]
                },
            ])]
        );
    }

    #[test]
    fn loose_text_with_no_bullet_becomes_a_paragraph() {
        let notes = "See the release notes on GitHub for what's new\nin this version.";
        assert_eq!(
            parse_blocks(notes),
            vec![Block::Paragraph(
                "See the release notes on GitHub for what's new in this version.".into()
            )]
        );
    }

    /// The whole point of summary mode: a real entry is a one-sentence lede
    /// followed by paragraphs of implementation detail, and only the lede is
    /// what changed for the user.
    #[test]
    fn lede_cuts_an_entry_at_its_first_sentence() {
        assert_eq!(
            first_sentence(
                "**A security audit interrupted by a dead session is no longer cached as a \
                 finished one.** `run_audit` collapsed every per-app failure to a log warning, \
                 so a session whose refresh token died mid-run produced a report silently \
                 missing applications."
            ),
            "**A security audit interrupted by a dead session is no longer cached as a finished \
             one.**"
        );
    }

    #[test]
    fn lede_keeps_a_single_sentence_entry_whole() {
        // Title-style entries put the summary *after* the bold run — cutting at
        // the bold would leave a bare "just verify-ui" with no statement at all.
        let entry = "**`just verify-ui`** — `verify` plus the browser GUI tests, for a box with \
                     Chrome.";
        assert_eq!(first_sentence(entry), entry);
        let unpunctuated = "Cold-tenant directory scans are de-duplicated";
        assert_eq!(first_sentence(unpunctuated), unpunctuated);
    }

    #[test]
    fn lede_does_not_split_on_abbreviations_versions_or_code() {
        // A period that isn't a sentence end: an abbreviation (lowercase
        // follows), a version number (digit follows), and one inside a code
        // span. Splitting on any of these truncates the summary mid-thought.
        for text in [
            "Tokens refresh lazily, e.g. 60s before expiry, behind a shared mutex.",
            "`webbrowser` 1.2.1 → 1.2.2, the crate used to open the sign-in URL.",
            "The `Cargo.toml` pin stays at 0.22 for now.",
        ] {
            assert_eq!(first_sentence(text), text, "wrongly split: {text}");
        }
    }

    #[test]
    fn summary_drops_internal_sections_and_nested_detail() {
        let notes = "### Fixed\n\n- **Sign-out clears the cache.** It used to leave the prior \
                     tenant's data behind.\n  - The list keys were the only ones invalidated.\n\n\
                     ### Internal\n\n- Moved target derivation into its own crate.\n";
        assert_eq!(
            summarize(&parse_blocks(notes)),
            vec![
                Block::Heading("Fixed".into()),
                Block::List(vec![Item {
                    text: "**Sign-out clears the cache.**".into(),
                    children: vec![],
                }]),
            ]
        );
    }

    #[test]
    fn a_release_with_only_internal_sections_says_so_instead_of_rendering_blank() {
        let notes = "### Internal\n\n- Refactored the throttle tracker.\n";
        assert_eq!(
            summarize(&parse_blocks(notes)),
            vec![Block::Paragraph(NO_USER_FACING_CHANGES.into())]
        );
    }

    /// The toggle is gated on `summary != full`, so notes that are already
    /// user-facing must summarise to themselves — otherwise every release shows
    /// a "Show technical details" control that reveals identical text.
    #[test]
    fn already_concise_notes_summarize_to_themselves() {
        let full = parse_blocks("### Added\n\n- A one-line entry that says what changed.\n");
        assert_eq!(summarize(&full), full);
    }
}
