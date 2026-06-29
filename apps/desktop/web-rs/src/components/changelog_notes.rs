//! Renders an updater changelog as formatted HTML instead of a raw-text dump.
//! The source is the updater manifest's `notes` field — the raw CHANGELOG.md
//! section for the release (`release.yml` slices it out) — so it arrives as
//! Markdown. This handles the small subset our changelog actually uses: `###`
//! headings, `-` bullet lists (one level of nesting + wrapped continuation
//! lines), and inline `**bold**`, `` `code` ``, and `[text](url)` links. The
//! notes are our own release content, never user input, so there's no untrusted
//! HTML to sanitise — we build elements, never inject raw markup.

use leptos::prelude::*;

#[component]
pub fn ChangelogNotes(notes: String) -> impl IntoView {
    view! { <div class="update-splash__notes">{render_blocks(parse_blocks(&notes))}</div> }
}

#[derive(Debug, PartialEq)]
enum Block {
    Heading(String),
    Paragraph(String),
    List(Vec<Item>),
}

#[derive(Debug, PartialEq)]
struct Item {
    text: String,
    children: Vec<Item>,
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

fn render_blocks(blocks: Vec<Block>) -> AnyView {
    blocks
        .into_iter()
        .map(|block| match block {
            Block::Heading(t) => {
                view! { <h4 class="update-splash__notes-h">{render_inline(&t)}</h4> }.into_any()
            }
            Block::Paragraph(t) => view! { <p>{render_inline(&t)}</p> }.into_any(),
            Block::List(items) => view! { <ul>{render_items(items)}</ul> }.into_any(),
        })
        .collect_view()
        .into_any()
}

fn render_items(items: Vec<Item>) -> AnyView {
    items
        .into_iter()
        .map(|item| {
            let children = (!item.children.is_empty())
                .then(|| view! { <ul>{render_items(item.children)}</ul> });
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
}
