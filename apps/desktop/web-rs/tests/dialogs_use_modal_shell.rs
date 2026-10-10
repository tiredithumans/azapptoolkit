//! Pins the dialog primitive: `components::modal_shell::ModalShell` is the only
//! file in `src/` that spells dialog markup — `role="dialog"` /
//! `role="alertdialog"`, `aria-modal`, the `modal-backdrop` class in any
//! position, or a thaw `Dialog` (which renders `role="dialog"` itself, and
//! without the `.modal-backdrop` that `hooks::modal_is_open` keys on, so the
//! bare-key shortcuts and the workspace's Escape would act behind it). Every
//! other dialog passes its content to `ModalShell` as children.
//!
//! Eleven dialogs (`ConfirmDialog`, the one-time secret reveal, the wizards,
//! the remediation modals) once hand-rolled the backdrop with their own
//! `use_focus_trap` / `use_escape` and a hard-coded title id. Two
//! `ConfirmDialog`s open at once — one left open in a workspace pane switched
//! away from, a second in the pane now shown — both pointed `aria-labelledby`
//! at the fixed `confirm-dialog-title`, so the second was announced by the
//! first one's title. The shell mints a title id per instance, so routing every
//! dialog through it fixes the whole class; this scan keeps a twelfth from
//! regrowing. See `docs/architecture/frontend-workspace.md` ("One primitive per
//! UI pattern").
//!
//! The scan walks every `.rs` file under `src/`; the one file it exempts is the
//! primitive itself, which must still spell the markup (so the rule cannot pass
//! vacuously after a rename). Comments are skipped, so a doc comment may name
//! the markup it is describing.
//!
//! Runs natively under `just web-test` (no WASM, no browser); gated off for
//! wasm32 like `aria_state_bindings.rs`, because it reads the filesystem.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::{Path, PathBuf};

/// The primitive, relative to `src/` — the one file allowed the markup.
const PRIMITIVE: &str = "components/modal_shell.rs";

/// Dialog markup that only the primitive may spell. The backdrop class is
/// matched separately ([`BACKDROP`]), because its selector form is legitimate.
const DIALOG_MARKUP: &[&str] = &[
    "role=\"dialog\"",
    "role=\"alertdialog\"",
    "aria-modal",
    // thaw's dialog components: the element, its surface, an import.
    "<Dialog",
    "DialogSurface",
    "thaw::Dialog",
];

/// The backdrop class, in any position of a `class` value or as a `class:`
/// toggle. Only the `.modal-backdrop` SELECTOR (the one `hooks::modal_is_open`
/// queries) is not markup, so an occurrence counts unless a `.` precedes it.
const BACKDROP: &str = "modal-backdrop";

/// Drops whole-line `//` comments (doc comments included) and cuts a trailing
/// ` //` comment, keeping newlines so reported line numbers stay true.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else if let Some(i) = line.find(" //") {
                &line[..i]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `(line, needle)` for every piece of dialog markup in `src` (already
/// comment-stripped).
fn dialog_markup(src: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        for needle in DIALOG_MARKUP {
            if line.contains(needle) {
                out.push((i + 1, *needle));
            }
        }
        if line
            .match_indices(BACKDROP)
            .any(|(at, _)| !line[..at].ends_with('.'))
        {
            out.push((i + 1, BACKDROP));
        }
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let file = entry.expect("dir entry").path();
        if file.is_dir() {
            rust_files(&file, out);
        } else if file.extension().is_some_and(|e| e == "rs") {
            out.push(file);
        }
    }
}

#[test]
fn every_dialog_renders_through_modal_shell() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();

    let mut primitive_markup = Vec::new();
    let mut offenders = Vec::new();
    for file in &files {
        let src = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()))
            .replace("\r\n", "\n");
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let found = dialog_markup(&strip_line_comments(&src));
        if rel == PRIMITIVE {
            primitive_markup = found.into_iter().map(|(_, needle)| needle).collect();
            continue;
        }
        for (line, needle) in found {
            offenders.push(format!("src/{rel}:{line}  {needle}"));
        }
    }

    assert!(
        files.len() >= 100,
        "walked only {} files under src/ — the walk is broken, and a rule that scans nothing \
         passes vacuously",
        files.len()
    );
    for needle in ["role=\"dialog\"", "aria-modal", BACKDROP] {
        assert!(
            primitive_markup.contains(&needle),
            "src/{PRIMITIVE} no longer spells `{needle}` — if the dialog primitive moved, point \
             PRIMITIVE at its new home rather than letting this scan exempt nothing"
        );
    }
    assert!(
        offenders.is_empty(),
        "dialog markup outside the dialog primitive. One primitive per UI pattern: render the \
         dialog through `components::modal_shell::ModalShell` (it owns the backdrop, \
         `role=\"dialog\"`, a per-instance `aria-labelledby` title id, the focus trap and \
         Escape — gated on `busy` / `close_on_escape`) and pass only the content as children; \
         extend ModalShell if it lacks something. See docs/architecture/frontend-workspace.md:\n  \
         {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_dialog_scanner_reads_the_shapes_the_tree_uses() {
    let found = |src: &str| -> Vec<&'static str> {
        dialog_markup(&strip_line_comments(src))
            .into_iter()
            .map(|(_, needle)| needle)
            .collect()
    };

    // The hand-rolled shape the eleven dialogs used.
    assert_eq!(
        found(
            "<div\n    class=\"modal-backdrop\"\n    role=\"dialog\"\n    aria-modal=\"true\"\n    \
             aria-labelledby=\"confirm-dialog-title\"\n>"
        ),
        [BACKDROP, "role=\"dialog\"", "aria-modal"]
    );
    // An `attr:` binding, an alert dialog, and a backdrop with extra classes.
    assert_eq!(found("<Div attr:aria-modal=\"true\" />"), ["aria-modal"]);
    assert_eq!(
        found("<div role=\"alertdialog\">"),
        ["role=\"alertdialog\""]
    );
    // The backdrop class in any position, and as a `class:` toggle.
    assert_eq!(
        found("<div class=\"modal-backdrop modal-backdrop--dim\">"),
        [BACKDROP]
    );
    assert_eq!(found("<div class=\"dim modal-backdrop\">"), [BACKDROP]);
    assert_eq!(
        found("<div class=format!(\"{x} modal-backdrop\")>"),
        [BACKDROP]
    );
    assert_eq!(found("<div class:modal-backdrop=move || x>"), [BACKDROP]);
    // thaw's dialog, which renders `role="dialog"` itself.
    assert_eq!(found("<Dialog open=open>"), ["<Dialog"]);
    assert_eq!(found("<DialogSurface>"), ["<Dialog", "DialogSurface"]);
    assert_eq!(found("use thaw::Dialog;"), ["thaw::Dialog"]);

    // Not markup: doc and line comments that name it, the selector that
    // `hooks::modal_is_open` queries, and the app's own `…Dialog` components.
    assert!(found("//! hand-rolled `<div role=\"dialog\" aria-modal=\"true\">`s").is_empty());
    assert!(found("/// (`role=\"dialog\"`, `aria-modal`)").is_empty());
    assert!(found("<b/> // was: role=\"dialog\" aria-modal=\"true\"").is_empty());
    assert!(found(".query_selector(\".modal-backdrop\")").is_empty());
    assert!(found("<ConfirmDialog open=open title=\"Remove?\" />").is_empty());
}
