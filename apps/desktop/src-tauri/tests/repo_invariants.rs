//! Cross-tree invariants that AGENTS.md could previously only state as prose.
//!
//! Sibling of `dependency_policy.rs` and written the same way: `include_str!` +
//! a small hand-rolled scan, so these run inside `just test` on every platform
//! rather than needing a shell script that `verify` could not portably call
//! (recipe lines run under PowerShell on Windows).
//!
//! One binary, five concern modules. It was a single 940-line file, which made
//! the rules hard to find and — more to the point — hid how coarse some of them
//! were: the fan-out rule matched per *file*, so `commands/bulk.rs` satisfied it
//! with a string that lived in an unrelated function while three of its
//! dispatches went ungated. A table belongs next to the rule that reads it.
//!
//! Cargo only compiles top-level `tests/*.rs` as test binaries, so the
//! `repo_invariants/` directory is picked up through these declarations alone.
//!
//! - [`fanout`] — dead-session gating in the long-running fan-outs
//! - [`cache`] — invalidate-on-`Ok`, pinned indexes, watch-before-fetch
//! - [`cancel`] — one `CancelToken` claim per long-running command
//! - [`commands`] — whole-command-layer scans, and the shared source table
//! - [`release`] — version identity, CHANGELOG format, mirrored lint block

#[path = "repo_invariants/cache.rs"]
mod cache;
#[path = "repo_invariants/cancel.rs"]
mod cancel;
#[path = "repo_invariants/commands.rs"]
mod commands;
#[path = "repo_invariants/fanout.rs"]
mod fanout;
#[path = "repo_invariants/release.rs"]
mod release;
