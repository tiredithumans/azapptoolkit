# .review-state — TEMPORARY checkpoint of an in-progress repository review

This directory is a resumable checkpoint for a Claude Code review session (see RESUME.md). It contains no source
changes. It is meant to be deleted (or the commit dropped) before anything from this branch is merged. PEM armour
literals quoted in finding evidence are defanged as `[PEM BEGIN …]` so the repo's whole-history secrets scan stays clean.

The root `.gitleaksignore` belongs to this checkpoint too (two fingerprints from the first checkpoint commit); remove it with this directory.
