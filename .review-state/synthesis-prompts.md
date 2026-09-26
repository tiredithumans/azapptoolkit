# Drafted prompts for the synthesis workflow (judges → section writers → assembler)

SCRATCH=/tmp/claude-0/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/scratchpad

## Judge (x2, parallel; lens A = operator risk & value; lens B = engineering leverage & maintainability)
Read SCRATCH/findings-index.md (one line per finding). For any candidate open its full record with
  jq '.findings[] | select(.id=="F123")' SCRATCH/all-findings.json
Also read SCRATCH/self-verified-notes.md. You may open the repo at /home/user/azapptoolkit read-only to settle doubts.
Return: top 15 ranked (id, rank, one-sentence why under your lens, effort), themes (name, ids, 2-sentence summary),
quick_wins (S-effort ids with real payoff, up to 20), strategic (L-effort ids worth a project, up to 8),
drop (ids you would leave out of the report as noise or already-covered, with why), duplicates (groups of ids that are the same finding).

## Section writers (x4, parallel), one per bucket file SCRATCH/buckets/<name>.json
Write SCRATCH/sections/<name>.md. Every finding in the bucket appears exactly once (merge exact duplicates per
possible_duplicate_of / same file:line: keep one entry, list the merged ids). Group by sub-theme, high→medium→low.
Format per finding:
  ### <id> · <severity> · <effort> · <title>
  `file:line` — verdict (confirmed / partially: <verifier correction summarized>)
  **Problem.** 2–4 sentences from evidence+rationale, quoting at most 3 lines of code.
  **Proposal.** 1–3 sentences.
Low-severity items: 2-line compact form (title line + one sentence problem/proposal).
Write in chunks (append with cat >> heredoc every ~20 findings). Do NOT invent file paths or ids; use only the JSON.
Return a JSON summary: counts, sub-theme list, the 5 items you consider most important in this bucket and why.

## Assembler (after writers), effort high
Inputs: judges JSON (inline), writers' summaries (inline), SCRATCH/buckets/meta.json (area_summaries, coverage_notes,
refuted, minor_nits, missing_agents), SCRATCH/self-verified-notes.md, critic assessment (inline), the four section files
(skim headings). Write SCRATCH/sections/0-head.md:
  # azapptoolkit — comprehensive project review (2026-09-26)
  How to read this / method (26 slices + 6 gap slices, adversarial verification, env limits: desktop crate not compiled here;
  counts table: findings by category × severity, verdict counts)
  Executive summary (10–15 sentences: overall state, strongest areas, the themes)
  Top priorities (12, reconciled from both judges; each: id(s), title, why it matters, effort, where to start)
  Quick wins (S-effort list) · Strategic projects (L-effort list)
  Scorecard per area (from area_summaries: 1–2 sentences each, backend-crates/backend-app/frontend/cross-cutting)
And SCRATCH/sections/9-tail.md: Refuted/dropped claims (short list), Minor nits appendix (grouped by area), Coverage notes.
Return JSON: executive_summary (string), top_priorities (array of {ids,title,effort,why}), counts.
