# Synthesis plan (drafted while finders run)

## WF5: review-gap-critic
- Critic agent (effort high) reads scratchpad/all-findings.json, findings-index.md, self-verified-notes.md, the 26 slice
  descriptions, AGENTS.md map. Returns assessment + up to 8 gap-finder prompts {key, prompt}.
- Same find → verify → recheck pipeline as review-slice over those prompts.
- Then: python3 consolidate.py <wf5 dir>  (labels find:/verify:/recheck: are compatible)

## WF6: review-synthesis
- Judge panel (parallel, effort high): judge:risk (operator risk & value first), judge:leverage (engineering
  leverage & maintainability first). Each reads findings-index.md + all-findings.json and returns
  {top:[{id,rank,why}], themes:[{name,ids,summary}], quick_wins:[ids], strategic:[ids], drop:[{id,why}]}.
- Section writers (parallel, one per theme bucket) each write scratchpad/sections/<n>-<name>.md and return a 3-line summary:
    1 bugs+security · 2 cleanup+refactor+perf+deps · 3 enhancements+features · 4 docs+tests+ci-tooling+a11y
  Every surviving finding (confirmed/partially/unverified) must appear exactly once, with id, file:line, evidence gist,
  proposal, effort, verdict flag; partially → include the verifier's correction.
- Assembler (effort high): reads judges + section summaries + area_summaries + coverage_notes; writes
  scratchpad/sections/0-head.md = title, executive summary, scorecard per area, top-12 priorities (reconciling
  the two judges), quick wins, larger projects, method & coverage (incl. env limits: desktop crate not compiled here).
  Also writes scratchpad/sections/9-tail.md = refuted-claims list + minor nits appendix.
- I cat sections in order → scratchpad/azapptoolkit-review-2026-09-26.md; spot-check 5+ top items; SendUserFile.
