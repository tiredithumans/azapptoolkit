export const meta = {
  name: 'review-section-writers',
  description: 'Four parallel writers turn the verified finding buckets into report sections, each verified for completeness',
  phases: [
    { title: 'Write', detail: 'one writer per bucket' },
    { title: 'Check', detail: 'every finding id present exactly once' },
  ],
}

const SCRATCH = '/tmp/claude-0/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/scratchpad'

const WRITER_SCHEMA = {
  type: 'object',
  properties: {
    section_file: { type: 'string' },
    finding_count: { type: 'integer' },
    merged_groups: { type: 'array', items: { type: 'array', items: { type: 'string' } }, description: 'ids you merged into one entry' },
    subthemes: { type: 'array', items: { type: 'string' } },
    most_important: { type: 'array', items: { type: 'object', properties: { ids: { type: 'array', items: { type: 'string' } }, why: { type: 'string' } }, required: ['ids', 'why'] } },
    summary: { type: 'string', description: 'four to eight sentences on the state of this bucket for the executive summary' },
  },
  required: ['section_file', 'finding_count', 'merged_groups', 'subthemes', 'most_important', 'summary'],
}

const CHECK_SCHEMA = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    missing_ids: { type: 'array', items: { type: 'string' } },
    duplicate_ids: { type: 'array', items: { type: 'string' } },
    fixed: { type: 'boolean', description: 'true if you appended the missing entries yourself' },
    notes: { type: 'string' },
  },
  required: ['ok', 'missing_ids', 'duplicate_ids', 'fixed', 'notes'],
}

const BUCKETS = [
  { name: '1-bugs-security', title: 'Bugs and security', note: 'Order sub-themes by operator impact: data written to the tenant or the wrong result shown first (audit/scoring accuracy, remediation atomicity, backup/restore, auth/session), then security hardening, then robustness.' },
  { name: '2-cleanup-refactor-perf-deps', title: 'Cleanup, refactors, performance and dependencies', note: 'Sub-themes: dead code and stale comments; duplication that a shared helper would absorb; oversized modules and proposed splits; performance; dependency hygiene (declared-but-unused deps, duplicate majors, pins).' },
  { name: '3-enhancements-features', title: 'Enhancements and feature opportunities', note: 'Sub-themes by product area: audit and remediation; scoping (Exchange/SharePoint); credentials and SSO; enterprise apps and managed identities; operator tooling (search, DR, settings, readiness); Graph API capabilities not yet adopted; the product-gap proposals (keep their admin-value framing and the seam they extend).' },
  { name: '4-docs-tests-tooling-a11y', title: 'Documentation, tests, CI/tooling and accessibility', note: 'Sub-themes: docs drift (claim vs code) grouped by document; missing documentation; test gaps by crate/tier; CI and tooling; accessibility and UX consistency (keep the fe-a11y finder\u2019s primitive-first remediation ordering).' },
]

function writerPrompt(b) {
  return 'You are a section writer for a comprehensive review report of the azapptoolkit repository (/home/user/azapptoolkit; Rust: Tauri 2 backend + Leptos WASM frontend). Findings were produced by 26 reviewers and adversarially verified. Your bucket: "' + b.title + '".\n\nInput: ' + SCRATCH + '/buckets/' + b.name + '.json, a JSON array of finding objects with fields id, title, category, severity, effort, file, line, verdict (confirmed|partially|unverified), recheck, evidence, rationale, proposal, verifier_notes, recheck_notes, finder, possible_duplicate_of. It is large (about 300 to 430 KB), so do NOT read it in one go: first run  jq length  and  jq -r \'.[] | "\\(.id) \\(.severity) \\(.category) \\(.file):\\(.line) \\(.title)"\'  to see the whole list, then process it in slices of about 15 with  jq \'.[N:M]\'.\n\nOutput: write ' + SCRATCH + '/sections/' + b.name + '.md (create it fresh, then append with cat >> heredocs as you go; never rewrite the whole file). Structure:\n\n## ' + b.title + '\n\nOne short intro paragraph (what this bucket covers, counts by severity).\n\nThen sub-theme sections (### headings). ' + b.note + ' Within a sub-theme order high, medium, low.\n\nEntry format for HIGH and MEDIUM findings:\n\n#### <id> · <severity> · effort <S|M|L> · <title>\n`<file>:<line>` · <verdict>  (for partially: one clause summarising the verifier\u2019s correction from verifier_notes; for recheck present: mention "re-verified")\n**Problem.** Two to four sentences built from evidence and rationale; quote at most three short lines of code in a fenced block when the quote carries the point.\n**Proposal.** One to three sentences from proposal (use the corrected proposal already in the record).\n\nEntry format for LOW findings (compact, no fenced code):\n- **<id> · <title>** — `<file>:<line>` · <verdict>. One or two sentences: problem and proposal.\n\nRules:\n1. EVERY finding in the bucket appears exactly once, under its own id. The only exception: when possible_duplicate_of names ids that are genuinely the same finding at the same file (read both), merge them into one entry titled with the first id and list "also reported as F0xx" on the verdict line; both ids then count as covered.\n2. Never invent a file path, line number, code quote, or id. Everything must come from the JSON. Do not add findings of your own.\n3. Keep the verifier\u2019s corrections: if verdict is partially, the entry must say what was overstated.\n4. No em dashes in your prose (use commas or full stops); keep sentences under about 25 words; no marketing language.\n5. When you finish, run  grep -c "^#### F\\|^- \\*\\*F" <file>  and compare with the bucket length minus merged ids; append anything missing. Report the final count.\nReturn ONLY the structured output.'
}

function checkPrompt(b, w) {
  return 'You are the completeness checker for a report section. Bucket JSON: ' + SCRATCH + '/buckets/' + b.name + '.json (array; each object has an id like F123). Section markdown: ' + SCRATCH + '/sections/' + b.name + '.md. The writer reported ' + (w ? w.finding_count : 'unknown') + ' entries and these merged groups: ' + JSON.stringify(w ? w.merged_groups : []) + '.\n\nDo this mechanically with jq/grep: (1) list every id in the JSON; (2) list every id mentioned in the section (grep -o "F[0-9]\\{3\\}" | sort -u); (3) ids in JSON but not in the section are missing; ids that head more than one entry (#### Fxxx or - **Fxxx) are duplicates. (4) For each missing id, append a correctly formatted entry to the END of the section file under a final "### Additional items" heading, using ONLY the JSON record (same entry formats as the rest of the file: #### heading for high/medium, compact bullet for low; include file:line, verdict, Problem, Proposal). (5) Spot-check five random entries against their JSON record for a fabricated path or quote; note any you find (do not rewrite them, just report). Return ONLY the structured output with ok=true when nothing is missing after your fix.'
}

const results = await pipeline(
  BUCKETS,
  (b) => agent(writerPrompt(b), { label: 'write:' + b.name, phase: 'Write', schema: WRITER_SCHEMA }),
  async (w, b) => {
    if (!w) log('writer ' + b.name + ' returned nothing')
    const c = await agent(checkPrompt(b, w), { label: 'check:' + b.name, phase: 'Check', schema: CHECK_SCHEMA, effort: 'medium' })
    log(b.name + ': writer count ' + (w ? w.finding_count : '?') + ', check ok=' + (c ? c.ok : '?') + ' missing=' + (c ? c.missing_ids.length : '?'))
    return { bucket: b.name, writer: w, check: c }
  },
)
return { sections: results.filter(Boolean) }