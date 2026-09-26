export const meta = {
  name: 'review-slice',
  description: 'Deep-read finders over a slice of the repo, then adversarially verify each batch of findings, with a second refutation pass on high-severity bug/security items',
  phases: [
    { title: 'Find', detail: 'one deep-reading finder per sub-slice' },
    { title: 'Verify', detail: 'one adversarial verifier per finder batch' },
    { title: 'Recheck', detail: 'second independent refutation of high bug/security items' },
  ],
}

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    area_summary: { type: 'string', description: 'Two to four sentences on the state of this slice: what is strong, what is weak.' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          category: { type: 'string', enum: ['bug', 'security', 'cleanup', 'refactor', 'enhancement', 'feature', 'docs', 'test', 'perf', 'ci-tooling', 'a11y', 'deps'] },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          file: { type: 'string', description: 'repo-relative path from /home/user/azapptoolkit' },
          line: { type: 'integer' },
          evidence: { type: 'string', description: 'quoted code/doc lines proving the premise' },
          rationale: { type: 'string' },
          proposal: { type: 'string', description: 'what to change, where, expected effect' },
          effort: { type: 'string', enum: ['S', 'M', 'L'] },
        },
        required: ['title', 'category', 'severity', 'file', 'line', 'evidence', 'rationale', 'proposal', 'effort'],
      },
    },
    minor_nits: { type: 'array', items: { type: 'string' }, description: 'one-liners with file:line for trivial items' },
    coverage_notes: { type: 'string', description: 'files in your slice you did NOT read fully, or tools you could not use' },
  },
  required: ['area_summary', 'findings', 'minor_nits', 'coverage_notes'],
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          index: { type: 'integer' },
          verdict: { type: 'string', enum: ['confirmed', 'partially', 'refuted'] },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          notes: { type: 'string', description: 'why; cite file:line' },
          corrected_title: { type: 'string' },
          corrected_proposal: { type: 'string' },
        },
        required: ['index', 'verdict', 'severity', 'notes'],
      },
    },
  },
  required: ['verdicts'],
}

const PREAMBLE = `You are one finder in a comprehensive, ultra-thorough review of the azapptoolkit repository at /home/user/azapptoolkit: a Rust desktop app (Tauri 2 backend in apps/desktop/src-tauri + shared crates in crates/, Leptos 0.8 WASM frontend in apps/desktop/web-rs), about 124k lines, MSRV 1.98, edition 2024. AGENTS.md (already in your context) has the repo map and conventions; docs/architecture/*.md are the deep-dives.

The user asked: "Do a comprehensive thorough scan of this project and let me know any improvements, enhancements, features, or cleanup opportunities." Your job is YOUR SLICE (below). Find concrete, actionable items in these categories:
- bug: real correctness defects or races (cite the exact path that goes wrong)
- security: token/secret handling, logging, injection, trust boundaries, least privilege
- cleanup: dead code, duplication, stale comments or docs-in-code that contradict the code, leftovers, inconsistent naming/patterns
- refactor: structural improvements that reduce risk (a repeated pattern that should be one helper; a 2000-line module that should split by concern)
- enhancement: make an existing feature better (UX, robustness, edge-case coverage)
- feature: a capability an Entra/Exchange/SharePoint admin would want that this code is one seam away from
- docs: README/AGENTS/architecture claims that don't match code, or undocumented behaviour that should be documented
- test: meaningful coverage gaps (a rule/invariant with no test, an untested error path), fixture drift
- perf: real wins (serial calls that could batch, needless clones of large collections in hot paths, missing $top, over-broad cache invalidation)
- ci-tooling, a11y, deps: as relevant to your slice

Ground rules:
1. READ the code; do not infer from names. Every finding cites a repo-relative file path + line number and QUOTES the evidence (2 to 8 lines). A finding without real quoted evidence will be refuted by the verifier and wasted.
2. This codebase documents deliberate trade-offs heavily (block comments, AGENTS.md, docs/architecture/*.md, apps/desktop/src-tauri/tests/repo_invariants/). Before reporting, check whether the behaviour is a documented decision. If so, drop it, or explain concretely why the rationale no longer holds. Do not re-litigate settled decisions (opt-level=z, sharded GUI tests, sha2/p12-keystore holds, no rsa crate, GTK3 advisory ignore) without new evidence.
3. Every finding has a specific proposal: what to change, where, expected effect, and effort S (under an hour) / M (about a day) / L (multi-day).
4. Severity: high = a real bug, data-loss/security exposure, or a result that misleads the operator; medium = meaningful improvement; low = polish. Be honest: most findings are medium or low.
5. Cover your WHOLE slice (list its files with find/ls first) and read the largest files end to end. Aim for 8 to 20 substantive findings. Trivial nits (typos, a stray blank line) go in minor_nits as one-liners with file:line.
6. Cross-check before claiming something is missing (a helper, a test, an invalidation, a fixture): grep the repo first.
7. Read-only. Do NOT edit files. Do NOT run cargo build/test/clippy/check (the desktop crate cannot compile here because WebKitGTK is absent, and a separate agent owns tool runs) unless your slice explicitly says otherwise. grep/rg, find, wc, sed -n, cargo metadata and cargo tree are fine.
8. Return ONLY the structured output. coverage_notes must name any file in your slice you did not read fully.`

const VERIFY_PREAMBLE = `You are an adversarial verifier in a comprehensive review of /home/user/azapptoolkit (Rust: Tauri 2 backend + Leptos WASM frontend; AGENTS.md in your context has the map and conventions). Below are findings one reviewer produced. For EACH finding, open the cited file at the cited line and try to REFUTE it:
- Is the quoted evidence real and at roughly that location? Is the premise actually true (really dead / duplicated / unhandled / untested / undocumented / a bug)?
- Is it already handled elsewhere? grep the repo: helpers, apps/desktop/src-tauri/tests/repo_invariants/, apps/desktop/web-rs/tests/, docs/architecture/*.md, AGENTS.md, CHANGELOG.md.
- Is it a documented, deliberate decision (a block comment nearby, an AGENTS.md rule, an architecture doc) the reviewer did not engage with? If that rationale is sound, refute or downgrade.
- Would the proposal actually be an improvement under the repo's conventions (one primitive per UI pattern, tenant-scoped caches, invalidate only on Ok, cancel tokens, camelCase Graph models vs snake_case DTOs)? Is it feasible?
- Is the severity honest? Adjust it.
Verdicts: confirmed (premise and proposal hold), partially (true in part; give corrected_title and/or corrected_proposal and say what was overstated), refuted (say exactly why, citing file:line). Default to skepticism, but do not refute a real, useful finding merely because it is small. Read-only: do not edit files, do not run cargo build/test/clippy. Return ONLY the structured output, one verdict per finding index.`

const RECHECK_PREAMBLE = `You are the second, independent adversarial check on HIGH-severity bug/security findings in /home/user/azapptoolkit. A first verifier already confirmed these; your job is to try hard to REFUTE each one by reading the actual code paths end to end (callers, error handling, apps/desktop/src-tauri/tests/repo_invariants/, the relevant docs/architecture/*.md). For a bug: trace the concrete input or state that triggers it and confirm nothing upstream prevents it. For a security finding: confirm the exposure is reachable in the shipped build (not only in tests or the demo feature). If you cannot construct the failing path, downgrade (partially, with a corrected severity) or refute. Read-only. Return ONLY the structured output, one verdict per finding index.`

function fmt(x) {
  return '### [' + x.index + '] ' + x.title + '\n- category: ' + x.category + ' / severity: ' + x.severity + ' / effort: ' + x.effort + '\n- file: ' + x.file + ':' + x.line + '\n- evidence:\n' + x.evidence + '\n- rationale: ' + x.rationale + '\n- proposal: ' + x.proposal
}

const seen = new Set()
const results = await pipeline(
  args.finders,
  (f) => agent(PREAMBLE + '\n\n## Your slice: ' + f.key + '\n\n' + f.prompt, { label: 'find:' + f.key, phase: 'Find', schema: FINDINGS_SCHEMA }),
  (found, f) => {
    if (!found) { log('finder ' + f.key + ' returned nothing'); return null }
    const findings = (found.findings || []).map((x, i) => {
      const key = x.file + '::' + String(x.title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
      const duplicate = seen.has(key)
      if (!duplicate) seen.add(key)
      return { ...x, index: i, finder: f.key, duplicate }
    })
    log(f.key + ': ' + findings.length + ' findings, ' + (found.minor_nits || []).length + ' nits')
    return { finder: f.key, area_summary: found.area_summary, minor_nits: found.minor_nits || [], coverage_notes: found.coverage_notes, findings }
  },
  async (found, f) => {
    if (!found) return null
    const toVerify = found.findings.filter((x) => !x.duplicate)
    if (!toVerify.length) return { ...found, verified: [] }
    const v = await agent(VERIFY_PREAMBLE + '\n\n# Findings from reviewer "' + f.key + '"\n\n' + toVerify.map(fmt).join('\n\n'), { label: 'verify:' + f.key, phase: 'Verify', schema: VERIFY_SCHEMA })
    const byIdx = new Map(((v && v.verdicts) || []).map((d) => [d.index, d]))
    const verified = toVerify.map((x) => {
      const d = byIdx.get(x.index)
      if (!d) return { ...x, verdict: 'unverified', verifier_notes: '' }
      return { ...x, verdict: d.verdict, severity: d.severity || x.severity, verifier_notes: d.notes || '', title: d.corrected_title || x.title, proposal: d.corrected_proposal || x.proposal }
    })
    const c = verified.filter((x) => x.verdict === 'confirmed').length
    const p = verified.filter((x) => x.verdict === 'partially').length
    const r = verified.filter((x) => x.verdict === 'refuted').length
    log(f.key + ': verified: ' + c + ' confirmed, ' + p + ' partial, ' + r + ' refuted')
    return { ...found, verified }
  },
  async (found, f) => {
    if (!found || !found.verified) return found
    const hot = found.verified.filter((x) => x.verdict !== 'refuted' && x.severity === 'high' && (x.category === 'bug' || x.category === 'security'))
    if (!hot.length) return found
    const r = await agent(RECHECK_PREAMBLE + '\n\n# High-severity items from reviewer "' + f.key + '" (already confirmed once)\n\n' + hot.map(fmt).join('\n\n'), { label: 'recheck:' + f.key, phase: 'Recheck', schema: VERIFY_SCHEMA, effort: 'high' })
    const byIdx = new Map(((r && r.verdicts) || []).map((d) => [d.index, d]))
    const verified = found.verified.map((x) => {
      const d = byIdx.get(x.index)
      if (!d || !hot.includes(x)) return x
      return { ...x, recheck: d.verdict, severity: d.severity || x.severity, recheck_notes: d.notes || '', verdict: d.verdict === 'refuted' ? 'refuted' : x.verdict }
    })
    log(f.key + ': rechecked ' + hot.length + ' high bug/security items')
    return { ...found, verified }
  },
)
const kept = results.filter(Boolean)
const total = kept.reduce((n, r) => n + (r.verified || []).filter((x) => x.verdict !== 'refuted').length, 0)
log(args.label + ': ' + total + ' surviving findings across ' + kept.length + ' finders')
return { label: args.label, results: kept }