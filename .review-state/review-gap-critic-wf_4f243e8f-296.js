export const meta = {
  name: 'review-gap-critic',
  description: 'Completeness critic names uncovered areas or lenses of the repo review, then targeted gap finders run with adversarial verification',
  phases: [
    { title: 'Critic', detail: 'what did 26 finders miss?' },
    { title: 'Find', detail: 'one deep-reading finder per gap' },
    { title: 'Verify', detail: 'one adversarial verifier per finder batch' },
    { title: 'Recheck', detail: 'second refutation of high bug/security items' },
  ],
}

const SCRATCH = '/tmp/claude-0/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/scratchpad'

const CRITIC_SCHEMA = {
  type: 'object',
  properties: {
    assessment: { type: 'string', description: 'Three to six sentences: how complete is the review so far, and where are the blind spots?' },
    finders: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          key: { type: 'string', description: 'short kebab-case key, e.g. gap-concurrency' },
          prompt: { type: 'string', description: 'self-contained slice description: exact files to read, questions to answer, what to cross-check' },
        },
        required: ['key', 'prompt'],
      },
    },
  },
  required: ['assessment', 'finders'],
}

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    area_summary: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          category: { type: 'string', enum: ['bug', 'security', 'cleanup', 'refactor', 'enhancement', 'feature', 'docs', 'test', 'perf', 'ci-tooling', 'a11y', 'deps'] },
          severity: { type: 'string', enum: ['high', 'medium', 'low'] },
          file: { type: 'string' },
          line: { type: 'integer' },
          evidence: { type: 'string' },
          rationale: { type: 'string' },
          proposal: { type: 'string' },
          effort: { type: 'string', enum: ['S', 'M', 'L'] },
        },
        required: ['title', 'category', 'severity', 'file', 'line', 'evidence', 'rationale', 'proposal', 'effort'],
      },
    },
    minor_nits: { type: 'array', items: { type: 'string' } },
    coverage_notes: { type: 'string' },
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
          notes: { type: 'string' },
          corrected_title: { type: 'string' },
          corrected_proposal: { type: 'string' },
        },
        required: ['index', 'verdict', 'severity', 'notes'],
      },
    },
  },
  required: ['verdicts'],
}

const CRITIC_PROMPT = 'You are the completeness critic for a comprehensive review of /home/user/azapptoolkit (Rust: Tauri 2 backend in apps/desktop/src-tauri, shared crates in crates/, Leptos WASM frontend in apps/desktop/web-rs; AGENTS.md in your context has the repo map). Twenty-six finder agents each reviewed one slice and produced findings that are being adversarially verified. Your job: find what they MISSED, then write up to 6 self-contained gap-finder prompts.\n\nRead these files first:\n- ' + SCRATCH + '/slices.md (the 26 slices and their file scopes)\n- ' + SCRATCH + '/findings-index.md (one line per finding: id, verdict, severity, category, file:line, title)\n- ' + SCRATCH + '/all-findings.json: read ONLY the area_summaries and coverage_notes objects (use jq: jq .area_summaries FILE ; jq .coverage_notes FILE) plus, if useful, jq to list findings per file.\n- ' + SCRATCH + '/self-verified-notes.md\n\nThen determine, with evidence from the repo itself (run find/ls/wc/grep; read-only; no cargo build/test):\n1. Files or directories under crates/, apps/desktop/src-tauri/, apps/desktop/web-rs/src, docs/, .github/ that were in NO slice, or that a coverage_notes entry says was not read fully. List them with line counts; the biggest unread files are the best gap-finder targets.\n2. Lenses nobody applied. Candidates: concurrency and races across AppState and long-running commands; startup and cold-path performance (launch, first list load, WASM bundle size and Trunk config); memory growth in a long session (keep-alive panes, caches, toasts, open items); Windows and macOS specific paths (keyring chunking, file permissions, updater install modes, path handling); tenant switching end to end (backend + frontend consistency); error UX end to end (UiError code to on-screen text for the top 20 codes); logging strategy and observability (what a support engineer can and cannot diagnose from the log file); internationalisation and locale (date formats, number formats, hard-coded English); offline and degraded network behaviour; release and packaging (notarization, MSI vs NSIS, AppImage, rpm) beyond what tooling/docs covered; the demo build (feature = demo) fidelity; test-suite quality in the backend crates (assertion strength, duplicated fixtures) since fe-tests only covered the frontend.\n3. Categories under-represented per area (e.g. zero feature or perf findings for an area that plausibly has them) and any finding whose proposal implies a cross-area change nobody examined (a backend finding that needs a frontend change, or vice versa).\n\nRules for the prompts you write: each names the exact files (repo-relative) and the specific questions; each is doable by one agent reading maybe 3 to 8 thousand lines; do not duplicate a slice already run (slices.md) unless coverage_notes says it was not read fully, in which case name only the unread part; do not ask for cargo build/test/clippy (the desktop crate cannot compile here). Prefer gaps likely to yield real bugs or high-value improvements over completeness for its own sake. Return ONLY the structured output.'

const PREAMBLE = 'You are one finder in a comprehensive, ultra-thorough review of the azapptoolkit repository at /home/user/azapptoolkit: a Rust desktop app (Tauri 2 backend in apps/desktop/src-tauri + shared crates in crates/, Leptos 0.8 WASM frontend in apps/desktop/web-rs), about 124k lines, MSRV 1.98, edition 2024. AGENTS.md (already in your context) has the repo map and conventions; docs/architecture/*.md are the deep-dives. Twenty-six finders already covered the repo by slice; a completeness critic identified YOUR slice (below) as a gap. Find concrete, actionable items: bug, security, cleanup, refactor, enhancement, feature, docs, test, perf, ci-tooling, a11y, deps.\n\nGround rules:\n1. READ the code; do not infer from names. Every finding cites a repo-relative file path + line number and QUOTES the evidence (2 to 8 lines). A finding without real quoted evidence will be refuted by the verifier and wasted.\n2. This codebase documents deliberate trade-offs heavily (block comments, AGENTS.md, docs/architecture/*.md, apps/desktop/src-tauri/tests/repo_invariants/). Before reporting, check whether the behaviour is a documented decision; if so drop it or explain concretely why the rationale no longer holds.\n3. Every finding has a specific proposal: what to change, where, expected effect, effort S (under an hour) / M (about a day) / L (multi-day).\n4. Severity: high = real bug, data-loss/security exposure, or a result that misleads the operator; medium = meaningful improvement; low = polish. Be honest.\n5. Before reporting, check ' + SCRATCH + '/findings-index.md (grep the file path) so you do not repeat a finding another finder already made; if you find the same thing, skip it or add only what is new.\n6. Read-only. Do NOT edit files. Do NOT run cargo build/test/clippy/check. grep/rg, find, wc, sed -n, cargo metadata and cargo tree are fine.\n7. Return ONLY the structured output; coverage_notes must name any file in your slice you did not read fully.'

const VERIFY_PREAMBLE = 'You are an adversarial verifier in a comprehensive review of /home/user/azapptoolkit (Rust: Tauri 2 backend + Leptos WASM frontend; AGENTS.md in your context has the map and conventions). Below are findings one reviewer produced. For EACH finding, open the cited file at the cited line and try to REFUTE it: is the quoted evidence real; is the premise true; is it already handled elsewhere (grep helpers, apps/desktop/src-tauri/tests/repo_invariants/, apps/desktop/web-rs/tests/, docs/architecture/*.md, AGENTS.md, CHANGELOG.md); is it a documented deliberate decision; would the proposal actually be an improvement under the repo conventions; is the severity honest? Verdicts: confirmed, partially (give corrected_title/corrected_proposal), refuted (say exactly why, citing file:line). Default to skepticism but do not refute a real, useful finding merely because it is small. Read-only; no cargo build/test/clippy. Return ONLY the structured output, one verdict per finding index.'

const RECHECK_PREAMBLE = 'You are the second, independent adversarial check on HIGH-severity bug/security findings in /home/user/azapptoolkit. A first verifier already confirmed these; try hard to REFUTE each by reading the actual code paths end to end (callers, error handling, tests, docs/architecture). For a bug: trace the concrete input or state that triggers it. For a security finding: confirm the exposure is reachable in the shipped build. If you cannot construct the failing path, downgrade or refute. Read-only. Return ONLY the structured output, one verdict per finding index.'

function fmt(x) {
  return '### [' + x.index + '] ' + x.title + '\n- category: ' + x.category + ' / severity: ' + x.severity + ' / effort: ' + x.effort + '\n- file: ' + x.file + ':' + x.line + '\n- evidence:\n' + x.evidence + '\n- rationale: ' + x.rationale + '\n- proposal: ' + x.proposal
}

phase('Critic')
const critic = await agent(CRITIC_PROMPT, { label: 'critic', phase: 'Critic', schema: CRITIC_SCHEMA, effort: 'high' })
const finders = ((critic && critic.finders) || []).slice(0, 6)
log('critic proposed ' + finders.length + ' gap finders: ' + finders.map((f) => f.key).join(', '))
if (!finders.length) return { assessment: critic ? critic.assessment : 'critic returned nothing', results: [] }

const results = await pipeline(
  finders,
  (f) => agent(PREAMBLE + '\n\n## Your slice: ' + f.key + '\n\n' + f.prompt, { label: 'find:' + f.key, phase: 'Find', schema: FINDINGS_SCHEMA }),
  (found, f) => {
    if (!found) { log('finder ' + f.key + ' returned nothing'); return null }
    const findings = (found.findings || []).map((x, i) => ({ ...x, index: i, finder: f.key }))
    log(f.key + ': ' + findings.length + ' findings')
    return { finder: f.key, area_summary: found.area_summary, minor_nits: found.minor_nits || [], coverage_notes: found.coverage_notes, findings }
  },
  async (found, f) => {
    if (!found) return null
    if (!found.findings.length) return { ...found, verified: [] }
    const v = await agent(VERIFY_PREAMBLE + '\n\n# Findings from reviewer "' + f.key + '"\n\n' + found.findings.map(fmt).join('\n\n'), { label: 'verify:' + f.key, phase: 'Verify', schema: VERIFY_SCHEMA })
    const byIdx = new Map(((v && v.verdicts) || []).map((d) => [d.index, d]))
    const verified = found.findings.map((x) => {
      const d = byIdx.get(x.index)
      if (!d) return { ...x, verdict: 'unverified', verifier_notes: '' }
      return { ...x, verdict: d.verdict, severity: d.severity || x.severity, verifier_notes: d.notes || '', title: d.corrected_title || x.title, proposal: d.corrected_proposal || x.proposal }
    })
    log(f.key + ': verified: ' + verified.filter((x) => x.verdict === 'confirmed').length + ' confirmed, ' + verified.filter((x) => x.verdict === 'partially').length + ' partial, ' + verified.filter((x) => x.verdict === 'refuted').length + ' refuted')
    return { ...found, verified }
  },
  async (found, f) => {
    if (!found || !found.verified) return found
    const hot = found.verified.filter((x) => x.verdict !== 'refuted' && x.severity === 'high' && (x.category === 'bug' || x.category === 'security'))
    if (!hot.length) return found
    const r = await agent(RECHECK_PREAMBLE + '\n\n# High-severity items from reviewer "' + f.key + '"\n\n' + hot.map(fmt).join('\n\n'), { label: 'recheck:' + f.key, phase: 'Recheck', schema: VERIFY_SCHEMA, effort: 'high' })
    const byIdx = new Map(((r && r.verdicts) || []).map((d) => [d.index, d]))
    const verified = found.verified.map((x) => {
      const d = byIdx.get(x.index)
      if (!d || !hot.includes(x)) return x
      return { ...x, recheck: d.verdict, severity: d.severity || x.severity, recheck_notes: d.notes || '', verdict: d.verdict === 'refuted' ? 'refuted' : x.verdict }
    })
    return { ...found, verified }
  },
)
return { assessment: critic.assessment, results: results.filter(Boolean) }