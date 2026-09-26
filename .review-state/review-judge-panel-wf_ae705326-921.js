export const meta = {
  name: 'review-judge-panel',
  description: 'Two independent judges with different lenses rank the verified review findings, name themes, quick wins and strategic projects',
  phases: [{ title: 'Judge', detail: 'operator-risk lens and engineering-leverage lens in parallel' }],
}

const SCRATCH = '/tmp/claude-0/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/scratchpad'

const JUDGE_SCHEMA = {
  type: 'object',
  properties: {
    lens: { type: 'string' },
    top: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          rank: { type: 'integer' },
          ids: { type: 'array', items: { type: 'string' }, description: 'one id, or several when they are the same issue or must be fixed together' },
          title: { type: 'string' },
          why: { type: 'string', description: 'one or two sentences under your lens' },
          effort: { type: 'string', enum: ['S', 'M', 'L'] },
          where_to_start: { type: 'string', description: 'file:line and the first concrete step' },
        },
        required: ['rank', 'ids', 'title', 'why', 'effort', 'where_to_start'],
      },
    },
    themes: {
      type: 'array',
      items: {
        type: 'object',
        properties: { name: { type: 'string' }, ids: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } },
        required: ['name', 'ids', 'summary'],
      },
    },
    quick_wins: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, why: { type: 'string' } }, required: ['id', 'why'] }, description: 'S-effort items with real payoff, up to 20' },
    strategic: { type: 'array', items: { type: 'object', properties: { ids: { type: 'array', items: { type: 'string' } }, title: { type: 'string' }, why: { type: 'string' } }, required: ['ids', 'title', 'why'] }, description: 'L-effort items worth a project, up to 8' },
    drop_or_downgrade: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, why: { type: 'string' } }, required: ['id', 'why'] }, description: 'findings you would leave out of the headline report or downgrade, with why' },
    cross_area_pairs: { type: 'array', items: { type: 'object', properties: { ids: { type: 'array', items: { type: 'string' } }, note: { type: 'string' } }, required: ['ids', 'note'] }, description: 'backend and frontend findings that must ship together' },
    overall: { type: 'string', description: 'six to ten sentences: the state of the codebase under your lens' },
  },
  required: ['lens', 'top', 'themes', 'quick_wins', 'strategic', 'drop_or_downgrade', 'cross_area_pairs', 'overall'],
}

function judgePrompt(lens, guidance) {
  return 'You are a prioritisation judge for a comprehensive review of the azapptoolkit repository (/home/user/azapptoolkit: Rust, Tauri 2 backend + Leptos WASM frontend; a security tool for Entra ID app registrations). About 490 findings were produced by 32 reviewer agents and adversarially verified. Your lens: ' + lens + '. ' + guidance + '\n\nInputs (read in this order):\n1. ' + SCRATCH + '/findings-index.md : one line per finding (id | verdict | severity | category | effort | file:line | title). Findings marked "pending" are still awaiting verification (a second pass is running); do NOT put a pending item in your top list unless you open the code yourself and confirm it.\n2. For any candidate, the full record: jq \'.findings[] | select(.id=="F123")\' ' + SCRATCH + '/all-findings.json (fields: evidence, rationale, proposal, verifier_notes, recheck_notes).\n3. ' + SCRATCH + '/self-verified-notes.md (facts the lead session verified directly).\n4. ' + SCRATCH + '/critic.json (the completeness critic\u2019s assessment, incl. cross-area pairings it flagged).\n5. The repo itself, read-only, to settle doubts (grep/sed). No cargo build/test.\n\nProduce: a top 15 (rank 1 = most important under your lens; group ids that are the same issue, e.g. F036+F139, F105+F284, F151+F251, F140+F164, or that must ship together), 6 to 10 themes covering most surviving findings, quick wins (S effort with real payoff), strategic projects (L effort), items you would drop or downgrade from the headline report (say why), cross-area pairs, and an overall assessment. Be concrete: every top item names file:line and a first step. No em dashes in prose. Return ONLY the structured output.'
}

phase('Judge')
const judges = await parallel([
  () => agent(judgePrompt('operator risk and value', 'Rank by what most misleads or harms the Entra admin using the tool: wrong or falsely reassuring audit results, tenant mutations whose reported outcome differs from what landed, data loss or duplication paths (DR, create/retry), inert documented controls, session and secret handling. Then the enhancements and features that most change what an admin can do. Weight severity and blast radius over code elegance.'), { label: 'judge:risk', schema: JUDGE_SCHEMA, effort: 'high' }),
  () => agent(judgePrompt('engineering leverage and maintainability', 'Rank by leverage: fixes and refactors that remove a class of bugs (a missing invariant test that would have caught several findings, a bypassed primitive, a shared helper, a module split), performance wins on large tenants, dependency and toolchain hygiene, documentation drift that misleads contributors, and CI gaps. Prefer small changes that prevent recurrence over one-off patches; still surface the highest-severity bugs, but explain them as root causes.'), { label: 'judge:leverage', schema: JUDGE_SCHEMA, effort: 'high' }),
])
return { judges: judges.filter(Boolean) }