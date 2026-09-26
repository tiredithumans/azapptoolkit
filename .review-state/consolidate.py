#!/usr/bin/env python3
"""Rebuild verified findings from the workflow journals (started + result records joined by agentId)."""
import json, sys, glob, os, re, collections

BASE = "/root/.claude/projects/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/subagents/workflows"
OUT = "/tmp/claude-0/-home-user-azapptoolkit/12cb2860-e7bf-55f0-b15e-42e55e824c8b/scratchpad/all-findings.json"
wf_labels = {"wf_d88485ea-39b": "backend-crates", "wf_e68e5b2b-501": "backend-app", "wf_142c1a69-d8e": "frontend", "wf_005ba226-6d7": "cross-cutting", "wf_4f243e8f-296": "gap-critic"}
extra = [a for a in sys.argv[1:]]  # extra wf dirs (synthesis / gap workflows)
for a in extra:
    wf_labels[os.path.basename(a)] = os.path.basename(a)

all_findings, summaries, nits, coverage, missing = [], {}, {}, {}, []
for wf, wlabel in wf_labels.items():
    path = os.path.join(BASE, wf, "journal.jsonl")
    if not os.path.exists(path):
        continue
    started, results = {}, {}
    for line in open(path):
        try: rec = json.loads(line)
        except Exception: continue
        if rec.get("type") == "started":
            started[rec["agentId"]] = (rec.get("label") or "", rec.get("phase") or "")
        elif rec.get("type") == "result":
            results[rec["agentId"]] = rec.get("result")
    finders, verifiers, rechecks = {}, {}, {}
    done_labels = set()
    for aid, (label, phase) in started.items():
        res = results.get(aid)
        if res is None: continue
        kind, _, key = label.partition(":")
        done_labels.add(label)
        if kind == "find": finders[key] = res
        elif kind == "verify": verifiers[key] = res
        elif kind == "recheck": rechecks[key] = res
    for aid, (label, phase) in started.items():
        if label not in done_labels and f"{wlabel}/{label}" not in missing:
            missing.append(f"{wlabel}/{label}")
    for key, res in finders.items():
        summaries[f"{wlabel}/{key}"] = res.get("area_summary", "")
        nits[f"{wlabel}/{key}"] = res.get("minor_nits", [])
        coverage[f"{wlabel}/{key}"] = res.get("coverage_notes", "")
        vmap = {v["index"]: v for v in (verifiers.get(key) or {}).get("verdicts", [])}
        rmap = {v["index"]: v for v in (rechecks.get(key) or {}).get("verdicts", [])}
        for i, f in enumerate(res.get("findings", [])):
            f = dict(f); f["index"] = i; f["finder"] = key; f["workflow"] = wlabel
            v = vmap.get(i)
            if v:
                f["verdict"] = v["verdict"]; f["severity"] = v.get("severity") or f["severity"]
                f["verifier_notes"] = v.get("notes", "")
                if v.get("corrected_title"): f["title"] = v["corrected_title"]
                if v.get("corrected_proposal"): f["proposal"] = v["corrected_proposal"]
            else:
                f["verdict"] = "unverified" if key in verifiers else "pending"
            r = rmap.get(i)
            if r:
                f["recheck"] = r["verdict"]; f["recheck_notes"] = r.get("notes", "")
                f["severity"] = r.get("severity") or f["severity"]
                if r["verdict"] == "refuted": f["verdict"] = "refuted"
            all_findings.append(f)

# stable ids + compact index for judges/writers
all_findings.sort(key=lambda f: (f["workflow"], f["finder"], f["index"]))
for n, f in enumerate(all_findings, 1):
    f["id"] = f"F{n:03d}"
# cross-workflow duplicate hints: same file, |line diff| <= 40, or same file + shared rare title words
def words(t): return set(w for w in re.findall(r"[a-z_]{5,}", t.lower()) if w not in {"should","which","their","there","never","always","after","before","because","would","could","without","while","every","these","those","other","first","still","being"})
for i, a in enumerate(all_findings):
    dups = []
    for b in all_findings[:i]:
        if a["file"] != b["file"]: continue
        close = abs(int(a["line"]) - int(b["line"])) <= 12 and a["finder"] != b["finder"]
        shared = len(words(a["title"]) & words(b["title"]))
        if close or shared >= 4:
            dups.append(b["id"])
    if dups: a["possible_duplicate_of"] = dups
IDX = OUT.replace("all-findings.json", "findings-index.md")
with open(IDX, "w") as fh:
    fh.write("# Findings index (id | verdict | severity | category | effort | file:line | title)\n\n")
    for f in all_findings:
        if f["verdict"] == "refuted": continue
        fh.write(f"- {f['id']} | {f['verdict']}{'/'+f['recheck'] if f.get('recheck') else ''} | {f['severity']} | {f['category']} | {f['effort']} | {f['file']}:{f['line']} | {f['title']}{' [dup? ' + ','.join(f['possible_duplicate_of']) + ']' if f.get('possible_duplicate_of') else ''}\n")
    fh.write("\n# Refuted (for the record)\n\n")
    for f in all_findings:
        if f["verdict"] != "refuted": continue
        fh.write(f"- {f['id']} | refuted | {f['category']} | {f['file']}:{f['line']} | {f['title']} :: {f.get('verifier_notes','')[:200]}\n")
json.dump({"findings": all_findings, "area_summaries": summaries, "minor_nits": nits, "coverage_notes": coverage, "missing_results": missing}, open(OUT, "w"), indent=1)
alive = [f for f in all_findings if f["verdict"] not in ("refuted",)]
print(f"total findings: {len(all_findings)}  surviving: {len(alive)}  missing agents: {len(missing)}")
c = collections.Counter((f["verdict"]) for f in all_findings); print("verdicts:", dict(c))
c = collections.Counter((f["severity"], f["category"]) for f in alive)
for k, v in sorted(c.items()): print(f"  {k[0]:6} {k[1]:12} {v}")
print("per finder:", dict(collections.Counter(f["workflow"]+"/"+f["finder"] for f in alive)))
if missing: print("MISSING:", missing)

# ---- per-bucket exports for the section writers ----
BUCKETS = {
    "1-bugs-security": {"bug", "security"},
    "2-cleanup-refactor-perf-deps": {"cleanup", "refactor", "perf", "deps"},
    "3-enhancements-features": {"enhancement", "feature"},
    "4-docs-tests-tooling-a11y": {"docs", "test", "ci-tooling", "a11y"},
}
sev_rank = {"high": 0, "medium": 1, "low": 2}
os.makedirs("buckets", exist_ok=True)
keep = ["id", "title", "category", "severity", "effort", "file", "line", "verdict", "recheck", "evidence", "rationale", "proposal", "verifier_notes", "recheck_notes", "finder", "workflow", "possible_duplicate_of"]
for name, cats in BUCKETS.items():
    rows = [ {k: f.get(k) for k in keep if f.get(k) not in (None, "", [])} for f in all_findings if f["category"] in cats and f["verdict"] != "refuted" and f["workflow"] != "gap-critic" ]
    rows.sort(key=lambda f: (sev_rank.get(f["severity"], 3), f["file"], int(f["line"])))
    json.dump(rows, open(f"buckets/{name}.json", "w"), indent=1)
    print(f"bucket {name}: {len(rows)} findings, {sum(1 for r in rows if r['severity']=='high')} high, {sum(1 for r in rows if r['severity']=='medium')} medium")
# refuted list + nits + area summaries for the assembler
json.dump({"refuted": [ {k: f.get(k) for k in ["id","title","file","line","category","verifier_notes","recheck_notes"]} for f in all_findings if f["verdict"] == "refuted"],
           "area_summaries": summaries, "coverage_notes": coverage, "minor_nits": nits, "missing_agents": missing},
          open("buckets/meta.json", "w"), indent=1)

# gap-critic findings get their own bucket (the four main sections were written before they existed)
rows = [ {k: f.get(k) for k in keep if f.get(k) not in (None, "", [])} for f in all_findings if f["workflow"] == "gap-critic" and f["verdict"] != "refuted" ]
rows.sort(key=lambda f: (sev_rank.get(f["severity"], 3), f["file"], int(f["line"])))
json.dump(rows, open("buckets/5-gap-slices.json", "w"), indent=1)
print(f"bucket 5-gap-slices: {len(rows)} findings, {sum(1 for r in rows if r['severity']=='high')} high, {sum(1 for r in rows if r['severity']=='medium')} medium")
