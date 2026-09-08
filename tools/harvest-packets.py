#!/usr/bin/env python3
"""harvest-packets.py -- stages 2-3 of a rule harvest: model packets and their gates.

Why: the judgement stages of a harvest (which fixes generalise, into which
rule) cost model tokens per diff. This script keeps that spend bounded and
verifiable: it writes one packet file per unit of work, so a cheap subagent
reads the diff and the orchestrator never does; it validates every reply
against a schema and discards what does not conform; and it cross-checks cheap
labels against the deterministic signals from harvest-history.py. Pipeline and
model routing: .claude/skills/astgrep-rules/references/harvest-pipeline.md

Usage:
  harvest-packets.py label-emit   --corpus candidates.jsonl --work WORK
  harvest-packets.py label-ingest --corpus candidates.jsonl --work WORK
  harvest-packets.py cluster-emit --corpus candidates.jsonl --work WORK [--chunk 12]
  harvest-packets.py cluster-ingest --work WORK
  harvest-packets.py dedupe       --work WORK [--threshold 0.5]
  harvest-packets.py status       --work WORK

Layout under WORK:
  label/packets/<short>.json    one candidate each, for a Haiku-class agent
  label/replies/<short>.json    the agent's reply (schema below)
  label/labels.jsonl            validated labels, one per candidate
  cluster/packets/<key>.json    one (language, class) cluster, for a Sonnet agent
  cluster/replies/<key>.json    proposals for that cluster
  cluster/proposals.jsonl       validated proposals, one per line
  dedupe.tsv                    proposal -> nearest shipped/rejected rule, score

Reply schemas (validated on ingest; anything else is rejected and listed):
  label:    {"id": short, "class": TAXONOMY member, "language": "go"|"c",
             "confidence": "low"|"medium"|"high", "summary": <=160 chars}
  cluster:  {"cluster": key, "proposals": [{"id": kebab-case, "language",
             "claim", "classification": "syntactic"|"taint"|"cross-function"|
             "noise", "positive": source, "near_miss": source,
             "supporting": [shorts], "overlaps": [rule ids], "rationale"}]}
Labels must match the corpus language hint. Proposal IDs must be globally
unique across replies; reconcile duplicate replies before ingesting again.
Each proposal must cite at least one supporting commit from its cluster.
Cluster emission revalidates current label replies against the manifest and
cached labels; edited replies require another label-ingest before clustering.
Exit: 0 when every reply present is valid; 1 when any reply was rejected or a
packet has no reply (listed on stderr), so a grind loop can gate on it.
Side effects: writes only under WORK. No network, no model calls: dispatching
the packets is the orchestrator's job (see the pipeline reference).
Emission is idempotent only for identical input. Changed or incomplete packet
state is refused with existing data preserved; use a fresh WORK and regenerate
replies. Each stage's manifest binds ingestion to the emitted packet set and
exact UTF-8 prompt bytes in PROMPT.md; changed instructions require fresh work.
Limits: dedupe is token overlap on ids, messages and rejected-candidate
entries -- it ranks likely duplicates for a reader, it does not decide.
Extend: TAXONOMY and harvest-history.py:signal_terms() together; schemas in validate_*().
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Fixed defect taxonomy. The label agent must pick one; "other" is allowed so
# it never has to force a fit. Each class maps to the harvest signal that
# should usually accompany it, which is how label-ingest measures agreement.
TAXONOMY = {
    "nil-deref": "nil-deref",
    "bounds": "bounds",
    "int-cast": "int-cast",
    "pool-reset": "pool-reuse",
    "panic-on-input": "panic",
    "unchecked-err": "unchecked-err",
    "concurrency": "concurrency",
    "alloc-free": "alloc",
    "memcpy-len": "memcpy",
    "string-len": "string-len",
    "encoding": "encoding",
    "api-misuse": None,
    "logic": None,
    "other": None,
}
DIFF_LIMIT = 3000  # chars of diff per candidate inside a packet


def read_jsonl(path: Path) -> list[dict]:
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except (OSError, ValueError) as error:
        sys.exit(f"cannot read JSONL input {path}: {error}; run the preceding stage first")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def language_of(candidate: dict) -> str:
    return "c" if any(f.endswith((".c", ".h")) for f in candidate["files"]) else "go"


def trimmed_diff(diff: str) -> str:
    return diff if len(diff) <= DIFF_LIMIT else diff[:DIFF_LIMIT] + "\n[...truncated]"


def label_packets(corpus):
    """Build the canonical packet contents used by both emission and ingest."""
    return {c["short"]: {
        "id": c["short"], "repo": c["repo"], "subject": c["subject"],
        "files": c["files"], "language_hint": language_of(c),
        "diff": trimmed_diff(c["diff"]),
        "candidate_digest": hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest(),
    } for c in corpus}


def packet_state(stage: Path, expected: dict, prompt: str, allow_new: bool = False) -> bool:
    """Refuse stale/incomplete state without deleting any packets or replies."""
    paths = sorted((stage / "packets").glob("*.json"))
    if (allow_new and not paths and not (stage / "manifest.json").exists()
            and not (stage / "PROMPT.md").exists()
            and not any((stage / "replies").glob("*.json"))):
        return True
    if not allow_new and not (stage / "manifest.json").exists():
        print("missing packet manifest; run the emit stage first", file=sys.stderr)
        return False
    actual = {}
    try:
        actual = {path.stem: json.loads(path.read_text()) for path in paths}
        manifest = json.loads((stage / "manifest.json").read_text())
        prompt_bytes = (stage / "PROMPT.md").read_bytes()
    except (OSError, ValueError) as error:
        print(f"invalid packet state: {error}; use a fresh --work directory", file=sys.stderr)
        return False
    extra_replies = {p.stem for p in (stage / "replies").glob("*.json")} - expected.keys()
    if (actual != expected or extra_replies
            or manifest != {"packets": expected, "prompt": prompt}
            or prompt_bytes != prompt.encode("utf-8")):
        print("stale or incomplete packet state; use a fresh --work directory "
              "and regenerate replies (existing files preserved)", file=sys.stderr)
        return False
    return True


def emit_packets(stage: Path, expected: dict, prompt: str) -> bool:
    """Idempotent emission; incompatible prior work is retained and refused."""
    if not packet_state(stage, expected, prompt, allow_new=True):
        return False
    (stage / "packets").mkdir(parents=True, exist_ok=True)
    (stage / "replies").mkdir(exist_ok=True)
    (stage / "PROMPT.md").write_bytes(prompt.encode("utf-8"))
    for key, packet in expected.items():
        (stage / "packets" / f"{key}.json").write_text(json.dumps(packet, indent=1))
    (stage / "manifest.json").write_text(json.dumps(
        {"packets": expected, "prompt": prompt}, sort_keys=True))
    return True


# ---------------------------------------------------------------- label stage

LABEL_PROMPT = """You classify one bug-fix commit into a fixed defect taxonomy.
Read the diff. Reply with exactly one JSON object and nothing else:
{"id": "<the id field>", "class": <one of the classes>, "language": "go"|"c",
 "confidence": "low"|"medium"|"high", "summary": "<=160 chars: what was wrong>"}
Classes: %s
Rules: pick the class that names the defect the fix removes, not the code area.
Use "other" when none fits. Do not judge whether the fix is important or
generalisable; do not propose rules; do not explain outside the JSON."""


def label_emit(args) -> int:
    corpus = read_jsonl(args.corpus)
    out = args.work / "label" / "packets"
    if not emit_packets(args.work / "label", label_packets(corpus),
                        LABEL_PROMPT % ", ".join(TAXONOMY)):
        return 1
    print(f"wrote {len(corpus)} label packets to {out}", file=sys.stderr)
    return 0


def validate_label(reply: dict, packet_id: str) -> str | None:
    if not isinstance(reply, dict):
        return "not an object"
    if reply.get("id") != packet_id:
        return f"id mismatch: {reply.get('id')!r}"
    if not isinstance(reply.get("class"), str) or reply["class"] not in TAXONOMY:
        return f"class not in taxonomy: {reply.get('class')!r}"
    if reply.get("language") not in ("go", "c"):
        return f"bad language: {reply.get('language')!r}"
    if reply.get("confidence") not in ("low", "medium", "high"):
        return f"bad confidence: {reply.get('confidence')!r}"
    s = reply.get("summary")
    if not isinstance(s, str) or not s.strip() or len(s) > 160:
        return "summary missing or over 160 chars"
    return None


def collect_labels(stage, corpus):
    """Derive validated labels from the current replies without writing state."""
    packets = sorted((stage / "packets").glob("*.json"))
    labels, bad, missing, agree = [], [], [], 0
    for p in packets:
        reply_path = stage / "replies" / p.name
        if not reply_path.exists():
            missing.append(p.stem)
            continue
        try:
            reply = json.loads(reply_path.read_text())
        except json.JSONDecodeError as e:
            bad.append((p.stem, f"invalid JSON: {e}"))
            continue
        err = validate_label(reply, p.stem)
        if err:
            bad.append((p.stem, err))
            continue
        c = corpus[p.stem]
        if reply["language"] != language_of(c):
            bad.append((p.stem, f"language disagrees with corpus: expected {language_of(c)!r}"))
            continue
        expected_signal = TAXONOMY[reply["class"]]
        # Agreement: the class's companion signal was seen by the regex pass.
        # Disagreement is not an error; it routes the candidate to the
        # "unresolved" cluster so a stronger reader sees it.
        agreed = expected_signal is None or expected_signal in c["signals"]
        agree += agreed
        labels.append({**reply, "agreed": agreed, "signals": c["signals"],
                       "density": c["density"], "repo": c["repo"], "url": c["url"]})
    return labels, bad, missing, agree


def label_ingest(args) -> int:
    corpus = {c["short"]: c for c in read_jsonl(args.corpus)}
    if not packet_state(args.work / "label", label_packets(corpus.values()),
                        LABEL_PROMPT % ", ".join(TAXONOMY)):
        return 1
    labels, bad, missing, agree = collect_labels(args.work / "label", corpus)
    write_jsonl(args.work / "label" / "labels.jsonl", labels)
    hist: dict[str, int] = defaultdict(int)
    for lb in labels:
        hist[lb["class"]] += 1
    print(f"labels: {len(labels)} valid, {len(bad)} rejected, {len(missing)} missing; "
          f"signal agreement {agree}/{len(labels)}", file=sys.stderr)
    for k, n in sorted(hist.items(), key=lambda kv: -kv[1]):
        print(f"  {k:16s} {n}", file=sys.stderr)
    for stem, why in bad:
        print(f"REJECT {stem}: {why}", file=sys.stderr)
    for stem in missing[:20]:
        print(f"MISSING {stem}", file=sys.stderr)
    return 1 if bad or missing else 0


# -------------------------------------------------------------- cluster stage

CLUSTER_PROMPT = """You propose ast-grep rules from a cluster of bug-fix commits
that share one defect class and language. Read every diff. For each *reusable*
defect shape you can state as a single-function syntactic claim, emit one
proposal. Reply with exactly one JSON object and nothing else:
{"cluster": "<the cluster field>", "proposals": [
  {"id": "<lang>-<kebab-case-defect>", "language": "go"|"c",
   "claim": "one sentence: the exact syntax shape that is reported",
   "classification": "syntactic"|"taint"|"cross-function"|"noise",
   "positive": "<minimal inert source that must match>",
   "near_miss": "<minimal inert source differing in one property that must not match>",
   "supporting": ["<commit shorts from this cluster that exhibit it>"],
   "overlaps": ["<ids from shipped_rules that cover the same ground, or empty>"],
   "rationale": "<=300 chars: why this generalises beyond the originating code"}
]}
Rules: a claim that needs types, dataflow, ownership, reachability, or a guard
elsewhere is "taint" or "cross-function" -- still emit it, with the reason, so
it can be recorded as rejected and not re-mined. Do not repeat a shipped or
rejected rule; cite it in overlaps instead. An empty proposals list is a valid
answer. Do not write YAML."""


def shipped_rules(language: str) -> list[dict]:
    rows = []
    for path in sorted((ROOT / "rules" / language).rglob("*.yml")):
        document = yaml.safe_load(path.read_text())
        if not isinstance(document, dict):
            sys.exit(f"invalid shipped rule {path}: expected a YAML mapping")
        msg = " ".join(str(document.get("message", "")).split())
        rows.append({"id": path.stem, "message": msg[:160]})
    return rows


def rejected_entries(language: str) -> list[str]:
    path = ROOT / "docs" / "rejected-candidates.md"
    if not path.exists():
        return []
    section = re.split(r"^## ", path.read_text(), flags=re.MULTILINE)
    out = []
    for block in section:
        head = block.split("\n", 1)[0]
        if language in head.split() or (language == "c" and "nginx" in head):
            # Two entry spellings exist in the file: "- `id`" and "- **id**".
            out += re.findall(r"^- (?:`([^`]+)`|\*\*([^*]+)\*\*)", block, re.MULTILINE)
    out = [a or b for a, b in out]
    return out


def cluster_labels(args, corpus):
    """Require current complete labeling before any cluster packet writes."""
    labels = read_jsonl(args.work / "label" / "labels.jsonl")
    if not packet_state(args.work / "label", label_packets(corpus.values()),
                        LABEL_PROMPT % ", ".join(TAXONOMY)):
        return None
    current, bad, missing, _ = collect_labels(args.work / "label", corpus)
    if bad or missing or labels != current:
        print("label replies changed or are invalid; run label-ingest first", file=sys.stderr)
        return None
    if {label["id"] for label in labels} != corpus.keys():
        print("labels do not cover current corpus; run label-ingest first", file=sys.stderr)
        return None
    if args.chunk < 1:
        print("--chunk must be positive", file=sys.stderr)
        return None
    return labels


def cluster_emit(args) -> int:
    corpus = {c["short"]: c for c in read_jsonl(args.corpus)}
    labels = cluster_labels(args, corpus)
    if labels is None:
        return 1
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for lb in labels:
        cls = lb["class"] if lb["agreed"] or lb["class"] in ("other", "logic", "api-misuse") \
            else "unresolved"
        groups[(lb["language"], cls)].append(lb)
    out = args.work / "cluster" / "packets"
    expected = {}
    n = 0
    for (lang, cls), members in sorted(groups.items()):
        if len(members) < args.min_size:
            continue
        members.sort(key=lambda m: -m["density"])
        # A cluster larger than --chunk is split into numbered parts so one
        # packet stays within a single bounded read; each part carries the
        # same shipped/rejected context and is proposed on independently.
        parts = [members[i:i + args.chunk] for i in range(0, len(members), args.chunk)]
        for idx, part in enumerate(parts, 1):
            key = f"{lang}-{cls}" + (f"-{idx}" if len(parts) > 1 else "")
            packet = {
                "cluster": key, "language": lang, "class": cls,
                "part": f"{idx}/{len(parts)}",
                "candidates": [{
                    "short": m["id"], "url": m["url"], "subject": corpus[m["id"]]["subject"],
                    "summary": m["summary"], "diff": trimmed_diff(corpus[m["id"]]["diff"]),
                } for m in part],
                "shipped_rules": shipped_rules(lang),
                "rejected_candidates": rejected_entries(lang),
            }
            expected[key] = packet
            n += 1
            print(f"  {key:28s} {len(part):3d} candidates", file=sys.stderr)
    if not emit_packets(args.work / "cluster", expected, CLUSTER_PROMPT):
        return 1
    print(f"wrote {n} cluster packets to {out}", file=sys.stderr)
    return 0


# Harvest proposals cover Go/C only; rule-scaffold also accepts other languages
# and shorter names for manually authored rules.
KEBAB = re.compile(r"^(go|c|nginx)-[a-z0-9]+(-[a-z0-9]+)+$")


def proposal_shape(proposal) -> str | None:
    """Reject malformed model fields before string and set operations."""
    strings = ("id", "language", "claim", "classification", "positive", "near_miss", "rationale")
    if not isinstance(proposal, dict):
        return "not an object"
    for field in strings:
        value = proposal.get(field)
        if not isinstance(value, str) or not value.strip():
            return f"{field} must be a nonempty string"
    for field in ("supporting", "overlaps"):
        value = proposal.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            return f"{field} must be a list of strings"
    return None


def validate_proposal(proposal: dict, members: set[str]) -> str | None:
    """Check typed proposal fields against the published cluster schema."""
    error = proposal_shape(proposal)
    if error:
        return error
    if not KEBAB.fullmatch(proposal["id"]):
        return f"id {proposal['id']!r} is not <lang>-kebab-case"
    language = proposal["language"]
    prefixes = ("c-", "nginx-") if language == "c" else ("go-",)
    if language not in ("go", "c") or not proposal["id"].startswith(prefixes):
        return "language and id prefix disagree"
    if proposal["classification"] not in ("syntactic", "taint", "cross-function", "noise"):
        return "bad classification"
    if not proposal["supporting"] or not set(proposal["supporting"]) <= members:
        return "supporting must cite at least one commit and only commits from the cluster"
    if proposal["positive"].strip() == proposal["near_miss"].strip():
        return "positive equals near_miss"
    if len(proposal["rationale"]) > 300:
        return "rationale over 300 chars"
    return None


def validate_cluster(reply: dict, key: str, members: set[str],
                     language: str) -> tuple[str | None, list]:
    if not isinstance(reply, dict) or reply.get("cluster") != key:
        return "cluster key mismatch or not an object", []
    props = reply.get("proposals")
    if not isinstance(props, list):
        return "proposals is not a list", []
    for i, p in enumerate(props):
        error = validate_proposal(p, members)
        if error:
            return f"proposal {i}: {error}", []
        if p["language"] != language:
            return f"proposal {i}: language disagrees with cluster: expected {language!r}", []
    return None, props


def cluster_manifest(stage):
    """Require the complete packet set recorded by cluster emission."""
    try:
        manifest = json.loads((stage / "manifest.json").read_text())
    except (OSError, ValueError) as error:
        print(f"missing or invalid cluster manifest: {error}; run cluster-emit first",
              file=sys.stderr)
        return None
    packets = manifest.get("packets") if isinstance(manifest, dict) else None
    if not isinstance(packets, dict):
        print("cluster manifest lacks packet mapping; use a fresh --work directory", file=sys.stderr)
        return None
    if not packet_state(stage, packets, CLUSTER_PROMPT):
        return None
    return packets


def reject_duplicate_proposals(proposals, bad):
    """Keep every ambiguous ID out of scaffold input and retain replies to reconcile."""
    duplicates = {rule_id for rule_id, count in Counter(p["id"] for p in proposals).items()
                  if count > 1}
    by_cluster = defaultdict(set)
    for proposal in proposals:
        if proposal["id"] in duplicates:
            by_cluster[proposal["cluster"]].add(proposal["id"])
    for cluster, ids in sorted(by_cluster.items()):
        bad.append((cluster, f"duplicate proposal id: {', '.join(sorted(ids))}; reconcile replies"))
    return [proposal for proposal in proposals if proposal["id"] not in duplicates]


def cluster_packet_fields(packet):
    """Validate one packet from the manifest snapshot consumed by ingestion."""
    try:
        if not isinstance(packet, dict):
            raise TypeError("packet must be an object")
        candidates = packet.get("candidates")
        language = packet.get("language")
        if not isinstance(candidates, list):
            raise TypeError("candidates must be a list")
        if not candidates:
            raise ValueError("candidates must not be empty")
        if not isinstance(language, str):
            raise TypeError("language must be a string")
        if not language:
            raise ValueError("language must not be empty")
        if any(not isinstance(candidate, dict)
               or not isinstance(candidate.get("short"), str)
               or not candidate["short"] for candidate in candidates):
            raise TypeError("every candidate needs a nonempty string short id")
        return ({candidate["short"] for candidate in candidates}, language), None
    except (ValueError, KeyError, TypeError) as error:
        return None, f"invalid packet: {error}"


def cluster_ingest(args) -> int:
    packets = cluster_manifest(args.work / "cluster")
    if packets is None:
        return 1
    proposals, bad, missing = [], [], []
    for stem, packet in sorted(packets.items()):
        reply_path = args.work / "cluster" / "replies" / f"{stem}.json"
        if not reply_path.exists():
            missing.append(stem)
            continue
        loaded, error = cluster_packet_fields(packet)
        if error:
            bad.append((stem, error))
            continue
        members, language = loaded
        try:
            reply_text = reply_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            bad.append((stem, f"cannot read reply: {error}"))
            continue
        try:
            reply = json.loads(reply_text)
        except json.JSONDecodeError as e:
            bad.append((stem, f"invalid JSON: {e}"))
            continue
        err, props = validate_cluster(reply, stem, members, language)
        if err:
            bad.append((stem, err))
            continue
        for pr in props:
            proposals.append({**pr, "cluster": stem})
    proposals = reject_duplicate_proposals(proposals, bad)
    write_jsonl(args.work / "cluster" / "proposals.jsonl", proposals)
    hist: dict[str, int] = defaultdict(int)
    for pr in proposals:
        hist[pr["classification"]] += 1
    print(f"proposals: {len(proposals)} from {len(packets) - len(bad) - len(missing)} clusters; "
          f"{len(bad)} rejected, {len(missing)} missing", file=sys.stderr)
    for k, n in sorted(hist.items()):
        print(f"  {k:16s} {n}", file=sys.stderr)
    for stem, why in bad:
        print(f"REJECT {stem}: {why}", file=sys.stderr)
    for stem in missing:
        print(f"MISSING {stem}", file=sys.stderr)
    return 1 if bad or missing else 0


# --------------------------------------------------------------------- dedupe

STOP = {"the", "a", "an", "of", "in", "on", "to", "and", "or", "is", "for", "with",
        "without", "not", "go", "c", "nginx", "rule", "call", "use", "uses", "used"}


def tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2 and t not in STOP}


def dedupe(args) -> int:
    """Rank each proposal against shipped and rejected rules by token containment.

    Containment (proposal tokens found in the target) rather than Jaccard, so a
    long shipped message cannot dilute a short id that names the same thing.
    The proposal's own `overlaps` list is reported alongside: a self-declared
    overlap is a stronger signal than any string score.
    """
    proposals = read_jsonl(args.work / "cluster" / "proposals.jsonl")
    index: list[tuple[str, str, set[str]]] = []
    for lang in ("go", "c"):
        for r in shipped_rules(lang):
            index.append((r["id"], "shipped", tokens(r["id"] + " " + r["message"])))
        for rid in rejected_entries(lang):
            index.append((rid, "rejected", tokens(rid)))
    rows = ["proposal\tclassification\tnearest\tkind\tscore\tdeclared\tflag"]
    flagged = 0
    for p in proposals:
        mine = tokens(p["id"]) | tokens(p["claim"])
        idt = tokens(p["id"])
        best = ("", "", 0.0)
        for rid, kind, theirs in index:
            # Id-vs-id containment weighs most; claim tokens refine ties.
            score = 0.7 * (len(idt & theirs) / max(len(idt), 1)) \
                + 0.3 * (len(mine & theirs) / max(len(mine), 1))
            if score > best[2]:
                best = (rid, kind, score)
        declared = ",".join(p.get("overlaps") or [])
        flag = "DUP?" if best[2] >= args.threshold or declared else ""
        flagged += bool(flag)
        rows.append(f"{p['id']}\t{p['classification']}\t{best[0]}\t{best[1]}\t"
                    f"{best[2]:.2f}\t{declared}\t{flag}")
    (args.work / "dedupe.tsv").write_text("\n".join(rows) + "\n")
    print(f"dedupe: {len(proposals)} proposals, {flagged} flagged (score >= {args.threshold} "
          f"or declared overlap); see {args.work / 'dedupe.tsv'}", file=sys.stderr)
    return 0


def status(args) -> int:
    def count(rel):
        d = args.work / rel
        return len(list(d.glob("*.json"))) if d.exists() else 0
    lab = args.work / "label" / "labels.jsonl"
    prop = args.work / "cluster" / "proposals.jsonl"
    print(f"label   packets={count('label/packets')} replies={count('label/replies')} "
          f"valid={len(read_jsonl(lab)) if lab.exists() else 0}")
    print(f"cluster packets={count('cluster/packets')} replies={count('cluster/replies')} "
          f"proposals={len(read_jsonl(prop)) if prop.exists() else 0}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, needs_corpus in (
        ("label-emit", label_emit, True), ("label-ingest", label_ingest, True),
        ("cluster-emit", cluster_emit, True), ("cluster-ingest", cluster_ingest, False),
        ("dedupe", dedupe, False), ("status", status, False),
    ):
        sp = sub.add_parser(name)
        sp.add_argument("--work", type=Path, required=True)
        if needs_corpus:
            sp.add_argument("--corpus", type=Path, required=True)
        if name == "cluster-emit":
            sp.add_argument("--min-size", type=int, default=1)
            sp.add_argument("--chunk", type=int, default=12,
                            help="max candidates per packet; larger clusters split")
        if name == "dedupe":
            sp.add_argument("--threshold", type=float, default=0.5)
        sp.set_defaults(fn=fn)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
