#!/usr/bin/env python3
"""harvest-packets.py -- mechanically sift fixes and gate bounded model packets.

Why: the judgement stages of a harvest (which fixes generalise, into which
rule) cost model tokens per diff. This script keeps that spend bounded and
verifiable: it writes one packet file per unit of work, so a cheap subagent
reads the diff and the orchestrator never does; it validates every reply
against a schema and discards what does not conform; and it cross-checks cheap
labels against the deterministic signals from harvest-history.py. Pipeline and
model routing: docs/authoring.md#harvest-and-draft-pipeline

Usage:
  harvest-packets.py cluster-emit --mechanical --corpus candidates.jsonl --work WORK
  harvest-packets.py label-emit   --corpus candidates.jsonl --work WORK
  harvest-packets.py label-ingest --corpus candidates.jsonl --work WORK
  harvest-packets.py cluster-emit --corpus candidates.jsonl --work WORK [--chunk 12]
  harvest-packets.py cluster-ingest --work WORK
  harvest-packets.py dedupe       --work WORK [--threshold 0.5]
  harvest-packets.py status       --work WORK
  harvest-packets.py queue        --work WORK [--route semantic-model] [--json]

Layout under WORK:
  label/packets/<short>.json    one candidate each, for a Haiku-class agent
  label/replies/<short>.json    the agent's reply (schema below)
  label/labels.jsonl            validated labels, one per candidate
  cluster/packets/<key>.json    one (language, class) cluster, for a Sonnet agent
  cluster/evidence/<short>.json fuller diff, read only when a packet requests it
  cluster/replies/<key>.json    proposals for that cluster
  cluster/proposals.jsonl       validated proposals, one per line
  cluster/dispositions.jsonl    one validated outcome per candidate
  dedupe.tsv                    proposal digest -> nearest shipped/rejected rule, score

Reply schemas (validated on ingest; anything else is rejected and listed):
  label:    {"id": short, "class": TAXONOMY member, "language": native language,
             "confidence": "low"|"medium"|"high", "summary": <=160 chars}
  cluster:  {"cluster": key, "proposals": [{"id": kebab-case, "language",
             "claim", "classification": "syntactic"|"taint"|"cross-function"|
             "noise", "positive": source, "near_miss": source,
             "supporting": [shorts], "overlaps": [rule ids], "rationale"}],
             "dispositions": [[short, [proposal ids]] | [short, reason], ...]}
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
Mechanical clustering preserves every candidate. It routes only simple,
single-file, recognized-signal rewrites to a cheap proposal pass. Ambiguous,
multi-file, many-hunk, truncated, insertion, and deletion shapes receive the
semantic route. Small semantic diffs remain inline; larger ones use a changed-
line excerpt and an on-demand evidence file. Routes are workload hints, never
finding verdicts. The complete post-proposal dedupe still checks every shipped
and rejected ID.
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
CHANGE_LIMIT = 1800
CONTEXT_LINES = 2
RELATED_LIMIT = 12
CHEAP_HUNK_LIMIT = 2
LANGUAGE_SUFFIXES = {
    ".bash": "bash", ".c": "c", ".h": "c", ".go": "go", ".java": "java",
    ".js": "javascript", ".cjs": "javascript", ".mjs": "javascript",
    ".jsx": "javascript", ".lua": "lua", ".php": "php", ".phtml": "php",
    ".py": "python", ".sh": "bash",
}
ID_PREFIXES = {
    "bash": ("sh-",), "c": ("c-", "nginx-", "zstd-"), "go": ("go-",),
    "java": ("java-",), "javascript": ("js-",), "lua": ("lua-",),
    "php": ("php-", "wp-"), "python": ("py-",),
}
NATIVE_LANGUAGES = tuple(ID_PREFIXES)
DISPOSITION_REASONS = {"duplicate", "noise", "no-generalization", "unclear"}
SIGNAL_FAMILIES = {
    "nil-deref": "memory", "alloc": "memory", "free": "memory",
    "pool-reuse": "memory", "memcpy": "memory", "bounds": "bounds",
    "int-cast": "bounds", "string-len": "bounds", "unchecked-err": "api",
    "encoding": "api", "panic": "api", "concurrency": "concurrency",
}
STOP = {"the", "a", "an", "of", "in", "on", "to", "and", "or", "is", "for", "with",
        "without", "not", "go", "c", "nginx", "rule", "call", "use", "uses", "used"}


def read_jsonl(path: Path) -> list[dict]:
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except (OSError, ValueError) as error:
        sys.exit(f"cannot read JSONL input {path}: {error}; run the preceding stage first")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def language_of(candidate: dict) -> str:
    files = candidate.get("files") if isinstance(candidate, dict) else None
    if not isinstance(files, list) or not files or any(not isinstance(f, str) for f in files):
        sys.exit("candidate files must be a nonempty list of strings")
    languages = {
        None if Path(filename).suffix == ".C"
        else LANGUAGE_SUFFIXES.get(Path(filename).suffix.lower())
        for filename in files
    }
    if None in languages:
        sys.exit("candidate contains a source extension unsupported by the native rule pack")
    declared = candidate.get("language")
    if declared is not None and (not isinstance(declared, str) or declared not in ID_PREFIXES):
        sys.exit(f"candidate has unsupported language {declared!r}")
    if len(languages) != 1:
        sys.exit("mixed-language candidates must be split before packet emission")
    language = languages.pop()
    if language is None:  # narrowed above at runtime; keep static checkers honest
        sys.exit("candidate contains an unsupported source extension")
    if declared is not None and declared != language:
        sys.exit(f"candidate language disagrees with source paths: expected {language!r}")
    return language


def cluster_corpus(path: Path) -> dict[str, dict]:
    """Load the cluster-stage schema and reject duplicate or malformed candidates."""
    rows = read_jsonl(path)
    corpus = {}
    for index, candidate in enumerate(rows, 1):
        if not isinstance(candidate, dict):
            sys.exit(f"candidate {index} is not an object")
        required_strings = ("short", "subject", "diff", "url")
        if any(not isinstance(candidate.get(field), str) for field in required_strings):
            sys.exit(f"candidate {index} needs string short, subject, diff, and url")
        rule_id = candidate["short"]
        if not rule_id or rule_id in corpus:
            sys.exit(f"candidate {index} has empty or duplicate short id {rule_id!r}")
        language_of(candidate)
        signals = candidate.get("signals")
        if not isinstance(signals, list) or any(not isinstance(value, str) for value in signals):
            sys.exit(f"candidate {rule_id!r} signals must be a list of strings")
        density = candidate.get("density")
        if isinstance(density, bool) or not isinstance(density, (int, float)):
            sys.exit(f"candidate {rule_id!r} density must be numeric")
        corpus[rule_id] = candidate
    return corpus


def trimmed_diff(diff: str) -> str:
    return diff if len(diff) <= DIFF_LIMIT else diff[:DIFF_LIMIT] + "\n[...truncated]"


def tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 2 and t not in STOP}


def diff_line_sets(lines: list[str]) -> tuple[set[int], set[int]]:
    """Return changed-content and pre-hunk metadata line indexes."""
    changed: set[int] = set()
    metadata: set[int] = set()
    in_hunk = False
    for index, line in enumerate(lines):
        if line.startswith("diff --git "):
            in_hunk = False
        elif line.startswith("@@ "):
            in_hunk = True
        elif in_hunk and line.startswith(("+", "-")):
            changed.add(index)
        elif not in_hunk and line.startswith(("index ", "--- ", "+++ ")):
            metadata.add(index)
    return changed, metadata


def changed_excerpt(diff: str) -> str:
    """Keep changed lines, hunk identity, and two nearby context lines."""
    lines = diff.splitlines()
    changed, metadata = diff_line_sets(lines)
    selected = {index for index, line in enumerate(lines)
                if line.startswith(("diff --git ", "@@ "))}
    for index in changed:
        selected.update(range(max(0, index - CONTEXT_LINES),
                              min(len(lines), index + CONTEXT_LINES + 1)))
    selected_lines = [line for index, line in enumerate(lines)
                      if index in selected and index not in metadata]
    text = "\n".join(selected_lines)
    return text if len(text) <= CHANGE_LIMIT else text[:CHANGE_LIMIT] + "\n[...truncated]"


def edit_kind(diff: str) -> str:
    """Classify the source edit shape without claiming what the defect means."""
    lines = diff.splitlines()
    changed, _metadata = diff_line_sets(lines)
    added = any(lines[index].startswith("+") for index in changed)
    removed = any(lines[index].startswith("-") for index in changed)
    if added and removed:
        return "rewrite"
    if added:
        return "insert"
    if removed:
        return "delete"
    return "empty"


def model_route(candidate: dict, kind: str, family: str) -> tuple[str, str]:
    """Reserve cheap review for bounded, unambiguous rewrite evidence."""
    if kind != "rewrite":
        return "semantic-model", f"edit-{kind}"
    if family == "general":
        return "semantic-model", "unrecognized-signal"
    if len(candidate["files"]) != 1:
        return "semantic-model", "multi-file"
    hunks = sum(line.startswith("@@ ") for line in candidate["diff"].splitlines())
    if hunks < 1 or hunks > CHEAP_HUNK_LIMIT:
        return "semantic-model", "complex-hunks"
    if changed_excerpt(candidate["diff"]).endswith("\n[...truncated]"):
        return "semantic-model", "excerpt-truncated"
    return "cheap-model", "simple-rewrite"


def signal_family(candidate: dict) -> str:
    """Choose a broad deterministic batching hint, never a defect verdict."""
    signals = candidate.get("signals", [])
    return SIGNAL_FAMILIES.get(signals[0], "general") if signals else "general"


def related_prior(candidates: list[dict], rules: list[dict],
                  rejected: list[str]) -> tuple[list[dict], list[str]]:
    """Return bounded hints; the later dedupe still evaluates the complete index."""
    query = set()
    for candidate in candidates:
        query |= tokens(candidate["subject"] + " " + " ".join(candidate.get("signals", []))
                        + " " + changed_excerpt(candidate["diff"]))
    scored_rules = []
    for rule in rules:
        score = len(query & tokens(rule["id"] + " " + rule["message"]))
        if score:
            scored_rules.append((score, rule["id"], rule))
    scored_rejected = []
    for rule_id in rejected:
        score = len(query & tokens(rule_id))
        if score:
            scored_rejected.append((score, rule_id))
    scored_rules.sort(key=lambda row: (-row[0], row[1]))
    scored_rejected.sort(key=lambda row: (-row[0], row[1]))
    return ([row[2] for row in scored_rules[:RELATED_LIMIT]],
            [row[1] for row in scored_rejected[:RELATED_LIMIT]])


def label_packets(corpus):
    """Build the canonical packet contents used by both emission and ingest."""
    return {c["short"]: {
        "id": c["short"], "repo": c["repo"], "subject": c["subject"],
        "files": c["files"], "language_hint": language_of(c),
        "diff": trimmed_diff(c["diff"]),
        "candidate_digest": hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest(),
    } for c in corpus}


def packet_state(stage: Path, expected: dict, prompt: str, allow_new: bool = False,
                 evidence: dict[str, dict] | None = None) -> bool:
    """Refuse stale/incomplete state without deleting any packets or replies."""
    evidence = evidence or {}
    paths = sorted((stage / "packets").glob("*.json"))
    if (allow_new and not paths and not (stage / "manifest.json").exists()
            and not (stage / "PROMPT.md").exists()
            and not any((stage / "evidence").glob("*.json"))
            and not any((stage / "replies").glob("*.json"))):
        return True
    if not allow_new and not (stage / "manifest.json").exists():
        print("missing packet manifest; run the emit stage first", file=sys.stderr)
        return False
    actual = {}
    try:
        actual = {path.stem: json.loads(path.read_text()) for path in paths}
        actual_evidence = {path.stem: json.loads(path.read_text())
                           for path in sorted((stage / "evidence").glob("*.json"))}
        manifest = json.loads((stage / "manifest.json").read_text())
        prompt_bytes = (stage / "PROMPT.md").read_bytes()
    except (OSError, ValueError) as error:
        print(f"invalid packet state: {error}; use a fresh --work directory", file=sys.stderr)
        return False
    extra_replies = {p.stem for p in (stage / "replies").glob("*.json")} - expected.keys()
    expected_manifest = {"packets": expected, "prompt": prompt}
    if evidence:
        expected_manifest["evidence"] = evidence
    if (actual != expected or extra_replies
            or actual_evidence != evidence or manifest != expected_manifest
            or prompt_bytes != prompt.encode("utf-8")):
        print("stale or incomplete packet state; use a fresh --work directory "
              "and regenerate replies (existing files preserved)", file=sys.stderr)
        return False
    return True


WINDOWS_DEVICE_STEMS = ({"CON", "PRN", "AUX", "NUL"}
                        | {f"COM{i}" for i in range(1, 10)}
                        | {f"LPT{i}" for i in range(1, 10)})


def emission_key(key: object) -> bool:
    """Accept a portable basename after the `.json` suffix is added."""
    return (isinstance(key, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", key) is not None
            and len(key.encode("ascii")) + len(".json") <= 255
            and key.split(".", 1)[0].upper() not in WINDOWS_DEVICE_STEMS)


def emission_keys(keys) -> bool:
    """Validate components and case-insensitive uniqueness within one directory."""
    return (all(emission_key(key) for key in keys)
            and len({key.casefold() for key in keys}) == len(keys))


def emit_packets(stage: Path, expected: dict, prompt: str,
                 evidence: dict[str, dict] | None = None) -> bool:
    """Idempotent emission; incompatible prior work is retained and refused."""
    evidence = evidence or {}
    if not emission_keys(expected) or not emission_keys(evidence):
        print("invalid packet or evidence key; expected a basename identifier",
              file=sys.stderr)
        return False
    if not packet_state(stage, expected, prompt, allow_new=True, evidence=evidence):
        return False
    (stage / "packets").mkdir(parents=True, exist_ok=True)
    (stage / "replies").mkdir(exist_ok=True)
    (stage / "PROMPT.md").write_bytes(prompt.encode("utf-8"))
    for key, packet in expected.items():
        (stage / "packets" / f"{key}.json").write_bytes(
            packet_text(packet).encode("utf-8"))
    if evidence:
        (stage / "evidence").mkdir(exist_ok=True)
        for key, record in evidence.items():
            (stage / "evidence" / f"{key}.json").write_text(json.dumps(record, indent=1))
    manifest = {"packets": expected, "prompt": prompt}
    if evidence:
        manifest["evidence"] = evidence
    (stage / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    return True


def packet_text(packet: dict) -> str:
    """Serialize exactly as persisted so accounting matches dispatched input."""
    return json.dumps(packet, indent=1)


def source_bytes(text: str) -> int:
    """Count Git text while preserving bytes decoded with surrogateescape."""
    return len(text.encode("utf-8", "surrogateescape"))


# ---------------------------------------------------------------- label stage

LABEL_PROMPT = """You classify one bug-fix commit into a fixed defect taxonomy.
Read the diff. Reply with exactly one JSON object and nothing else:
{"id": "<the id field>", "class": <one of the classes>, "language": <the language_hint>,
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
    if reply.get("language") not in NATIVE_LANGUAGES:
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

CLUSTER_PROMPT = """You propose ast-grep rules from a same-language fix cluster.
Its class is only a batching hint: either an AI defect label or a mechanical
signal-family plus edit shape. The route selects model capacity, not a verdict.
Read every subject and bounded diff. For every *reusable* defect shape you can
state as a single-function syntactic claim, emit one proposal. Reply with
exactly one JSON object and nothing else:
{"cluster": "<the cluster field>", "proposals": [
  {"id": "<repository prefix>-<kebab-case-defect>", "language": "<cluster language>",
   "claim": "one sentence: the exact syntax shape that is reported",
   "classification": "syntactic"|"taint"|"cross-function"|"noise",
   "positive": "<minimal inert source that must match>",
   "near_miss": "<minimal inert source differing in one property that must not match>",
   "supporting": ["<commit shorts from this cluster that exhibit it>"],
   "overlaps": ["<ids from shipped_rules that cover the same ground, or empty>"],
   "rationale": "<=300 chars: why this generalises beyond the originating code"}
], "dispositions": [
  ["<candidate short>", ["<proposal ids supported by that candidate>"]],
  ["<candidate short with no proposal>", "duplicate"|"noise"|"no-generalization"|"unclear"]
]}
ID prefixes: sh- for bash, c-/nginx-/zstd- for C, go-, java-, js-, lua-,
php-/wp-, and py-. Rules: a claim that needs types, dataflow, ownership,
reachability, or a guard elsewhere is "taint" or "cross-function" -- still emit it, so
it can be recorded as rejected and not re-mined. Do not repeat a shipped or
rejected rule; cite it in overlaps instead. Account for every candidate exactly
once in dispositions. Proposal references and supporting lists must agree in
both directions. An empty proposals list is valid only with a reason for every
candidate. Start with each bounded diff excerpt. Read its `evidence` file only
when the excerpt is truncated or does not establish the claim. Do not write YAML."""


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


def candidate_groups(args, corpus: dict[str, dict], mechanical: bool):
    """Build workload groups, using AI labels only on the legacy path."""
    groups: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    if mechanical:
        for candidate in corpus.values():
            kind = edit_kind(candidate["diff"])
            family = signal_family(candidate)
            route, reason = model_route(candidate, kind, family)
            groups[(language_of(candidate), f"{family}-{kind}", route)].append({
                "id": candidate["short"], "language": language_of(candidate),
                "class": f"{family}-{kind}", "edit": kind,
                "density": candidate["density"],
                "route": route, "route_reason": reason,
            })
        return groups
    labels = cluster_labels(args, corpus)
    if labels is None:
        return None
    for label in labels:
        cls = label["class"] if label["agreed"] or label["class"] in \
            ("other", "logic", "api-misuse") else "unresolved"
        groups[(label["language"], cls, "semantic-model")].append(label)
    return groups


def packet_candidate(member: dict, corpus: dict[str, dict], mechanical: bool) -> dict:
    """Render one legacy or mechanically sifted proposal input."""
    candidate = corpus[member["id"]]
    row = {"short": member["id"], "url": candidate["url"],
           "subject": candidate["subject"]}
    if mechanical:
        full_diff = trimmed_diff(candidate["diff"])
        needs_evidence = (member["route"] == "semantic-model"
                          and len(candidate["diff"]) > CHANGE_LIMIT)
        # Small semantic fixes are cheaper and safer to show in full. Larger
        # ones get a bounded excerpt plus an explicit on-demand evidence file.
        excerpt = changed_excerpt(candidate["diff"]) \
            if member["route"] == "cheap-model" or needs_evidence else full_diff
        row.update({"signals": candidate.get("signals", []), "edit": member["edit"],
                    "route_reason": member["route_reason"],
                    "diff": excerpt})
        if needs_evidence:
            row["evidence"] = f"cluster/evidence/{member['id']}.json"
    else:
        row.update({"summary": member["summary"], "diff": trimmed_diff(candidate["diff"])})
    return row


def packet_evidence(packets: dict[str, dict], corpus: dict[str, dict]) -> dict[str, dict]:
    """Store fuller diffs only where the bounded packet excerpt omits context."""
    ids = {candidate["short"] for packet in packets.values()
           for candidate in packet["candidates"] if "evidence" in candidate}
    return {candidate_id: {
        "short": candidate_id,
        "files": corpus[candidate_id]["files"],
        "diff": trimmed_diff(corpus[candidate_id]["diff"]),
    } for candidate_id in sorted(ids)}


def write_sift_artifacts(work: Path, expected: dict[str, dict], corpus: dict[str, dict],
                         groups: dict[tuple[str, str, str], list[dict]]) -> None:
    """Persist a compact route ledger and reproducible size/count metrics."""
    prompt_bytes = len(CLUSTER_PROMPT.encode("utf-8"))
    rows = ["candidate\tlanguage\tcluster\tedit\troute\treason\tpacket_bytes\tinput_bytes"]
    for packet in (expected[key] for key in sorted(expected)):
        size = len(packet_text(packet).encode("utf-8"))
        for candidate in packet["candidates"]:
            rows.append(f"{candidate['short']}\t{packet['language']}\t{packet['class']}\t"
                        f"{candidate['edit']}\t{packet['route']}\t"
                        f"{candidate['route_reason']}\t{size}\t{size + prompt_bytes}")
    (work / "sift.tsv").write_text("\n".join(rows) + "\n")
    raw_bytes = sum(source_bytes(candidate["diff"]) for candidate in corpus.values())
    packet_bytes = sum(len(packet_text(packet).encode("utf-8"))
                       for packet in expected.values())
    deferred_diff_bytes = sum(
        source_bytes(trimmed_diff(corpus[candidate["short"]]["diff"]))
        - source_bytes(candidate["diff"])
        for packet in expected.values() for candidate in packet["candidates"]
        if "evidence" in candidate
    )
    cheap = sum(member["route"] == "cheap-model"
                for members in groups.values() for member in members)
    semantic_ids = {member["id"] for members in groups.values() for member in members
                    if member["route"] == "semantic-model"}
    reasons = Counter(member["route_reason"]
                      for members in groups.values() for member in members)
    metrics = {"candidates": len(corpus), "packets": len(expected),
               "raw_diff_bytes": raw_bytes, "packet_bytes": packet_bytes,
               "prompt_bytes": prompt_bytes,
               "dispatch_input_bytes": packet_bytes + prompt_bytes * len(expected),
               "deferred_diff_bytes": deferred_diff_bytes,
               "on_demand_evidence": sum(
                   "evidence" in candidate for packet in expected.values()
                   for candidate in packet["candidates"]),
               "cheap_model": cheap, "semantic_model": len(semantic_ids),
               "semantic_diff_truncated": sum(
                   len(corpus[candidate_id]["diff"]) > DIFF_LIMIT
                   for candidate_id in semantic_ids),
               "route_reasons": dict(sorted(reasons.items()))}
    (work / "sift-metrics.json").write_text(
        json.dumps(metrics, sort_keys=True, separators=(",", ":")) + "\n")


def cluster_parts(groups: dict[tuple[str, str, str], list[dict]], min_size: int, chunk: int):
    """Yield stable bounded slices without mutating the route ledger."""
    for (language, cls, route), members in sorted(groups.items()):
        if len(members) < min_size:
            continue
        ordered = sorted(members, key=lambda member: -member["density"])
        total = (len(ordered) + chunk - 1) // chunk
        for start in range(0, len(ordered), chunk):
            yield language, cls, route, start // chunk + 1, total, ordered[start:start + chunk]


def build_cluster_packets(groups: dict[tuple[str, str, str], list[dict]], corpus: dict[str, dict],
                          mechanical: bool, min_size: int, chunk: int) -> dict[str, dict]:
    """Build bounded packets while loading each language's prior-rule index once."""
    expected: dict[str, dict] = {}
    prior = {language: (shipped_rules(language), rejected_entries(language))
             for language in {language for language, _, _ in groups}}
    for language, cls, route, index, total, part in cluster_parts(groups, min_size, chunk):
        route_key = "cheap" if route == "cheap-model" else "semantic"
        key = f"{language}-{cls}" + (f"-{route_key}" if mechanical else "") \
            + (f"-{index}" if total > 1 else "")
        related_rules, related_rejected = related_prior(
            [corpus[member["id"]] for member in part], *prior[language])
        expected[key] = {
            "cluster": key, "language": language, "class": cls, "route": route,
            "part": f"{index}/{total}",
            "candidates": [packet_candidate(member, corpus, mechanical) for member in part],
            "shipped_rules": related_rules if mechanical else prior[language][0],
            "rejected_candidates": related_rejected if mechanical else prior[language][1],
        }
        print(f"  {key:28s} {len(part):3d} candidates", file=sys.stderr)
    return expected


def cluster_emit(args) -> int:
    corpus = cluster_corpus(args.corpus)
    if args.chunk < 1 or args.min_size < 1:
        print("--chunk and --min-size must be positive", file=sys.stderr)
        return 1
    mechanical = getattr(args, "mechanical", False)
    if mechanical and args.min_size != 1:
        print("--mechanical requires --min-size 1 so no candidate is omitted", file=sys.stderr)
        return 1
    groups = candidate_groups(args, corpus, mechanical)
    if groups is None:
        return 1
    out = args.work / "cluster" / "packets"
    expected = build_cluster_packets(
        groups, corpus, mechanical, args.min_size, args.chunk)
    evidence = packet_evidence(expected, corpus) if mechanical else {}
    if mechanical:
        emitted = [candidate["short"] for packet in expected.values()
                   for candidate in packet["candidates"]]
        if len(emitted) != len(corpus) or set(emitted) != corpus.keys():
            print("mechanical packet coverage is incomplete or duplicated", file=sys.stderr)
            return 1
    if not emit_packets(args.work / "cluster", expected, CLUSTER_PROMPT, evidence=evidence):
        return 1
    if mechanical:
        write_sift_artifacts(args.work, expected, corpus, groups)
    print(f"wrote {len(expected)} cluster packets to {out}", file=sys.stderr)
    return 0


KEBAB = re.compile(r"^[a-z][a-z0-9]*-[a-z0-9]+(?:-[a-z0-9]+)+$")


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
    prefixes = ID_PREFIXES.get(language, ())
    if not prefixes or not proposal["id"].startswith(prefixes):
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


def disposition_references(disposition, index: int, members: set[str], seen: set[str],
                           proposal_ids: set[str]) -> tuple[str | None, str, set[str]]:
    """Validate and normalize one compact [candidate, outcome] row."""
    if not isinstance(disposition, list) or len(disposition) != 2:
        return f"disposition {index}: expected [candidate, outcome]", "", set()
    candidate, outcome = disposition
    if not isinstance(candidate, str) or candidate not in members or candidate in seen:
        return f"disposition {index}: candidate is foreign, invalid, or repeated", "", set()
    if isinstance(outcome, str):
        if outcome not in DISPOSITION_REASONS:
            return f"disposition {index}: bad no-proposal reason", "", set()
        return None, candidate, set()
    valid_ids = isinstance(outcome, list) and bool(outcome) \
        and all(isinstance(item, str) for item in outcome) \
        and len(outcome) == len(set(outcome))
    if not valid_ids:
        return (f"disposition {index}: proposal ids must be a nonempty unique string list",
                "", set())
    references = set(outcome)
    if not references <= proposal_ids:
        return f"disposition {index}: references an unknown proposal", "", set()
    return None, candidate, references


def validate_dispositions(dispositions, members: set[str], proposals: list[dict]) -> str | None:
    """Prove exact candidate coverage and both-direction proposal support."""
    if not isinstance(dispositions, list):
        return "dispositions is not a list"
    proposal_by_id = {proposal["id"]: proposal for proposal in proposals}
    seen: set[str] = set()
    references: dict[str, set[str]] = {}
    for index, disposition in enumerate(dispositions):
        error, candidate, proposal_ids = disposition_references(
            disposition, index, members, seen, set(proposal_by_id))
        if error:
            return error
        seen.add(candidate)
        references[candidate] = proposal_ids
    if seen != members:
        return "dispositions must account for every cluster candidate exactly once"
    for proposal_id, proposal in proposal_by_id.items():
        supported = set(proposal["supporting"])
        referenced = {candidate for candidate, ids in references.items()
                      if proposal_id in ids}
        if referenced != supported:
            return f"proposal {proposal_id!r}: supporting and dispositions disagree"
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
    disposition_error = validate_dispositions(reply.get("dispositions"), members, props)
    return (disposition_error, []) if disposition_error else (None, props)


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
        print("cluster manifest lacks packet mapping; use a fresh --work directory",
              file=sys.stderr)
        return None
    evidence = manifest.get("evidence", {})
    if not isinstance(evidence, dict):
        print("cluster manifest has invalid evidence mapping; use a fresh --work directory",
              file=sys.stderr)
        return None
    if not packet_state(stage, packets, CLUSTER_PROMPT, evidence=evidence):
        return None
    return packets


def reject_duplicate_proposals(proposals, bad):
    """Reject whole clusters with ambiguous IDs so aggregates stay self-consistent."""
    duplicates = {rule_id for rule_id, count in Counter(p["id"] for p in proposals).items()
                  if count > 1}
    by_cluster = defaultdict(set)
    for proposal in proposals:
        if proposal["id"] in duplicates:
            by_cluster[proposal["cluster"]].add(proposal["id"])
    for cluster, ids in sorted(by_cluster.items()):
        bad.append((cluster, f"duplicate proposal id: {', '.join(sorted(ids))}; reconcile replies"))
    affected = set(by_cluster)
    return [proposal for proposal in proposals if proposal["cluster"] not in affected], affected


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


def read_cluster_reply(stage: Path, stem: str, packet) -> tuple[list, list, str | None]:
    """Read and validate one reply; return `missing` separately from bad data."""
    reply_path = stage / "replies" / f"{stem}.json"
    if not reply_path.exists():
        return [], [], "missing"
    loaded, error = cluster_packet_fields(packet)
    if error:
        return [], [], error
    members, language = loaded
    try:
        reply_text = reply_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as read_error:
        return [], [], f"cannot read reply: {read_error}"
    try:
        reply = json.loads(reply_text)
    except json.JSONDecodeError as json_error:
        return [], [], f"invalid JSON: {json_error}"
    error, proposals = validate_cluster(reply, stem, members, language)
    if error:
        return [], [], error
    dispositions = [{"candidate": candidate, "outcome": outcome, "cluster": stem}
                    for candidate, outcome in reply["dispositions"]]
    return [{**proposal, "cluster": stem} for proposal in proposals], dispositions, None


def collect_cluster_replies(stage: Path, packets: dict[str, dict]):
    """Collect valid reply rows while retaining packet-local failures."""
    proposals, dispositions, bad, missing = [], [], [], []
    for stem, packet in sorted(packets.items()):
        cluster_proposals, cluster_dispositions, error = read_cluster_reply(
            stage, stem, packet)
        if error == "missing":
            missing.append(stem)
            continue
        if error:
            bad.append((stem, error))
            continue
        proposals.extend(cluster_proposals)
        dispositions.extend(cluster_dispositions)
    return proposals, dispositions, bad, missing


def report_cluster_ingest(proposals: list[dict], dispositions: list[dict],
                          bad: list[tuple[str, str]], missing: list[str], total: int) -> None:
    """Emit a bounded human summary after structured artifacts are written."""
    hist = Counter(proposal["classification"] for proposal in proposals)
    print(f"proposals: {len(proposals)} from {total - len(bad) - len(missing)} clusters; "
          f"{len(bad)} rejected, {len(missing)} missing", file=sys.stderr)
    for classification, count in sorted(hist.items()):
        print(f"  {classification:16s} {count}", file=sys.stderr)
    reasons = Counter(row["outcome"] for row in dispositions
                      if isinstance(row["outcome"], str))
    for reason, count in sorted(reasons.items()):
        print(f"  no-rule/{reason:8s} {count}", file=sys.stderr)
    for stem, why in bad:
        print(f"REJECT {stem}: {why}", file=sys.stderr)
    for stem in missing:
        print(f"MISSING {stem}", file=sys.stderr)


def cluster_ingest(args) -> int:
    stage = args.work / "cluster"
    packets = cluster_manifest(stage)
    if packets is None:
        return 1
    proposals, dispositions, bad, missing = collect_cluster_replies(stage, packets)
    proposals, duplicate_clusters = reject_duplicate_proposals(proposals, bad)
    dispositions = [row for row in dispositions if row["cluster"] not in duplicate_clusters]
    write_jsonl(args.work / "cluster" / "proposals.jsonl", proposals)
    write_jsonl(args.work / "cluster" / "dispositions.jsonl", dispositions)
    report_cluster_ingest(proposals, dispositions, bad, missing, len(packets))
    return 1 if bad or missing else 0


# --------------------------------------------------------------------- dedupe

def dedupe(args) -> int:
    """Rank each proposal against shipped and rejected rules by token containment.

    Containment (proposal tokens found in the target) rather than Jaccard, so a
    long shipped message cannot dilute a short id that names the same thing.
    The proposal's own `overlaps` list is reported alongside: a self-declared
    overlap is a stronger signal than any string score.
    """
    proposals = read_jsonl(args.work / "cluster" / "proposals.jsonl")
    index: list[tuple[str, str, set[str]]] = []
    for lang in NATIVE_LANGUAGES:
        for r in shipped_rules(lang):
            index.append((r["id"], "shipped", tokens(r["id"] + " " + r["message"])))
        for rid in rejected_entries(lang):
            index.append((rid, "rejected", tokens(rid)))
    rows = ["proposal\tproposal_digest\tclassification\tnearest\tkind\tscore\tdeclared\tflag"]
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
        digest = hashlib.sha256(json.dumps(
            p, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        rows.append(f"{p['id']}\t{digest}\t{p['classification']}\t{best[0]}\t{best[1]}\t"
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
    disposition = args.work / "cluster" / "dispositions.jsonl"
    print(f"label   packets={count('label/packets')} replies={count('label/replies')} "
          f"valid={len(read_jsonl(lab)) if lab.exists() else 0}")
    print(f"cluster packets={count('cluster/packets')} replies={count('cluster/replies')} "
          f"proposals={len(read_jsonl(prop)) if prop.exists() else 0} "
          f"dispositions={len(read_jsonl(disposition)) if disposition.exists() else 0}")
    metrics = args.work / "sift-metrics.json"
    if metrics.exists():
        try:
            row = json.loads(metrics.read_text(encoding="utf-8"))
            print(f"sift    candidates={row['candidates']} packets={row['packets']} "
                  f"cheap={row['cheap_model']} semantic={row['semantic_model']} "
                  f"semantic_truncated={row.get('semantic_diff_truncated', 0)} "
                  f"evidence={row.get('on_demand_evidence', 0)} "
                  f"packet_bytes={row['packet_bytes']} prompt_bytes={row.get('prompt_bytes', 0)} "
                  f"dispatch_bytes={row.get('dispatch_input_bytes', row['packet_bytes'])} "
                  f"deferred={row.get('deferred_diff_bytes', 0)}")
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
            print(f"invalid sift metrics: {error}", file=sys.stderr)
            return 1
    return 0


def queue(args) -> int:
    """List only packet replies that still need work, without reading packet bodies."""
    if args.limit < 1:
        print("--limit must be positive", file=sys.stderr)
        return 1
    stage = (args.work / "cluster").resolve()
    packets = cluster_manifest(stage)
    if packets is None:
        return 1
    replies = {}
    valid_proposals = []
    for stem, packet in sorted(packets.items()):
        proposals, _dispositions, error = read_cluster_reply(stage, stem, packet)
        replies[stem] = error
        valid_proposals.extend(proposals)
    duplicate_errors: list[tuple[str, str]] = []
    reject_duplicate_proposals(valid_proposals, duplicate_errors)
    duplicate_by_cluster = dict(duplicate_errors)
    tasks = []
    for stem, packet in sorted(packets.items()):
        route = packet.get("route")
        if args.route not in ("all", route):
            continue
        error = replies[stem] or duplicate_by_cluster.get(stem)
        if error is None:
            continue
        tasks.append({
            "cluster": stem,
            "route": route,
            "candidates": len(packet.get("candidates", [])),
            "state": "missing" if error == "missing" else "retry",
            "error": "" if error == "missing" else error[:160],
            "prompt": str(stage / "PROMPT.md"),
            "packet": str(stage / "packets" / f"{stem}.json"),
            "reply": str(stage / "replies" / f"{stem}.json"),
        })
    selected = tasks[:args.limit]
    if args.json:
        print(json.dumps({"tasks": selected, "remaining": len(tasks) - len(selected)},
                         separators=(",", ":"), sort_keys=True))
    else:
        for task in selected:
            print(f"{task['route']}\t{task['state']}\t{task['cluster']}\t"
                  f"{task['packet']}\t{task['reply']}")
        print(f"queue: shown={len(selected)} remaining={len(tasks) - len(selected)}",
              file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn, needs_corpus in (
        ("label-emit", label_emit, True), ("label-ingest", label_ingest, True),
        ("cluster-emit", cluster_emit, True), ("cluster-ingest", cluster_ingest, False),
        ("dedupe", dedupe, False), ("status", status, False), ("queue", queue, False),
    ):
        sp = sub.add_parser(name)
        sp.add_argument("--work", type=Path, required=True)
        if needs_corpus:
            sp.add_argument("--corpus", type=Path, required=True)
        if name == "cluster-emit":
            sp.add_argument("--min-size", type=int, default=1)
            sp.add_argument("--chunk", type=int, default=12,
                            help="max candidates per packet; larger clusters split")
            sp.add_argument("--mechanical", action="store_true",
                            help="skip AI labels; bound context and cluster mechanically")
        if name == "dedupe":
            sp.add_argument("--threshold", type=float, default=0.5)
        if name == "queue":
            sp.add_argument("--route", default="all",
                            choices=("all", "cheap-model", "semantic-model"))
            sp.add_argument("--limit", type=int, default=20)
            sp.add_argument("--json", action="store_true")
        sp.set_defaults(fn=fn)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
