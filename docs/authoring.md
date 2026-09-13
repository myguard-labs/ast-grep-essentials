# Authoring rules

Checked against ast-grep 0.45.3 on 2026-09-06. The linked upstream pages are
living references; the lockfile and fixtures define this repository's baseline.

## Record enrichment provenance

Every active rule starts with these three comments:

```yaml
# MyGuard rule: https://github.com/myguard-labs/ast-grep-essentials | https://deb.myguard.nl
# Last enriched: 2026-09-13 by qwen3-coder-30b
# Last touched: 2026-09-11 by Thijs Eilander
```

`Last enriched` records the date and reviewer for the latest complete semantic
review of the rule, message, note, fixtures, sources, and documented limits.
Use an exact model ID or a person's public author name. An automated model run
must name its model; do not record a client or orchestration tool as the
reviewer. The standard automated path uses the local Arc-hosted
`qwen3-coder-30b` endpoint and has no Codex, Claude, credentials, proxy
inheritance, or cloud fallback.

`Last touched` records the date and author of the latest substantive edit to
the rule file. For an existing rule, derive both from its most recent Git commit
before adding or refreshing provenance-only comments. Adding or updating only
these comments does not count as touching the rule. A later matcher, diagnostic,
severity, utility, constraint, transform, or fix edit updates `Last touched`;
fixture-only and documentation-only edits do not.

Use ISO 8601 calendar dates (`YYYY-MM-DD`). Keep both comments directly below
the MyGuard comment. During the one-rule-per-PR migration, reviewers enforce
their position and shape; after every active rule has migrated, the inventory
tests enforce the contract pack-wide. These are YAML comments because ast-grep
rejects unsupported top-level metadata, while comments travel with copied rules
and do not change scanning.

Enrichment is review work, not a timestamping shortcut. Run the complete
fixture suite after a pack-wide enrichment, review every proposed matcher or
diagnostic change, and update `Last enriched` only for rules actually examined.
The date and reviewer say who performed that examination; they do not claim
that the reviewer authored the rule or that the rule has no semantic limits.

Ship each enriched rule in its own pull request. That PR may include only the
rule and its directly paired artifacts: its fixture, snapshot, limitation or
source entry, and source plan when one exists. Do not combine two rule IDs in
one enrichment PR, even when their changes are mechanical or closely related.
Repository-wide tooling, tests, and documentation belong in a separate
foundation PR. This keeps each semantic review, provenance claim, test result,
and rollback independently auditable.

## Harvest and draft pipeline

The repository contains the complete command pipeline for turning project
history into rule drafts. Keep its working directory outside the checkout; only
reviewed rules, fixtures, harvest indexes, and source or limitation notes belong
in Git.

1. `harvest-history.py` builds a ranked JSONL corpus and a Markdown index from
   one or more Git histories.
2. `harvest-packets.py cluster-emit --mechanical` routes every candidate into a
   bounded proposal packet. Large semantic diffs are reduced to changed-line
   excerpts; their fuller evidence files are read only when needed. Use `queue`
   to dispatch only missing or invalid replies, then run `cluster-ingest` and
   `dedupe`.
3. `rule-batch.py` validates the proposal and deduplication ledgers, separates
   duplicates and semantic-only proposals, and tests whether syntactic
   proposals have a safe fixture seed. Review `draft-plan.tsv` before using
   `--apply-seeded`. `--queue` lists only unfinished actionable rules and
   `--task ID` emits one compact drafting packet. Both modes revalidate the
   full plan against the current proposal and deduplication ledgers, and fail
   when that plan is stale.
   After reviewing a task's `PASS`, or explicitly accepting its `PARKED` report,
   use the emitted `--mark-reviewed ID` command to remove that exact proposal
   and rule/fixture version from the queue.
4. `rule-scaffold.py` writes a rule/fixture pair and updates the rule-count
   guard. `rule-draft.py` permits four distinct rule/fixture attempts and calls
   `rule-probe.py` for a bounded, isolated verdict.
5. A probe pass proves the local rule contracts only. Review the claim and
   matcher generality, update `sources.md` and `limitations.md` when applicable,
   then run the full `npm test` suite before committing.

Each command's `--help` output defines its flags. Its module docstring and the
persisted packet prompts define artifacts, exit codes, and failure behavior.
A minimal stage 2 through stage 4 sequence is:

```bash
python3 tools/harvest-packets.py cluster-emit --mechanical --corpus C.jsonl --work WORK
python3 tools/harvest-packets.py queue --work WORK --route semantic-model --json
python3 tools/harvest-packets.py cluster-ingest --work WORK
python3 tools/harvest-packets.py dedupe --work WORK
python3 tools/rule-batch.py --work WORK --category correctness
python3 tools/rule-batch.py --work WORK --category correctness --apply-seeded
python3 tools/rule-batch.py --work WORK --category correctness --queue --json
python3 tools/rule-batch.py --work WORK --category correctness --task RULE-ID
# After completing the emitted task's matcher and generality review:
python3 tools/rule-batch.py --work WORK --category correctness --mark-reviewed RULE-ID
```

Harvesting, proposal validation, and fixture-seed checks cover the repository's
native Bash, C, Go, Java, JavaScript, Lua, PHP, and Python packs. PowerShell uses
an optional custom parser and remains outside this generic isolated workflow.

## Generate from a canonical plan

For native-language rules that benefit from repeatable mechanical construction,
keep a v1 plan at `plans/<language>/<category>/<id>.yml`. A plan owns the
corresponding rule and fixture, records positive and negative contrasts, and
can pin exact JSON oracles for ranges, text, diagnostics, labels, or fixed output.

```bash
python3 tools/rule-plan.py plans/python/security/py-tempfile-mktemp.yml
npm run generate:check
npm run generate
```

Plan preflight compiles the matcher, rejects malformed or unreachable local
utilities, runs the isolated fixture contrasts, and weakens structural clauses
one at a time. Every selected mutation must break a test. Generated files carry
an ownership marker; regeneration refuses to overwrite a hand-authored file.
`npm run generate:check` is read-only and fails on drift.

For imported rules, keep license and source provenance in `comments` and
vendor-specific top-level metadata in `extensions`. The compiler rejects
extension keys that could override ast-grep configuration. This makes imported
rules plan-owned without discarding their attribution contract.

Use `python3 tools/rule-mechanics.py metamorph PLAN` to emit bounded lookalike
and boundary candidates for review. Candidates deliberately have no invented
expected result. Use `differential` with two engine binaries and a bounded local
corpus to compare normalized, duplicate-sensitive findings across upgrades.
The versioned `tests/differential/v1` corpus runs in `test:mechanics`; after an
intentional engine or rule behavior change, inspect the JSON delta before using
`corpus-update` to accept the new baseline.

## Define the claim

Start with a small inert example that should match and a closely related one
that should not. Decide whether the rule detects a syntax defect or merely
identifies a site for review. Syntax matching cannot establish runtime
reachability, pointer types, ownership, or input trust. Use a compiler, a
semantic analyzer, or a targeted test for those claims.
See the [upstream FAQ](https://ast-grep.github.io/advanced/faq.html).

## Build the matcher

Use `ast-grep run -l <language> -p '<pattern>' <fixture>` to explore. Patterns
must parse into the intended node. Inspect `--debug-query=sexp` for unexpected
zero or excessive matches. A C `f($ARG)` can parse as a type expression; use a
contextual pattern or a `call_expression` with a `function` field matcher.

`$NAME` captures one named node, `$$NAME` can capture an unnamed node, and
`$$$ARGS` captures a sequence. Reusing a captured name requires matching content;
`$_` is noncapturing. Quote patterns in the shell to preserve dollars.
[Pattern syntax](https://ast-grep.github.io/guide/pattern-syntax.html).

A rule object combines its fields as a conjunction. `kind` plus `pattern` is
valid when both describe the same node. Use `pattern: {context: ..., selector:
...}` to select a node from parseable surrounding code. A mismatched kind can
make the conjunction empty; it does not mean these fields cannot compose.
Use an ordered `all` array when later clauses depend on earlier captures.
[Composition](https://ast-grep.github.io/guide/rule-config/composite-rule.html).

`has` and `inside` traverse children and ancestors; `follows` and `precedes`
express sibling relationships. Choose `field` and `stopBy` deliberately:
`stopBy: end` broadens traversal and can cross contexts that the rule should
exclude. Two required children need two `has` clauses under `all`, not one child
required to have two incompatible kinds.
[Relations](https://ast-grep.github.io/guide/rule-config/relational-rule.html).

Use `constraints` to narrow captured metavariables and local `utils` with
`matches` for reusable logic. Keep utility IDs valid and test every imported
rule with the installed engine. Prefer local utilities for portable rules;
global utilities require consumer `utilDirs` wiring.
[Utilities](https://ast-grep.github.io/guide/rule-config/utility-rule.html),
[rule configuration](https://ast-grep.github.io/reference/yaml.html).

Constrain the operand named in the diagnostic, not every descendant of its
enclosing call. Add near misses with a similar function name, an unrelated
argument, and the same expression outside the intended control-flow position.
In Go, a literal `t` receiver is not evidence of a test handle: constrain its
enclosing parameter syntax when the rule depends on `*testing.T`; aliases still
need semantic analysis.
Regexes search node text; anchor them when an exact name is intended. On 0.45.3,
a PHP positional-argument capture can be an `argument` node wrapping the
expression, so verify its shape before applying a `kind` constraint.

A descendant test proves syntax is present, not that a Boolean condition
implies a guard. For guard rules, pair `&&` and `||` cases and test the branch in
which the protected access executes. A NULL comparison nested under the wrong
operator can otherwise suppress the exact dereference the rule should report.

Quoted tokens are parser nodes, not interchangeable source text. In PHP,
single-quoted literals are `string` nodes while double-quoted literals are
`encapsed_string` nodes. In Bash, quote an executable, an option and an option
value in separate fixtures; also test whether an argument-taking option consumes
the following word before treating that word as another flag.

## Add and test

Put the rule in `rules/<language>/<category>/<id>.yml` and matching fixtures in
`tests/<language>/<category>/<id>.yml`. Use `security` for security review and
`correctness` for general API/logic mistakes.
Tests identify the rule by `id`; use realistic syntax including PHP open tags
and complete C functions where context affects parsing.

The directory and `language` key name the parser, while the rule ID names the
domain. nginx has no separate grammar here: keep its rules under `c` with
`language: c`, and use an `nginx-*` ID only when the finding depends on an nginx
API, data model, lifecycle, ABI, or source policy. Use a `c-*` ID when the claim
remains useful and unchanged in ordinary C code. A renamed consumer-facing ID
may keep a `severity: off` alias when explicit promotion can preserve meaningful
compatibility without duplicating normal diagnostics; document the remaining
migration work in `docs/id-migrations.md`.

Add `invalid` detections, `valid` near misses, lexical lookalikes, and relevant
boundary shapes. For advisory rules, a safe call may intentionally match:
record that limit rather than weakening the test to imply semantic precision.
Run `npm test`. When authoring, `ast-grep test --skip-snapshot-tests` checks
match behavior; review snapshot additions with `ast-grep test -i`. Snapshots
also protect match ranges and fixes. Confirm the positive fails when the
matcher is removed or broken. [Testing](https://ast-grep.github.io/guide/test-rule.html).

Snapshot files can retain cases that no longer exist in `invalid`; the fixture
runner does not reject those orphan keys. The inventory gate requires snapshot
keys to equal the current invalid fixtures.

`tests/arm_coverage.json` records 50 alternatives whose deletion survived the
fixture runner at revision `38d2973`. It preserves their original paths and
indices: 39 now have distinguishing fixtures with exact diagnostic counts;
11 redundant alternatives were removed with a structural explanation. Scope
arguments about Go declaration boundaries and Python lambdas assume valid
language syntax. The C parser-recovery exclusion remains and has an explicit
malformed-source fixture.

The normal test command enumerates every removable `any` arm beneath each
current main `rule` matcher and runs its isolated fixture/snapshot suite. A
survivor must have a distinguishing JSON count witness. Utilities are outside
this deletion inventory. One known mutation removes the only binding for a
constrained metavariable; its exact parse error is reported separately and
never counted as a kill. Unexpected tool failures and invalid rules fail the
gate. The command also checks each retained witness and its deleted count. Keep
the current path/index aligned when editing alternatives; retain the original
identity for attribution. The JWT witnesses explicitly require one diagnostic
when both legacy keyword spellings occur, in either order.

Exercise each alternative and supported API, including its argument positions.
Inspect secondary labels as well as detection counts: nested `has` relations
can annotate the same range twice. A captured condition with a constraint can
check descendants without repeating their labels; regenerate snapshots only
after checking the resulting ranges.

Main messages and notes interpolate metavariables too. Avoid literal
metavariable-shaped text such as a dollar-prefixed uppercase name in a
diagnostic, or assert the emitted JSON text explicitly; snapshots do not store
the main message or note.
`tests/test_diagnostics.py` checks the first invalid fixture of every rule against
its declared message, note and severity, with an explicit rule-count guard that
must be updated whenever a rule is added or removed.
Keep diagnostic prose literal; intentional interpolation requires a corresponding
emitted-text contract instead of silently changing that equality check.

Before adding a `fix`, establish that every match admits that rewrite. Preview
it, inspect the diff, and test both replacement text and surrounding syntax.
Use `transform`, `rewriters`, or fix-range expansion only when a concrete
rewrite requires them. [Rewriting](https://ast-grep.github.io/guide/rewrite-code.html).

## Integrate

`ruleDirs` paths resolve relative to `sgconfig.yml`; `testConfigs.testDir`
selects tests. Excluded experiments stay in `docs/candidates`. Always pass an
explicit config in automated consumers and validate that rules and tests were
discovered. [Project config](https://ast-grep.github.io/reference/sgconfig.html).

Check exit status and parse failures, not just stdout. Warnings can produce
findings with exit zero. A misspelled `--error=<id>` may also exit zero; validate
IDs and test a positive control. `languageGlobs` changes parser selection, so
verify existing native rules still run after overrides.
[Scan CLI](https://ast-grep.github.io/reference/cli/scan.html).

On 0.45.3, `ast-grep-ignore` must be the first alphabetic text in a comment to
act as a suppression directive. A prose mention later in a comment no longer
suppresses a finding or produces an unused-suppression diagnostic.
