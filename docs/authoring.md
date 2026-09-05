# Authoring rules

Checked against ast-grep 0.45.2 on 2026-09-04. The linked upstream pages are
living references; the lockfile and fixtures define this repository's baseline.

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
Regexes search node text; anchor them when an exact name is intended. On 0.45.2,
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
`correctness` for general API/logic mistakes. Keep nginx under language `c`.
Tests identify the rule by `id`; use realistic syntax including PHP open tags
and complete C functions where context affects parsing.

Add `invalid` detections, `valid` near misses, lexical lookalikes, and relevant
boundary shapes. For advisory rules, a safe call may intentionally match:
record that limit rather than weakening the test to imply semantic precision.
Run `npm test`. When authoring, `ast-grep test --skip-snapshot-tests` checks
match behavior; review snapshot additions with `ast-grep test -i`. Snapshots
also protect match ranges and fixes. Confirm the positive fails when the
matcher is removed or broken. [Testing](https://ast-grep.github.io/guide/test-rule.html).

Snapshot files can retain cases that no longer exist in `invalid`; the fixture
runner does not reject those orphan keys. During review, compare the snapshot
keys explicitly with the current invalid fixtures.

Exercise each alternative and supported API, including its argument positions.
Inspect secondary labels as well as detection counts: nested `has` relations
can annotate the same range twice. A captured condition with a constraint can
check descendants without repeating their labels; regenerate snapshots only
after checking the resulting ranges.

Main messages and notes interpolate metavariables too. Avoid literal
metavariable-shaped text such as a dollar-prefixed uppercase name in a
diagnostic, or assert the emitted JSON text explicitly; snapshots do not store
the main message or note.

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
