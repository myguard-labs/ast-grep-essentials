# Complex ast-grep rules

This guide is the design and generation contract for rules that need more than
one local pattern. Read [authoring](authoring.md) first. The pinned engine,
repository fixtures, and consumer configuration are authoritative when living
upstream documentation differs.

Complexity is justified when the syntactic claim needs several independently
testable facts: API identity, operand position, enclosing syntax, sibling order,
or an explicit exclusion. Deeply nested YAML is not evidence of a stronger
claim. ast-grep matches one target AST node at a time and cannot prove types,
alias identity, dataflow, control flow, ownership, reachability, or input trust.

## Design the contract

Write these before YAML:

1. **Target** — the one node and source range the diagnostic should report.
2. **Positive facts** — syntax that must exist for that node to match.
3. **Exclusions** — closely related syntax that must suppress the match.
4. **Boundaries** — function, class, block, argument, or sibling limits that a
   relation must not cross.
5. **Limits** — semantic facts the matcher approximates but cannot establish.
6. **Contrast matrix** — one positive and one safe case per matcher branch or
   meaningful boundary.

A useful claim is narrow and falsifiable: “match `Cipher.getInstance` when its
captured transformation argument is the literal `RSA/None/NoPadding`.” “Detect
insecure cryptography” is not a syntactic contract.

## Build from the target outward

Start with a kind or a parseable pattern that selects the diagnostic target.
This also lets ast-grep prune unrelated node kinds before evaluating expensive
relations or regular expressions.

```yaml
rule:
  kind: call_expression
  has:
    field: function
    regex: ^dangerous_api$
```

Use `--debug-query=sexp` with the pinned binary before designing relations. A
source fragment can parse as a different node than the same text in a complete
program. Use a pattern object when the fragment is incomplete or ambiguous:

```yaml
pattern:
  context: |
    function probe() {
      dangerous($ARG);
    }
  selector: call_expression
```

Choose strictness deliberately. `smart` is the default; `cst` includes unnamed
tokens, while `ast`, `relaxed`, and `signature` progressively ignore more
syntax. Loose strictness is not a repair for an incorrectly parsed pattern.

## Compose facts correctly

`all` and `any` combine rules evaluated against the same target node. They do
not quantify over different children. Require two different descendants with
two `has` clauses:

```yaml
all:
  - has:
      kind: identifier
      regex: ^source$
  - has:
      kind: string_literal
```

Do not place both kinds beneath one `has: {all: ...}`; that asks one descendant
to have two incompatible kinds. Use an explicit, ordered `all` when a later
clause consumes a metavariable bound by an earlier clause. Rule-object field
order is not guaranteed.

Use metavariables by AST role:

- `$NAME` captures one named node.
- `$$NAME` may capture an unnamed node.
- `$$$ARGS` captures a sequence and must be tested at minimum and larger
  arities.
- `$_` is non-capturing.
- Reusing a name requires matching source content, not symbol identity.

Put exact text checks in `constraints` on the captured operand named by the
diagnostic. Anchor regular expressions unless substring matching is intended.
A constraint cannot filter a `$$$` sequence.

## Bound relations

Relations filter the target through surrounding syntax:

| Relation | Direction | Typical use |
| --- | --- | --- |
| `has` | child/descendant | required call, operand, or property |
| `inside` | parent/ancestor | enclosing handler, declaration, or expression |
| `follows` | previous siblings | earlier check or declaration |
| `precedes` | later siblings | later use or mutation |

Prefer a grammar `field` and `stopBy: neighbor` when the relationship is local.
`stopBy: end` walks without a semantic scope boundary and can cross nested
functions, callbacks, classes, blocks, or unrelated arguments. When deep
search is required, name the stop condition:

```yaml
inside:
  kind: catch_clause
  stopBy:
    any:
      - kind: function_declaration
      - kind: arrow_function
      - kind: class_declaration
```

Every `stopBy: end` needs a valid fixture with the required syntax just beyond
the intended boundary. Structural containment and sibling order do not prove
Boolean implication, dominance, reachability, or runtime sequencing.

## Use utilities as propositions

Extract repeated or independently testable concepts into local `utils`, then
reference them with `matches`:

```yaml
utils:
  is-target-callee:
    has:
      field: function
      regex: ^target\.decode$
  has-disabled-check:
    has:
      field: arguments
      has:
        kind: "false"

rule:
  kind: call_expression
  all:
    - matches: is-target-callee
    - matches: has-disabled-check
```

Name utilities after the syntactic fact they establish. Keep identifiers
portable and free of spaces, metavariables, dots, or operators. Prefer local
utilities unless reuse warrants global utilities and every consumer wires the
same `utilDirs`. Composite utility dependency cycles are invalid. Recursive
descent is possible only when each relational step advances to another node.

If a matcher expands into repeated copies for receiver, call, assignment, and
argument variants, stop and look for a shared target kind, grammar field,
contextual pattern, or utility. Each remaining `any` arm must own a fixture
whose expected diagnostic disappears when that arm is deleted.

## Recognize useful rule archetypes

### Direct API and literal

Bind the call and constrain the dangerous operand. Test qualified, unqualified,
similar-name, safe-literal, computed, and wrong-position cases.

### Import-sensitive API

Require the expected import and call shape to reduce name collisions. State
that aliases, shadowing, dot imports, and re-exports remain semantic-analysis
limits unless their syntax is explicitly covered.

### Missing option or guard

Confine absence checks to one expression, literal, builder chain, or tightly
bounded statement group. A rule cannot prove that a setting or guard is absent
elsewhere in an object lifecycle or control-flow graph.

### Ordered operations

`follows` and `precedes` can nominate check/use, mutate/use, and resource
lifecycle sites for review. Matching equal identifier text does not prove the
same value, object, path, or allocation.

### Framework or domain API

Constrain distinctive declarations, parameters, imports, or receivers when
syntax permits. Keep generic-language rules separate from framework rules when
their claims or dismissal criteria differ.

## Generate the rule and contrast matrix

Use one versioned plan outside the repository. It holds the claim, complete
configuration, matcher facts, provenance, and contrast matrix, so neither a
model nor a human has to synchronize several partial files:

```yaml
version: 1
id: javascript-target-check-disabled
language: javascript
category: security
severity: warning
message: Review target.decode calls with checking disabled
note: Dismiss when another verifier establishes the runtime guarantee.
source: https://github.com/coderabbitai/ast-grep-essentials/blob/REV/RULE.yml
match:
  target:
    kind: call_expression
  require:
    - has:
        field: function
        regex: ^target\.decode$
  exclude:
    - pattern: target.decode($TOKEN, true)
  any:
    - pattern: target.decode($TOKEN, false)
    - pattern: 'target.decode($TOKEN, { verify: false })'
cases:
  invalid:
    - target.decode(token, false)
    - 'target.decode(token, { verify: false })'
  valid:
    - target.decode(token, true)
    - similar.decode(token, false)
```

`match.target` selects the diagnostic node. `require` adds ordered positive
facts, `exclude` compiles to negated clauses, and `any` supplies supported
alternatives. Use `rule` instead of `match` when the matcher cannot be expressed
more clearly through those four fields. A plan may also include `utils`,
`constraints`, `labels`, `fix`, `transform`, `rewriters`, `files`, `ignores`,
`url`, and `metadata` at its top level.

Check the plan with a one-line verdict, optionally preview the complete
transaction, then generate the mirrored rule and fixture:

```sh
python3 tools/rule-scaffold.py \
  --plan /tmp/javascript-target-check-disabled.yml --check
# Human review only; this prints the full generated YAML:
python3 tools/rule-scaffold.py \
  --plan /tmp/javascript-target-check-disabled.yml --dry-run
python3 tools/rule-scaffold.py \
  --plan /tmp/javascript-target-check-disabled.yml
```

Before touching the repository, the generator runs every case against the
pinned engine. Every `invalid` source must emit this rule ID and every `valid`
source must emit none. It also rejects schema drift, missing contrast arms,
duplicate or contradictory sources, invalid utility IDs, undefined local
utilities, unbound constraints, and invalid provenance. The older explicit
flags remain available for simple and harvest-generated scaffolds; omitting a
matcher there still creates an intentionally invalid TODO rule. Automated
drafting uses `--check`, whose bounded one-line success result avoids feeding
rendered YAML back into the model; `--dry-run` is reserved for human review.

Run the focused probe next:

```sh
python3 tools/rule-probe.py javascript-target-check-disabled --sexp
python3 tools/rule-probe.py javascript-target-check-disabled --snapshot
```

Only the snapshot command may generate the new snapshot. Read its ranges,
labels, and fix output before accepting it.

### Start from a parser-assisted contrast

When the matcher shape is not yet known, ask the pinned parser for a v1 draft
instead of inferring node names from source text:

```sh
python3 tools/rule-scaffold.py --synthesize-plan --language python \
  --positive 'danger(user)' --near-miss 'danger("safe")' \
  --archetype api-argument
```

The output is structured candidate data, not an accepted rule: complete its
metadata and review the contextual target and positive-only `kind`/`field`
facts. The other compiled archetypes are `missing-option`, `import-sensitive`,
and `ordered-operation`. Parser results are cached in-process by pinned engine
version, language, and source digest.

Alternatives may use `{name, rule, witness}` objects. Names must be unique and
every witness must be a distinct `cases.invalid` entry; the compiler removes
this generator metadata from emitted rule YAML. Preflight deletes each named
arm and rejects `ANY_ARM_SURVIVED` when its witness still matches.

Set `mutation_limit` from 1 through 32 to weaken that many anchored regex,
grammar-field, and traversal-bound clauses. A surviving mutant fails with the
stable `MUTATION_SURVIVED` code and clause path. The default is zero for v1
compatibility. Preflight diagnostics include elapsed milliseconds and output
bytes so benchmark fixtures can assert process and output budgets without
depending on human-readable ast-grep logs.

## Test a contrast matrix, not examples

At minimum cover:

| Dimension | Detection | Safe control |
| --- | --- | --- |
| API | exact supported spelling | similar or unrelated spelling |
| operand | dangerous value | safe value |
| position | dangerous argument/property | same syntax elsewhere |
| arity | minimum and extended supported forms | missing required operand |
| scope | intended context | nested or adjacent foreign context |
| Boolean shape | executing dangerous branch | opposite operator/branch |
| lexical | executable syntax | comment and string lookalikes |
| parser | complete valid source | relevant malformed/recovery boundary |

For every `any` arm, delete it and require its distinguishing fixture or exact
count witness to fail. For every exclusion, remove it and require a safe case
to become noisy. Also mutate anchored names, traversal bounds, argument
positions, and capture bindings when those clauses carry the claim.

An `invalid` fixture only proves that at least one match exists. Use emitted
JSON and exact counts for multi-site examples. Snapshots preserve selected
ranges and fixes, not every diagnostic contract; the repository's diagnostics
and inventory tests cover message, note, severity, IDs, discovery, and current
snapshot ownership separately.

## Add a fix only when every match is safe

A `fix` is a stronger contract than a diagnostic. Verify every matcher
alternative admits the same rewrite, then test:

- Exact replacement text and resulting syntax.
- Comment and formatting preservation where promised.
- Evaluation order and side effects.
- Overlapping matches.
- A second application produces no further change.

Use `transform` for `replace`, `substring`, or case conversion. Use ordered
`rewriters` only when a captured subtree needs structural rewriting; the first
matching rewriter wins. Do not add a fix to an advisory rule whose semantic
uncertainty can change the correct edit.

## Wire consumers explicitly

Rules are not integrated merely because their fixtures pass. Consumer configs
must name the intended `ruleDirs`, any `utilDirs`, custom languages, and
`languageGlobs`. Paths resolve from the consuming config, not the rule file.

Exercise a known positive through the real consumer path and config:

```sh
npx ast-grep scan \
  --config /path/to/consumer/sgconfig.yml \
  --inspect=summary \
  --json=compact \
  /path/to/consumer-positive
```

Capture stdout, stderr, and status. Warning-only findings and unknown severity
promotions may still exit zero. Verify the rule ID in the loaded inventory and
the emitted finding. Add an excluded-path control when file selection is part
of the contract. Treat vendored copies and their snapshots as separate changes.

## Completion gate

Before shipping a complex rule:

- The syntactic claim and semantic limit are explicit.
- The target range is intentional.
- Patterns parse to the intended nodes on the pinned engine.
- Dependent capture checks use ordered `all`.
- Regexes are anchored where names are exact.
- Relations use fields and bounded traversal where possible.
- Every alternative and exclusion has a distinguishing control.
- Comment/string, scope, arity, operand-position, and malformed boundaries are
  represented when relevant.
- Fixes are safe for every match and idempotent.
- The focused probe passes and its snapshot is reviewed.
- `npm test` passes without accepting snapshots automatically.
- A real consumer config discovers the rule and reports a known positive.
- Source evidence and limitations are recorded in their canonical documents.

## What the complete CodeRabbit pack teaches

The public CodeRabbit pack was inspected exhaustively at commit
[`73120109`](https://github.com/coderabbitai/ast-grep-essentials/tree/73120109bf45c284d0cd8a37bdd7082e80e92e87),
not sampled. A recursive YAML census covered all 184 rule files and 185 fixture
files across its 15 language directories.^1 The counts below mean “rule files
containing this key at least once”; nested occurrences are higher.

| Construct | Rules | Construct | Rules |
| --- | ---: | --- | ---: |
| local `utils` | 143 | `matches` | 142 |
| `any` | 139 | `kind` | 132 |
| `has` | 106 | `all` | 104 |
| `stopBy` | 104 | `not` | 94 |
| `inside` | 92 | `pattern` | 54 |
| `regex` | 43 | `nthChild` | 42 |
| top-level `constraints` | 36 | `follows` | 33 |
| `precedes` | 23 | `field` | 20 |
| `fix` | 1 | `transform` / `rewriters` | 0 |

The pack defines 519 local utilities. Its recurring design is therefore not a
large source pattern: it selects nodes by `kind`, factors predicates into local
utilities, composes them with `matches`, and relates them through descendant,
ancestor, and sibling searches. Useful examples include API/argument matching,
import-sensitive calls, missing cookie or TLS settings, hard-coded credential
positions, and check-then-use statement order.

The corpus also supplies negative design evidence:

- The largest rules repeat hundreds of nested relations and alternatives; the
  most complex exceed 1,000 lines. That makes branch ownership and capture
  propagation difficult to review. Prefer shared target kinds, grammar fields,
  constrained captures, small proposition-like utilities, and a deletion
  witness for every remaining branch.
- `nthChild` appears in 42 rules and `field` in only 20. Child positions are
  sometimes necessary on the historical grammars, but named grammar fields are
  clearer and less sensitive to punctuation or grammar changes when available.
- Deep `stopBy: end` chains encode structural proximity, not control flow,
  value identity, or taint. Ordered-operation rules are review nominations
  unless another analyzer establishes those semantic properties.
- The repository's pinned 0.31.1 binary^2 reports 185 passing suites with 482
  invalid and 221 valid cases, yet the fixture inventory includes a duplicate
  `dont-call-system-c` ID, a C fixture under `tests/java/`, one fixture without
  the `-test` suffix, and one suite without a valid case. A green upstream
  runner is therefore not an inventory, uniqueness, or contrast-matrix proof.
- The same pack does not load unchanged on 0.45.3: the Ruby
  [`force-ssl-false-ruby`](https://github.com/coderabbitai/ast-grep-essentials/blob/73120109bf45c284d0cd8a37bdd7082e80e92e87/rules/ruby/security/force-ssl-false-ruby.yml)
  rule uses a utility ID containing reserved characters.
  Utility names and every imported matcher must be validated on the consuming
  engine, even when the source suite is green.

These findings justify this repository's stricter generator, mirrored fixtures,
global ID checks, exact snapshot ownership, arm-deletion witnesses, and pinned
consumer discovery test. CodeRabbit remains a pattern catalog and source of
candidate claims; it is not an executable dependency or a quality oracle.

## Prior art and current authority

CodeRabbit's public `ast-grep-essentials` pack is useful prior art for API,
argument-position, import-context, missing-setting, and statement-order rules:
<https://github.com/coderabbitai/ast-grep-essentials>. Its public revision
`73120109` contains 184 rules and pins ast-grep 0.31.1. It passes its original
suite but does not load unchanged on this repository's 0.45.3 baseline because
at least one historical utility ID is no longer valid. Imported matchers must
be reduced to a local claim, regenerated with local controls, and verified on
the pinned engine rather than copied as dependencies.

Upstream references:

- [Rule configuration](https://ast-grep.github.io/reference/yaml.html)
- [Pattern parsing](https://ast-grep.github.io/advanced/pattern-parse.html)
- [Composite rules](https://ast-grep.github.io/guide/rule-config/composite-rule.html)
- [Relational rules](https://ast-grep.github.io/guide/rule-config/relational-rule.html)
- [Utility rules](https://ast-grep.github.io/guide/rule-config/utility-rule.html)
- [Testing](https://ast-grep.github.io/guide/test-rule.html)
- [Transforms](https://ast-grep.github.io/guide/rewrite/transform.html)
- [Rewriters](https://ast-grep.github.io/guide/rewrite/rewriter.html)
- [Performance model](https://ast-grep.github.io/blog/optimize-ast-grep.html)

## Sources

1. CodeRabbit. “[ast-grep-essentials at
   73120109](https://github.com/coderabbitai/ast-grep-essentials/tree/73120109bf45c284d0cd8a37bdd7082e80e92e87).”
   March 31, 2025. Retrieved September 11, 2026.
2. CodeRabbit. “[package-lock.json at
   73120109](https://github.com/coderabbitai/ast-grep-essentials/blob/73120109bf45c284d0cd8a37bdd7082e80e92e87/package-lock.json).”
   March 31, 2025. Retrieved September 11, 2026.
3. ast-grep. “[Configuration
   Reference](https://ast-grep.github.io/reference/yaml.html).” Retrieved
   September 11, 2026.
4. ast-grep. “[Composite
   Rule](https://ast-grep.github.io/guide/rule-config/composite-rule.html).”
   Retrieved September 11, 2026.
5. ast-grep. “[Relational
   Rules](https://ast-grep.github.io/guide/rule-config/relational-rule.html).”
   Retrieved September 11, 2026.
6. ast-grep. “[Reusing Rule as
   Utility](https://ast-grep.github.io/guide/rule-config/utility-rule.html).”
   Retrieved September 11, 2026.
7. ast-grep. “[Deep Dive into ast-grep's Pattern
   Syntax](https://ast-grep.github.io/advanced/pattern-parse.html).” Retrieved
   September 11, 2026.
