# astgrep-rules

We build [ast-grep](https://ast-grep.github.io/) rules that catch bugs and point
out suspicious code worth a closer look. Scans are fast and use no AI tokens,
so you can run them while coding, before a commit, during review, or in CI.
Humans, agents, and scripts can then act on the findings.

The rules cover security and correctness patterns in Bash, C, C++, C#, Go,
HTML, Java, JavaScript, Kotlin, Lua, PHP, Python, Ruby, Rust, Scala, Swift, and
TypeScript, including checks for nginx code. A match tells you where to look;
it does not prove that the code is vulnerable.

## Run a scan

From this checkout, install the pinned engine and scan your source:

```sh
npm ci
npx ast-grep scan -c sgconfig.yml /path/to/source
```

Warnings and informational findings are advisory. Errors can fail the scan.
Before making a rule block commits or CI, check its ID and try it against code
you know should trigger it.

### Use the rules in another project

Copy the native-language `ruleDirs` entries from `sgconfig.yml` and adjust their
paths relative to your own config. Keep tests and `docs/candidates` out of rule
discovery.

If your config currently imports the parent `rules/` directory, update it before
upgrading. That directory also contains PowerShell rules, which need the custom
parser registration in `sgconfig.powershell.yml`. Importing the whole directory
without that registration will make the native scan fail.

Importing rule directories does not import the rest of the config. For PHP,
also copy the `languageGlobs` mapping (`php: ['*.php', '*.phtml']`) so both file
extensions use the PHP parser.

Rule IDs stay the same when files move. When an ID changes, follow the
[migration notes](docs/id-migrations.md) to update suppressions, overrides,
filters, and reports. A disabled compatibility alias can temporarily preserve
an old ID if you explicitly enable it, but doing so emits both the old and new
IDs.

### What about Perl?

The pinned ast-grep 0.45.3 has no built-in Perl parser. Its experimental
[custom-language support](https://ast-grep.github.io/advanced/custom-language.html)
needs a separately compiled tree-sitter shared library for each platform. Until
we can package and test that parser and its discovery across supported
platforms, use a Perl analyzer. We do not parse Perl as another language.

## Add a rule

Start with a small example of the problem and a similar example that should
pass. Give the rule a stable ID that is unique across the pack, and write a
message that explains what needs attention. The [authoring guide](docs/authoring.md)
covers the matcher syntax and review requirements.

Every rule needs tests: examples it should catch, near misses it should leave
alone, comment and string lookalikes, and relevant boundary cases. Keep the
examples inert; the tests parse them without running them.

We want useful findings with manageable noise. Advisory rules can flag safe
code too, provided they explain why the pattern deserves review. Be clear about
what the rule cannot know: syntax alone cannot establish runtime reachability,
data flow, ownership, or exploitability. Record those limits in
[limitations](docs/limitations.md). Candidates that need more evidence or a
different analyzer stay outside the active rules.

### Where files go

- `rules/<language>/<category>/<id>.yml` holds the rule.
- `tests/<language>/<category>/<id>.yml` holds its `valid` and `invalid` examples.
- `plans/<language>/<category>/` holds the source plans for generated rules.
- `docs/` explains rule design, sources, limitations, and rejected candidates.

The language directory names the parser. nginx rules use C, with `nginx-*` IDs
for nginx-specific checks and `c-*` IDs for checks that also apply to ordinary
C. See [nginx classification](docs/nginx-classification.md) for the distinction.

### Run the tests

```sh
npm ci
python3 -m pip install -r requirements-dev.txt
npm test
```

The suite checks that rules have tests, catch their intended examples, and
leave the negative controls alone. Snapshots also check the reported match
ranges and fixes. Review snapshot changes with `npx ast-grep test -i` and
inspect the diff; CI never accepts them automatically.

## Generate rules from plans

For a complex rule, keep the matcher and test cases together in a versioned
plan under `plans/`. Compile the plan, check every generated artifact, and then
regenerate the plan-owned rules and fixtures:

```sh
python3 tools/rule-plan.py plans/python/security/py-tempfile-mktemp.yml
npm run generate:check
npm run generate
```

The generator checks the plan's structure, references, bindings, and expected
matches before writing files. `generate:check` catches differences between
plans and generated files, checks exact expected results, and rejects matcher
or utility mutations that the tests fail to detect. The
[authoring guide](docs/authoring.md#generate-from-a-canonical-plan) and
[plan README](plans/README.md) explain the format and workflow.

For deeper checks, `tools/rule-mechanics.py` can suggest transformed test cases
with `metamorph PLAN`, test fixes with `validate-fixes`, and compare two engine
builds with `differential`. Suggested cases still need someone to decide whether
they should match. Fix checks verify that the finding disappears, the result
parses, and applying the fix again makes no further change. Engine comparisons
use stable findings over a bounded corpus.

We aim to automate as much of rule harvesting, triage, generation, and testing
as practical, keeping AI token use low. When a bug found elsewhere could become
a reusable check, capture it as a candidate. Online issue reports and fixes are
another source; viable candidates become tested rules.

## License

The [MyGuard Internal Use License 1.0](LICENSE) permits internal use, including
internal commercial use. Outside GitHub, distribution to third parties is
prohibited. GitHub users retain applicable on-service rights, and the license
defines a limited fork and branch workflow for pull-request contributions.

## Rule sources

The active pack includes 184 rules copied from
[CodeRabbit's ast-grep essentials](https://github.com/coderabbitai/ast-grep-essentials)
at commit `73120109bf45c284d0cd8a37bdd7082e80e92e87`. Git attributes their original
creation to ESS-ENN. The upstream root `LICENSE` is Apache License 2.0; each
copied rule carries that license notice and an exact source link, and the
import is tracked in
[`docs/coderabbit-rules.json`](docs/coderabbit-rules.json).

## Further reading

Rule enrichment uses one pull request per rule ID. A rule PR may carry that
rule's fixture, snapshot, source or limitation entry, and source plan, but never
a second rule. Pack-wide enrichment tooling and policy changes use a separate
foundation PR. See the [authoring guide](docs/authoring.md#record-enrichment-provenance)
for the required `Last enriched` and `Last touched` comments and their exact
meaning.

See [sources](docs/sources.md) for rule evidence and
[rejected candidates](docs/rejected-candidates.md) for patterns we investigated
but chose not to ship.

[The MyGuard AI coding workflow](https://deb.myguard.nl/articles/ai-coding-workflow-memory-skills-review/)
describes how we develop and review this pack, choose severity, and check that
rules are discovered and tested.
