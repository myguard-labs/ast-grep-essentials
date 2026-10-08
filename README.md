# astgrep-rules

[ast-grep security rules pack](https://deb.myguard.nl/articles/ast-grep-security-rules-pack/)

Public, curated ast-grep security and correctness rules with their fixtures,
scan configuration, licenses, and a pinned ast-grep engine. Rule creation,
enrichment, planning, and validation tooling live in the private MyGuard
harness.

The pack covers Bash, C, C++, C#, Go, HTML, Java, JavaScript, Kotlin, Lua, PHP,
Python, Ruby, Rust, Scala, Swift, and TypeScript, including checks for nginx
code. A match identifies code that deserves review; it does not by itself prove
that the code is vulnerable.

## Run a scan

Install the pinned engine and scan a source tree:

```sh
npm ci
npx ast-grep scan -c sgconfig.yml /path/to/source
```

Warnings and informational findings are advisory. Verify a rule ID against
known positive and negative examples before making it block commits or CI.

Native rules live under `rules/<language>/<category>/<id>.yml`; matching YAML
fixtures live under `tests/<language>/<category>/<id>.yml`. Import the explicit
native-language `ruleDirs` from `sgconfig.yml`, not the parent `rules/`
directory. The latter also contains PowerShell rules, which require the custom
parser configured separately in `sgconfig.powershell.yml`.

For PHP consumers, copy the `languageGlobs` mapping too, so both `.php` and
`.phtml` files use the PHP parser. The pinned ast-grep release has no built-in
Perl parser, so this pack does not parse Perl as another language.

## Contribute a rule

A rule change should contain one stable, globally unique rule ID and its YAML
fixture. Fixtures need positive examples, near misses, comment and string
lookalikes, and relevant boundary cases. Keep every example inert: validation
parses fixtures and never needs to execute them.

Rule enrichment uses one pull request per rule ID. A rule PR may include that
rule's fixture and snapshot, but never a second rule. MyGuard runs the private
authoring and validation harness before merging changes to this public corpus.

## Reviewed packs

A reviewed pack is a commit that carries a signed annotated tag named
`reviewed-YYYYMMDD-N` (N starts at 1 per day). Consumers that need a reviewed
pack pin such a tag's commit, not an arbitrary `main` commit.
`ci/promote.py` owns the gates:

```sh
python3 ci/promote.py check            # gates over the working tree
python3 ci/promote.py check --rev REF  # gates over one commit
python3 ci/promote.py baseline         # rewrite ci/baselines/promotion.json
python3 ci/promote.py tag              # clean tree, HEAD == origin/main only
```

`check` blocks when any of these fails:

- `ast-grep test` with snapshots, or `python -m unittest discover -s ci/tests`;
- a rule added or changed since the previous `reviewed-*` tag (every rule
  when none exists) has no mirrored fixture with both `valid` and `invalid`
  cases; such rules are listed as withheld;
- the pinned engine differs from `package.json` or the baseline, or the
  pinned corpus `ci/corpus` no longer matches the baseline digest;
- a rule reports more corpus findings than its baseline count plus
  `fp.new_rule_threshold` (a rule absent from the baseline counts from 0),
  unless `fp.acknowledged` lists that rule with a count at least that high;
- the median wall time of the timed corpus scans exceeds
  `median_seconds * (1 + tolerance_ratio) + tolerance_seconds` from the
  baseline (defaults 50% plus 0.25 s; timings are host-specific, so rebaseline
  on the host that tags).

`baseline` keeps the tolerances and threshold, absorbs current counts, and
clears acknowledgements. `tag` reruns `check` on HEAD, creates the signed tag
with the gate summary as its message, and prints the push command; it never
pushes. PowerShell rules get the fixture gate but their snapshot tests need
the separately built parser (`sgconfig.powershell.yml`).

The corpus is MyGuard-authored source, copied from the commits listed in
`ci/corpus/SOURCES.md` or written for it under `ci/corpus/samples/`; it is
scan input only and is never built or run. PowerShell sources are not part of
the corpus scan, which uses the default `sgconfig.yml`.

## Rule sources

The active pack incorporates 184 rules from
[CodeRabbit's ast-grep essentials](https://github.com/coderabbitai/ast-grep-essentials),
copied at commit `73120109bf45c284d0cd8a37bdd7082e80e92e87`. That upstream
project is now archived and no longer maintained, so those rules are carried
forward here.

The incorporated rules remain under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), and the
upstream license text is retained verbatim at
[`LICENSES/CodeRabbit-ast-grep-essentials-Apache-2.0.txt`](LICENSES/CodeRabbit-ast-grep-essentials-Apache-2.0.txt).
Each incorporated rule records its exact upstream source, its Apache-2.0
notice, and any MyGuard modification in its leading comments and `metadata`
block. Rules original to this pack are covered by the repository license
described below.

## License

The [MyGuard Internal Use License 1.0](LICENSE) permits internal use, including
internal commercial use. Outside GitHub, distribution to third parties is
prohibited. GitHub users retain applicable on-service rights, and the license
defines a limited fork and branch workflow for pull-request contributions.
