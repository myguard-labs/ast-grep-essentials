# AGENTS.md — ast-grep Essentials

This repository ships ast-grep rules. The private Python authoring and
scheduling harness lives in the sibling `ast-grep-harness` repository.

## Rule delivery

- One created, enriched, or repaired rule per signed commit. The commit may
  also contain only that rule's exact mirrored fixture, owned snapshot,
  limitation/source entry, and source plan.
- Work in an isolated temporary worktree based on fresh `origin/main`. Run the
  focused probe, changed-rule validation with npm's current latest ast-grep,
  and Codex-driven PR-Agent before committing.
- Push the validated commit directly with `git push origin HEAD:main`. A
  non-fast-forward rejection is a stop/retry signal; never force it. Verify
  `origin/main` resolves to the pushed commit before reporting completion.
- CodeRabbit is disabled and is not a delivery gate for this repository.
- No-change validations produce no commit.

Repository-wide tooling, CI, workflow, dependency, or policy changes still use
a non-default branch and pull request under the parent repository instructions.
Never mix them into a rule commit.

## Rule validation

Every changed rule ships with its mirrored positive and negative fixture.
Load and test only changed rules in harness-supported languages; do not add a
whole-language sweep or rule-lint pass. Parser errors, zero executed tests,
fixture failures, missing or misplaced fixtures, unsafe paths, registry
substitution, or version drift block delivery.
