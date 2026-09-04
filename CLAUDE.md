# Rule-authoring contract

- Active rules: `rules/<language>/<category>/<id>.yml`; nginx uses language `c`.
- Tests mirror that path under `tests/`; keep IDs stable and globally unique.
- Every rule needs positive, near-miss, and comment/string controls. Advisory
  rules may intentionally match safe code; document that boundary.
- Read `docs/authoring.md` before changing matchers; explain semantic limits in
  `docs/limitations.md`. Rejected experiments stay outside `rules/`.
- Run `npm ci`, install `requirements-dev.txt`, and run `npm test`.
  Inventory validation checks discovery and IDs; review fixture semantics
  separately to establish that near misses exercise the intended boundary.
- Review snapshot changes; do not regenerate them merely to silence failures.
- Keep fixtures inert: ast-grep parses snippets; never execute unsafe examples.
