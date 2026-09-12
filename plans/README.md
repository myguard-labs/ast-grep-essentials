# Canonical rule plans

New mechanically generated rules keep their versioned source plan under
`plans/<language>/<category>/<id>.yml`. The mirrored rule and fixture remain
ordinary ast-grep YAML for downstream compatibility.

Run `npm run generate:check` to preflight plans, exact oracles, mutations, and
generated-file drift. Run `npm run generate` to update only artifacts owned by
plans. Existing handcrafted rules can be migrated independently.

Imported rules preserve required license and source comments through the
single-line `comments` list. Non-native top-level metadata belongs under
`extensions`; reserved ast-grep configuration keys cannot be overridden there.
Structurally redundant mutations retained for diagnostic-label compatibility
may be named under `mutation_exclusions`; each needs a reviewable rationale.
