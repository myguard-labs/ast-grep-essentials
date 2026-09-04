# Detection boundaries

These migrated rules primarily identify review candidates. Tests demonstrate
syntax coverage; they do not prove all variants of a bug are detected.

- `c-memcpy-sizeof-pointer` also matches valid fixed-array and struct copies:
  ast-grep cannot resolve the identifier's type. Keep it advisory.
- Allocation, slab, response-header, reload, and intervention rules flag sites;
  they cannot prove a missing guard, initialization, or cleanup on every path.
- `c-format-string` checks format arguments in its listed libc calls; aliases
  and wrappers need separate rules. The ctype cast exclusion is broad and does
  not prove the argument has the correct type.
- `php-sql-string-interp` currently matches function calls, not all database
  member-call AST shapes. No interprocedural SQL or command dataflow is modeled.
- The Python YAML rule recognizes SafeLoader/CSafeLoader spellings, including
  `yaml.` qualification. Aliases and positional loaders require review; their
  safety cannot be inferred from names. Modern PyYAML requires a Loader, so a
  missing one can be an API error rather than unsafe deserialization.
- `go-exec-sprintf` flags formatted arguments for review. Go's `exec.Command`
  does not invoke a shell automatically; formatting alone is not proof of
  command injection. Inspect the executable, arguments, and whether a shell runs.
- `c-snprintf-return-advance` covers direct compound assignments. Separately
  stored return values require another analysis; nginx formatting functions
  have different return contracts from libc.

The original alignment experiment under `candidates/` was rejected for false
positives. Its dated measurements are historical evidence, not current counts.
Use type/alignment diagnostics and executed-path sanitizers for that question.

The time truncation rule covers explicit casts and direct integer declarations.
Assignments to previously declared variables need type resolution and remain
outside this matcher.
