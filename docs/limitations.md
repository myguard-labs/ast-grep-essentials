# Detection boundaries

These migrated rules primarily identify review candidates. Tests demonstrate
syntax coverage; they do not prove all variants of a bug are detected.

- `c-prctl-set-dumpable` recognizes decimal `1` with optional `U`/`L`
  suffixes (either order and case), not computed values, aliases, or other
  integer spellings. Zero remains excluded.
- `c-memcpy-sizeof-pointer` also matches valid fixed-array and struct copies:
  ast-grep cannot resolve the identifier's type. Keep it advisory.
- Allocation, slab, response-header, reload, and intervention rules flag sites;
  they cannot prove a missing guard, initialization, or cleanup on every path.
- `c-format-string` checks format arguments in its listed libc calls; aliases
  and wrappers need separate rules. The ctype rule excludes a direct
  `unsigned char` cast, but cannot infer already-safe integer ranges, EOF, or
  typedefs. A cast elsewhere inside an expression does not make its result safe.
- `php-sql-string-interp` recognizes its listed function names and query
  positions, not database member calls or aliases. No interprocedural SQL or
  command dataflow is modeled.
- `php-extract-superglobal` recognizes a direct superglobal as the first
  positional argument. Named arguments, aliases and transformed arrays need
  separate analysis. A superglobal used only to compute flags or a prefix is
  not the extracted array.
- `php-exec-sink` inventories selected calls, including ordinary assertions.
  String evaluation by `assert` was deprecated in PHP 7.2 and removed in PHP 8.0;
  an assertion match is not a code-execution diagnosis on modern PHP. See the
  [PHP assertion contract](https://www.php.net/manual/en/function.assert.php).
- The Python YAML rule recognizes SafeLoader/CSafeLoader spellings, including
  `yaml.` qualification. Aliases and positional loaders require review; their
  safety cannot be inferred from names. Modern PyYAML requires a Loader, so a
  missing one can be an API error rather than unsafe deserialization.
- `go-exec-sprintf` flags formatted executable and argv expressions for review,
  while excluding `CommandContext`'s context argument. Go's `exec.Command`
  does not invoke a shell automatically; formatting alone is not proof of
  command injection. Inspect the executable, arguments, and whether a shell runs.
- `go-sql-sprintf` checks the documented query position for ordinary and
  context-aware methods. Syntax cannot distinguish a DB or transaction receiver
  from a prepared statement, whose Query/Exec arguments are bound values, so a
  formatted first argument on a statement remains an advisory candidate.
- `c-shell-exec` inventories its listed shell and direct-execution APIs.
  Exec arguments remain separate argv elements, but the selected program can
  interpret them. The `*p` variants can also invoke a shell after an `ENOEXEC`
  failure; see [exec(3)](https://man7.org/linux/man-pages/man3/exec.3.html).
  Executable selection, option handling and PATH lookup still need review.
  The inventory is not exhaustive: `execve` remains outside this rule.
- `nginx-shm-exists-reload-test` identifies `shm.exists` references within an
  `if` condition, including compound conditions. It excludes ordinary writes
  and argument uses outside conditions; it does not prove that the condition
  is the sole reload guard or cover every possible control-flow form.
- `c-snprintf-return-advance` covers direct compound assignments. Separately
  stored return values require another analysis; nginx formatting functions
  have different return contracts from libc.

The original alignment experiment under `candidates/` was rejected for false
positives. Its dated measurements are historical evidence, not current counts.
Use type/alignment diagnostics and executed-path sanitizers for that question.

The time truncation rule covers explicit casts and direct integer declarations.
It includes qualifiers, signed/unsigned forms, and individual declarators in a
multi-declaration. Assignments to previously declared variables need type
resolution and remain outside this matcher.

## nginx-zstd-module history batch

Replayed against the code as it stood before each cited fix: seven of the nine
rules flag the bug that motivated them. The two that do not are recorded in
their own notes -- the format rule cannot see a signed `%L` holding an unsigned
value, and the conf-return rule cannot see a code assigned to a local before
being returned. Both need type information a syntactic matcher does not have.

Rules mined from the nginx-zstd-module commit history (2018 to 2026-09).
Each rule's `note` names the commit that motivated it.

- `nginx-table-missing-sentinel` asks whether a sentinel appears anywhere in
  an initialised `ngx_conf_enum_t`, `ngx_conf_bitmask_t`,
  `ngx_command_t`, `ngx_http_variable_t` or `ngx_stream_variable_t` array,
  at any depth so a preprocessor block cannot displace it, and accepts the
  expanded `{ ngx_null_string, NULL, NULL, 0, 0, 0 }` form as well as the
  macro. It does not check whether the sentinel is last, so one in the middle
  passes even though the walker stops there. Position-based matching was
  tried first and
  rejected: a trailing comment is a named node, so it took the last slot and
  produced an error-level false positive on a correctly terminated table. The
  sentinel must appear as a real identifier child: a string or comment merely
  naming `ngx_null_string` does not satisfy it. A table filled at runtime, or
  terminated through a macro with another name, is not checked.
- `nginx-command-offset-struct-mismatch` counts fields with `ofRule` so that
  inline comments between them do not shift the positions. It trusts the
  `*_main_conf_t`,
  `*_srv_conf_t`, `*_loc_conf_t` naming convention and fires only for generic
  `ngx_*_set_*_slot` handlers. A custom handler may reinterpret the offset
  (Angie's `status_zone` stores a main-conf field under the srv offset) and
  is skipped; a struct that does not follow the convention is skipped too.
- `nginx-format-libc-length-modifier` checks the format argument at its known
  position per function: second for `ngx_sprintf`, `ngx_log_stderr` and
  `ngx_log_abort`, third for `ngx_snprintf`/`ngx_slprintf`/`ngx_vslprintf`,
  fourth for the log and conf-log family. Positions skip comment nodes, so an
  inline comment before the format does not hide it. A `%lu` sitting in a data
  argument is therefore not flagged. `%l` and `%ul` are legal nginx
  conversions and stay quiet; `%lu`, `%ld`, `%zu`, `%zi`, `%zo`, `%zX`, `%hu`,
  `%lld` and a bare `%u` without a conversion letter fire, as do `%*hu` and
  `%*zu`: nginx's `*` is a string-length prefix that consumes a `size_t`, not a
  width, so the libc modifier after it is still copied literally. Note what nginx
  actually does with these: `%l` consumes a long and then prints the trailing
  `u` literally, so the argument list is not shifted; a bare `%u` consumes
  nothing. An escaped `%%` is not a conversion and is left alone.
  Adjacent literals are judged piece by piece, skipping any piece whose
  specifier could continue across a join, so `"%lu" " bytes"` is flagged
  while `"%l" "u"`, `"%" "%lu"` and `"%u" "i"` are passed over. A piece
  ending in an escaped `%%` also suppresses the next one, so `"100%%" "%lu"`
  is missed. `ngx_http_log_error` is not checked: despite the name it is
  nginx's log handler, not a formatting call. Wrappers, macros and
  format strings held in variables are not seen. Measured zero hits on the
  Angie tree.
- `c-duplicate-boolean-clause` sees only adjacent operands: `a && b && a`
  does not match, because the chain parses as `(a && b) && a` and the two
  `a` are never siblings. It compares operand text, so two clauses that
  differ only in spacing are still distinct, and it cannot tell a volatile or
  macro-expanded operand from a pure one. A repeated volatile read is
  re-evaluated and may differ, so those matches are review candidates rather
  than proven dead code. Operands containing a call are
  excluded: nginx's DoH parser repeats `skip_name()` on purpose. Anything
  under a preprocessor condition or a tree-sitter ERROR node is excluded; a
  continued `#if` line recovers into an ERROR subtree and matched wrongly.
- `nginx-strstrn-length-off-by-one` matches only `sizeof(lit) - 1` with the
  same literal as the needle. A hand-counted length or a named needle is left
  to review. The defect is a missed match, not an over-read: the `ngx_strncmp` /
  `ngx_strncasecmp` compare behind each function stops at the needle's NUL.
- `zstd-ifdef-on-enum-constant` flags every `#ifdef`, `#ifndef` and
  `defined()` on a `ZSTD_c_`, `ZSTD_d_` or `ZSTD_e_` name, but the right fix
  depends on which kind the name is. A stable parameter is a plain enumerator,
  so `#ifdef` and `defined()` are always false and `#ifndef` is always true;
  a `ZSTD_VERSION_NUMBER` gate replaces the guard either way.
  An experimental parameter is a macro alias visible only under
  `ZSTD_STATIC_LINKING_ONLY` (`zstd.h`), where the guard is meaningful and a
  version-only replacement would reference an undeclared identifier. The rule
  cannot tell them apart; the reviewer does.
- `nginx-conf-return-code-confusion` sees return statements only. A code
  stored in a local and returned later needs the local's type. `u_char *` and
  `char **` functions are excluded, and the `char *` side requires an
  `ngx_conf_t *` first parameter, or exactly the `ngx_cycle_t *` plus `void *`
  pointer pair of the core module `init_conf` callback (`core/ngx_module.h`), so
  an unrelated `char *` helper returning a sentinel is not flagged. A return
  inside a nested function is attributed to that function, not the enclosing
  handler. Parameters are matched structurally, so a variadic or by-value
  signature, a double pointer, or a by-value parameter is rejected, but a
  callback written through a typedef alias, or in K&R style, is not
  recognised.
- `nginx-buf-flush-before-last-buf` matches the direct `else if` shape on the
  same buffer expression. Two independent `if` statements, or a compound
  condition on either branch (`else if (b->last_buf || b->sync)`), do not
  match.
- `nginx-pool-cleanup-add-size-discarded` recognises the allocation as a plain
  assignment, a declaration with an initialiser, or an assignment inside an
  `if` condition or body, and requires the `->data` assignment to follow it in
  source
  order, as siblings in the same function body, so an allocation in one
  function does not pair with a write in another. It does no path analysis, so
  the two may sit on branches that never both execute, including an allocation
  in an `if` arm and a write in its `else`; the rule is `info` severity for
  that reason. A GNU nested function
  is not parsed as one by tree-sitter, so an allocation inside it counts as
  the enclosing body's; nginx does not use that extension.
  `ngx_pool_cleanup_add` always allocates the cleanup record and allocates the
  `data` block only when the size is non-zero at runtime
  (`core/ngx_palloc.c`); the rule cannot evaluate the expression, so a macro
  or variable that happens to be zero still matches.
