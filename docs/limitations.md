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

## Added rules

- `go-tls-insecure-skip-verify` and `py-requests-verify-false` match a literal
  `true`/`False`. The Go rule also allows redundant parentheses and comments
  and requires the field to sit in the nearest
  enclosing `tls.Config` composite literal; another struct carrying the same
  field name does not match. Post-construction assignments are not matched
  because the receiver type is unavailable syntactically. The Python rule
  matches `requests`, `requests.Session()`, and lexically named local
  session/client receivers; object attributes and aliases under other names are
  missed. A value supplied through a variable, config field or build flag is
  not detected; that path needs configuration review.
- `go-defer-in-loop` uses the nearest enclosing function as the boundary, so a
  defer inside a closure or goroutine within the loop is correctly excluded. It
  does not model whether the loop is bounded or the resource cheap, and it does
  not cover a helper called in the loop that defers internally.
- `py-hardcoded-tempfile` is lexical: it matches `/tmp/` and `/var/tmp/` string
  prefixes anywhere, including read-only paths and paths later replaced. It
  cannot see `TMPDIR` overrides or a path already produced by `mkdtemp`.
- `php-file-inclusion-variable` fires when a variable, subscript, call or
  interpolated string reaches the included path. A path built only from
  literals, constants, `__DIR__` or `dirname(__FILE__)` does not match; any
  other call in the path still does. It does not model taint, so
  an internal, non-request variable still matches and needs review.
- `c-strncat-size-misuse` binds the size operand to the destination argument
  and matches only when that expression is the complete length argument. It
  covers `strncat` with `sizeof`/`strlen` and `strncpy` with `sizeof`, including
  parenthesized destinations and both `sizeof(dst)` and `sizeof dst`;
  `strncpy(dst, src, strlen(dst))` is not classified as a whole-buffer overflow.
  Correct remaining-space forms subtract and do not match. An array
  passed as a pointer parameter still makes `sizeof` wrong for a different
  reason this rule does not diagnose.

## Second batch

- `go-http-no-timeout` treats clients and servers separately. A client needs a
  positive `Timeout`; a server needs a positive `WriteTimeout` plus either a
  positive `ReadHeaderTimeout` or a positive `ReadTimeout` from which a zero
  `ReadHeaderTimeout` can inherit. A negative `ReadHeaderTimeout` disables that
  protection, and `IdleTimeout` alone does not bound active requests. The
  `http.` qualifier is required, so an unrelated type does not match and a
  dot-imported one is missed. Nested transport timeouts and assignments after
  construction are not detected. Literal zero and lexically unary-negative
  values are caught; other computed values are treated as configured.
- `go-error-swallowed` cannot tell an error from any other discarded return, so
  it approximates: an assignment binding `err*`, `e` or `ok*` is excluded, as
  is an assignment whose right-hand expressions are all common cleanup calls
  (Close/Flush/Sync/Kill/Wait/Remove/Set*Deadline). A mixed right-hand side
  still matches. Measured on labs/gozer, labs/gyzor and labs/mailstrix, most raw
  matches came from vendored dependencies; scope scans to first-party
  directories. Test files legitimately discard results and dominate the rest.
- `py-jwt-decode-unverified` matches `jwt.decode` and bare `decode` when the
  module has a top-level exact `from jwt import decode`. Function-local imports,
  aliases and shadowing are not resolved. Verification disabled through a
  variable or a prebuilt options dict is also not detected.
- `py-mutable-default-arg` flags the literal default. It cannot tell whether the
  parameter is ever mutated, so a read-only default still matches; the fix is
  cheap either way.
- `php-weak-crypto` is a call inventory. md5/sha1 over non-secret data is a
  legitimate use and matches; the rule cannot see what the argument holds.
  `crypt()` also matches because the rule cannot inspect the salt-selected
  algorithm and cost. A suitable salt can select a strong password algorithm,
  but `password_hash()` is preferred for new code because it selects the
  algorithm, salt and cost safely.
- `c-return-stack-address` binds the returned identifier to a same-function
  declaration without a storage class, so a `static` local does not match. It
  does not resolve shadowing, so a name also declared in an inner scope, or one
  that is a parameter pointer, still needs the declaration checked.

## Third batch

Rules chosen against the 2025 CWE Top 25 (CISA/MITRE, published 2025-12-11,
scored over 39,080 CVE records) after mapping the existing pack for gaps.
See <https://cwe.mitre.org/data/definitions/1435.html>.

- `php-echo-superglobal-xss` covers CWE-79, rank 1. It matches a superglobal
  reaching echo/print and clears the match only when a recognised HTML or URL
  escaper wraps that value itself. In an attribute-like concatenation, literal
  flag masks (including bitwise-OR combinations) must escape the surrounding
  quote: `ENT_QUOTES` protects either delimiter, while `ENT_COMPAT` protects
  only double-quoted attributes. Masks that omit the required quote escaping
  remain findings but are sufficient for ordinary element text. An escaper
  around another operand of the same statement does not count. `json_encode`
  is not treated as an escaper because it leaves `<` alone without
  `JSON_HEX_TAG`. An escaper
  applied earlier and stored in a variable is not visible to it, and a value
  echoed into a non-HTML response is
  a legitimate dismissal.
- `php-upload-unvalidated-name` covers CWE-434. A structural call pattern binds
  the destination expression, whose nested key may use either PHP quote style
  but must be `name`, so
  the legitimate `$_FILES[...]["tmp_name"]` source, and a destination built
  from `size`, `type` or `error`, do not fire. It cannot see validation
  performed earlier in the function.
- `go-zip-slip` covers CWE-22. It matches a `.Name` field read inside
  filepath.Join, the archive-entry shape, and excludes a `.Name()` method call
  because `os.DirEntry` over a local directory cannot carry traversal — that
  distinction came from a false positive on
  labs/mailstrix/internal/mailstrix/scanner.go. `filepath.Clean` on the entry
  name is not containment and does not suppress the match. The `.Name`
  receiver type is unresolved, so a trusted non-archive struct can
  false-positive. A containment check on a later line is not seen; Go 1.24+
  `os.OpenRoot` is the recommended fix and all
  first-party Go modules here are 1.24 or newer.
- `py-ssrf-request-fstring` covers CWE-918 and flags an interpolated URL, not a
  proven SSRF. The receiver is matched lexically (`requests`, `httpx`,
  `urllib3`, `aiohttp`, a local `session`/`client` name, or bare `urlopen`), so
  a dict or cache `.get()` with an interpolated key does not match. Only the
  first positional or named `url` argument is inspected, except that
  `request(method, url)` uses the second positional argument; interpolated
  payloads do not match. Object attributes and clients held under other names
  are missed. An interpolated path under a fixed host is the common benign
  shape.
- `py-mark-safe-interpolation` covers CWE-79 in Django: interpolation happens
  before `mark_safe` marks the result, so the payload is already embedded.
  `format_html` is the fix. `mark_safe` over a constant, including a
  concatenation of literals only or a no-argument `.format()`, does not match.
- `c-free-without-null` is hygiene for CWE-416/CWE-415, not a use-after-free
  finding: ast-grep models no dataflow, so it cannot prove a later use. It is
  `info` severity because short-lived scopes legitimately free without
  clearing. Test and fuzz harnesses commonly have that shape; scope corpus
  scans to production sources. A later plain reassignment suppresses this
  advisory, except self-assignment with optional parentheses around the value.
  This remains a syntactic check; it does not prove a replacement value is safe.

## Fourth batch

Selected against the OWASP Top 10:2025 (announced November 2025, final
January 2026), which added two categories the pack had no coverage for:
A03 Software Supply Chain Failures and A10 Mishandling of Exceptional
Conditions. SSRF was absorbed into A01 Broken Access Control in this edition.
See <https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/>.

- `py-bare-except` and `py-except-pass` cover A10/CWE-396/CWE-390.
  `py-bare-except` excludes only an unconditional terminal bare `raise`, the
  documented cleanup idiom; a conditional re-raise, work after the re-raise,
  or `raise Other()` still matches.
  `py-except-pass` matches only a body whose single statement is `pass` or
  `...`, comments aside, so `pass` followed by real work or nested in a loop
  does not match; ruff E722 and flake8
  differ on that case, and PEP 760 proposed removing the bare form outright.
  `py-except-pass` is `info` because narrowly typed clauses that deliberately
  ignore an error are common and legitimate: all 34 first-party hits measured
  were typed (BrokenPipeError, SystemExit, OSError), mostly CI tooling.
  `py-bare-except` stays `warning` — it catches KeyboardInterrupt and
  SystemExit, so it is the form that actually fails open.
- `go-unchecked-type-assertion` covers CWE-476. It distinguishes `v := x.(T)`
  from `v, ok := x.(T)` by the arity of both expression lists, including
  multi-value right-hand sides. Direct and once-parenthesized comma-ok
  assignments and declarations do not match; redundantly nested parentheses
  can still report. Type switches do not match.
  The rule cannot tell whether the dynamic type is already guaranteed, so an
  assertion immediately after a type switch still matches. Measured 6
  first-party hits, all genuine single-value assertions.
- `nginx-unchecked-array-push` checks for the guard rather than inventorying
  call sites as `nginx-unchecked-palloc` does and covers both assignment and
  declaration-initializer forms. Suppression requires the immediately
  following `if` either to test non-NULL and scope the use, or to detect NULL
  and directly return or `goto`. Unrelated comparisons and NULL checks that
  merely log still match. A reverse-order compound condition is rejected when
  its direct earlier operand dereferences the pointer. Later guards remain
  advisory matches, and a guard in
  a called helper is invisible. Upstream nginx tracks the same omission in
  nginx/nginx#526.
- `php-strcmp-loose-compare` and `php-hash-loose-compare` cover CWE-697 type
  juggling. They match `==`, `!=` and `<>` only when the relevant call is a
  direct, optionally parenthesized operand, so a call nested in another
  expression does not count. Only one optional parenthesis layer is supported;
  redundantly nested parentheses can be missed. The first is an authentication
  bypass before PHP 8, where an array
  argument makes strcmp return NULL and NULL == 0 holds; PHP 8 raises a
  TypeError instead, but the comparison stays wrong on any pre-8 deployment.
  The second covers magic hashes, where two 0e-prefixed digit strings compare
  equal. Neither rule can tell whether the compared value is a secret, so a
  loose comparison of non-security hashes also matches.

## Fifth batch

Adds `bash` as a fifth language, closing OWASP A03:2025 Software Supply Chain
Failures — the remaining 2025 category with no coverage. Most of A03 is
registry, SBOM and provenance territory that no AST matcher can reach; these
two rules cover only its code-level slice.

- `sh-curl-pipe-shell` matches a stdout fetch to its rightward interpreter. A
  shell may be bare, use stdin-preserving options, or end in `-s`/`--`; Python,
  Perl and Ruby may be bare or use the explicit `-` stdin form. Quoted curl, wget,
  interpreter and option tokens are recognized; quoted `sudo` is not.
  Arguments after explicit stdin selectors are argv and
  remain covered, while script-path and inline-script forms do not match. Curl
  must not select an output file;
  `-o -`, `-o-`, `--output=-`, and combined common-option forms such as `-sLo-`
  explicitly select stdout. Output options are checked at every argument position;
  separate `-o -` / `--output -` and wget `-O -` / `--output-document -`
  require adjacent option and value tokens. Wget must explicitly select stdout.
  Values following the listed common argument-taking curl/wget options are not
  treated as output options. This is bounded syntax matching, not complete option
  parsing: other value-taking options, ambiguous chains of option-shaped values,
  `--` option termination, and multiple conflicting output selections are outside
  the rule's precision claim. Short wget clusters recognize no-argument flags
  before `O`, including `q`, `c`, `S` and `nv`; argument-taking flags consume
  the remaining cluster (`-UO-` sets a user agent, not stdout). `sudo` supports
  any sequence or cluster of the no-argument `-E`, `-H`, `-n` and `-S` options;
  `-u root`, `-uroot`, `--user root`, and `--user=root` can be interleaved with
  them. User option values are not mistaken for commands, and `sudo tee` and
  `sudo install` do not match. The rule cannot see whether a checksum is
  verified elsewhere in the script.
- `sh-tls-verify-disabled` matches the flag, not the intent, and binds each
  flag to the command that defines it: curl `-k`/`--insecure` (inside a short
  cluster of common no-argument flags such as `-sSk` too; argument-taking forms
  such as `-ok` and `-Hk` are not treated as `-k`, and `-K` is the config file),
  wget `--no-check-certificate`, and pip `--trusted-host` with or without
  `=host`; quoted command and option tokens are recognized. A token used as the
  value of a known curl option that requires an argument is not treated as a
  flag; that allowlist may need extending when curl adds options.
  wget `-k` is `--convert-links` and does not match. `curl --cacert`
  or `--capath`
  and `pip --cert` pointing at a private CA bundle are the correct alternative
  and do not match; `curl --cert` is a client certificate, not a trust option.
- `go-context-cancel-leak` fires only when cancel is assigned to the blank
  identifier. A bound cancel that is never deferred is the more common defect
  and is invisible to this matcher; `go vet` does catch the lostcancel case.
- `php-insecure-cookie-flags` checks the options-array form, reporting when
  either `httponly` or `secure` is absent or not literally `true`, and the
  legacy positional form. A named `expires_or_options:` array is recognized in
  any argument order and is not interpreted as the positional signature.
  Named `secure:` and `httponly:` arguments are also recognized in any source
  order. Outside the options-array form, each flag may be supplied either by its
  legacy positional slot or by its named argument, so a positional `secure`
  followed by a named `httponly:` is handled correctly. Both resolved values
  must be literal `true`; missing, false, computed, or later duplicate unsafe
  entries match. Comments containing option-like text do not affect the result.
- `py-tarfile-extractall` covers CWE-22. The receiver must be bound from
  `tarfile.open`, `tarfile.TarFile` or `tarfile.TarFile.open` by a preceding
  assignment in the same statement list, the statement list containing an
  enclosing `if`, or the nearest enclosing `with`; alternatively, the call may
  be chained directly on that open. A simple intervening assignment in the
  relevant statement list stops the match. Other control-flow bindings and
  reassignments, and bindings in another file, are not modelled, so the rule is
  a warning rather than an error. On Python 3.14+, the default `data` filter
  reduces path and link risks, but untrusted archives still require prior
  inspection and resource limits. `zipfile.ZipFile.extractall` has no `filter`
  parameter and is outside this tar-specific rule; Python only attempts to
  prevent path traversal there and still requires prior inspection for
  untrusted ZIP archives. The `filter` keyword must be on the extract call
  itself, not on a nested call. Only `"data"`, `"tar"`, `data_filter`,
  `tar_filter`, and their `tarfile.` forms suppress the finding; `None`,
  `"fully_trusted"`, and arbitrary computed filters remain findings.
  Per PEP 706, Python 3.12-3.13 emit a
  DeprecationWarning but still extract with the `fully_trusted` filter, so a
  match on those versions is exploitable; 3.14+ defaults to `data`. Check the
  interpreter floor and archive trust before dismissing. Found one true
  positive outside this repo, at tools/patch-management.py:36.
- `c-scanf-unbounded-string` matches a `%s`, `%[`, `%ls` or `%l[` conversion
  with no field width in the scanf family. The format is the first argument of
  `scanf`/`vscanf` and the second of `fscanf`/`sscanf`/`vfscanf`/`vsscanf`.
  An assignment-suppressed `%*s` and
  an escaped `%%s` write nothing and do not match. Adjacent string literals are
  treated as one format, and POSIX `n$` selectors are not confused with field
  widths. It reads the format literal, so a format passed through a variable is
  not seen.

## Sixth batch

Mined from the git and memory history of the owned submodules (2026-09-05),
selecting shapes with a measured hit rate on this codebase rather than from a
generic catalog.

- `nginx-unchecked-module-ctx` checks for the guard rather than inventorying
  call sites: a match means no recognized NULL guard of the assigned name is
  encountered before the first member access in the same block. Both the
  assignment form and the declaration-initializer form are covered. A
  short-circuit member access inside a non-NULL `&&` consequence is safe, as is
  the alternative of a NULL `||` condition. The inverse branches do not prove
  safety. A standalone `ctx && ready` or `ctx || fallback` does not suppress a
  later dereference. A NULL condition suppresses later reports only when its
  consequence directly returns or jumps without dereferencing the context; a
  branch that logs or dereferences first is not a guard. Reversed `NULL == ctx`
  checks and `(*ctx).field` accesses are recognized. The rule cannot prove the
  site is reachable with a NULL context. A reverse-order compound condition is
  rejected when its direct earlier operand dereferences the context. A
  documented construction invariant remains a legitimate dismissal.
- `c-send-without-nosignal` covers `send()` and `sendmsg()`; `sendto()` is
  the datagram call in practice and SIGPIPE is a stream-socket concern, so a
  stream socket written through `sendto()` with a NULL address is not seen. It
  considers the flags protected only when `MSG_NOSIGNAL` is used alone or in an
  OR-only identifier/macro/common decimal, octal or hexadecimal constant mask,
  including parenthesized operands; clearing, masking, toggling, arithmetic and
  conditional expressions still match. It reads only that argument, so a
  program that installs `signal(SIGPIPE, SIG_IGN)` at startup or sets
  `SO_NOSIGPIPE` on the socket is safe and still matches. It does not model
  which of the three defences is present. Measured 3 first-party hits, all in
  `labs/nginx-label-autoconf-module` active health probes, where that module
  has no `SIGPIPE`, `MSG_NOSIGNAL` or `SO_NOSIGPIPE` reference anywhere — the
  shape the recurring-findings catalog flags as worst, since the crash lands on
  exactly the peer-closes case a prober exists to exercise. `write()` to a
  socket carries the same hazard and is deliberately out of scope: it is not
  distinguishable from ordinary file I/O at the AST level.

## Seventh batch

Derived from the nginx development guide's documented return conventions
(2026-09-05), then filtered by measured hit rate on `modules/nginx/*` and
`labs/nginx-*` (18010 C files). Shapes with no measured defects were dropped
rather than shipped: `ngx_cpymem`/`ngx_movemem` with a discarded return matched
0 sites, and the `ngx_sprintf` family's "return value used as a length" defect
is not separable at the AST level from the documented `p = ngx_sprintf(p, ...)`
chaining idiom, which accounts for all 394 assignment sites sampled.

- `nginx-atoi-unchecked` matches an ngx_atoi-family assignment or declaration
  initializer with no comparison operator involving the assigned lvalue in the
  enclosing function. The
  function-wide guard search is deliberate: an earlier draft that demanded a
  literal `NGX_ERROR` comparison, or that searched only sibling statements,
  produced 55 hits with 13 first-party matches that were all false positives —
  code correctly validating by range (`if (first < 100)`) or guarding after an
  enclosing if/else. Two sites in the original corpus were confirmed real:
  `http-let/ngx_http_let_module.c:179` adds an unvalidated offset to a pointer,
  so `NGX_ERROR` underflows `ret->data` on attacker-shaped substring arguments,
  and `nchan/.../redis_nodeset_parser.c:61` stores `NGX_ERROR` directly into
  `r->min`/`r->max`. The trade is false negatives: a comparison on an unrelated
  path still suppresses the match, and the rule cannot see validation performed
  in a callee. Member and indirect lvalues are included.
- `nginx-send-header-return-ignored` matches a discarded direct call expression
  statement, including one or two parenthesis layers and casts. It does not
  model whether a body
  follows, so a handler that sends only headers and finalizes is harmless and
  still matches. First-party modules in the original sample already used the
  `rc == NGX_ERROR || rc > NGX_OK || r->header_only` idiom.
  `http-js-challenge/ngx_http_js_challenge.c:239` was confirmed: it calls
  `ngx_http_output_filter` unconditionally afterwards, which emits a body for a
  HEAD request and writes after a filter has already finalized the request.

## Eighth batch: measured rejections, no rules shipped

A second research pass (2026-09-05) mined the
[nginx security advisories](https://nginx.org/en/security_advisories.html)
rather than the development guide, on the theory that CVE root causes would
suggest shapes the API-contract pass missed. Every candidate was rejected on
measurement against `modules/nginx/*` and `labs/nginx-*`. The measurements are
recorded here so the same seams are not re-mined.

- `ngx_palloc(pool, sizeof(ngx_buf_t))` without a following `ngx_memzero`, the
  uninitialised-flags shape behind several memory-disclosure CVEs: 1 site in the
  whole corpus. Modules use `ngx_calloc_buf` and `ngx_create_temp_buf` (117
  sites), which zero or fully initialise the structure.
- `ngx_list_push(&r->headers_out.headers)` with no `->hash` assignment, which
  silently drops the header because iteration skips `hash == 0`: 7 raw hits, all
  false positives. Every one assigned the whole struct with `*ho = *h`, which
  carries `hash` from the source header. With struct copy, `ngx_memcpy` and
  `ngx_memzero` added as dismissals the rule measures 0.
- `ngx_strlchr`/`ngx_strnstr`/`ngx_strcasestrn` result used with no guard, a NULL
  dereference on crafted input: 4 raw hits, all on attacker-controlled data
  (`tc_url`, `unparsed_uri`), and all false positives — each site guards with
  `if (p)`, a truthiness test rather than a comparison. With `!$V` and the
  parenthesised-condition forms added, the rule measures 0.
- Allocation size computed by multiplication is already covered by
  `c-alloc-mul-overflow`, which carries the nginx pool allocators alongside
  `malloc`; a separate nginx rule would duplicate it.
- Three shapes were too broad to be selective and were not narrowed further:
  `ngx_cpymem`/`ngx_memcpy` whose length argument is a pointer subtraction (326
  hits), `$A->len - $B` underflow arithmetic (170), and pool allocation with a
  multiplied size (219, and already covered). At those rates the rule would
  flag mostly correct code.

The recurring false-positive mechanism across both research passes is the same:
a guard expressed as a truthiness test, a range check, or a struct copy rather
than the literal comparison the first draft of a matcher expects. Measure every
candidate against the corpus and read the hits before shipping; a raw count is
not a defect count.

## Ninth batch: ngx_log_debugN arity is not expressible in ast-grep

Mined from 305 C-touching `fix` commits across the owned `labs/nginx-*` modules
(2026-09-05), on the theory that bugs already fixed here recur. Commit
`e09f571`, "fix: correct ngx_log_debug macro argument count", suggested a rule:
`ngx_log_debugN` encodes its vararg count in the macro name, so a call whose
argument count disagrees with `N` passes an argument the varargs machinery never
reads, and the format directive prints an adjacent stack slot.

The class is real and it recurred: a string-aware argument counter over the
2522 `ngx_log_debugN` calls in `modules/nginx/*` and `labs/nginx-*` finds
exactly one mismatch, `labs/nginx-skeleton-module/src/ngx_http_skel_module.c:271`,
where an `ngx_log_debug2` passes three varargs.

It is nonetheless not expressible as an ast-grep rule. The check is arithmetic
over a capture — "the argument count must equal the digit in the callee name" —
so the only encoding is nine explicit alternatives keyed on `nthChild`. That
encoding does not work, and the reason is worth recording: `nthChild` over an
`argument_list` does not index arguments. A correct five-argument
`ngx_log_debug2` reports a child at `nthChild: 6`, and so does the genuinely
defective six-argument call, so true and false positives are indistinguishable
by count. Adjacent-macro concatenation (`FOO_BASENAME FOO_EXT`) is one source of
the extra child while still matching a five-metavariable pattern, and a
preprocessor conditional inside the argument list is another. An intermediate
draft that excluded `concatenated_string` outright also suppressed the one true
positive, whose format string is split across adjacent literals.

Use a script for this check, not a rule. Shift-width truncation
(`1u << s` assigned to an `ngx_uint_t`, from commit `d1488a8`) was rejected
separately: 297 sites, nearly all constant shifts such as `1u << 20` that are
correct, and the defective form is only defective when the destination is
64-bit, which is a type question ast-grep cannot answer.

## Tenth batch: mined from quality-lint catalogs

Previous passes mined CVE, CWE Top 25, OWASP, the nginx development guide and
this codebase's own fix history — all security-shaped. This pass (2026-09-05)
mined the correctness/nit catalogs instead: staticcheck's SA/S checks and
ruff's flake8-bugbear (B) rules, on the theory that the pack's `correctness`
category was thin — 11 of 69 rules, and every one of the third-party packs the
superrepo consumer vendors alongside this one is security-only, so a plain
quality defect has no lens at all. Every candidate was measured against
first-party code before shipping;
`labs/build_psol/src` is upstream pagespeed and was excluded from the counts.

- `py-raise-without-from` covers ruff B904/CWE-390. Measured 16 hits across 347
  first-party Python files, all genuine: 12 in `tools/mariadb-mcp`, 2 in
  `tools/wp_mcp_client.py`, 2 in `labs/nginx-http-sentinel-module`. Every one
  interpolates the caught exception into the message while dropping the
  explicit chain. It excludes `from None`, the documented suppression idiom,
  and a bare re-raise. It requires the raised expression to be a call, so
  `raise SomeError` (a class, no call) is a false negative; `raise SomeError()`
  and `raise mod.SomeError("x")` both match, so the gap is narrow. A raise
  inside a function or lambda defined within the handler is excluded because
  the matcher cannot determine whether that callable is invoked while the
  exception is still active. A class body defined in the handler runs
  immediately, while the exception is still active; it is excluded only as a
  matcher boundary. A raise inside a `with` block in the handler still runs
  under the active exception and does match.
- `py-zip-without-strict` covers ruff B905/PEP 618. Measured 9 first-party
  hits; three are alignment invariants where truncation would corrupt output
  rather than crash — `eilandert/mailstrix-yara-gen/src/schedule.py:156` pairs
  cron fields with their ranges, `eilandert/mailstrix-yara-gen/src/classifier.py:216`
  pairs feature names with importances, and
  `tools/mariadb-mcp/src/server.py:829` zips three parallel
  lists. It is `info` because shortest-wins is sometimes deliberate. The
  second-positional-argument test excludes one-positional-argument `zip()` even
  when keyword arguments or dictionary splats are present; `zip(*rows)` is
  included separately. A `.zip()` method call is excluded by the
  anchored `^zip$` regex, which sees the attribute node's full text `obj.zip`;
  the `kind: identifier` beside it is redundant and kept only as a guard
  against a future loosening of that anchor. A locally shadowed `zip` still
  matches — the rule resolves no bindings.

Measured rejections, recorded so the seams are not re-mined:

- A `requests`/session call with no `timeout=` argument: 0 first-party hits.
  Every call site in `tools/website-tester` and `labs/webtester` already passes
  one. The `go-http-no-timeout` analogue stays the only timeout rule.
- Go was measured clean on the classic staticcheck shapes across 2366
  first-party non-vendor files: `time.Tick` 0, `signal.Notify` 0, `rand.Seed`
  0, `time.Now().Sub` 0, `fmt.Sprintf("%s", x)` 0, `x == true` 0, defer in a
  range loop 0. golangci-lint already runs on those modules, so the shapes a
  Go linter covers are not worth re-encoding here.
- `in_array($needle, $haystack)` without the strict flag: 43 raw hits, 41 in
  `labs/vimbadmin/vendor` and the rest third-party, against 240 already-strict
  calls. First-party PHP does not carry the defect.
- Bash shapes (`cd $D` 1653, `rm -rf $V` 496) are too broad to narrow into a
  selective matcher at this corpus size; shellcheck already covers them.

The parse trap worth recording: a rule whose `all` array contains only `kind`
plus `not`/`inside` clauses is rejected with "Rule must have one positive
matcher" — `kind` alone does not satisfy it. Adding a positive `has` fixes it.
The `not: {has: {field: cause}}` spelling for excluding `raise ... from` also
failed to compose; `not: {pattern: 'raise $EXC($$$ARGS) from $CAUSE'}` works
and was verified against both forms on 0.45.3.

The splat case was caught in review: `zip(*rows)` is a single `list_splat`
argument that expands to many iterables, so the `nthChild: 2` clause alone
made the common transpose idiom a false negative. The shipped rule matches
either a second argument or a `list_splat`.

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
  including later arrays in a comma-separated declaration. It checks at any depth
  so a preprocessor block cannot displace the sentinel, and accepts the
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

## Cross-language security expansion

This batch covers every ast-grep-supported programming language measured in the
first-party corpus: Bash, C, Go, Java, JavaScript, Lua, PHP, and Python. Perl is
the material exception: 0.45.3 rejects it as an unsupported built-in language.
Upstream custom-language support requires a platform-specific tree-sitter
shared library and is experimental, so parsing Perl as Bash or another language
would create false confidence. Perl remains assigned to a Perl-native analyzer
until that parser build and every consumer config are portable and tested.
The module config maps both `.php` and `.phtml` to PHP. `ruleDirs` imports do
not inherit `languageGlobs`, so each consumer config must repeat that mapping;
the module's discovery test proves its own config rather than every consumer.
The API claims below were checked against the
[ast-grep language list](https://ast-grep.github.io/reference/languages.html),
[Linux temporary-file documentation](https://man7.org/linux/man-pages/man3/tmpnam.3.html),
[Python security guidance](https://docs.python.org/3/library/security_warnings.html),
[Go TLS contract](https://pkg.go.dev/crypto/tls#Config),
[PHP header contract](https://www.php.net/manual/en/function.header.php),
[Bash eval contract](https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html),
and the [Lua standard-library contract](https://www.lua.org/manual/5.4/manual.html#6.9).

- `c-insecure-temp-name` and `py-tempfile-mktemp` inventory APIs that choose a
  name without atomically creating the file. They do not prove that the caller
  later opens the path unsafely. C wrappers, function pointers, Python import
  aliases, and the bare `from tempfile import mktemp` spelling are missed.
- `py-ssl-cert-none` matches the direct qualified assignment, but cannot infer
  the receiver type or client/server role. On a client it disables server
  certificate validation; on a server it can mean that client certificates are
  not requested. Alias imports, helper methods, and configuration dataflow are
  outside the matcher.
- `php-open-redirect-superglobal` sees request superglobals only while they are
  syntactically inside the first positional Location-header argument or the
  named `header:` argument. A value validated and stored earlier is invisible,
  as is an unsafe value stored earlier, so both directions require review.
  Encoding a URL does not establish an allowed origin and deliberately does not
  suppress the finding.
- `sh-eval-expansion` flags reparsing of parameter and command substitutions.
  It cannot decide whether their values are trusted. Direct, `builtin eval`,
  and `command eval` forms match; aliases, other wrappers, and text that only
  expands into another expansion are missed.
  `sh-ssh-host-key-check-disabled` binds the literal disabling option to direct
  or `command`-prefixed ssh/scp/sftp commands before the remote-command region;
  config files, arrays, variables, and other wrappers are not resolved. Its
  conservative operand boundary can miss the option after another option's
  separate value. `accept-new` is outside its stricter literal claim.
- `go-tls-min-version` recognizes the named SSLv3, TLS 1.0, and TLS 1.1
  constants in the nearest `tls.Config` literal. Numeric values, aliases,
  computed constants, and later assignments are missed. The Go default and
  TLS 1.2/1.3 remain negative controls.
- `js-dynamic-code-execution` inventories non-empty direct eval and Function
  calls, whether Function is invoked with or without `new`. A fixed literal
  still matches; symbol shadowing can false-positive, while aliases, indirect
  eval, and member calls are missed.
- `lua-execution-sink` inventories direct shell/process and chunk-loading APIs.
  It cannot distinguish trusted fixed input or local functions shadowing the
  global names. `os.execute()` without a command only checks for shell support
  and is excluded.
- `java-process-exec` inventories direct Runtime execution and a ProcessBuilder
  started immediately or after one chained configuration call. These Java APIs
  do not themselves invoke a shell, so separate fixed arguments can be safe.
  A direct start on a typed ProcessBuilder method or constructor parameter also
  matches, with nested methods, constructors, and lambdas treated as new scopes.
  Longer fluent chains, locally stored builders, aliases, wrappers, and
  executable trust require semantic review.

## 2026 harvest: cross-language expansion

Rules mined from 2025-2026 advisories, CVEs and API contracts across eight
languages, grouped below by language. Per-rule evidence is in
[sources](sources.md); candidates rejected during this harvest are in
[rejected candidates](rejected-candidates.md).

One bullet per shipped rule. Each states what the matcher establishes
syntactically and what it cannot see: every rule here is a single-file syntactic
matcher, so none resolves a type, proves a value is attacker-reachable, or
establishes that a guard runs on every path. Several therefore identify a review
site rather than a proven defect.

## c and nginx

- `c-realloc-assign-same-pointer` matches the identifier text on both sides of
  the assignment. A program that aborts on allocation failure is unaffected, and
  a reallocation routed through a struct field or a differently named variable
  is not matched.
- `c-memset-before-free-secret` requires the zeroing call and the free to be
adjacent sibling statements. A wipe separated by other statements, or performed
  in a helper, is missed. Whether the buffer held key material is not visible to
  syntax.
- `c-memcmp-on-secret` gates entirely on an identifier-name regex, so hash-table
  and configuration comparisons using one of those words are reported and key
  material in a neutrally named buffer is missed.
- `c-read-return-ignored` matches an expression statement only. An explicit
  `(void)` cast parses as a cast expression and is exempt by construction.
  Whether the buffer is then used as if it had been filled is out of scope.
- `c-toctou-access-then-open` pairs the check and the action by first-argument
  identifier text within one function definition, in either order. It cannot see
whether the directory is attacker-writable, and misses paths rebuilt into
another
  variable.
- `c-chroot-without-chdir` is a co-occurrence check inside one function. A
  `chdir` performed by the caller reports here. It says nothing about
  descriptors opened before the chroot or privileges not yet dropped.
- `c-setuid-return-ignored` matches an expression statement; a `(void)` cast is
  exempt. It does not check that `setgroups` and `setgid` preceded `setuid`.
- `c-getenv-to-path-sink` requires the `getenv` call to appear inside the sink
  call's own argument list, so the common shape of storing the value in a local
  first is not matched. It cannot tell whether the process is privileged.
- `c-rand-for-secret` gates on the name of the assignment target, so key
  material flowing through a neutrally named intermediate is missed and a jitter
  value named with one of those words is reported.
- `c-off-by-one-le-sizeof` is advisory: the comparison is correct whenever the
  guarded branch copies exactly that many bytes and writes no terminator. The
matcher reports the comparison in an `if` or `while` condition and does not
inspect
  the guarded body.
- `c-strtok-not-reentrant` is a call-name match. It does not prove that two
  tokenisations can overlap; a single-threaded program with one call site is
  unaffected in practice.
- `nginx-str-data-passed-to-libc` matches a member named `data` in an argument
  to a NUL-expecting function. It does not verify the struct is an `ngx_str_t`,
  and buffers the module terminated itself are safe and still match.
- `nginx-strlen-on-ngx-str-data` has the same `data`-member limitation; an
  unrelated member of that name holding a terminated string is reported.
- `nginx-slab-locked-without-lock` is intraprocedural. A helper genuinely only
reached from a locked caller reports here unless its own name contains `locked`,
which the rule treats as that declaration. A lock taken through a macro is
invisible.
- `nginx-shm-data-write-without-lock` is advisory co-occurrence. Functions whose
  name ends in `init_zone` are excluded as one-shot setup; other one-shot setup
  paths are not recognised, and a lock taken by the caller is invisible.
- `nginx-escape-uri-alloc-without-double` requires both calls in one function
  with the sizing result reaching the allocation through the same named
  variable. The two-pass escape split across length and copy handlers, which is
  nginx's own structure, is not seen. `ngx_escape_html` and `ngx_escape_json`
  return the extra byte count already and are excluded.
- `nginx-finalize-plus-return-rc` is advisory. It cannot tell whether the
  enclosing function is a content handler, where the double finalize bites, or
  an event callback, where the return value is discarded and the pattern is
  harmless.
- `nginx-init-returns-http-status` identifies the hook by name suffix, so a hook
registered under another name is missed and an ordinary helper ending in one of
those suffixes is reported. Only a literal `NGX_HTTP_` identifier in a `return`
is
  matched.
- `nginx-use-after-finalize` does not model the reference count: a request whose
count is still above one survives the finalize and the later access is correct.
A
tail `return` immediately after the finalize does not match, nor does a use in a
  different block.

## go

- `go-template-html-cast` flags a typed-string conversion whose operand is not a
  string literal. It cannot see a sanitiser, so a value returned from
  bluemonday or read from trusted configuration also matches; keep it advisory.
- `go-template-parse-dynamic` recognizes a non-literal argument to a `Parse`
  method on a template-named receiver. Template text read from an embedded
  filesystem matches identically to attacker-supplied text. `ParseFiles` and
  `ParseFS` are outside the matcher.
- `go-text-template-response` is a file-level pairing of the `text/template` and
  `net/http` imports, not a claim about any expression. A package that renders
  text templates for mail or config while separately serving HTTP matches.
- `go-file-open-request-path` requires the request accessor to be nested inside
  the filesystem call or its join, in one expression. The variable-carried form
  is not matched at all, and a containment check in a helper is invisible.
  Joining onto a base directory does not clear the finding, because a parent
  segment is still resolved relative to that base.
- `go-path-check-string-match` fires on the substring test or single
  replacement itself, with no view of the filesystem call it guards. It cannot
  tell whether the check is the only guard, so a layered check matches.
- `go-http-server-no-header-timeout` inspects the literal or the bare
  `ListenAndServe` call. A timeout assigned to the server on a later statement
  is not seen, and a loopback-only or proxied listener matches anyway.
- `go-request-body-unbounded` searches the enclosing function declaration for a
  `MaxBytesReader` or `LimitReader` call. A limit applied by middleware, or on a
  reader built in another function, is invisible and produces a match.
- `go-decompress-readall` requires the decompressing reader construction and the
  full read to sit in one function declaration. A reader passed in as a
  parameter is not matched. `io.Copy` to a file is a sibling shape not covered.
- `go-exec-shell-c` requires a literal shell name and a literal command-string
  flag in the argument positions before the command. A command assembled purely
  from trusted constants in a variable still matches. It does not overlap
  `go-exec-sprintf`, which keys on a formatted argument rather than a shell.
- `go-http-request-url-ssrf` matches only a request accessor written directly as
  the URL argument. Any validation performed on a named variable before the
  fetch puts the call outside the matcher entirely.
- `go-http-redirect-request-value` likewise covers the direct-argument form
  only; the variable-carried redirect is not matched, whether or not it is
  validated.
- `go-mac-compare-variable-time` keys on a `Sum` call as one side of the
  comparison. A MAC compared through an intermediate variable is missed, and a
  non-security checksum comparison that happens to use `Sum` matches.
- `go-aes-gcm-static-nonce` detects a byte-literal nonce, a `[]byte("...")`
  conversion, and a `make` buffer never randomised inside the same function. A
  nonce filled by a helper matches spuriously; a correct counter-derived nonce
  maintained outside the function also matches.
- `go-rsa-generatekey-small` reads an integer literal only. A size held in a
  variable or a named constant is not decidable here.
- `go-cipher-mode-weak` matches constructor names. It cannot see an
  encrypt-then-MAC layer that supplies the missing integrity, and it flags
  decrypt-only legacy paths equally.
- `go-jwt-unverified` covers the unverified-parse entry points and the
  none-algorithm constants by name. A key function that omits an algorithm check
  is a separate, undecidable claim and is not attempted here.
- `go-cookie-insecure-flags` reads keyed fields of one composite literal and
  gates on a credential-looking name. Flags set field-by-field after
  construction are missed; gin's positional `SetCookie` is not covered.
- `go-cors-wildcard-credentials` requires both settings in one configuration
  literal. A config assembled across statements, or the reflected-origin
  middleware shape written as two `Header().Set` calls, is not matched.
- `go-file-perm-world-writable` tests the numeric literal's other-write bit and
  `os.ModePerm`. The process umask may clear that bit at runtime, and a mode
  behind a named constant is not visible.
- `go-tempfile-fixed-path` recognizes a literal path under a shared temporary
  directory, or a literal name joined onto `os.TempDir`. A path built from
  `TMPDIR` or another environment variable is missed.
- `go-strconv-atoi-narrow-cast` requires the parse call to be the operand of the
  conversion in one expression. The two-statement form is missed, and a
  conversion whose input was already range-checked matches.
- `go-unsafe-pointer-uintptr-arith` matches only when the arithmetic result is
  stored, which is the shape `unsafe.Pointer` rule 3 forbids; the valid
  single-expression form is correctly excluded. `go vet`'s unsafeptr check
  overlaps part of this ground.
- `go-xml-decoder-strict-off` matches the field assignment by name and does not
  check the decoder's input. Go's XML decoder resolves no external entities, so
  this is parser hardening rather than XXE.
- `go-gob-decode-network` uses connection-shaped identifiers and `Body`/`Conn`
  field names as the network signal. A gob stream between trusted processes
  matches, and a limit applied to the reader elsewhere is not seen.

## php and wordpress

- `wp-rest-permission-return-true` recognizes the `__return_true` literal, an
  arrow function returning `true`, and a closure whose body is a single `return
  true`. It cannot decide whether a route is meant to be public, and it does not
  see a capability check performed inside the route callback instead of the
  permission callback.
- `wp-ajax-nopriv-registration` matches the hook-name literal only. It is an
  inventory rule: it does not inspect the handler body, so a genuinely public
  front-end endpoint matches. A hook name assembled from a variable is
  invisible.
- `wp-update-user-meta-request-key` sees a superglobal in the meta-key argument.
  Sanitizer wrappers are treated as transparent because they restrict
  characters, not which key is written. A key reaching the call through a
  variable, a `foreach` key, or `WP_REST_Request::get_param()` escapes the rule.
- `wp-update-user-role-request` covers `set_role`/`add_role`/`add_cap` arguments
  and the `role` entry of a `wp_update_user`/`wp_insert_user` array literal. An
  `in_array` allowlist applied in a preceding statement is invisible, so a
  guarded assignment through a variable does not match and a guarded assignment
  written inline does.
- `wp-update-option-request-key` checks only the option-name position. A literal
  option name written with a request-derived value is a different,
  lower-severity class that needs the surrounding capability check to judge,
  which syntax cannot see.
- `wp-wpdb-prepare-quoted-placeholder` regex-matches the literal SQL text of the
  first `prepare` argument. A query assembled in a variable before the call is
  invisible, and a quoted percent sequence that is data rather than a
  placeholder would match.
- `wp-wpdb-orderby-interpolation` excludes the `{$wpdb->...}` identifier forms
  but cannot see an allowlist applied to the interpolated variable in a
  preceding statement, so a query that already restricts the column to a fixed
  set still matches. Treat it as "confirm the allowlist", not as proof of
  injection.
- `wp-unlink-request-path` treats `sanitize_text_field`, `esc_attr` and
  `wp_unslash` as transparent because none removes a traversal sequence. It does
  not treat a `basename` wrapper as safe either, so a basename-guarded delete
  matches and is the routine dismissal. A path assembled in a preceding
  statement is invisible.
- `wp-template-include-request` keys on superglobals and on subscripts of
  `$atts`/`$attributes`, which is a shortcode naming convention rather than a
  guarantee. A slug reaching the call through another variable is invisible. It
  complements `php-file-inclusion-variable`, which covers `include`/`require`.
- `wp-remote-request-user-url` treats `esc_url_raw` and `sanitize_url` as
  transparent. A URL read from a REST request object or passed through a
  variable is invisible, and `wp_safe_remote_*` is itself only a partial defence
  against DNS rebinding, so the safe side is "reviewed", not "proven".
- `wp-redirect-not-safe` treats `esc_url`/`esc_url_raw` as transparent. A
  destination reaching the call through a variable, or one already filtered by
  `wp_validate_redirect`, is invisible. It complements
  `php-open-redirect-superglobal`, which matches the raw `header()` call and
  does not see `wp_redirect`.
- `wp-verify-nonce-result-discarded` matches only an expression statement whose
  whole expression is the call. A result assigned to a variable and then never
  branched on is not syntactically distinguishable from a legitimate use.
- `wp-check-ajax-referer-nodie-unchecked` requires the third positional argument
  to be the literal `false`. A stop argument supplied through a variable or as a
  named argument escapes the rule.
- `wp-maybe-unserialize-untrusted` excludes the legitimate
  `get_option`/`get_post_meta`/`get_user_meta` sources. A payload that reaches
  the call through a variable is invisible. `php-unserialize` covers the plain
  `unserialize` function.
- `wp-echo-option-unescaped` does not check that the chosen escaper suits the
  surrounding context: `esc_html` around a value placed in an `href` satisfies
  the rule but is still wrong. A value fetched in a preceding statement and
  echoed later is invisible.
- `wp-shortcode-atts-unescaped-output` keys on the `$atts`/`$args`/`$attributes`
  naming convention, so a same-named array of trusted values is the routine
  dismissal. `esc_attr` around a URL satisfies the rule but is the wrong escaper
  for that context.
- `wp-is-admin-as-authorization` matches only an `if` whose condition is
  `is_admin()` and whose body is a single return, exit or die. Loading admin
  assets behind such a guard is a legitimate use; the finding matters when the
  code after the guard changes state. A capability check elsewhere in the
  function is invisible.
- `wp-unzip-file-request` matches a superglobal in the archive or destination
  argument. Even a fixed destination is unsafe when entry names are not
  filtered, so a match with a literal target needs review rather than dismissal;
  an archive path held in a variable is invisible.
- `php-create-function-call` matches by name. On PHP 8 the call is a fatal error
  rather than a sink, which is the routine dismissal for dead legacy code that
  still needs removing.
- `php-dynamic-callable-from-request` requires the superglobal subscript to be
  the whole callable expression, so an allowlist lookup that merely indexes a
  local map with request data does not match. A callable assembled into a
  variable in a preceding statement is invisible.
- `php-preg-replace-eval-modifier` regex-matches the modifier letters after the
  closing delimiter for the common delimiters only. A pattern assembled in a
  variable is invisible. On PHP 7 and later the call fails instead of executing.
- `php-libxml-entity-loading-enabled` sees only an explicit flag constant or a
  literal `false`. A flag value computed in a variable is invisible, and on PHP
  before 8.0 the unsafe behaviour was the default, so an unflagged parse there
  is still vulnerable and this rule cannot prove it.
- `php-secret-compare-not-hash-equals` keys on a secret-shaped superglobal
  subscript key. It cannot tell how many attempts an attacker can make, so a
  value compared once behind strict rate limiting is the routine dismissal.
  `php-hash-loose-compare` covers the hash-function comparison shapes.
- `php-mail-header-request` is position-based on the fourth argument of
  `mail`/`wp_mail`. A direct `sanitize_email`/`filter_var` wrapper suppresses
  the match; a check performed on a preceding line, or a header assembled in a
  variable, is invisible.
- `php-fetch-request-url` treats `esc_url_raw` and `filter_var` as transparent
  because a well-formed URL can still name an internal host, and it does not
  treat `basename` as safe. A target held in a variable is invisible.
- `php-file-write-request-path` covers the write sinks other than
  `move_uploaded_file`, which `php-upload-unvalidated-name` owns. An extension
  allowlist applied earlier in the function is invisible.
- `php-dotdot-strip-as-traversal-guard` does not check that the stripped value
  reaches a filesystem call, so stripping dot sequences from data that is never
  used as a path matches and is the routine dismissal. A search string held in a
  variable is invisible.

## python

- `py-torch-load-untrusted` sees only the absence of a literal
  `weights_only=True` in the argument list. A torch module imported under
  another name, and the keyword supplied through a dictionary splat or a
  variable, are not resolved, and the trust level of the checkpoint path is
  unknown.
- `py-numpy-load-allow-pickle` requires the literal `True`. A flag held in a
variable, folded from configuration, or splatted in, is invisible, and the rule
  cannot tell whether the file is one the same program wrote.
- `py-pickle-equivalent-loads` matches qualified module calls only. A loader
  imported bare with `from dill import loads`, or bound to an alias, is not
  resolved, and the rule reports the sink without any knowledge of the source.
- `py-joblib-load` matches any receiver whose text ends in `joblib`, which
  covers the `sklearn.externals.joblib` spelling but also an unrelated object
  with that name. It has no view of where the model file came from.
- `py-zipfile-extractall` matches `extractall` on any receiver, so a zip, tar,
  wheel or an unrelated class with that method name are indistinguishable, and
  the archive's provenance is unknown.
- `py-lxml-parser-resolve-entities` cannot determine whether the constructor
  belongs to `lxml.etree`, nor whether the parser is only ever used on documents
  the deployment generated. It also does not see a parser configured after
  construction by attribute assignment.
- `py-stdlib-xml-parse` recognises modules by name, so a `defusedxml` module
  bound to the short name `ET` is indistinguishable from the stdlib one; only an
explicit `defusedxml.` prefix is excluded. Document provenance is not modelled.
- `py-render-template-string-dynamic` requires the interpolation or
  concatenation to appear in the call itself. A template assembled into a
  variable one statement earlier, or loaded from a database, is not seen.
- `py-jinja2-autoescape-off` reads the constructor arguments only. An
  environment whose `autoescape` attribute is set afterwards is not seen, and a
  legitimately non-markup environment (configuration, SQL, plain-text mail)
  matches by design.
- `py-flask-debug-true` matches `run(debug=True)` on any receiver and cannot
  tell a development entry point from a module the deployment imports.
- `py-flask-hardcoded-secret-key` requires a plain string literal. A key read
  from the environment, or built by interpolation, is not matched, and the rule
  cannot tell a test placeholder from a production fallback.
- `py-django-debug-true` and `py-django-allowed-hosts-wildcard` see one module.
  Split settings packages where a later module overrides the value, and values
  derived from the environment, are outside the matcher's view.
- `py-sql-string-build` requires the dynamic construction to occur in the call's
  first argument. A statement built into a variable first is not seen, and an
  interpolated identifier the program itself chose from a fixed set is a
  legitimate match the rule cannot distinguish.
- `py-django-queryset-request-kwargs` matches the method name, not the receiver
  type, so any object with a `filter` or `values` method matches. A parameter
  dictionary copied to a variable, and validation done there, are not seen.
- `py-open-redirect-request` and `py-open-request-arg` require the request
  expression to be the call's own first argument. Any validation performed on an
  intermediate variable is invisible, and a framework-sanitised value still
  matches when written inline.
- `py-requests-no-timeout` sees only the `requests` module spelling. A session
  with a mounted adapter carrying a timeout, an outer deadline, and a timeout
  passed through a dictionary splat are all invisible.
- `py-ssl-unverified-context` matches three specific spellings. A context
  weakened inside a helper function or driven by a configuration flag is not
  seen, and a test against a local self-signed fixture matches by design.
- `py-paramiko-autoadd-policy` requires the policy to be named in the call. A
policy held in a variable, or a custom class that auto-accepts, is not matched.
- `py-jwt-alg-none-or-mixed` reads literal algorithm lists only. A list built
  from configuration or a constant defined elsewhere is not seen, and a
  same-family rollover pair is deliberately not matched.
- `py-os-system-popen` requires the dynamic construction in the first argument.
  A command built into a variable first is not seen, and a value already passed
  through `shlex.quote` inside an f-string still matches.
- `py-is-literal-compare` is pure syntax with no semantic limit worth noting; it
  reports every `is` comparison against a literal of the listed kinds.
- `py-world-writable-perms` reads octal literals. A mode computed from `stat`
  constants, read from configuration, or masked at runtime is invisible; the
  sticky-bit shared-directory mode is excluded by an explicit exception.
- `py-cryptography-weak-primitives` matches constructor and keyword spellings.
  PKCS1 v1.5 used for signature verification is deliberately excluded, and a
  primitive kept only to read legacy data still matches.
- `py-cors-wildcard-credentials` treats a missing origin setting as the library
  default wildcard. Origins supplied from configuration, and a `resources`
  mapping whose nested origins are wildcards, are outside the matcher's view.
- `py-random-for-secret` is a name heuristic over the assignment target and
  recognises the module by the literal `random` prefix, so an aliased import is
  missed and a jitter value with a matching name is a false positive.
  `random.SystemRandom` is excluded.
- `py-secret-compare-equals` is a name and shape heuristic. A comparison of a
  value that merely looks secret matches, and a comparison against a slow-KDF
  password verifier result is not a timing problem despite matching.
- `py-assert-for-auth` is a name heuristic over the assert condition's source
  text. Asserts in test modules, which are never run under `-O`, match by design
  and are normally excluded at the scanner by path.
- `py-format-on-request-template` requires the request expression to be the
  format receiver or the `Template` argument. A template loaded from a database
  or an editable configuration file is the same defect and is not seen.
- `py-weak-hash-for-password` is a name heuristic over the argument source text.
  A checksum of a variable that happens to carry a matching name is a false
  positive, and `usedforsecurity=False` is not modelled.
- `py-ldap-xpath-filter-build` does not resolve the receiver type, so any
  `search` method on any object matches when its argument is interpolated.
  Whether the interpolated value is caller-controlled is unknown.
- `py-dynamic-import-request` requires the request expression in the name
  position of the call. A name copied to a variable first, and a loop that
  spreads a request dictionary over `setattr`, are not seen.

## javascript

- `js-child-process-shell-interpolation` sees a template literal or a `+`
  concatenation in the command slot of an `exec` family call. It cannot tell
  whether the interpolated value was validated upstream, and it does not read
  the `shell` option, so a `spawn` with an argv array and a concatenated
  executable path still matches while a shell-enabled call built from a variable
  does not.
- `js-dom-html-sink` recognises `DOMPurify.sanitize`, `sanitizeHtml` and
  `escapeHtml` by name only. A sanitizer under any other name, or one applied on
  an earlier line, reads as an unsafe value; a locally defined function called
  `sanitize` reads as safe.
- `js-express-open-redirect` requires the `req.*` access to be a direct argument
  of `res.redirect`. A value copied into a local variable, or checked against an
  allowlist before the call, is invisible, and so is a redirect helper wrapping
  the call.
- `js-express-reflected-response` matches only a template or a concatenation in
  the first argument. It cannot see a `Content-Type` set earlier that would make
  the body inert, and it does not recognise escaping wrappers, so an escaped
  concatenation still matches.
- `js-tls-verification-disabled` matches only literal `false`, the literal
  string `"0"` and an empty `checkServerIdentity`. A verification flag driven by
  an environment lookup or a configuration value is missed in both directions.
- `js-weak-hash-algorithm` cannot distinguish a security digest from a cache key
  or an ETag, which is the dominant benign use of MD5; it is a warning for that
  reason. An algorithm name held in a variable is not matched.
- `js-weak-cipher-algorithm` reads the algorithm string literally. It does not
  check IV uniqueness or key length, and a transformation assembled from
  configuration is missed.
- `js-jwt-algorithm-unpinned` looks only at the call site, so an options object
  built in a variable is reported as unpinned even when it pins the algorithm.
  `jwt.decode`, which never verifies, is deliberately out of scope.
- `js-cors-credentials-wildcard` does not follow an `origin` callback function,
  which can be safe or unsafe, and it does not correlate the two manual header
  calls with one another; each is judged on its own shape.
- `js-express-static-dotfiles` does not look at what the served directory
  contains, so a purpose-built directory of dotfiles matches.
- `js-vm-sandbox-dynamic-source` excludes a literal source even though the `vm`
  module is not an isolation boundary for literals either. It cannot show that
  the dynamic string is attacker-controlled.
- `js-insecure-random-secret` is a name heuristic. A security value under a
  neutral name is missed; a cosmetic identifier containing `key` or `session` is
  reported.

## java

- `java-weak-hash-algorithm` matches string literals only. A constant or a
  configured algorithm name is missed, and MD5 used as a checksum is a known
  false positive, which is why it is a warning.
- `java-weak-cipher-transformation` lists block ciphers explicitly on the ECB
  arm, because `ECB` in an RSA transformation is a naming artefact. It cannot
  see key length or IV reuse.
- `java-native-deserialization-sink` is a call-site matcher: an
`ObjectInputFilter` installed on a separate statement, or a `Yaml` built with a
  `SafeConstructor` and stored in a variable, is not visible, so a filtered
  stream still matches.
- `java-sql-concat-query` requires at least one non-literal operand in the
  concatenation. A query assembled into a local variable first, and a bare
  identifier argument, are both invisible.
- `java-jndi-lookup-dynamic` treats any non-literal name as dynamic, so a name
  read from a configuration constant is reported. That false positive is
  accepted because a reachable dynamic lookup is severe.
- `java-expression-eval-dynamic` does not model a restricted SpEL evaluation
  context, so a `SimpleEvaluationContext`-guarded parse matches. The receiver is
  recognised by variable name for the parser and engine cases.
- `java-trust-all-tls` treats a body containing any statement as non-empty, so a
  stub that only logs is missed. A trust-all stub confined to a test profile
  still matches.
- `java-response-open-redirect` needs the request read in the argument itself.
  An allowlist check on an earlier line, or a value carried through a local
  variable, is invisible.
- `java-cookie-missing-flags` matches an inline `Cookie` construction only; a
  cookie configured through a variable and then added is missed. On the
`ResponseCookie` arm a chain that sets one of the two flags is left alone, so a
  chain missing only `secure` is not reported. Container-level cookie
  configuration is invisible.
- `java-xml-factory-doctype-unset` scopes the hardening search to the enclosing
  method. A factory hardened in a helper, in a field initialiser, or by a
  secure-processing wrapper is a false positive, which is why it is a warning.
- `java-spring-csrf-disabled` cannot see whether the same chain sets a stateless
session policy, which makes disabling CSRF defensible, so a token-only API is a
  known false positive.
- `java-format-string-not-literal` does not distinguish the locale-first
  `Formatter` overloads, so a call passing a `Locale` first is reported, and a
  constant format string held in a field is reported as non-literal.

## lua

- `lua-sql-string-concat` recognises `ngx.quote_sql_str` and `tonumber` by name
only; a local function with either name reads as safe. A statement built into a
  variable on an earlier line is not matched.
- `lua-redirect-user-target` does not report an escaped value used as the whole
  location, even though `ngx.escape_uri` only protects a value placed in a query
  slot.
- `lua-response-reflect-unescaped` excludes `ngx.var.upstream_http_*` because
  those originate upstream, and it cannot see a content type set earlier that
  would make the body inert.
- `lua-subrequest-user-uri` inspects the first, URI argument only. The `args`
  option table is deliberately not inspected because the module escapes it, and
  `capture_multi` is not covered because its URIs sit in a nested table.
- `lua-http-client-verify-disabled` matches a literal `false` only; a verify
  flag passed through a variable or a configuration lookup is missed.
- `lua-io-open-user-path` requires an `ngx` request token in the path, which
  excludes the Kong plugin loader idiom but also misses a request value carried
  through a local variable. A traversal check on an earlier line is invisible.
- `lua-regex-user-pattern` does not check the fourth argument of `string.find`,
  so a plain find with `true` is reported even though it does no pattern
  matching.
- `lua-uri-args-unbounded` matches a literal zero only. A no-argument call is
  deliberately not matched because the module applies a default of 100, and a
  limit passed in a variable is missed; the matcher does not check that the
  `truncated` error is handled.
- `lua-insecure-random-token` is a name heuristic on the assignment target. A
security value under a neutral name is missed; a cosmetic identifier containing
  one of the listed words is reported. The `os.tmpname` arm is precise.
- `lua-cjson-decode-unprotected` cannot see whether `cjson` was required as
  `cjson.safe` at the top of the file, because the call site looks identical, so
  a file using the safe module is a false positive. An enclosing `pcall` several
  frames up is also not seen.
- `lua-exit-without-return` reports a bare terminating call even as the last
  statement of a handler, where it behaves like a return in most phases. Which
  phase the code runs in is not visible.

## bash

- `sh-world-writable-permissions` reads the mode as a literal token, so a mode
passed in a variable is missed, and a wide mode on a private per-user directory
  is still reported.
- `sh-secret-on-command-line` decides that a value is a secret from the variable
  name. A secret under a neutral name is missed, and a non-secret variable whose
  name happens to contain `KEY` is reported.
- `sh-predictable-temp-path` matches literal `/tmp` and `/var/tmp` paths and the
  dry-run `mktemp`. A path built from a `TMPDIR` expansion is not matched, and
  whether the directory is really shared is not checked.
- `sh-rm-rf-unguarded-variable` cannot see a `set -u` at the top of the file or
  a guard written as a separate test, so a script that already checks the
  variable is reported.
- `sh-container-isolation-disabled` matches literal flags and their separate
  values. Options composed in a variable are missed, and a lab script that
  legitimately needs a privileged container matches.
- `sh-host-hardening-disabled` reads literal tokens, so the same action
  performed through a variable or a configuration management tool is missed; a
  deliberate temporary change in an interactive script still matches.
- `sh-archive-extract-to-system-root` cannot see where the archive came from, so
  a vendor tarball extracted into the root matches. Extraction into any other
  directory is not reported, even though a malicious archive can escape it.
- `sh-path-search-includes-cwd` does not follow a PATH assembled in another
  variable and assigned later, and it does not judge whether the listed
  directories are themselves writable.
- `sh-remote-shell-string-interpolation` excludes the argv-after-double-dash
  form for `ssh` and excludes a single-word interpolating operand such as the
  host. It cannot tell whether the interpolated value is attacker-controlled,
  and a value already quoted for the remote shell still matches.
- `sh-process-substitution-shell-input` covers process substitution and here
  strings, which `sh-curl-pipe-shell` does not reach because no pipeline is
  involved. Vendor install instructions use this shape.
- `sh-printf-format-not-literal` reports a format string held in a variable on
  purpose, for example a reusable table row layout.
- `sh-arithmetic-context-injection` cannot see a `case` or regex guard applied
  on an earlier line, so a script that already validates the value is reported.
  Arithmetic on a variable from a non-positional source is not matched.
