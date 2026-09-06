# Limitations of the harvested C / nginx rules

- `c-realloc-assign-same-pointer` matches the identifier text on both sides of the
  assignment. A program that aborts on allocation failure is unaffected, and a
  reallocation routed through a struct field or a differently named variable is
  not matched.
- `c-memset-before-free-secret` requires the zeroing call and the free to be
  adjacent sibling statements. A wipe separated by other statements, or performed
  in a helper, is missed. Whether the buffer held key material is not visible to
  syntax.
- `c-memcmp-on-secret` gates entirely on an identifier-name regex, so hash-table
  and configuration comparisons using one of those words are reported and key
  material in a neutrally named buffer is missed.
- `c-strncpy-no-terminator` matches the destination identifier appearing both as an
  argument and inside the `sizeof` bound. It does not look for a following explicit
  terminator assignment, so a correctly terminated site still matches; a bound given
  as a macro is not matched at all.
- `c-read-return-ignored` matches an expression statement only. An explicit `(void)`
  cast parses as a cast expression and is exempt by construction. Whether the buffer
  is then used as if it had been filled is out of scope.
- `c-toctou-access-then-open` pairs the check and the action by first-argument
  identifier text within one function definition, in either order. It cannot see
  whether the directory is attacker-writable, and misses paths rebuilt into another
  variable.
- `c-chroot-without-chdir` is a co-occurrence check inside one function. A `chdir`
  performed by the caller reports here. It says nothing about descriptors opened
  before the chroot or privileges not yet dropped.
- `c-setuid-return-ignored` matches an expression statement; a `(void)` cast is
  exempt. It does not check that `setgroups` and `setgid` preceded `setuid`.
- `c-getenv-to-path-sink` requires the `getenv` call to appear inside the sink call's
  own argument list, so the common shape of storing the value in a local first is not
  matched. It cannot tell whether the process is privileged.
- `c-rand-for-secret` gates on the name of the assignment target, so key material
  flowing through a neutrally named intermediate is missed and a jitter value named
  with one of those words is reported.
- `c-off-by-one-le-sizeof` is advisory: the comparison is correct whenever the
  guarded branch copies exactly that many bytes and writes no terminator. The
  matcher reports the comparison in an `if` or `while` condition and does not inspect
  the guarded body.
- `c-strtok-not-reentrant` is a call-name match. It does not prove that two
  tokenisations can overlap; a single-threaded program with one call site is
  unaffected in practice.
- `nginx-str-data-passed-to-libc` matches a member named `data` in an argument to a
  NUL-expecting function. It does not verify the struct is an `ngx_str_t`, and
  buffers the module terminated itself are safe and still match.
- `nginx-strlen-on-ngx-str-data` has the same `data`-member limitation; an unrelated
  member of that name holding a terminated string is reported.
- `nginx-slab-locked-without-lock` is intraprocedural. A helper genuinely only
  reached from a locked caller reports here unless its own name contains `locked`,
  which the rule treats as that declaration. A lock taken through a macro is invisible.
- `nginx-shm-data-write-without-lock` is advisory co-occurrence. Functions whose name
  ends in `init_zone` are excluded as one-shot setup; other one-shot setup paths are
  not recognised, and a lock taken by the caller is invisible.
- `nginx-escape-uri-alloc-without-double` requires both calls in one function with the
  sizing result reaching the allocation through the same named variable. The two-pass
  escape split across length and copy handlers, which is nginx's own structure, is not
  seen. `ngx_escape_html` and `ngx_escape_json` return the extra byte count already
  and are excluded.
- `nginx-finalize-plus-return-rc` is advisory. It cannot tell whether the enclosing
  function is a content handler, where the double finalize bites, or an event
  callback, where the return value is discarded and the pattern is harmless.
- `nginx-init-returns-http-status` identifies the hook by name suffix, so a hook
  registered under another name is missed and an ordinary helper ending in one of
  those suffixes is reported. Only a literal `NGX_HTTP_` identifier in a `return` is
  matched.
- `nginx-use-after-finalize` does not model the reference count: a request whose
  count is still above one survives the finalize and the later access is correct. A
  tail `return` immediately after the finalize does not match, nor does a use in a
  different block.
