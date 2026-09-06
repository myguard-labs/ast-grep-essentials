# Detection boundaries — harvested Go rules

One bullet per rule, in the style of `docs/limitations.md`. All of these are
syntactic matchers: none resolves a type, proves a value is attacker-reachable,
or establishes that a guard runs on every path.

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
