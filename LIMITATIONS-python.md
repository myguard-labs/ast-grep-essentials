# Python rule limitations

Each bullet states what the matcher establishes syntactically and what it cannot
see. Syntax cannot prove taint, type, reachability or configuration precedence,
so several of these rules identify a review site rather than a proven defect.

- `py-torch-load-untrusted` sees only the absence of a literal `weights_only=True`
  in the argument list. A torch module imported under another name, and the
  keyword supplied through a dictionary splat or a variable, are not resolved,
  and the trust level of the checkpoint path is unknown.
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
- `py-render-template-string-dynamic` requires the interpolation or concatenation
  to appear in the call itself. A template assembled into a variable one
  statement earlier, or loaded from a database, is not seen.
- `py-jinja2-autoescape-off` reads the constructor arguments only. An environment
  whose `autoescape` attribute is set afterwards is not seen, and a legitimately
  non-markup environment (configuration, SQL, plain-text mail) matches by design.
- `py-flask-debug-true` matches `run(debug=True)` on any receiver and cannot tell
  a development entry point from a module the deployment imports.
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
