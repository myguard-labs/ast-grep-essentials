# Rule evidence

Source advisory, CVE or API contract behind each rule shipped in the 2026
cross-language harvest. Upstream pages are living references; the claim each
rule makes is fixed by its fixtures, not by the linked page.

- `c-realloc-assign-same-pointer` — CWE-401; curl coding style
  (`Curl_saferealloc`) <https://curl.se/dev/internals.html>
- `c-memset-before-free-secret` — CWE-14
  <https://cwe.mitre.org/data/definitions/14.html>; glibc `explicit_bzero`,
  OpenSSL `OPENSSL_cleanse`
- `c-memcmp-on-secret` — CWE-208
  <https://cwe.mitre.org/data/definitions/208.html>; OpenSSL `CRYPTO_memcmp`
  contract
  <https://cwe.mitre.org/data/definitions/170.html>
- `c-read-return-ignored` — CWE-252
  <https://cwe.mitre.org/data/definitions/252.html>
- `c-toctou-access-then-open` — CWE-367
  <https://cwe.mitre.org/data/definitions/367.html>; sudo CVE-2025-32463
  <https://www.oligo.security/blog/new-sudo-vulnerabilities-cve-2025-32462-and-cve-2025-32463>
- `c-chroot-without-chdir` — CWE-243
  <https://cwe.mitre.org/data/definitions/243.html>; sudo CVE-2025-32463
- `c-setuid-return-ignored` — CWE-273
  <https://cwe.mitre.org/data/definitions/273.html>; CWE-250
- `c-getenv-to-path-sink` — CWE-427
  <https://cwe.mitre.org/data/definitions/427.html>; sudo CVE-2025-32463
- `c-rand-for-secret` — CWE-338
  <https://cwe.mitre.org/data/definitions/338.html>; `ngx_random` is `random()`
  seeded from pid/time
- `c-off-by-one-le-sizeof` — CWE-193
  <https://cwe.mitre.org/data/definitions/193.html>; CVE-2026-27784,
  CVE-2026-27654 length-boundary overflows
- `c-strtok-not-reentrant` — CWE-663
  <https://cwe.mitre.org/data/definitions/663.html>
- `nginx-str-data-passed-to-libc` — nginx development guide, ngx_str_t is not
  NUL-terminated
  <https://nginx.org/en/docs/dev/development_guide.html#string_overview>
- `nginx-strlen-on-ngx-str-data` — same as above
- `nginx-slab-locked-without-lock` — nginx slab API contract,
  `src/core/ngx_slab.c`
- `nginx-shm-data-write-without-lock` — nginx limit_req / limit_conn /
  ssl_session_cache shared-zone implementations
- `nginx-escape-uri-alloc-without-double` — CVE-2026-42945
  <https://nginx.org/en/security_advisories.html> and
  <https://www.akamai.com/blog/security-research/nginx-critical-heap-buffer-overflow-cve-2026-42945>;
  `ngx_escape_uri` returns the escaped-character count, each costing two extra
  bytes
- `nginx-finalize-plus-return-rc` — nginx development guide, request
  finalization
  <https://nginx.org/en/docs/dev/development_guide.html#http_request_finalization>
- `nginx-init-returns-http-status` — nginx module init hook contracts,
  `ngx_init_modules` and `ngx_http_block`
- `nginx-use-after-finalize` — CVE-2026-40701 resolver UAF
  <https://nginx.org/en/security_advisories.html>; nginx development guide,
  request finalization

Rule id -> evidence consulted during the harvest.

- `go-template-html-cast` — <https://pkg.go.dev/html/template> (typed strings);
  CVE-2026-27142, CVE-2026-39823, CVE-2026-56858 html/template escaper bugs
  (golang/go#78913);
  <https://www.sourcery.ai/vulnerabilities/go-template-html-vulnerable>
- `go-template-parse-dynamic` —
  <https://onsecurity.io/article/go-ssti-method-research/> ;
  <https://gusralph.info/go-ssti-research/> ;
  <https://github.com/github/securitylab/issues/812>
- `go-text-template-response` —
  <https://www.oligo.security/blog/safe-by-default-or-vulnerable-by-design-golang-server-side-template-injection>
- `go-file-open-request-path` — CVE-2026-35471 (goshs traversal, file deletion);
  GO-2026-4585 (FileBrowser share traversal); GO-2026-4502 (echo Static
  backslash); CVE-2026-25766; <https://pkg.go.dev/net/http#ServeFile> caveat
- `go-path-check-string-match` — GO-2026-4502 echo backslash traversal on
  Windows; CVE-2026-35471; <https://pkg.go.dev/path/filepath#IsLocal>
- `go-http-server-no-header-timeout` — gosec G112/G114;
  <https://github.com/securego/gosec/issues/823> ;
  <https://github.com/cert-manager/cert-manager/pull/6534>
- `go-request-body-unbounded` — CVE-2026-54448 (Trivy); CVE-2026-73232 (ffuf);
  <https://pkg.go.dev/net/http#MaxBytesReader>
- `go-decompress-readall` — CVE-2026-54448; CVE-2026-32282 (archive/tar sparse
  map);
  <https://www.vulncheck.com/advisories/rpcx-denial-of-service-via-gzip-decompression-bomb-in-wire-protocol>
- `go-exec-shell-c` — CVE-2026-29042 (nuclio,
  github.com/nuclio/nuclio/pull/4030);
  <https://snyk.io/blog/understanding-go-command-injection-vulnerabilities/>
- `go-http-request-url-ssrf` — CVE-2026-27018 (Gotenberg scheme bypass);
  CVE-2026-33205 (Gin SSRF); CVE-2025-47912, CVE-2026-25679 (net/url host
  parsing)
- `go-http-redirect-request-value` — CVE-2026-52802 (Gogs redirect_to);
  CVE-2022-25295 (gophish backslash bypass);
  <https://www.stackhawk.com/blog/golang-open-redirect-guide-examples-and-prevention/>
- `go-mac-compare-variable-time` — CVE-2024-30257 (1panel);
  <https://pkg.go.dev/crypto/hmac#Equal> ;
  <https://www.slingacademy.com/article/avoiding-timing-attacks-with-constant-time-comparisons-in-go/>
- `go-aes-gcm-static-nonce` — CVE-2026-26014 (Pion DTLS nonce reuse);
  <https://pkg.go.dev/crypto/cipher#AEAD>
- `go-rsa-generatekey-small` — gosec G403; crypto/rsa Go 1.24 minimum-size
  release note
- `go-cipher-mode-weak` — gosec G405/G501; Go 1.24 deprecation of CFB/OFB
  (<https://pkg.go.dev/crypto/cipher>)
- `go-jwt-unverified` — CVE-2026-22817, CVE-2026-27804, CVE-2026-23552
  (algorithm confusion); CVE-2025-30204 (ParseUnverified allocation DoS);
  <https://pkg.go.dev/github.com/golang-jwt/jwt/v5#UnsafeAllowNoneSignatureType>
- `go-cookie-insecure-flags` — CVE-2025-34291 (Langflow SameSite/CORS chain);
  OWASP Session Management Cheat Sheet
- `go-cors-wildcard-credentials` —
  <https://pentesterlab.com/blog/golang-cors-vulnerabilities> ; CVE-2025-34291;
  CVE-2026-30924 (qui);
  <https://github.com/gofiber/fiber/security/advisories/GHSA-fmg4-x8pw-hjhg>
- `go-file-perm-world-writable` — gosec G302/G306;
  <https://github.com/securego/gosec/issues/1126> (ModePerm); CWE-276
- `go-tempfile-fixed-path` — gosec G303; CWE-377
- `go-strconv-atoi-narrow-cast` — gosec G109/G115;
  <https://docs.boostsecurity.io/rules/gosec-109.html>
- `go-unsafe-pointer-uintptr-arith` — <https://pkg.go.dev/unsafe#Pointer> (rule
  3); go vet unsafeptr
- `go-xml-decoder-strict-off` — <https://pkg.go.dev/encoding/xml#Decoder>
  (Strict, Entity)
- `go-gob-decode-network` — <https://pkg.go.dev/encoding/gob> (security note:
  not designed to be hardened against adversarial inputs)

- `wp-rest-permission-return-true` — CVE-2026-4020 (Gravity SMTP),
  CVE-2026-1916;
  <https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/#permissions-callback>
- `wp-ajax-nopriv-registration` — CVE-2026-18316 (Solace Extra), CVE-2026-4003
  (Users manager PN), CVE-2026-3478 (Redux Framework nopriv SSRF)
- `wp-update-user-meta-request-key` — CVE-2026-3629 (Import and Export Users and
  Customers), CVE-2026-4003 (GHSA-f474-j5g7-2pch)
- `wp-update-user-role-request` — Patchstack: User Role Editor <= 4.24 privilege
  escalation; Bulk Change Role 1.1; Pods 3.3.9 unauthenticated privilege
  escalation
- `wp-update-option-request-key` — CVE-2026-18316 (Solace Extra arbitrary
  `update_option`), Patchstack Modular DS <= 2.5.1 arbitrary option update
- `wp-wpdb-prepare-quoted-placeholder` —
  <https://developer.wordpress.org/reference/classes/wpdb/prepare/> (WP 4.8.3
  `_doing_it_wrong` on quoted placeholders); CVE-2026-3180 (Contest Gallery)
- `wp-wpdb-orderby-interpolation` — CVE-2026-5073 (ARMember Premium
  `arm_get_directory_members` order/orderby)
- `wp-unlink-request-path` — CVE-2026-16940 (Custom Fields for WooCommerce),
  CVE-2026-8713 (Avada), CVE-2026-14982 (WP File Download), CVE-2026-6070,
  CVE-2026-15450, CVE-2026-13492
- `wp-template-include-request` — CVE-2026-1257 (Administrative Shortcodes),
  CVE-2026-11613 (Divi Ajax Filter), CVE-2026-78562 (Verdure Core),
  CVE-2026-32537 (Visual Portfolio)
- `wp-remote-request-user-url` — CVE-2026-3478 (Redux Framework), CVE-2026-13147
  (Kirki), CVE-2026-19050 (ProSolution), CVE-2026-4302 (WowOptin),
  CVE-2026-10586 (Essential Blocks)
- `wp-redirect-not-safe` —
  <https://developer.wordpress.org/reference/functions/wp_redirect/> ("does not
  validate the URL"); Patchstack open-redirect entries 2025-2026
- `wp-verify-nonce-result-discarded` —
  <https://developer.wordpress.org/apis/security/nonces/>; Wordfence CSRF
  advisories 2026 (Points and Rewards for WooCommerce CVE-2026-10628 family)
- `wp-check-ajax-referer-nodie-unchecked` —
  <https://developer.wordpress.org/reference/functions/check_ajax_referer/>
  (`$stop` parameter)
- `wp-maybe-unserialize-untrusted` — CVE-2026-78265 (The Events Calendar),
  CVE-2026-57713 (Events Manager), EssentialPlugin supply-chain compromise
  (April 2026)
- `wp-echo-option-unescaped` — WPCS `WordPress.Security.EscapeOutput`; Wordfence
  stored-XSS advisories where a contributor-writable option was echoed
- `wp-shortcode-atts-unescaped-output` — Patchstack: Ultimate Member 2.11.2
  shortcode template tag (2026); thehackernews.com 2026/08 WordPress pre-auth
  XSS to PHP code execution
- `wp-is-admin-as-authorization` —
  <https://developer.wordpress.org/reference/functions/is_admin/> ("does not
  check if the user is an administrator"); CVE-2026-14357 (DevKit Pro)
- `wp-unzip-file-request` — CVE-2026-18316 (Solace Extra `action-import-zip`),
  CVE-2026-14357 (DevKit Pro theme install), HackerOne 205481 (`unzip_file`
  traversal)
- `php-create-function-call` — PHP 8.0 removal of `create_function`;
  <https://www.php.net/manual/en/function.create-function.php>
- `php-dynamic-callable-from-request` — CVE-2026-63030 (WordPress core REST
  batch, "wp2shell");
  <https://www.php.net/manual/en/functions.variable-functions.php>
- `php-preg-replace-eval-modifier` — PHP 7.0 removal of the `/e` modifier;
  <https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php>
- `php-libxml-entity-loading-enabled` — CVE-2021-29447 (WordPress 5.7 XXE,
  Sonar); <https://www.php.net/manual/en/libxml.constants.php>
- `php-secret-compare-not-hash-equals` —
  <https://www.php.net/manual/en/function.hash-equals.php>; CVE-2026-4003
  (`userspn_secret_token`)
- `php-mail-header-request` — CVE-2026-48019 (Laravel CRLF in mail address
  validation); OWASP host/mail header injection
- `php-fetch-request-url` — CVE-2026-6514 (InfusedWoo Pro SSRF), CVE-2026-10586
  (Essential Blocks), CVE-2026-4809 (laravel-mediable remote image fetch)
- `php-file-write-request-path` — CVE-2026-15748 (Forminator), CVE-2026-19598
  (Everest Forms), CVE-2026-19513 (Gravity Forms), CVE-2026-84374 (Laravel Excel
  `Disk::copy`)
- `php-dotdot-strip-as-traversal-guard` — Fix diffs for CVE-2026-8713 (Avada)
  and CVE-2026-14982 (WP File Download), which replaced string stripping with
  `realpath` prefix checks

- `py-torch-load-untrusted` — CVE-2025-32434 (torch.load weights_only bypass,
  fixed 2.6) — <https://www.miggo.io/vulnerability-database/cve/CVE-2025-32434>
  ; GHSA-9pf3-7rrr-x5jh
- `py-numpy-load-allow-pickle` — CVE-2019-6446 (numpy allow_pickle default) ;
  <https://numpy.org/doc/stable/reference/generated/numpy.load.html>
- `py-pickle-equivalent-loads` —
  <https://afine.com/blogs/pickle-deserialization-in-ml-pipelines-the-rce-that-wont-go-away>
  ; CWE-502
- `py-joblib-load` —
  <https://afine.com/blogs/pickle-deserialization-in-ml-pipelines-the-rce-that-wont-go-away>
  ; CWE-502
- `py-zipfile-extractall` — CVE-2024-8088 (zipfile infinite loop) —
  <https://explore.alas.aws.amazon.com/CVE-2024-8088.html> ; CPython gh-146581 /
  PR 146591 (unpack_archive path handling)
- `py-lxml-parser-resolve-entities` — CVE-2025-6985 (langchain-text-splitters
  XXE) —
  <https://advisories.gitlab.com/pkg/pypi/langchain-text-splitters/CVE-2025-6985/>
  ; CWE-611
- `py-stdlib-xml-parse` —
  <https://codeql.github.com/codeql-query-help/python/py-xxe/> ;
  <https://docs.python.org/3/library/xml.html#xml-vulnerabilities>
- `py-render-template-string-dynamic` —
  <https://codepathfinder.dev/registry/python/flask/PYTHON-FLASK-AUDIT-008> ;
  CWE-1336 (SSTI)
- `py-jinja2-autoescape-off` —
  <https://jinja.palletsprojects.com/en/stable/api/#autoescaping> ; CWE-79
- `py-flask-debug-true` —
  <https://flask.palletsprojects.com/en/stable/debugging/> ; CWE-489
- `py-flask-hardcoded-secret-key` —
  <https://django.readthedocs.io/en/stable/howto/deployment/checklist.html> ;
  CWE-798
- `py-django-debug-true` —
  <https://www.invicti.com/web-application-vulnerabilities/django-debug-mode-enabled>
  ; CWE-489
- `py-django-allowed-hosts-wildcard` —
  <https://django.readthedocs.io/en/stable/howto/deployment/checklist.html> ;
  CWE-644
- `py-sql-string-build` — CVE-2026-1312, CVE-2026-1287 (Django ORM alias
  injection) —
  <https://github.com/django/django/commit/15e70cb83e6f7a9a2a2f651f30b28b5cb20febeb>
  ,
  <https://github.com/django/django/commit/e891a84c7ef9962bfcc3b4685690219542f86a22>
  ; CWE-89
- `py-django-queryset-request-kwargs` —
  <https://github.com/django/django/commit/0c0f5c2178c01ada5410cd53b4b207bf7858b952>
  ; CVE-2026-1207 —
  <https://securityonline.info/django-sql-injection-cve-2026-1207/>
- `py-open-redirect-request` — CVE-2023-49438 (Flask-Security) —
  <https://app.opencve.io/cve/CVE-2023-49438> ; CVE-2025-32962
  (Flask-AppBuilder) —
  <https://www.miggo.io/vulnerability-database/cve/CVE-2025-32962> ; CWE-601
- `py-open-request-arg` — CVE-2026-27641 (Flask-Uploads path traversal) —
  <https://www.sentinelone.com/vulnerability-database/cve-2026-27641/> ;
  GHSA-g78x-q3x8-r6m4 ; CWE-22
- `py-requests-no-timeout` —
  <https://www.sourcery.ai/vulnerabilities/python-requests-best-practice-use-timeout>
  ; <https://github.com/auth0/auth0-python/issues/82> ; CWE-400
- `py-ssl-unverified-context` —
  <https://precli.readthedocs.io/stable/rules/python/stdlib/ssl-create-unverified-context/>
  ; CWE-295
- `py-paramiko-autoadd-policy` —
  <https://codeql.github.com/codeql-query-help/python/py-paramiko-missing-host-key-validation/>
  ;
  <https://docs.aws.amazon.com/codeguru/detector-library/python/do-not-auto-add-or-warning-missing-hostkey-policy/>
  ; CWE-322
- `py-jwt-alg-none-or-mixed` — GHSA-752w-5fwx-jx9f (CVE-2026-32597) —
  <https://github.com/advisories/GHSA-752w-5fwx-jx9f> ;
  <https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4>
  ; CWE-347
- `py-os-system-popen` — <https://cwe.mitre.org/data/definitions/78.html> ;
  <https://docs.python.org/3/library/subprocess.html#security-considerations>
- `py-is-literal-compare` —
  <https://docs.python.org/3/whatsnew/3.8.html#changes-in-python-behavior>
  (SyntaxWarning for `is` with a literal)
- `py-world-writable-perms` — <https://cwe.mitre.org/data/definitions/732.html>
  ;
  <https://bandit.readthedocs.io/en/latest/plugins/b103_set_bad_file_permissions.html>
- `py-cryptography-weak-primitives` —
  <https://codepathfinder.dev/registry/python/cryptography/PYTHON-CRYPTO-SEC-030>
  ; <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/> ;
  CWE-327
- `py-cors-wildcard-credentials` —
  <https://flask-cors.readthedocs.io/en/latest/api.html#flask_cors.CORS> ;
  <https://fastapi.tiangolo.com/tutorial/cors/> ; CWE-942
- `py-random-for-secret` — <https://docs.python.org/3/library/random.html>
  (warning box) ; CWE-338
- `py-secret-compare-equals` —
  <https://precli.readthedocs.io/0.7.6/rules/python/stdlib/hmac-timing-attack/>
  ; CWE-208
- `py-assert-for-auth` —
  <https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html> ;
  CWE-617
- `py-format-on-request-template` —
  <https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/> ; CWE-134
- `py-weak-hash-for-password` —
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
  ; CWE-916
- `py-ldap-xpath-filter-build` —
  <https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html>
  ; <https://cwe.mitre.org/data/definitions/643.html>
- `py-dynamic-import-request` — CVE-2025-68664 (langchain-core) —
  <https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html>
  ; <https://unit42.paloaltonetworks.com/langchain-vulnerabilities/> ; CWE-470

Rule id -> CVE, advisory or normative documentation the claim rests on.

## javascript

- `js-child-process-shell-interpolation` — CWE-78; Node `child_process` security
  note on `exec` shell semantics; GHSA-3g6g-gq4r-xjm9 (emissary command
  injection)
- `js-dom-html-sink` — CWE-79 (DOM-based); React documentation on
  `dangerouslySetInnerHTML`; MDN `Element.innerHTML` security note
- `js-express-open-redirect` — CWE-601; Express `res.redirect` documentation
- `js-express-reflected-response` — CWE-79; OWASP Node.js security cheat sheet;
  Express `res.send` content-type behaviour
- `js-tls-verification-disabled` — CWE-295; Node TLS documentation on
  `rejectUnauthorized` and `NODE_TLS_REJECT_UNAUTHORIZED`
- `js-weak-hash-algorithm` — CWE-327, CWE-328; SHAttered SHA-1 collision (2017);
  RFC 6151 (MD5 collision guidance)
- `js-weak-cipher-algorithm` — CWE-327; Node crypto DEP0106 (`createCipher`
  deprecation, MD5-derived key, no IV)
- `js-jwt-algorithm-unpinned` — CVE-2015-9235 (alg=none), CVE-2022-23540,
  CVE-2022-23541, GHSA-8cf7-32gw-wr33 (jsonwebtoken)
- `js-cors-credentials-wildcard` — CWE-942; Fetch Standard rule that
  `Access-Control-Allow-Origin: *` is invalid with credentials; `cors` npm
  documentation
- `js-express-static-dotfiles` — CWE-538; `serve-static` `dotfiles` option
  documentation
- `js-vm-sandbox-dynamic-source` — CVE-2023-37466, CVE-2023-37903,
  GHSA-cchq-frgv-rjh5, GHSA-g644-9gfx-q4q4 (vm2, project archived 2023); Node
  `vm` documentation stating it is not a security mechanism
- `js-insecure-random-secret` — CWE-338; MDN `Math.random` note that it is not
  cryptographically secure

## java

- `java-weak-hash-algorithm` — CWE-327, CWE-328; NIST SP 800-131A Rev. 2 (SHA-1
  disallowed for signatures)
- `java-weak-cipher-transformation` — CWE-327; JCA standard names (a bare `AES`
  selects `AES/ECB/PKCS5Padding` in SunJCE); Bleichenbacher padding-oracle class
  for RSA PKCS#1 v1.5
- `java-native-deserialization-sink` — CWE-502; CVE-2022-1471 (SnakeYAML),
  CVE-2019-12384 (Jackson default typing), CVE-2021-39144 (XStream)
- `java-sql-concat-query` — CWE-89; OWASP SQL Injection Prevention Cheat Sheet;
  Spring `JdbcTemplate` documentation
- `java-jndi-lookup-dynamic` — CVE-2021-44228 (Log4Shell), CVE-2018-1000632
  style JNDI injection; CWE-74
- `java-expression-eval-dynamic` — CVE-2022-22963 (Spring Cloud Function SpEL),
  CVE-2022-22947; CWE-917
- `java-trust-all-tls` — CWE-295; "Why Eve and Mallory Love Android" (Fahl et
  al., CCS 2012) trust-all TrustManager study
- `java-response-open-redirect` — CWE-601; Spring MVC `redirect:` prefix
  documentation
- `java-cookie-missing-flags` — CWE-1004, CWE-614; Servlet `Cookie` API; RFC
  6265 §4.1.2.5-4.1.2.6
- `java-xml-factory-doctype-unset` — CWE-611; OWASP XXE Prevention Cheat Sheet;
  CVE-2026-24400 (AssertJ default DocumentBuilderFactory)
- `java-spring-csrf-disabled` — CWE-352; Spring Security CSRF documentation and
  its stateless-API guidance
- `java-format-string-not-literal` — CWE-134; `java.util.Formatter` contract for
  `UnknownFormatConversionException`

## lua

- `lua-sql-string-concat` — CWE-89; lua-resty-mysql README (`ngx.quote_sql_str`
  escaping requirement)
- `lua-redirect-user-target` — CWE-601; lua-nginx-module `ngx.redirect`
  documentation
- `lua-response-reflect-unescaped` — CWE-79, CWE-113; CVE-2026-31908 (APISIX
  forward-auth header injection)
- `lua-subrequest-user-uri` — CVE-2020-11724, CVE-2024-33452 (lua-nginx-module
  subrequest smuggling); lua-nginx-module `ngx.location.capture` documentation
  on the escaped `args` table
- `lua-http-client-verify-disabled` — CWE-295; lua-resty-http `ssl_verify`
  option documentation; OpenResty `lua_ssl_trusted_certificate`
- `lua-io-open-user-path` — CWE-22, CWE-829; Kong custom plugin loading
  documentation
- `lua-regex-user-pattern` — CWE-1333, CWE-400; lua-nginx-module `ngx.re`
  documentation (`o` flag, `lua_regex_cache_max_entries`)
- `lua-uri-args-unbounded` — CWE-770; lua-nginx-module `ngx.req.get_uri_args`
  documentation (`max_args`, default 100, `0` means unlimited)
- `lua-insecure-random-token` — CWE-338, CWE-377; lua-resty-random README on the
  per-worker `math.random` seed
- `lua-cjson-decode-unprotected` — lua-cjson documentation (`decode` raises on
  invalid JSON; `cjson.safe` returns nil plus error); Kong and APISIX plugin
  conventions
- `lua-exit-without-return` — lua-nginx-module `ngx.exit` documentation
  recommending `return ngx.exit(...)` to make termination explicit

## bash

- `sh-world-writable-permissions` — CWE-732; Debian Policy §10.9; Lintian
  `maintainer-script-should-not-use-recursive-chown-or-chmod`
- `sh-secret-on-command-line` — CWE-214, CWE-532; `proc(5)` on the
  world-readable `cmdline`; MySQL client documentation recommending `MYSQL_PWD`
  or an option file over `-p`
- `sh-predictable-temp-path` — CWE-377, CWE-367; CVE-2017-9525 (cron postinst
  symlink); `mktemp(1)` documentation of `-u`
- `sh-rm-rf-unguarded-variable` — CWE-73; the Steam `rm -rf "$STEAMROOT/"*`
  incident (ValveSoftware/steam-for-linux#3671); ShellCheck SC2115
- `sh-container-isolation-disabled` — CWE-250, CWE-284; Docker run reference on
  `--privileged` and host namespaces; CIS Docker Benchmark
- `sh-host-hardening-disabled` — CWE-693; `setenforce(8)`, `ufw(8)`; `proc(5)`
  on `randomize_va_space`; Yama LSM documentation on `ptrace_scope`
- `sh-archive-extract-to-system-root` — CWE-22; GNU tar documentation on
  `-P`/`--absolute-names` and `--no-same-owner`; Snyk Zip Slip research
- `sh-path-search-includes-cwd` — CWE-426, CWE-427; POSIX shell PATH semantics
  for an empty element
- `sh-remote-shell-string-interpolation` — CWE-78; `ssh(1)` note that the remote
  command is executed by the remote shell
- `sh-process-substitution-shell-input` — CWE-494; OWASP A03:2025 Software
  Supply Chain Failures
- `sh-printf-format-not-literal` — CWE-134; ShellCheck SC2059; POSIX `printf`
  format handling
- `sh-arithmetic-context-injection` — CWE-78; bash manual on arithmetic
  evaluation recursively expanding names and evaluating array subscripts;
  published bash arithmetic-injection write-ups (2023-2025)
