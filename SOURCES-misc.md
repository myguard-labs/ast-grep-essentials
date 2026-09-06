# Sources — javascript, java, lua, bash harvest

Rule id -> CVE, advisory or normative documentation the claim rests on.

## javascript

| rule | evidence |
| --- | --- |
| js-child-process-shell-interpolation | CWE-78; Node `child_process` security note on `exec` shell semantics; GHSA-3g6g-gq4r-xjm9 (emissary command injection) |
| js-dom-html-sink | CWE-79 (DOM-based); React documentation on `dangerouslySetInnerHTML`; MDN `Element.innerHTML` security note |
| js-express-open-redirect | CWE-601; Express `res.redirect` documentation |
| js-express-reflected-response | CWE-79; OWASP Node.js security cheat sheet; Express `res.send` content-type behaviour |
| js-tls-verification-disabled | CWE-295; Node TLS documentation on `rejectUnauthorized` and `NODE_TLS_REJECT_UNAUTHORIZED` |
| js-weak-hash-algorithm | CWE-327, CWE-328; SHAttered SHA-1 collision (2017); RFC 6151 (MD5 collision guidance) |
| js-weak-cipher-algorithm | CWE-327; Node crypto DEP0106 (`createCipher` deprecation, MD5-derived key, no IV) |
| js-jwt-algorithm-unpinned | CVE-2015-9235 (alg=none), CVE-2022-23540, CVE-2022-23541, GHSA-8cf7-32gw-wr33 (jsonwebtoken) |
| js-cors-credentials-wildcard | CWE-942; Fetch Standard rule that `Access-Control-Allow-Origin: *` is invalid with credentials; `cors` npm documentation |
| js-express-static-dotfiles | CWE-538; `serve-static` `dotfiles` option documentation |
| js-vm-sandbox-dynamic-source | CVE-2023-37466, CVE-2023-37903, GHSA-cchq-frgv-rjh5, GHSA-g644-9gfx-q4q4 (vm2, project archived 2023); Node `vm` documentation stating it is not a security mechanism |
| js-insecure-random-secret | CWE-338; MDN `Math.random` note that it is not cryptographically secure |

## java

| rule | evidence |
| --- | --- |
| java-weak-hash-algorithm | CWE-327, CWE-328; NIST SP 800-131A Rev. 2 (SHA-1 disallowed for signatures) |
| java-weak-cipher-transformation | CWE-327; JCA standard names (a bare `AES` selects `AES/ECB/PKCS5Padding` in SunJCE); Bleichenbacher padding-oracle class for RSA PKCS#1 v1.5 |
| java-native-deserialization-sink | CWE-502; CVE-2022-1471 (SnakeYAML), CVE-2019-12384 (Jackson default typing), CVE-2021-39144 (XStream) |
| java-sql-concat-query | CWE-89; OWASP SQL Injection Prevention Cheat Sheet; Spring `JdbcTemplate` documentation |
| java-jndi-lookup-dynamic | CVE-2021-44228 (Log4Shell), CVE-2018-1000632 style JNDI injection; CWE-74 |
| java-expression-eval-dynamic | CVE-2022-22963 (Spring Cloud Function SpEL), CVE-2022-22947; CWE-917 |
| java-trust-all-tls | CWE-295; "Why Eve and Mallory Love Android" (Fahl et al., CCS 2012) trust-all TrustManager study |
| java-response-open-redirect | CWE-601; Spring MVC `redirect:` prefix documentation |
| java-cookie-missing-flags | CWE-1004, CWE-614; Servlet `Cookie` API; RFC 6265 §4.1.2.5-4.1.2.6 |
| java-xml-factory-doctype-unset | CWE-611; OWASP XXE Prevention Cheat Sheet; CVE-2026-24400 (AssertJ default DocumentBuilderFactory) |
| java-spring-csrf-disabled | CWE-352; Spring Security CSRF documentation and its stateless-API guidance |
| java-format-string-not-literal | CWE-134; `java.util.Formatter` contract for `UnknownFormatConversionException` |

## lua

| rule | evidence |
| --- | --- |
| lua-sql-string-concat | CWE-89; lua-resty-mysql README (`ngx.quote_sql_str` escaping requirement) |
| lua-redirect-user-target | CWE-601; lua-nginx-module `ngx.redirect` documentation |
| lua-response-reflect-unescaped | CWE-79, CWE-113; CVE-2026-31908 (APISIX forward-auth header injection) |
| lua-subrequest-user-uri | CVE-2020-11724, CVE-2024-33452 (lua-nginx-module subrequest smuggling); lua-nginx-module `ngx.location.capture` documentation on the escaped `args` table |
| lua-http-client-verify-disabled | CWE-295; lua-resty-http `ssl_verify` option documentation; OpenResty `lua_ssl_trusted_certificate` |
| lua-io-open-user-path | CWE-22, CWE-829; Kong custom plugin loading documentation |
| lua-regex-user-pattern | CWE-1333, CWE-400; lua-nginx-module `ngx.re` documentation (`o` flag, `lua_regex_cache_max_entries`) |
| lua-uri-args-unbounded | CWE-770; lua-nginx-module `ngx.req.get_uri_args` documentation (`max_args`, default 100, `0` means unlimited) |
| lua-insecure-random-token | CWE-338, CWE-377; lua-resty-random README on the per-worker `math.random` seed |
| lua-cjson-decode-unprotected | lua-cjson documentation (`decode` raises on invalid JSON; `cjson.safe` returns nil plus error); Kong and APISIX plugin conventions |
| lua-exit-without-return | lua-nginx-module `ngx.exit` documentation recommending `return ngx.exit(...)` to make termination explicit |

## bash

| rule | evidence |
| --- | --- |
| sh-world-writable-permissions | CWE-732; Debian Policy §10.9; Lintian `maintainer-script-should-not-use-recursive-chown-or-chmod` |
| sh-secret-on-command-line | CWE-214, CWE-532; `proc(5)` on the world-readable `cmdline`; MySQL client documentation recommending `MYSQL_PWD` or an option file over `-p` |
| sh-predictable-temp-path | CWE-377, CWE-367; CVE-2017-9525 (cron postinst symlink); `mktemp(1)` documentation of `-u` |
| sh-rm-rf-unguarded-variable | CWE-73; the Steam `rm -rf "$STEAMROOT/"*` incident (ValveSoftware/steam-for-linux#3671); ShellCheck SC2115 |
| sh-container-isolation-disabled | CWE-250, CWE-284; Docker run reference on `--privileged` and host namespaces; CIS Docker Benchmark |
| sh-host-hardening-disabled | CWE-693; `setenforce(8)`, `ufw(8)`; `proc(5)` on `randomize_va_space`; Yama LSM documentation on `ptrace_scope` |
| sh-archive-extract-to-system-root | CWE-22; GNU tar documentation on `-P`/`--absolute-names` and `--no-same-owner`; Snyk Zip Slip research |
| sh-path-search-includes-cwd | CWE-426, CWE-427; POSIX shell PATH semantics for an empty element |
| sh-remote-shell-string-interpolation | CWE-78; `ssh(1)` note that the remote command is executed by the remote shell |
| sh-process-substitution-shell-input | CWE-494; OWASP A03:2025 Software Supply Chain Failures |
| sh-printf-format-not-literal | CWE-134; ShellCheck SC2059; POSIX `printf` format handling |
| sh-arithmetic-context-injection | CWE-78; bash manual on arithmetic evaluation recursively expanding names and evaluating array subscripts; published bash arithmetic-injection write-ups (2023-2025) |
