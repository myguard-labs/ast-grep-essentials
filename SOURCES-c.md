# Sources for the C / nginx rules

| rule id | evidence |
| --- | --- |
| c-realloc-assign-same-pointer | CWE-401; curl coding style (`Curl_saferealloc`) https://curl.se/dev/internals.html |
| c-memset-before-free-secret | CWE-14 https://cwe.mitre.org/data/definitions/14.html; glibc `explicit_bzero`, OpenSSL `OPENSSL_cleanse` |
| c-memcmp-on-secret | CWE-208 https://cwe.mitre.org/data/definitions/208.html; OpenSSL `CRYPTO_memcmp` contract |
| c-strncpy-no-terminator | CWE-170 https://cwe.mitre.org/data/definitions/170.html |
| c-read-return-ignored | CWE-252 https://cwe.mitre.org/data/definitions/252.html |
| c-toctou-access-then-open | CWE-367 https://cwe.mitre.org/data/definitions/367.html; sudo CVE-2025-32463 https://www.oligo.security/blog/new-sudo-vulnerabilities-cve-2025-32462-and-cve-2025-32463 |
| c-chroot-without-chdir | CWE-243 https://cwe.mitre.org/data/definitions/243.html; sudo CVE-2025-32463 |
| c-setuid-return-ignored | CWE-273 https://cwe.mitre.org/data/definitions/273.html; CWE-250 |
| c-getenv-to-path-sink | CWE-427 https://cwe.mitre.org/data/definitions/427.html; sudo CVE-2025-32463 |
| c-rand-for-secret | CWE-338 https://cwe.mitre.org/data/definitions/338.html; `ngx_random` is `random()` seeded from pid/time |
| c-off-by-one-le-sizeof | CWE-193 https://cwe.mitre.org/data/definitions/193.html; CVE-2026-27784, CVE-2026-27654 length-boundary overflows |
| c-strtok-not-reentrant | CWE-663 https://cwe.mitre.org/data/definitions/663.html |
| nginx-str-data-passed-to-libc | nginx development guide, ngx_str_t is not NUL-terminated https://nginx.org/en/docs/dev/development_guide.html#string_overview |
| nginx-strlen-on-ngx-str-data | same as above |
| nginx-slab-locked-without-lock | nginx slab API contract, `src/core/ngx_slab.c` |
| nginx-shm-data-write-without-lock | nginx limit_req / limit_conn / ssl_session_cache shared-zone implementations |
| nginx-escape-uri-alloc-without-double | CVE-2026-42945 https://nginx.org/en/security_advisories.html and https://www.akamai.com/blog/security-research/nginx-critical-heap-buffer-overflow-cve-2026-42945; `ngx_escape_uri` returns the escaped-character count, each costing two extra bytes |
| nginx-finalize-plus-return-rc | nginx development guide, request finalization https://nginx.org/en/docs/dev/development_guide.html#http_request_finalization |
| nginx-init-returns-http-status | nginx module init hook contracts, `ngx_init_modules` and `ngx_http_block` |
| nginx-use-after-finalize | CVE-2026-40701 resolver UAF https://nginx.org/en/security_advisories.html; nginx development guide, request finalization |
