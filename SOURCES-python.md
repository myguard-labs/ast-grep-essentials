# Python rule sources

| rule id | evidence |
| --- | --- |
| py-torch-load-untrusted | CVE-2025-32434 (torch.load weights_only bypass, fixed 2.6) — https://www.miggo.io/vulnerability-database/cve/CVE-2025-32434 ; GHSA-9pf3-7rrr-x5jh |
| py-numpy-load-allow-pickle | CVE-2019-6446 (numpy allow_pickle default) ; https://numpy.org/doc/stable/reference/generated/numpy.load.html |
| py-pickle-equivalent-loads | https://afine.com/blogs/pickle-deserialization-in-ml-pipelines-the-rce-that-wont-go-away ; CWE-502 |
| py-joblib-load | https://afine.com/blogs/pickle-deserialization-in-ml-pipelines-the-rce-that-wont-go-away ; CWE-502 |
| py-zipfile-extractall | CVE-2024-8088 (zipfile infinite loop) — https://explore.alas.aws.amazon.com/CVE-2024-8088.html ; CPython gh-146581 / PR 146591 (unpack_archive path handling) |
| py-lxml-parser-resolve-entities | CVE-2025-6985 (langchain-text-splitters XXE) — https://advisories.gitlab.com/pkg/pypi/langchain-text-splitters/CVE-2025-6985/ ; CWE-611 |
| py-stdlib-xml-parse | https://codeql.github.com/codeql-query-help/python/py-xxe/ ; https://docs.python.org/3/library/xml.html#xml-vulnerabilities |
| py-render-template-string-dynamic | https://codepathfinder.dev/registry/python/flask/PYTHON-FLASK-AUDIT-008 ; CWE-1336 (SSTI) |
| py-jinja2-autoescape-off | https://jinja.palletsprojects.com/en/stable/api/#autoescaping ; CWE-79 |
| py-flask-debug-true | https://flask.palletsprojects.com/en/stable/debugging/ ; CWE-489 |
| py-flask-hardcoded-secret-key | https://django.readthedocs.io/en/stable/howto/deployment/checklist.html ; CWE-798 |
| py-django-debug-true | https://www.invicti.com/web-application-vulnerabilities/django-debug-mode-enabled ; CWE-489 |
| py-django-allowed-hosts-wildcard | https://django.readthedocs.io/en/stable/howto/deployment/checklist.html ; CWE-644 |
| py-sql-string-build | CVE-2026-1312, CVE-2026-1287 (Django ORM alias injection) — https://github.com/django/django/commit/15e70cb83e6f7a9a2a2f651f30b28b5cb20febeb , https://github.com/django/django/commit/e891a84c7ef9962bfcc3b4685690219542f86a22 ; CWE-89 |
| py-django-queryset-request-kwargs | https://github.com/django/django/commit/0c0f5c2178c01ada5410cd53b4b207bf7858b952 ; CVE-2026-1207 — https://securityonline.info/django-sql-injection-cve-2026-1207/ |
| py-open-redirect-request | CVE-2023-49438 (Flask-Security) — https://app.opencve.io/cve/CVE-2023-49438 ; CVE-2025-32962 (Flask-AppBuilder) — https://www.miggo.io/vulnerability-database/cve/CVE-2025-32962 ; CWE-601 |
| py-open-request-arg | CVE-2026-27641 (Flask-Uploads path traversal) — https://www.sentinelone.com/vulnerability-database/cve-2026-27641/ ; GHSA-g78x-q3x8-r6m4 ; CWE-22 |
| py-requests-no-timeout | https://www.sourcery.ai/vulnerabilities/python-requests-best-practice-use-timeout ; https://github.com/auth0/auth0-python/issues/82 ; CWE-400 |
| py-ssl-unverified-context | https://precli.readthedocs.io/stable/rules/python/stdlib/ssl-create-unverified-context/ ; CWE-295 |
| py-paramiko-autoadd-policy | https://codeql.github.com/codeql-query-help/python/py-paramiko-missing-host-key-validation/ ; https://docs.aws.amazon.com/codeguru/detector-library/python/do-not-auto-add-or-warning-missing-hostkey-policy/ ; CWE-322 |
| py-jwt-alg-none-or-mixed | GHSA-752w-5fwx-jx9f (CVE-2026-32597) — https://github.com/advisories/GHSA-752w-5fwx-jx9f ; https://dev.to/iamdevbox/jwt-algorithm-confusion-attacks-cve-2026-22817-cve-2026-27804-and-cve-2026-23552-fix-guide-4ac4 ; CWE-347 |
| py-os-system-popen | https://cwe.mitre.org/data/definitions/78.html ; https://docs.python.org/3/library/subprocess.html#security-considerations |
| py-is-literal-compare | https://docs.python.org/3/whatsnew/3.8.html#changes-in-python-behavior (SyntaxWarning for `is` with a literal) |
| py-world-writable-perms | https://cwe.mitre.org/data/definitions/732.html ; https://bandit.readthedocs.io/en/latest/plugins/b103_set_bad_file_permissions.html |
| py-cryptography-weak-primitives | https://codepathfinder.dev/registry/python/cryptography/PYTHON-CRYPTO-SEC-030 ; https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/ ; CWE-327 |
| py-cors-wildcard-credentials | https://flask-cors.readthedocs.io/en/latest/api.html#flask_cors.CORS ; https://fastapi.tiangolo.com/tutorial/cors/ ; CWE-942 |
| py-random-for-secret | https://docs.python.org/3/library/random.html (warning box) ; CWE-338 |
| py-secret-compare-equals | https://precli.readthedocs.io/0.7.6/rules/python/stdlib/hmac-timing-attack/ ; CWE-208 |
| py-assert-for-auth | https://bandit.readthedocs.io/en/latest/plugins/b101_assert_used.html ; CWE-617 |
| py-format-on-request-template | https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/ ; CWE-134 |
| py-weak-hash-for-password | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html ; CWE-916 |
| py-ldap-xpath-filter-build | https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html ; https://cwe.mitre.org/data/definitions/643.html |
| py-dynamic-import-request | CVE-2025-68664 (langchain-core) — https://thehackernews.com/2025/12/critical-langchain-core-vulnerability.html ; https://unit42.paloaltonetworks.com/langchain-vulnerabilities/ ; CWE-470 |
