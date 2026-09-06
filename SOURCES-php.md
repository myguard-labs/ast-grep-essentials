# PHP / WordPress rule sources

| rule id | evidence |
| --- | --- |
| wp-rest-permission-return-true | CVE-2026-4020 (Gravity SMTP), CVE-2026-1916; https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/#permissions-callback |
| wp-ajax-nopriv-registration | CVE-2026-18316 (Solace Extra), CVE-2026-4003 (Users manager PN), CVE-2026-3478 (Redux Framework nopriv SSRF) |
| wp-update-user-meta-request-key | CVE-2026-3629 (Import and Export Users and Customers), CVE-2026-4003 (GHSA-f474-j5g7-2pch) |
| wp-update-user-role-request | Patchstack: User Role Editor <= 4.24 privilege escalation; Bulk Change Role 1.1; Pods 3.3.9 unauthenticated privilege escalation |
| wp-update-option-request-key | CVE-2026-18316 (Solace Extra arbitrary `update_option`), Patchstack Modular DS <= 2.5.1 arbitrary option update |
| wp-wpdb-prepare-quoted-placeholder | https://developer.wordpress.org/reference/classes/wpdb/prepare/ (WP 4.8.3 `_doing_it_wrong` on quoted placeholders); CVE-2026-3180 (Contest Gallery) |
| wp-wpdb-orderby-interpolation | CVE-2026-5073 (ARMember Premium `arm_get_directory_members` order/orderby) |
| wp-unlink-request-path | CVE-2026-16940 (Custom Fields for WooCommerce), CVE-2026-8713 (Avada), CVE-2026-14982 (WP File Download), CVE-2026-6070, CVE-2026-15450, CVE-2026-13492 |
| wp-template-include-request | CVE-2026-1257 (Administrative Shortcodes), CVE-2026-11613 (Divi Ajax Filter), CVE-2026-78562 (Verdure Core), CVE-2026-32537 (Visual Portfolio) |
| wp-remote-request-user-url | CVE-2026-3478 (Redux Framework), CVE-2026-13147 (Kirki), CVE-2026-19050 (ProSolution), CVE-2026-4302 (WowOptin), CVE-2026-10586 (Essential Blocks) |
| wp-redirect-not-safe | https://developer.wordpress.org/reference/functions/wp_redirect/ ("does not validate the URL"); Patchstack open-redirect entries 2025-2026 |
| wp-verify-nonce-result-discarded | https://developer.wordpress.org/apis/security/nonces/; Wordfence CSRF advisories 2026 (Points and Rewards for WooCommerce CVE-2026-10628 family) |
| wp-check-ajax-referer-nodie-unchecked | https://developer.wordpress.org/reference/functions/check_ajax_referer/ (`$stop` parameter) |
| wp-maybe-unserialize-untrusted | CVE-2026-78265 (The Events Calendar), CVE-2026-57713 (Events Manager), EssentialPlugin supply-chain compromise (April 2026) |
| wp-echo-option-unescaped | WPCS `WordPress.Security.EscapeOutput`; Wordfence stored-XSS advisories where a contributor-writable option was echoed |
| wp-shortcode-atts-unescaped-output | Patchstack: Ultimate Member 2.11.2 shortcode template tag (2026); thehackernews.com 2026/08 WordPress pre-auth XSS to PHP code execution |
| wp-is-admin-as-authorization | https://developer.wordpress.org/reference/functions/is_admin/ ("does not check if the user is an administrator"); CVE-2026-14357 (DevKit Pro) |
| wp-unzip-file-request | CVE-2026-18316 (Solace Extra `action-import-zip`), CVE-2026-14357 (DevKit Pro theme install), HackerOne 205481 (`unzip_file` traversal) |
| php-create-function-call | PHP 8.0 removal of `create_function`; https://www.php.net/manual/en/function.create-function.php |
| php-dynamic-callable-from-request | CVE-2026-63030 (WordPress core REST batch, "wp2shell"); https://www.php.net/manual/en/functions.variable-functions.php |
| php-preg-replace-eval-modifier | PHP 7.0 removal of the `/e` modifier; https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php |
| php-libxml-entity-loading-enabled | CVE-2021-29447 (WordPress 5.7 XXE, Sonar); https://www.php.net/manual/en/libxml.constants.php |
| php-secret-compare-not-hash-equals | https://www.php.net/manual/en/function.hash-equals.php; CVE-2026-4003 (`userspn_secret_token`) |
| php-mail-header-request | CVE-2026-48019 (Laravel CRLF in mail address validation); OWASP host/mail header injection |
| php-fetch-request-url | CVE-2026-6514 (InfusedWoo Pro SSRF), CVE-2026-10586 (Essential Blocks), CVE-2026-4809 (laravel-mediable remote image fetch) |
| php-file-write-request-path | CVE-2026-15748 (Forminator), CVE-2026-19598 (Everest Forms), CVE-2026-19513 (Gravity Forms), CVE-2026-84374 (Laravel Excel `Disk::copy`) |
| php-dotdot-strip-as-traversal-guard | Fix diffs for CVE-2026-8713 (Avada) and CVE-2026-14982 (WP File Download), which replaced string stripping with `realpath` prefix checks |
