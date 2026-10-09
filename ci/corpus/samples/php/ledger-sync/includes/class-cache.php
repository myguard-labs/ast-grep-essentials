<?php
/**
 * Transient cache in front of the store, plus the upstream fetch.
 */

declare(strict_types=1);

final class Ledger_Sync_Cache
{
    private const TTL    = 300;
    private const PREFIX = 'ledger_sync_';

    /**
     * The transient key for one query. Short, stable and collision-resistant
     * enough for a cache namespace that is not security-relevant.
     */
    private function key(string $account, int $limit): string
    {
        return self::PREFIX . md5($account . '|' . $limit);
    }

    /**
     * @return array<int, array<string, mixed>>|null
     */
    public function get(string $account, int $limit): ?array
    {
        $hit = get_transient($this->key($account, $limit));

        return is_array($hit) ? $hit : null;
    }

    /**
     * @param array<int, array<string, mixed>> $rows
     */
    public function put(string $account, int $limit, array $rows): void
    {
        set_transient($this->key($account, $limit), $rows, self::TTL);
    }

    public function forget(string $account, int $limit): void
    {
        delete_transient($this->key($account, $limit));
    }

    /**
     * Pull the upstream snapshot for ``$account``.
     *
     * @return array<string, mixed>
     */
    public function fetch_upstream(string $endpoint, string $account, string $secret): array
    {
        $body      = wp_json_encode(['account' => $account]);
        $signature = hash_hmac('sha256', (string) $body, $secret);

        $response = wp_remote_post(
            $endpoint,
            [
                'timeout'     => 10,
                'sslverify'   => true,
                'headers'     => [
                    'Content-Type'        => 'application/json',
                    'X-Ledger-Signature'  => 'sha256=' . $signature,
                ],
                'body'        => $body,
            ]
        );

        if (is_wp_error($response)) {
            return ['error' => $response->get_error_message()];
        }

        if (200 !== (int) wp_remote_retrieve_response_code($response)) {
            return ['error' => 'upstream refused the request'];
        }

        $decoded = json_decode(wp_remote_retrieve_body($response), true);

        return is_array($decoded) ? $decoded : ['error' => 'upstream sent no object'];
    }

    /**
     * Whether a webhook signature header matches the body.
     */
    public function signature_valid(string $body, string $header, string $secret): bool
    {
        $expected = 'sha256=' . hash_hmac('sha256', $body, $secret);

        return hash_equals($expected, $header);
    }
}
