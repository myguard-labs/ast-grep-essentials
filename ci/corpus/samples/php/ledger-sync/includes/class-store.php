<?php
/**
 * The custom mirror table and every query against it.
 */

declare(strict_types=1);

final class Ledger_Sync_Store
{
    private const SUFFIX  = 'ledger_entry';
    private const SORTABLE = ['id', 'account', 'cents', 'synced_at'];

    private wpdb $db;

    public function __construct(wpdb $db)
    {
        $this->db = $db;
    }

    private function table(): string
    {
        return $this->db->prefix . self::SUFFIX;
    }

    public function schema(): string
    {
        $table   = $this->table();
        $collate = $this->db->get_charset_collate();

        return "CREATE TABLE {$table} (
            id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            account   VARCHAR(64)     NOT NULL DEFAULT '',
            cents     BIGINT          NOT NULL DEFAULT 0,
            memo      TEXT            NOT NULL,
            synced_at DATETIME        NOT NULL,
            PRIMARY KEY  (id),
            KEY account (account),
            KEY synced_at (synced_at)
        ) {$collate};";
    }

    /**
     * Insert one entry and return its new id.
     */
    public function insert(string $account, int $cents, string $memo): int
    {
        $ok = $this->db->insert(
            $this->table(),
            [
                'account'   => $account,
                'cents'     => $cents,
                'memo'      => $memo,
                'synced_at' => current_time('mysql', true),
            ],
            ['%s', '%d', '%s', '%s']
        );

        return $ok ? (int) $this->db->insert_id : 0;
    }

    /**
     * Entries for one account, newest first.
     *
     * @return array<int, array<string, mixed>>
     */
    public function by_account(string $account, int $limit, string $orderby): array
    {
        $column = in_array($orderby, self::SORTABLE, true) ? $orderby : 'id';
        $table  = $this->table();

        $sql = $this->db->prepare(
            "SELECT id, account, cents, memo, synced_at FROM {$table}
             WHERE account = %s ORDER BY {$column} DESC LIMIT %d",
            $account,
            $limit
        );

        return (array) $this->db->get_results($sql, ARRAY_A);
    }

    public function balance(string $account): int
    {
        $table = $this->table();

        return (int) $this->db->get_var(
            $this->db->prepare(
                "SELECT COALESCE(SUM(cents), 0) FROM {$table} WHERE account = %s",
                $account
            )
        );
    }

    /**
     * Entries for several accounts at once.
     *
     * @param array<int, string> $accounts
     * @return array<int, array<string, mixed>>
     */
    public function by_accounts(array $accounts): array
    {
        if ([] === $accounts) {
            return [];
        }

        $table        = $this->table();
        $placeholders = implode(', ', array_fill(0, count($accounts), '%s'));

        $sql = $this->db->prepare(
            "SELECT account, SUM(cents) AS total FROM {$table}
             WHERE account IN ({$placeholders}) GROUP BY account",
            ...$accounts
        );

        return (array) $this->db->get_results($sql, ARRAY_A);
    }

    /**
     * Drop entries older than the retention window.
     */
    public function prune(int $days = 400): int
    {
        $table = $this->table();

        return (int) $this->db->query(
            $this->db->prepare(
                "DELETE FROM {$table} WHERE synced_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
                max(1, $days)
            )
        );
    }
}
