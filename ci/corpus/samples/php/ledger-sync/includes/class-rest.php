<?php
/**
 * The plugin's REST surface.
 */

declare(strict_types=1);

final class Ledger_Sync_Rest
{
    private const NAMESPACE = 'ledger-sync/v1';

    private Ledger_Sync_Store $store;

    public function __construct(Ledger_Sync_Store $store)
    {
        $this->store = $store;
    }

    public function register_routes(): void
    {
        register_rest_route(
            self::NAMESPACE,
            '/entries',
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [$this, 'list_entries'],
                'permission_callback' => [$this, 'may_read'],
                'args'                => [
                    'account' => [
                        'required'          => true,
                        'type'              => 'string',
                        'sanitize_callback' => 'sanitize_key',
                    ],
                    'limit'   => [
                        'default'           => 50,
                        'type'              => 'integer',
                        'sanitize_callback' => 'absint',
                    ],
                    'orderby' => [
                        'default' => 'id',
                        'type'    => 'string',
                        'enum'    => ['id', 'account', 'cents', 'synced_at'],
                    ],
                ],
            ]
        );

        register_rest_route(
            self::NAMESPACE,
            '/entries',
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [$this, 'create_entry'],
                'permission_callback' => [$this, 'may_write'],
            ]
        );
    }

    public function may_read(WP_REST_Request $request): bool
    {
        unset($request);

        return current_user_can('read');
    }

    public function may_write(WP_REST_Request $request): bool
    {
        unset($request);

        return current_user_can('manage_options');
    }

    public function list_entries(WP_REST_Request $request): WP_REST_Response
    {
        $account = (string) $request->get_param('account');
        $limit   = min(500, max(1, (int) $request->get_param('limit')));
        $orderby = (string) $request->get_param('orderby');

        return new WP_REST_Response(
            [
                'account' => $account,
                'balance' => $this->store->balance($account),
                'entries' => $this->store->by_account($account, $limit, $orderby),
            ],
            200
        );
    }

    public function create_entry(WP_REST_Request $request): WP_REST_Response
    {
        $account = sanitize_key((string) $request->get_param('account'));
        $cents   = (int) $request->get_param('cents');
        $memo    = sanitize_text_field((string) $request->get_param('memo'));

        if ('' === $account) {
            return new WP_REST_Response(['error' => 'account is required'], 400);
        }

        $id = $this->store->insert($account, $cents, $memo);
        if (0 === $id) {
            return new WP_REST_Response(['error' => 'the entry could not be stored'], 500);
        }

        return new WP_REST_Response(['id' => $id], 201);
    }
}
