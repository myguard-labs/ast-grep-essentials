<?php
/**
 * The options screen and the form handler behind it.
 */

declare(strict_types=1);

final class Ledger_Sync_Settings
{
    private const OPTION = 'ledger_sync_settings';
    private const NONCE  = 'ledger_sync_save';

    /**
     * Current settings, with defaults for anything never saved.
     *
     * @return array<string, string|int>
     */
    public function current(): array
    {
        $saved = get_option(self::OPTION, []);
        if (!is_array($saved)) {
            $saved = [];
        }

        return [
            'endpoint' => (string) ($saved['endpoint'] ?? ''),
            'account'  => (string) ($saved['account'] ?? ''),
            'retries'  => (int) ($saved['retries'] ?? 3),
        ];
    }

    public function register_page(): void
    {
        add_options_page(
            __('Ledger Sync', 'ledger-sync'),
            __('Ledger Sync', 'ledger-sync'),
            'manage_options',
            'ledger-sync',
            [$this, 'render_page']
        );
    }

    public function render_page(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to manage these settings.', 'ledger-sync'));
        }

        $settings = $this->current();
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Ledger Sync', 'ledger-sync'); ?></h1>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="ledger_sync_save" />
                <?php wp_nonce_field(self::NONCE); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ledger-endpoint"><?php echo esc_html__('Endpoint', 'ledger-sync'); ?></label></th>
                        <td><input id="ledger-endpoint" name="endpoint" type="url" class="regular-text"
                                   value="<?php echo esc_attr($settings['endpoint']); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ledger-account"><?php echo esc_html__('Account', 'ledger-sync'); ?></label></th>
                        <td><input id="ledger-account" name="account" type="text" class="regular-text"
                                   value="<?php echo esc_attr($settings['account']); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ledger-retries"><?php echo esc_html__('Retries', 'ledger-sync'); ?></label></th>
                        <td><input id="ledger-retries" name="retries" type="number" min="0" max="10"
                                   value="<?php echo esc_attr((string) $settings['retries']); ?>" /></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    /**
     * Validate and persist the submitted form.
     */
    public function handle_save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to manage these settings.', 'ledger-sync'), '', ['response' => 403]);
        }
        check_admin_referer(self::NONCE);

        $endpoint = isset($_POST['endpoint']) ? esc_url_raw(wp_unslash((string) $_POST['endpoint'])) : '';
        $account  = isset($_POST['account']) ? sanitize_key(wp_unslash((string) $_POST['account'])) : '';
        $retries  = isset($_POST['retries']) ? absint(wp_unslash((string) $_POST['retries'])) : 3;

        if ('' !== $endpoint && !wp_http_validate_url($endpoint)) {
            add_settings_error('ledger_sync', 'endpoint', __('The endpoint is not a usable URL.', 'ledger-sync'));
            $endpoint = '';
        }

        update_option(self::OPTION, [
            'endpoint' => $endpoint,
            'account'  => $account,
            'retries'  => min($retries, 10),
        ]);

        wp_safe_redirect(add_query_arg('updated', '1', admin_url('options-general.php?page=ledger-sync')));
        exit;
    }
}
