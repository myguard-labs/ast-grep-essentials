<?php
/**
 * Plugin Name: Ledger Sync
 * Description: Fixed scan corpus. Mirrors ledger entries into a custom table.
 * Version:     1.4.0
 * License:     GPL-2.0-or-later
 *
 * Never built or run; it exists so a rule change shows up as new noise on the
 * safe majority of this code or as lost recall on its known findings.
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

define('LEDGER_SYNC_VERSION', '1.4.0');
define('LEDGER_SYNC_DIR', plugin_dir_path(__FILE__));

require_once LEDGER_SYNC_DIR . 'includes/class-settings.php';
require_once LEDGER_SYNC_DIR . 'includes/class-store.php';
require_once LEDGER_SYNC_DIR . 'includes/class-cache.php';
require_once LEDGER_SYNC_DIR . 'includes/class-rest.php';

/**
 * Wire the plugin into WordPress.
 */
function ledger_sync_boot(): void
{
    $settings = new Ledger_Sync_Settings();
    $store    = new Ledger_Sync_Store($GLOBALS['wpdb']);

    add_action('admin_menu', [$settings, 'register_page']);
    add_action('admin_post_ledger_sync_save', [$settings, 'handle_save']);
    add_action('rest_api_init', [new Ledger_Sync_Rest($store), 'register_routes']);
    add_action('ledger_sync_cron', [$store, 'prune'], 10, 0);
}
add_action('plugins_loaded', 'ledger_sync_boot');

/**
 * Create the mirror table on activation.
 */
function ledger_sync_activate(): void
{
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    $store = new Ledger_Sync_Store($GLOBALS['wpdb']);
    dbDelta($store->schema());

    if (!wp_next_scheduled('ledger_sync_cron')) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', 'ledger_sync_cron');
    }
}
register_activation_hook(__FILE__, 'ledger_sync_activate');

/**
 * Clear the schedule on deactivation.
 */
function ledger_sync_deactivate(): void
{
    $timestamp = wp_next_scheduled('ledger_sync_cron');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'ledger_sync_cron');
    }
}
register_deactivation_hook(__FILE__, 'ledger_sync_deactivate');
