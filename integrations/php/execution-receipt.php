<?php
/** Configure as an FPM pool auto_prepend_file for controlled integration probes. */
// The deployer precreates the private append-only file; the application cannot
// read it. Never log bodies, cookies, users, routes, tokens or client addresses.
$id = $_SERVER['HTTP_X_REQUEST_ID'] ?? '';
if (preg_match('/^[a-f0-9]{32}$/D', $id)) {
    $receipt = json_encode(['schema_version' => 1, 'id' => $id, 'php_started' => true]);
    $path = getenv('WAF_RECEIPT_PATH');
    if (is_string($path) && $path !== '') {
        // Failure must not masquerade as proof of absent PHP execution.
        if (file_put_contents($path, $receipt . "\n", FILE_APPEND | LOCK_EX) === false) {
            error_log('waf_receipt_write_failed');
        }
    }
}
