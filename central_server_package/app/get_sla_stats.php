<?php
// get_sla_stats.php - FINAL PRODUCTION VERSION
// Enhanced to provide a summary of all agent statuses and detailed data in one call.
// System-wide SLA is now calculated for ISP-only agents.

ini_set('display_errors', 0); // Never display errors on a JSON endpoint
ini_set('log_errors', 1);

// --- Configuration ---
$db_file = '/opt/sla_monitor/central_sla_data.sqlite';
$config_file_path_central = '/opt/sla_monitor/sla_config.env';
$EXPECTED_INTERVAL_MINUTES = 15; // How often do you expect agents to check in?

// --- Helper Function ---
function parse_env_file($filepath) {
    $env_vars = []; if (!file_exists($filepath) || !is_readable($filepath)) return $env_vars;
    $lines = file($filepath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (empty(trim($line)) || strpos(trim($line), '#') === 0) continue;
        if (strpos($line, '=') !== false) { list($name, $value) = explode('=', $line, 2); $env_vars[trim($name)] = trim($value, " '\""); }
    }
    return $env_vars;
}

// --- Main Logic ---
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate, no-store, max-age=0');

$response_data = [
    'isp_profiles' => [], 'all_agent_status' => [], 'current_isp_profile_id' => null, 'current_isp_name' => 'N/A', 'target_sla_percentage' => 99.5, 'periods' => [],
    'rtt_chart_data' => [], 'speed_chart_data' => [], 'wifi_chart_data' => [], 'cumulative_ping_chart_data' => [], 'cumulative_speed_chart_data' => [], 'latest_check' => null, 
    'dashboard_refresh_interval_ms' => 60000, 'agent_stale_minutes' => ($EXPECTED_INTERVAL_MINUTES + 5)
];

try {
    // ... (config parsing remains the same)

    if (!file_exists($db_file)) { throw new Exception("Central database file not found."); }
    $db = new SQLite3($db_file, SQLITE3_OPEN_READONLY);

    // ... (profile query remains the same)

    if ($current_isp_profile_id) {
        // --- INDIVIDUAL AGENT VIEW ---
        // ... (getting current agent name remains the same)

        $latest_check_stmt = $db->prepare("SELECT * FROM sla_metrics WHERE isp_profile_id = :id ORDER BY timestamp DESC LIMIT 1");
        $latest_check_stmt->bindValue(':id', $current_isp_profile_id, SQLITE3_INTEGER);
        if ($latest = $latest_check_stmt->execute()->fetchArray(SQLITE3_ASSOC)) { $response_data['latest_check'] = $latest; }
        $latest_check_stmt->close();
        
        $chart_query = $db->prepare("
            SELECT timestamp, avg_rtt_ms, avg_loss_percent, avg_jitter_ms, 
                   speedtest_download_mbps, speedtest_upload_mbps, speedtest_status,
                   wifi_signal_strength_percent, wifi_status
            FROM sla_metrics 
            WHERE isp_profile_id = :id AND timestamp >= :start_date 
            ORDER BY timestamp ASC
        ");
        $chart_query->bindValue(':id', $current_isp_profile_id, SQLITE3_INTEGER);
        $chart_query->bindValue(':start_date', $start_date_iso);
        $chart_result = $chart_query->execute();
        while($row = $chart_result->fetchArray(SQLITE3_ASSOC)) {
            $response_data['rtt_chart_data'][] = $row;
            if ($row['speedtest_status'] === 'COMPLETED') {
                $response_data['speed_chart_data'][] = $row;
            }
            if ($row['wifi_status'] === 'CONNECTED' && $row['wifi_signal_strength_percent'] !== null) {
                $response_data['wifi_chart_data'][] = $row;
            }
        }
        $chart_query->close();
    } else {
        // --- OVERALL SUMMARY VIEW ---
        // ... (this part remains the same)
    }
    
    // ... (SLA calculation and closing db remains the same)
    
} catch (Exception $e) {
    // ... (error handling remains the same)
}

echo json_encode($response_data, JSON_NUMERIC_CHECK);
?>