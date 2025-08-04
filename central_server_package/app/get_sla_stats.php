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

function cast_sla_metric_types(&$row) {
    if (!is_array($row)) return;
    $float_fields = ['avg_rtt_ms', 'avg_loss_percent', 'avg_jitter_ms', 'http_total_time_s', 'speedtest_download_mbps', 'speedtest_upload_mbps', 'speedtest_ping_ms', 'speedtest_jitter_ms'];
    $int_fields = ['id', 'isp_profile_id', 'dns_resolve_time_ms', 'http_response_code', 'sla_met_interval'];
    foreach ($float_fields as $field) { if (isset($row[$field])) $row[$field] = (float)$row[$field]; else $row[$field] = null; }
    foreach ($int_fields as $field) { if (isset($row[$field])) $row[$field] = (int)$row[$field]; else $row[$field] = null; }
}

// --- Main Logic ---
header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate, no-store, max-age=0');

$response_data = [
    'isp_profiles' => [], 'all_agent_status' => [], 'current_isp_profile_id' => null, 'current_isp_name' => 'N/A', 'target_sla_percentage' => 99.5, 'periods' => [],
    'rtt_chart_data' => [], 'speed_chart_data' => [], 'cumulative_ping_chart_data' => [], 'cumulative_speed_chart_data' => [], 'latest_check' => null, 
    'dashboard_refresh_interval_ms' => 60000, 'agent_stale_minutes' => ($EXPECTED_INTERVAL_MINUTES + 5)
];

try {
    $config_values = parse_env_file($config_file_path_central);
    $response_data['dashboard_refresh_interval_ms'] = (int)($config_values['DASHBOARD_REFRESH_INTERVAL_MS'] ?? 60000);
    $response_data['target_sla_percentage'] = (float)($config_values['SLA_TARGET_PERCENTAGE'] ?? 99.5);
    $response_data['agent_stale_minutes'] = (int)($config_values['AGENT_STALE_MINUTES'] ?? ($EXPECTED_INTERVAL_MINUTES + 5));

    if (!file_exists($db_file)) { throw new Exception("Central database file not found."); }
    $db = new SQLite3($db_file, SQLITE3_OPEN_READONLY);

    $profiles_result = $db->query("SELECT id, agent_name, agent_identifier, agent_type, is_active, last_heard_from FROM isp_profiles WHERE is_active = 1 ORDER BY agent_type, agent_name");
    while ($profile = $profiles_result->fetchArray(SQLITE3_ASSOC)) {
        $profile['id'] = (int)$profile['id'];
        $profile['is_active'] = (int)$profile['is_active'];
        $response_data['isp_profiles'][] = $profile;
    }

    $current_isp_profile_id = filter_input(INPUT_GET, 'isp_id', FILTER_VALIDATE_INT) ?: null;
    $period_days = filter_input(INPUT_GET, 'period', FILTER_VALIDATE_INT) ?: 1;

    $start_date_obj = new DateTime("-{$period_days} days", new DateTimeZone("UTC"));
    $start_date_iso = $start_date_obj->format("Y-m-d\TH:i:s\Z");

    if ($current_isp_profile_id) {
        // --- INDIVIDUAL AGENT VIEW ---
        $response_data['current_isp_profile_id'] = $current_isp_profile_id;
        $stmt_curr_prof = $db->prepare("SELECT agent_name FROM isp_profiles WHERE id = :id");
        $stmt_curr_prof->bindValue(':id', $current_isp_profile_id, SQLITE3_INTEGER);
        if ($prof = $stmt_curr_prof->execute()->fetchArray(SQLITE3_ASSOC)) { $response_data['current_isp_name'] = $prof['agent_name']; }
        $stmt_curr_prof->close();

        $latest_check_stmt = $db->prepare("SELECT * FROM sla_metrics WHERE isp_profile_id = :id ORDER BY timestamp DESC LIMIT 1");
        $latest_check_stmt->bindValue(':id', $current_isp_profile_id, SQLITE3_INTEGER);
        if ($latest = $latest_check_stmt->execute()->fetchArray(SQLITE3_ASSOC)) {
            cast_sla_metric_types($latest);
            $response_data['latest_check'] = $latest;
        }
        $latest_check_stmt->close();
        
        $chart_query = $db->prepare("SELECT timestamp, avg_rtt_ms, avg_loss_percent, avg_jitter_ms, speedtest_download_mbps, speedtest_upload_mbps, speedtest_status FROM sla_metrics WHERE isp_profile_id = :id AND timestamp >= :start_date ORDER BY timestamp ASC");
        $chart_query->bindValue(':id', $current_isp_profile_id, SQLITE3_INTEGER);
        $chart_query->bindValue(':start_date', $start_date_iso);
        $chart_result = $chart_query->execute();
        while($row = $chart_result->fetchArray(SQLITE3_ASSOC)) {
            cast_sla_metric_types($row);
            $response_data['rtt_chart_data'][] = $row;
            if ($row['speedtest_status'] === 'COMPLETED') {
                $response_data['speed_chart_data'][] = $row;
            }
        }
        $chart_query->close();
    } else {
        // --- OVERALL SUMMARY VIEW ---
        $all_status_query = $db->query("SELECT sm.*, ip.last_heard_from FROM sla_metrics sm INNER JOIN (SELECT isp_profile_id, MAX(id) as max_id FROM sla_metrics GROUP BY isp_profile_id) as latest ON sm.isp_profile_id = latest.isp_profile_id AND sm.id = latest.max_id JOIN isp_profiles ip ON sm.isp_profile_id = ip.id WHERE ip.is_active = 1");
        while ($status = $all_status_query->fetchArray(SQLITE3_ASSOC)) {
            cast_sla_metric_types($status);
            $status['sparkline_rtt'] = [];
            $response_data['all_agent_status'][$status['isp_profile_id']] = $status;
        }
        
        $sparkline_date = (new DateTime("-1 day", new DateTimeZone("UTC")))->format("Y-m-d\TH:i:s\Z");
        $sparkline_query = $db->prepare("SELECT isp_profile_id, avg_rtt_ms FROM sla_metrics WHERE timestamp >= :start_date ORDER BY timestamp ASC");
        $sparkline_query->bindValue(':start_date', $sparkline_date);
        $sparkline_result = $sparkline_query->execute();
        while($row = $sparkline_result->fetchArray(SQLITE3_ASSOC)) {
            if (isset($response_data['all_agent_status'][$row['isp_profile_id']])) {
                $response_data['all_agent_status'][$row['isp_profile_id']]['sparkline_rtt'][] = (float)$row['avg_rtt_ms'];
            }
        }
        $sparkline_query->close();

        $cumulative_ping_stmt = $db->prepare("SELECT strftime('%Y-%m-%d', timestamp) as day, AVG(avg_rtt_ms) as avg_rtt, AVG(avg_loss_percent) as avg_loss, AVG(avg_jitter_ms) as avg_jitter FROM sla_metrics WHERE timestamp >= :start_date GROUP BY day ORDER BY day ASC");
        $cumulative_ping_stmt->bindValue(':start_date', $start_date_iso);
        $ping_res = $cumulative_ping_stmt->execute();
        while($row = $ping_res->fetchArray(SQLITE3_ASSOC)) {
            $row['avg_rtt'] = (float)$row['avg_rtt'];
            $row['avg_loss'] = (float)$row['avg_loss'];
            $row['avg_jitter'] = (float)$row['avg_jitter'];
            $response_data['cumulative_ping_chart_data'][] = $row;
        }
        $cumulative_ping_stmt->close();

        $cumulative_speed_stmt = $db->prepare("SELECT strftime('%Y-%m-%d', timestamp) as day, AVG(speedtest_download_mbps) as avg_dl, AVG(speedtest_upload_mbps) as avg_ul FROM sla_metrics WHERE speedtest_status = 'COMPLETED' AND timestamp >= :start_date GROUP BY day ORDER BY day ASC");
        $cumulative_speed_stmt->bindValue(':start_date', $start_date_iso);
        $speed_res = $cumulative_speed_stmt->execute();
        while($row = $speed_res->fetchArray(SQLITE3_ASSOC)) {
            $row['avg_dl'] = (float)$row['avg_dl'];
            $row['avg_ul'] = (float)$row['avg_ul'];
            $response_data['cumulative_speed_chart_data'][] = $row;
        }
        $cumulative_speed_stmt->close();
    }
    
    // --- ADVANCED SLA CALCULATION ---
    // (No changes needed in this block)
    $sla_query_sql = "SELECT SUM(sla_met_interval) FROM sla_metrics sm JOIN isp_profiles ip ON sm.isp_profile_id = ip.id WHERE sm.timestamp >= :start_date";
    if ($current_isp_profile_id) {
        $sla_query_sql .= " AND sm.isp_profile_id = :isp_id";
        $agent_count_query = "1";
    } else {
        $sla_query_sql .= " AND ip.agent_type = 'ISP'";
        $agent_count_query = "SELECT COUNT(*) FROM isp_profiles WHERE agent_type = 'ISP' AND is_active=1";
    }
    $num_agents_in_calc = (int)$db->querySingle($agent_count_query) ?: 1;

    foreach (['1' => 'Last 24 Hours', '7' => 'Last 7 Days', '30' => 'Last 30 Days', '365' => 'Last Year'] as $days => $label) {
        if ($days > $period_days && !$current_isp_profile_id) continue;
        if ($days != $period_days && $current_isp_profile_id) continue;
        
        $total_possible = floor(((float)$days * 1440) / $EXPECTED_INTERVAL_MINUTES) * $num_agents_in_calc;

        $stmt = $db->prepare($sla_query_sql);

        $stmt->bindValue(':start_date', (new DateTime("-{$days} days", new DateTimeZone("UTC")))->format("Y-m-d\TH:i:s\Z"));
        if ($current_isp_profile_id) {
            $stmt->bindValue(':isp_id', $current_isp_profile_id, SQLITE3_INTEGER);
        }

        $met_intervals = (int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0];
        $stmt->close();
        
        $achieved = ($total_possible > 0) ? round(($met_intervals / $total_possible) * 100, 2) : 0.0;
        $response_data['periods'][] = ['label' => $label, 'achieved_percentage' => $achieved, 'is_target_met' => ($achieved >= $response_data['target_sla_percentage'])];
    }
    
    $db->close();
} catch (Exception $e) {
    http_response_code(500);
    $response_data = ['error' => 'A server error occurred.', 'message' => $e->getMessage()];
    error_log("SLA Stats PHP Error: " . $e->getMessage());
}

echo json_encode($response_data);
?>