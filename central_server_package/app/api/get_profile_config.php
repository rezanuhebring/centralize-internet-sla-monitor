<?php
// /var/www/html/sla_status/api/get_profile_config.php
$db_file = '/opt/sla_monitor/central_sla_data.sqlite';
$config_file = '/opt/sla_monitor/sla_config.env';
$log_file_api = '/var/log/sla_api.log'; 

function api_log_get_profile($message) { file_put_contents($GLOBALS['log_file_api'], date('[Y-m-d H:i:s T] ') . '[GetProfileCfg] ' . $message . PHP_EOL, FILE_APPEND); }

function load_config($file_path) {
    if (!file_exists($file_path)) return [];
    $lines = file($file_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $config = [];
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        list($key, $value) = explode('=', $line, 2);
        $config[trim($key)] = trim($value);
    }
    return $config;
}

header("Content-Type: application/json");
header('Cache-Control: no-cache, must-revalidate, no-store, max-age=0');

// --- API Key Authentication ---
$config = load_config($config_file);
$master_api_key = $config['CENTRAL_API_KEY'] ?? '';

if (!empty($master_api_key)) {
    $provided_api_key = $_SERVER['HTTP_X_API_KEY'] ?? '';
    if (!hash_equals($master_api_key, $provided_api_key)) {
        http_response_code(401);
        api_log_get_profile("Unauthorized: Invalid or missing API key from client trying to get profile.");
        echo json_encode(['error' => 'Unauthorized: API Key is invalid or missing.']);
        exit;
    }
}

$agent_identifier = $_GET['agent_id'] ?? null;
if (empty($agent_identifier)) { http_response_code(400); api_log_get_profile("Missing agent_id."); echo json_encode(['error' => 'Missing agent_id parameter.']); exit;}

// Sanitize the input to prevent XSS, although parameterization handles SQLi
$agent_identifier = htmlspecialchars($agent_identifier, ENT_QUOTES, 'UTF-8');

api_log_get_profile("Request for profile config from agent: " . $agent_identifier);

try {
    if (!file_exists($db_file)) {
        throw new Exception("Database file not found.");
    }
    if (!is_readable($db_file)) {
        $effUser = function_exists('posix_getpwuid') && function_exists('posix_geteuid') ? posix_getpwuid(posix_geteuid())['name'] : get_current_user();
        throw new Exception("Database not readable by web server (user: " . $effUser . ").");
    }
    
    $db = new SQLite3($db_file, SQLITE3_OPEN_READONLY);
    if (!$db) {
        throw new Exception("Could not connect to DB: " . $db->lastErrorMsg());
    }

    // Use prepared statements to prevent SQL injection
    $stmt = $db->prepare("SELECT * FROM isp_profiles WHERE agent_identifier = :agent_id LIMIT 1");
    if ($stmt === false) {
        throw new Exception("Failed to prepare SQL statement. Is the database table 'isp_profiles' missing? DB Error: " . $db->lastErrorMsg());
    }

    $stmt->bindValue(':agent_id', $agent_identifier, SQLITE3_TEXT);
    $result = $stmt->execute();
    $profile_config = $result->fetchArray(SQLITE3_ASSOC);
    $stmt->close();
    $db->close();

    if ($profile_config) {
        // Convert numeric strings from DB to actual numbers for JSON consistency
        foreach ($profile_config as $key => &$value) {
            if (is_numeric($value) && !in_array($key, ['agent_name', 'agent_identifier', 'agent_type', 'network_interface_to_monitor', 'teams_webhook_url', 'alert_hostname_override', 'notes', 'last_heard_from', 'last_reported_hostname', 'last_reported_source_ip'])) { 
                if (strpos($value, '.') !== false) { $value = (float)$value;} else { $value = (int)$value;}
            } elseif ($value === "NULL" || is_null($value)) {
                $value = null; 
            }
        } unset($value);
        api_log_get_profile("Served profile config for agent: " . $agent_identifier); echo json_encode($profile_config);
    } else { 
        http_response_code(404); api_log_get_profile("Profile config not found for agent: " . $agent_identifier); 
        echo json_encode(['error' => "Profile not found for agent_id '{$agent_identifier}'. Agent will be auto-created on next data submission with default thresholds."]); 
    }
} catch (Exception $e) { api_log_get_profile("Error for {$agent_identifier}: " . $e->getMessage()); http_response_code(500); echo json_encode(['error' => 'Server error: ' . $e->getMessage()]); }
?>