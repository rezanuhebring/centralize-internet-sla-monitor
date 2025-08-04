<?php
// /var/www/html/sla_status/api/get_profile_config.php
$db_file = '/opt/sla_monitor/central_sla_data.sqlite';
$log_file_api = '/var/log/sla_api.log'; 
function api_log_get_profile($message) { file_put_contents($GLOBALS['log_file_api'], date('[Y-m-d H:i:s T] ') . '[GetProfileCfg] ' . $message . PHP_EOL, FILE_APPEND); }

header("Content-Type: application/json");
header('Cache-Control: no-cache, must-revalidate, no-store, max-age=0');

// TODO: Implement robust API Key Authentication here

$agent_identifier = $_GET['agent_id'] ?? null;
if (empty($agent_identifier)) { http_response_code(400); api_log_get_profile("Missing agent_id."); echo json_encode(['error' => 'Missing agent_id parameter.']); exit;}

// FIX 3: Use htmlspecialchars instead of the deprecated FILTER_SANITIZE_STRING
$agent_identifier = htmlspecialchars($agent_identifier, ENT_QUOTES, 'UTF-8');

api_log_get_profile("Request for profile config from agent: " . $agent_identifier);

try {
    if (!file_exists($db_file)) { throw new Exception("Database file not found."); }
    if (!is_readable($db_file)) { $effUser = function_exists('posix_getpwuid') && function_exists('posix_geteuid') ? posix_getpwuid(posix_geteuid())['name'] : get_current_user(); throw new Exception("Database not readable by web server (user: " . $effUser . ").");}
    
    // FIX 2: Open in read-only mode, which is correct for a 'get' script.
    $db = new SQLite3($db_file, SQLITE3_OPEN_READONLY); 
    if (!$db) { throw new Exception("Could not connect to DB: " . SQLite3::lastErrorMsg()); }

    // FIX 2 (Continued): Remove the write operation on the read-only database.
    // The journal_mode is set once during DB creation in the setup script.
    // $db->exec("PRAGMA journal_mode=WAL;");

    // Return all stored fields for this agent profile
    $stmt = $db->prepare("SELECT * FROM isp_profiles WHERE agent_identifier = :agent_id LIMIT 1");
    
    // The code will now fail here if the table isn't found (see FIX 1)
    if ($stmt === false) {
        throw new Exception("Failed to prepare SQL statement. Is the database table 'isp_profiles' missing? DB Error: " . $db->lastErrorMsg());
    }

    $stmt->bindValue(':agent_id', $agent_identifier, SQLITE3_TEXT);
    $result = $stmt->execute(); 
    $profile_config = $result->fetchArray(SQLITE3_ASSOC); 
    $stmt->close(); 
    $db->close();

    if ($profile_config) {
        // Refactor: Improve maintainability of type conversion.
        // SQLite returns all values as strings, so we must explicitly cast to numeric types for JSON consistency.
        // This list contains columns that should remain strings even if they appear numeric (e.g., an agent_identifier of "12345").
        $string_columns = [
            'agent_name', 'agent_identifier', 'agent_type', 'network_interface_to_monitor',
            'teams_webhook_url', 'alert_hostname_override', 'notes', 'last_heard_from',
            'last_reported_hostname', 'last_reported_source_ip'
        ];

        foreach ($profile_config as $key => &$value) {
            if (is_null($value) || $value === "NULL") {
                $value = null;
                continue;
            }

            // Cast to number if the value is numeric AND the column is not in our explicit string list.
            if (is_numeric($value) && !in_array($key, $string_columns)) {
                if (strpos($value, '.') !== false) {
                    $value = (float)$value;
                } else {
                    $value = (int)$value;
                }
            }
        }
        unset($value);

        api_log_get_profile("Served profile config for agent: " . $agent_identifier);
        echo json_encode($profile_config);
    } else {
        http_response_code(404); api_log_get_profile("Profile config not found for agent: " . $agent_identifier); 
        echo json_encode(['error' => "Profile not found for agent_id '{$agent_identifier}'. Agent will be auto-created on next data submission with default thresholds."]); 
    }
} catch (Exception $e) { api_log_get_profile("Error for {$agent_identifier}: " . $e->getMessage()); http_response_code(500); echo json_encode(['error' => 'Server error: ' . $e->getMessage()]); }
?>