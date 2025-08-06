#!/bin/bash
# SLA Monitor Agent Script
# FINAL PRODUCTION VERSION - Includes health summary logic and all previous fixes.

# --- Configuration & Setup ---
AGENT_CONFIG_FILE="/opt/sla_monitor/agent_config.env"
LOG_FILE="/var/log/internet_sla_monitor_agent.log"
LOCK_FILE="/tmp/sla_monitor_agent.lock"

# --- Helper Functions ---
log_message() { echo "$(date '+%Y-%m-%d %H:%M:%S %Z'): [$AGENT_IDENTIFIER] $1"; }

# --- Lock File Logic ---
if ! mkdir "$LOCK_FILE" 2>/dev/null; then
    log_message "[LOCK] Previous instance is still running. Exiting."
    exit 1
fi
# Automatically remove the lock file when the script exits, for any reason.
trap 'rm -rf "$LOCK_FILE"' EXIT

# --- Source and Validate Configuration ---
if [ -f "$AGENT_CONFIG_FILE" ]; then set -a; source "$AGENT_CONFIG_FILE"; set +a; fi
DEFAULT_PING_HOSTS=("8.8.8.8" "1.1.1.1" "google.com")
PING_HOSTS=("${PING_HOSTS[@]:-${DEFAULT_PING_HOSTS[@]}}")
AGENT_IDENTIFIER="${AGENT_IDENTIFIER:-<UNIQUE_AGENT_ID>}"
AGENT_TYPE="${AGENT_TYPE:-ISP}"
CENTRAL_API_URL="${CENTRAL_API_URL:-http://<YOUR_CENTRAL_SERVER_IP>/api/submit_metrics.php}"
CENTRAL_API_KEY="${CENTRAL_API_KEY:-}"
PING_COUNT=${PING_COUNT:-10}
PING_TIMEOUT=${PING_TIMEOUT:-5}
DNS_CHECK_HOST="${DNS_CHECK_HOST:-www.google.com}"
DNS_SERVER_TO_QUERY="${DNS_SERVER_TO_QUERY:-}"
HTTP_CHECK_URL="${HTTP_CHECK_URL:-https://www.google.com}"
HTTP_TIMEOUT=${HTTP_TIMEOUT:-10}
ENABLE_PING=${ENABLE_PING:-true}
ENABLE_DNS=${ENABLE_DNS:-true}
ENABLE_HTTP=${ENABLE_HTTP:-true}
ENABLE_SPEEDTEST=${ENABLE_SPEEDTEST:-true}
NETWORK_INTERFACE_TO_MONITOR="${NETWORK_INTERFACE_TO_MONITOR:-}"
SPEEDTEST_ARGS="${SPEEDTEST_ARGS:-}"

log_message "Starting SLA Monitor Agent Script. Type: ${AGENT_TYPE}"

if [[ "$CENTRAL_API_URL" == *"YOUR_CENTRAL_SERVER_IP"* ]] || [ -z "$CENTRAL_API_URL" ]; then log_message "FATAL: CENTRAL_API_URL not configured in ${AGENT_CONFIG_FILE}. Exiting."; exit 1; fi
if [[ "$AGENT_IDENTIFIER" == *"<UNIQUE_AGENT_ID>"* ]] || [ -z "$AGENT_IDENTIFIER" ]; then log_message "FATAL: AGENT_IDENTIFIER not configured in ${AGENT_CONFIG_FILE}. Exiting."; exit 1; fi
if [ ${#PING_HOSTS[@]} -eq 0 ]; then log_message "WARN: PING_HOSTS array not defined in ${AGENT_CONFIG_FILE}. Disabling ping test for this run."; ENABLE_PING=false; fi

# --- Fetch Profile & Thresholds from Central Server ---
CENTRAL_PROFILE_CONFIG_URL="${CENTRAL_API_URL/submit_metrics.php/get_profile_config.php}?agent_id=${AGENT_IDENTIFIER}"
profile_curl_headers=()
if [ -n "$CENTRAL_API_KEY" ]; then
    profile_curl_headers+=("-H" "X-API-Key: $CENTRAL_API_KEY")
fi
_profile_json_from_central=$(curl -s -m 10 -G "${profile_curl_headers[@]}" "$CENTRAL_PROFILE_CONFIG_URL") # Add 10-sec timeout
if [ -n "$_profile_json_from_central" ] && echo "$_profile_json_from_central" | jq -e . > /dev/null 2>&1; then
    log_message "Successfully fetched profile config from central server."
    RTT_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".rtt_degraded // 100")
    RTT_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".rtt_poor // 250")
    LOSS_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".loss_degraded // 2")
    LOSS_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".loss_poor // 10")
    PING_JITTER_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".ping_jitter_degraded // 30")
    PING_JITTER_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".ping_jitter_poor // 50")
    DNS_TIME_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".dns_time_degraded // 300")
    DNS_TIME_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".dns_time_poor // 800")
    HTTP_TIME_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".http_time_degraded // 1.0")
    HTTP_TIME_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".http_time_poor // 2.5")
    SPEEDTEST_DL_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".speedtest_dl_degraded // 60")
    SPEEDTEST_DL_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".speedtest_dl_poor // 30")
    SPEEDTEST_UL_THRESHOLD_DEGRADED=$(echo "$_profile_json_from_central" | jq -r ".speedtest_ul_degraded // 20")
    SPEEDTEST_UL_THRESHOLD_POOR=$(echo "$_profile_json_from_central" | jq -r ".speedtest_ul_poor // 5")
else
    log_message "WARN: Failed to fetch profile config. Using hardcoded script defaults for thresholds."
    RTT_THRESHOLD_DEGRADED=100; RTT_THRESHOLD_POOR=250; LOSS_THRESHOLD_DEGRADED=2; LOSS_THRESHOLD_POOR=10; PING_JITTER_THRESHOLD_DEGRADED=30; PING_JITTER_THRESHOLD_POOR=50; DNS_TIME_THRESHOLD_DEGRADED=300; DNS_TIME_THRESHOLD_POOR=800; HTTP_TIME_THRESHOLD_DEGRADED=1.0; HTTP_TIME_THRESHOLD_POOR=2.5; SPEEDTEST_DL_THRESHOLD_DEGRADED=60; SPEEDTEST_DL_THRESHOLD_POOR=30; SPEEDTEST_UL_THRESHOLD_DEGRADED=20; SPEEDTEST_UL_THRESHOLD_POOR=5;
fi

# Auto-detect speedtest command.
SPEEDTEST_COMMAND_PATH="";
if command -v speedtest &>/dev/null; then SPEEDTEST_COMMAND_PATH=$(command -v speedtest);
elif command -v speedtest-cli &>/dev/null; then SPEEDTEST_COMMAND_PATH=$(command -v speedtest-cli); fi

# --- Main Logic ---
LOG_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AGENT_SOURCE_IP=$(ip route get 8.8.8.8 | awk '{print $7; exit}' 2>/dev/null || hostname -I | awk '{print $1}')
AGENT_HOSTNAME_LOCAL=$(hostname -s)
declare -A results_map

# --- PING TESTS ---
if [ "$ENABLE_PING" = true ]; then
    log_message "Performing ping tests..."; ping_interface_arg=""; if [ -n "$NETWORK_INTERFACE_TO_MONITOR" ]; then ping_interface_arg="-I $NETWORK_INTERFACE_TO_MONITOR"; fi
    total_rtt_sum=0.0; total_loss_sum=0; total_jitter_sum=0.0; ping_targets_up=0
    for host in "${PING_HOSTS[@]}"; do
        ping_output=$(sudo LANG=C ping ${ping_interface_arg} -c "$PING_COUNT" -W "$PING_TIMEOUT" -q "$host" 2>&1)
        if [ $? -eq 0 ]; then
            log_message "Ping to $host: SUCCESS"; packet_loss=$(echo "$ping_output" | grep -oP '\d+(?=% packet loss)'); rtt_line=$(echo "$ping_output" | grep 'rtt min/avg/max/mdev'); avg_rtt=$(echo "$rtt_line" | cut -d'=' -f2 | cut -d'/' -f2); avg_jitter=$(echo "$rtt_line" | cut -d'=' -f2 | cut -d'/' -f4 | sed 's/\s*ms//');
            ((ping_targets_up++)); total_rtt_sum=$(awk "BEGIN {print $total_rtt_sum + $avg_rtt}"); if [[ "$avg_jitter" =~ ^[0-9.]+$ ]]; then total_jitter_sum=$(awk "BEGIN {print $total_jitter_sum + $avg_jitter}"); fi; total_loss_sum=$((total_loss_sum + packet_loss));
        else
            log_message "Ping to $host: FAIL"
        fi
    done
    if [ "$ping_targets_up" -gt 0 ]; then results_map[ping_status]="UP"; results_map[ping_rtt]=$(awk "BEGIN {printf \"%.2f\", $total_rtt_sum / $ping_targets_up}"); results_map[ping_jitter]=$(awk "BEGIN {printf \"%.2f\", $total_jitter_sum / $ping_targets_up}"); results_map[ping_loss]=$(awk "BEGIN {printf \"%.1f\", $total_loss_sum / ${#PING_HOSTS[@]}}");
    else results_map[ping_status]="DOWN"; fi
fi

# --- DNS RESOLUTION TEST ---
if [ "$ENABLE_DNS" = true ]; then
    log_message "Performing DNS resolution test..."; source_ip_arg_for_dig=""; if [ -n "$NETWORK_INTERFACE_TO_MONITOR" ]; then _source_ip_agent=$(ip -4 addr show "$NETWORK_INTERFACE_TO_MONITOR" | grep -oP 'inet \K[\d.]+'); if [ -n "$_source_ip_agent" ]; then source_ip_arg_for_dig="+source=$_source_ip_agent"; fi; fi; dig_server_arg=""; if [ -n "$DNS_SERVER_TO_QUERY" ]; then dig_server_arg="@${DNS_SERVER_TO_QUERY}"; fi;
    start_time_dns=$(date +%s.%N); dns_output=$(dig +short +time=2 +tries=1 $source_ip_arg_for_dig $dig_server_arg "$DNS_CHECK_HOST" 2>&1);
    if [ $? -eq 0 ] && [ -n "$dns_output" ]; then end_time_dns=$(date +%s.%N); results_map[dns_status]="OK"; results_map[dns_time]=$(awk "BEGIN {printf \"%.0f\", ($end_time_dns - $start_time_dns) * 1000}"); else results_map[dns_status]="FAILED"; fi
fi

# --- HTTP CHECK ---
if [ "$ENABLE_HTTP" = true ]; then
    log_message "Performing HTTP check..."; interface_arg=""; if [ -n "$NETWORK_INTERFACE_TO_MONITOR" ]; then interface_arg="--interface $NETWORK_INTERFACE_TO_MONITOR"; fi
    curl_output_stats=$(curl ${interface_arg} -L -s -o /dev/null -w "http_code=%{http_code}\ntime_total=%{time_total}" --max-time "$HTTP_TIMEOUT" "$HTTP_CHECK_URL");
    if [ $? -eq 0 ]; then
        results_map[http_code]=$(echo "$curl_output_stats" | grep "http_code" | cut -d'=' -f2); results_map[http_time]=$(echo "$curl_output_stats" | grep "time_total" | cut -d'=' -f2 | sed 's/,/./');
        if [[ "${results_map[http_code]}" -ge 200 && "${results_map[http_code]}" -lt 400 ]]; then results_map[http_status]="OK"; else results_map[http_status]="ERROR_CODE"; fi
    else results_map[http_status]="FAILED_REQUEST"; fi
fi

# --- SPEEDTEST ---
if [ "$ENABLE_SPEEDTEST" = true ]; then
    if [ -n "$SPEEDTEST_COMMAND_PATH" ]; then
        log_message "Performing speedtest with '$SPEEDTEST_COMMAND_PATH' and args '$SPEEDTEST_ARGS'..."; speedtest_interface_arg=""; if [ -n "$NETWORK_INTERFACE_TO_MONITOR" ]; then _source_ip_agent=$(ip -4 addr show "$NETWORK_INTERFACE_TO_MONITOR" | grep -oP 'inet \K[\d.]+'); if [ -n "$_source_ip_agent" ]; then if [[ "$SPEEDTEST_ARGS" == *"--source"* ]]; then speedtest_interface_arg="--source $_source_ip_agent"; elif [[ "$SPEEDTEST_ARGS" == *"--interface"* ]]; then speedtest_interface_arg="--interface $NETWORK_INTERFACE_TO_MONITOR"; fi; fi; fi;
        speedtest_json_output=$(timeout 120s $SPEEDTEST_COMMAND_PATH $SPEEDTEST_ARGS $speedtest_interface_arg);
        if [ $? -eq 0 ] && echo "$speedtest_json_output" | jq -e . > /dev/null 2>&1; then
            if echo "$speedtest_json_output" | jq -e '.download.bandwidth' > /dev/null 2>&1; then
                log_message "Parsing speedtest output as Ookla JSON format."; dl_bytes_per_sec=$(echo "$speedtest_json_output" | jq -r '.download.bandwidth // 0'); ul_bytes_per_sec=$(echo "$speedtest_json_output" | jq -r '.upload.bandwidth // 0'); results_map[st_dl]=$(awk "BEGIN {printf \"%.2f\", $dl_bytes_per_sec * 8 / 1000000}"); results_map[st_ul]=$(awk "BEGIN {printf \"%.2f\", $ul_bytes_per_sec * 8 / 1000000}"); results_map[st_ping]=$(echo "$speedtest_json_output" | jq -r '.ping.latency // "null"'); results_map[st_jitter]=$(echo "$speedtest_json_output" | jq -r '.ping.jitter // "null"'); results_map[st_status]="COMPLETED";
            elif echo "$speedtest_json_output" | jq -e '.download' > /dev/null 2>&1; then
                log_message "Parsing speedtest output as community speedtest-cli JSON format."; st_dl_bps=$(echo "$speedtest_json_output" | jq -r '.download // 0'); st_ul_bps=$(echo "$speedtest_json_output" | jq -r '.upload // 0'); results_map[st_dl]=$(awk "BEGIN {printf \"%.2f\", $st_dl_bps / 1000000}"); results_map[st_ul]=$(awk "BEGIN {printf \"%.2f\", $st_ul_bps / 1000000}"); results_map[st_ping]=$(echo "$speedtest_json_output" | jq -r '.ping // "null"'); results_map[st_jitter]="null"; results_map[st_status]="COMPLETED";
            else log_message "Speedtest FAILED: JSON format not recognized."; results_map[st_status]="FAILED_PARSE"; fi
        else log_message "Speedtest FAILED: Command failed or produced non-JSON output."; results_map[st_status]="FAILED_EXEC"; fi
    else log_message "Speedtest SKIPPED: No speedtest command found."; results_map[st_status]="SKIPPED_NO_CMD"; fi
fi

# --- DETAILED HEALTH SUMMARY & SLA CALCULATION ---
log_message "Calculating health summary..."
health_summary="UNKNOWN"; sla_met_interval=0; is_greater() { awk -v n1="$1" -v n2="$2" 'BEGIN {exit !(n1 > n2)}'; };
rtt_val=${results_map[ping_rtt]:-9999}; loss_val=${results_map[ping_loss]:-100}; jitter_val=${results_map[ping_jitter]:-999}; dns_val=${results_map[dns_time]:-99999}; http_val=${results_map[http_time]:-999}; dl_val=${results_map[st_dl]:-0}; ul_val=${results_map[st_ul]:-0};
if [ "${results_map[ping_status]}" == "DOWN" ]; then health_summary="CONNECTIVITY_DOWN";
elif [ "${results_map[dns_status]}" == "FAILED" ] || [ "${results_map[http_status]}" == "FAILED_REQUEST" ]; then health_summary="CRITICAL_SERVICE_FAILURE";
else
    is_poor=false; is_degraded=false;
    if is_greater "$rtt_val" "$RTT_THRESHOLD_POOR" || is_greater "$loss_val" "$LOSS_THRESHOLD_POOR" || is_greater "$jitter_val" "$PING_JITTER_THRESHOLD_POOR" || is_greater "$dns_val" "$DNS_TIME_THRESHOLD_POOR" || is_greater "$http_val" "$HTTP_TIME_THRESHOLD_POOR"; then is_poor=true; fi
    if [ "${results_map[st_status]}" == "COMPLETED" ]; then if is_greater "$SPEEDTEST_DL_THRESHOLD_POOR" "$dl_val" || is_greater "$SPEEDTEST_UL_THRESHOLD_POOR" "$ul_val"; then is_poor=true; fi; fi
    if [ "$is_poor" = false ]; then
        if is_greater "$rtt_val" "$RTT_THRESHOLD_DEGRADED" || is_greater "$loss_val" "$LOSS_THRESHOLD_DEGRADED" || is_greater "$jitter_val" "$PING_JITTER_THRESHOLD_DEGRADED" || is_greater "$dns_val" "$DNS_TIME_THRESHOLD_DEGRADED" || is_greater "$http_val" "$HTTP_TIME_THRESHOLD_DEGRADED"; then is_degraded=true; fi
        if [ "${results_map[st_status]}" == "COMPLETED" ]; then if is_greater "$SPEEDTEST_DL_THRESHOLD_DEGRADED" "$dl_val" || is_greater "$SPEEDTEST_UL_THRESHOLD_DEGRADED" "$ul_val"; then is_degraded=true; fi; fi
    fi
    if [ "$is_poor" = true ]; then health_summary="POOR_PERFORMANCE"; elif [ "$is_degraded" = true ]; then health_summary="DEGRADED_PERFORMANCE"; else health_summary="GOOD_PERFORMANCE"; fi
fi
if [ "$health_summary" == "GOOD_PERFORMANCE" ]; then sla_met_interval=1; fi
log_message "Health Summary: $health_summary"
results_map[detailed_health_summary]="$health_summary"
results_map[current_sla_met_status]=$(if [ $sla_met_interval -eq 1 ]; then echo "MET"; else echo "NOT_MET"; fi)

# --- Construct Final JSON Payload ---
log_message "Constructing final JSON payload..."
payload=$(jq -n \
    --arg     timestamp                  "$LOG_DATE" \
    --arg     agent_identifier           "$AGENT_IDENTIFIER" \
    --arg     agent_type                 "${AGENT_TYPE:-ISP}" \
    --arg     agent_hostname             "$AGENT_HOSTNAME_LOCAL" \
    --arg     agent_source_ip            "$AGENT_SOURCE_IP" \
    --arg     detailed_health_summary    "${results_map[detailed_health_summary]}" \
    --arg     current_sla_met_status     "${results_map[current_sla_met_status]}" \
    --argjson ping_summary               "$(jq -n --arg status "${results_map[ping_status]:-N/A}" --arg rtt "${results_map[ping_rtt]:-null}" --arg loss "${results_map[ping_loss]:-null}" --arg jitter "${results_map[ping_jitter]:-null}" '{status: $status, average_rtt_ms: ($rtt | tonumber? // null), average_packet_loss_percent: ($loss | tonumber? // null), average_jitter_ms: ($jitter | tonumber? // null)}')" \
    --argjson dns_resolution             "$(jq -n --arg status "${results_map[dns_status]:-N/A}" --arg time "${results_map[dns_time]:-null}" '{status: $status, resolve_time_ms: ($time | tonumber? // null)}')" \
    --argjson http_check                 "$(jq -n --arg status "${results_map[http_status]:-N/A}" --arg code "${results_map[http_code]:-null}" --arg time "${results_map[http_time]:-null}" '{status: $status, response_code: ($code | tonumber? // null), total_time_s: ($time | tonumber? // null)}')" \
    --argjson speed_test                 "$(jq -n --arg status "${results_map[st_status]:-SKIPPED}" --arg dl "${results_map[st_dl]:-null}" --arg ul "${results_map[st_ul]:-null}" --arg ping "${results_map[st_ping]:-null}" --arg jitter "${results_map[st_jitter]:-null}" '{status: $status, download_mbps: ($dl | tonumber? // null), upload_mbps: ($ul | tonumber? // null), ping_ms: ($ping | tonumber? // null), jitter_ms: ($jitter | tonumber? // null)}')" \
    '$ARGS.named'
)

if ! echo "$payload" | jq . > /dev/null; then log_message "FATAL: Agent failed to generate valid final JSON. Aborting submission."; exit 1; fi

# --- Submit Data to Central API ---
log_message "Submitting data to central API: $CENTRAL_API_URL"
curl_headers=("-H" "Content-Type: application/json"); if [ -n "$CENTRAL_API_KEY" ]; then curl_headers+=("-H" "X-API-Key: $CENTRAL_API_KEY"); fi
api_response_file=$(mktemp); api_http_code=$(curl --silent --show-error --fail "${curl_headers[@]}" -X POST -d "$payload" "$CENTRAL_API_URL" --output "$api_response_file" --write-out "%{http_code}"); api_curl_exit_code=$?; api_response_body=$(cat "$api_response_file"); rm -f "$api_response_file"
if [ "$api_curl_exit_code" -eq 0 ]; then log_message "Data successfully submitted. HTTP code: $api_http_code. Response: $api_response_body"; else log_message "ERROR: Failed to submit data to central API. Curl exit: $api_curl_exit_code, HTTP code: $api_http_code. Response: $api_response_body"; fi

log_message "Agent monitor script finished."
exit 0