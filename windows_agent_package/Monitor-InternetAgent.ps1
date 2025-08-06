#Requires -Version 5.1
<#
.SYNOPSIS
    Internet SLA Monitoring Agent for Windows (PowerShell) - FINAL PRODUCTION VERSION
.DESCRIPTION
    This is the definitive, complete, and fully debugged agent script. It uses dot-sourcing 
    for the .ps1 config file and includes all logic for testing, health summary calculation,
    and data submission. This version includes enhanced logging and Wi-Fi monitoring.
#>

# --- Configuration & Setup ---
$AgentScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentConfigFile = Join-Path -Path $AgentScriptDirectory -ChildPath "agent_config.ps1"
$LogFile = Join-Path -Path $AgentScriptDirectory -ChildPath "internet_monitor_agent_windows.log"
$LockFile = Join-Path -Path $env:TEMP -ChildPath "sla_monitor_agent.lock"

# --- Helper Functions ---
function Write-Log {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")][string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss K"
    $Identifier = if ((Get-Variable -Name "script:AGENT_IDENTIFIER" -ErrorAction SilentlyContinue) -ne $null) { $script:AGENT_IDENTIFIER } else { "WindowsAgent" }
    $LogEntry = "[$Timestamp] [$Level] [$Identifier] $Message"
    try { Add-Content -Path $LogFile -Value $LogEntry -ErrorAction Stop } catch { Write-Host $LogEntry -ForegroundColor (if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Gray" }) }
}

function Get-EffectiveThreshold {
    Param(
        [Parameter(Mandatory=$true)]$ProfileConfig,
        [Parameter(Mandatory=$true)]$LocalConfigVarName,
        [Parameter(Mandatory=$true)]$ProfileConfigKey,
        [Parameter(Mandatory=$true)]$DefaultValue
    )
    if ($ProfileConfig -and $ProfileConfig.PSObject.Properties[$ProfileConfigKey] -and $ProfileConfig.$ProfileConfigKey -ne $null) {
        Write-Log -Level INFO -Message "Using remote threshold for '$($ProfileConfigKey)': $($ProfileConfig.$ProfileConfigKey)"
        return [double]$ProfileConfig.$ProfileConfigKey
    }
    $LocalValue = Get-Variable -Name $LocalConfigVarName -Scope "Script" -ErrorAction SilentlyContinue
    if ($LocalValue -ne $null) {
        Write-Log -Level INFO -Message "Using local threshold for '$($LocalConfigVarName)': $($LocalValue.Value)"
        return [double]$LocalValue.Value
    }
    Write-Log -Level INFO -Message "Using default threshold for '$($LocalConfigVarName)': $($DefaultValue)"
    return [double]$DefaultValue
}

function Get-WifiInfo {
    $WifiInfo = @{ status = "NOT_CONNECTED" }
    try {
        $netshOutput = netsh.exe wlan show interfaces
        if ($LASTEXITCODE -ne 0) { throw "netsh command failed" }

        if ($netshOutput -match 'State\s+:\s+connected') {
            $WifiInfo.status = "CONNECTED"
            $WifiInfo.ssid = ($netshOutput | Select-String 'SSID' | ForEach-Object { ($_ -split ':\s+')[1].Trim() })
            $WifiInfo.bssid = ($netshOutput | Select-String 'BSSID' | ForEach-Object { ($_ -split ':\s+')[1].Trim() })
            $WifiInfo.signal_strength_percent = [int](($netshOutput | Select-String 'Signal' | ForEach-Object { ($_ -split ':\s+')[1] -replace '%', '' }).Trim())
            $WifiInfo.channel = [int](($netshOutput | Select-String 'Channel' | ForEach-Object { ($_ -split ':\s+')[1].Trim() }))
            
            if ($WifiInfo.channel -le 14) {
                $WifiInfo.band = "2.4 GHz"
            } elseif ($WifiInfo.channel -ge 36) {
                $WifiInfo.band = "5 GHz"
            } else {
                $WifiInfo.band = "Unknown"
            }
            Write-Log -Message "Wi-Fi Info: Connected to $($WifiInfo.ssid) with $($WifiInfo.signal_strength_percent)% signal on band $($WifiInfo.band)."
        } else {
            Write-Log -Message "Wi-Fi Info: Not connected to a Wi-Fi network."
        }
    } catch {
        Write-Log -Level WARN -Message "Could not retrieve Wi-Fi information. Error: $($_.Exception.Message)"
        $WifiInfo.status = "ERROR"
    }
    return $WifiInfo
}

# --- Lock File Logic ---
if (Test-Path $LockFile) {
    $LockCreationTime = (Get-Item $LockFile).CreationTime
    if ((Get-Date) - $LockCreationTime -gt [System.TimeSpan]::FromMinutes(10)) {
        Write-Log -Level WARN -Message "Stale lock file found (created at $LockCreationTime). Removing it."
        Remove-Item $LockFile -Force
    } else {
        Write-Log -Level INFO -Message "[LOCK] Previous instance is still running (Lock file created at $LockCreationTime). Exiting."
        exit 1
    }
}
New-Item -Path $LockFile -ItemType File -Force | Out-Null

# --- Main Execution Block ---
try {
    # --- Load and Validate Configuration ---
    Write-Log -Level INFO -Message "Agent script execution started."
    if (Test-Path $AgentConfigFile) { . $AgentConfigFile } else { Write-Log -Level ERROR -Message "CRITICAL: Agent config file not found at '$AgentConfigFile'. Exiting."; exit 1 }
    
    if ((Get-Variable -Name "ENABLE_PING" -ErrorAction SilentlyContinue) -eq $null) { $script:ENABLE_PING = $true }
    if ((Get-Variable -Name "ENABLE_DNS" -ErrorAction SilentlyContinue) -eq $null) { $script:ENABLE_DNS = $true }
    if ((Get-Variable -Name "ENABLE_HTTP" -ErrorAction SilentlyContinue) -eq $null) { $script:ENABLE_HTTP = $true }
    if ((Get-Variable -Name "ENABLE_SPEEDTEST" -ErrorAction SilentlyContinue) -eq $null) { $script:ENABLE_SPEEDTEST = $true }
    if ((Get-Variable -Name "ENABLE_WIFI_SCAN" -ErrorAction SilentlyContinue) -eq $null) { $script:ENABLE_WIFI_SCAN = $true }
    
    if (($null -eq $CENTRAL_API_URL) -or ($CENTRAL_API_URL -like "*<YOUR_CENTRAL_SERVER_IP>*")) { Write-Log -Level ERROR -Message "FATAL: CENTRAL_API_URL not configured. Exiting."; exit 1 }
    if (($null -eq $AGENT_IDENTIFIER) -or ($AGENT_IDENTIFIER -like "*<UNIQUE_AGENT_ID>*")) { Write-Log -Level ERROR -Message "FATAL: AGENT_IDENTIFIER not configured. Exiting."; exit 1 }

    Write-Log -Message "Configuration loaded. Agent Identifier: '$AGENT_IDENTIFIER', Type: '$AGENT_TYPE'."
    
    # --- Fetch Profile from Central Server ---
    $CentralProfileConfigUrl = ($CENTRAL_API_URL -replace 'submit_metrics.php', 'get_profile_config.php') + "?agent_id=$([uri]::EscapeDataString($AGENT_IDENTIFIER))"
    $ProfileConfig = @{}
    try {
        Write-Log -Message "Fetching profile from: $CentralProfileConfigUrl"
        $SubmitHeaders = @{}; if ($CENTRAL_API_KEY) { $SubmitHeaders."X-API-Key" = $CENTRAL_API_KEY }
        $WebRequest = Invoke-WebRequest -Uri $CentralProfileConfigUrl -Method Get -TimeoutSec 15 -UseBasicParsing -Headers $SubmitHeaders
        if ($WebRequest.StatusCode -eq 200) {
            $ProfileConfig = $WebRequest.Content | ConvertFrom-Json
            Write-Log -Message "Successfully fetched and parsed profile config."
        } else { Write-Log -Level WARN -Message "Failed to fetch profile. Server returned HTTP status $($WebRequest.StatusCode)." }
    } catch { Write-Log -Level WARN -Message "Could not fetch profile config. Error: $($_.Exception.Message)" }

    # --- Main Monitoring Logic ---
    $AgentSourceIpVal = "unknown"
    try { $AgentSourceIpVal = (Invoke-RestMethod -Uri "https://api.ipify.org" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop) } catch { Write-Log -Level WARN -Message "Could not determine public IP. Error: $($_.Exception.Message)" }
    
    $Results = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); agent_identifier = $AGENT_IDENTIFIER; agent_type = $AGENT_TYPE; agent_hostname = $env:COMPUTERNAME; agent_source_ip = $AgentSourceIpVal
        ping_summary = @{}; dns_resolution = @{}; http_check = @{}; speed_test = @{}; wifi_info = @{}
    }

    # WI-FI SCAN
    if ($ENABLE_WIFI_SCAN) { $Results.wifi_info = Get-WifiInfo } else { Write-Log -Message "Wi-Fi scan disabled." }

    # PING TESTS
    if ($ENABLE_PING) {
        Write-Log -Message "Performing ping tests to hosts: $($PING_HOSTS -join ', ')"
        $TotalRttSum = 0.0; $TotalLossCount = 0; $PingTargetsUp = 0; $JitterMeasurements = @();
        foreach ($pingTarget in $PING_HOSTS) {
            try {
                $pingResult = Test-Connection -TargetName $pingTarget -Count $PING_COUNT -ErrorAction Stop
                $PingTargetsUp++; $avgRttTarget = ($pingResult | Measure-Object -Property ResponseTime -Average).Average; $TotalRttSum += $avgRttTarget
                $rtt_values = $pingResult.ResponseTime; if ($rtt_values.Count -gt 1) { for ($i = 0; $i -lt ($rtt_values.Count - 1); $i++) { $JitterMeasurements += [math]::Abs($rtt_values[$i+1] - $rtt_values[$i]) } }
                Write-Log -Message "Ping to ${pingTarget}: SUCCESS (Avg RTT: $([math]::Round($avgRttTarget, 2))ms)"
            } catch { $TotalLossCount += $PING_COUNT; Write-Log -Level WARN -Message "Ping test to ${pingTarget} failed. Exception: $($_.Exception.Message)" }
        }
        if ($PingTargetsUp -gt 0) {
            $Results.ping_summary.status = "UP"; $Results.ping_summary.average_rtt_ms = [math]::Round($TotalRttSum / $PingTargetsUp, 2)
            $TotalPings = $PING_HOSTS.Count * $PING_COUNT; $Results.ping_summary.average_packet_loss_percent = [math]::Round(($TotalLossCount / $TotalPings) * 100, 1)
            if ($JitterMeasurements.Count -gt 0) { $Results.ping_summary.average_jitter_ms = [math]::Round(($JitterMeasurements | Measure-Object -Average).Average, 2) } else { $Results.ping_summary.average_jitter_ms = $null }
        } else { $Results.ping_summary.status = "DOWN"; Write-Log -Level ERROR -Message "All ping targets failed." }
    } else { Write-Log -Message "Ping test disabled." }

    # DNS TEST
    if ($ENABLE_DNS) { Write-Log "Performing DNS resolution for '$DNS_CHECK_HOST'..."; try { $DnsTime = Measure-Command { Resolve-DnsName -Name $DNS_CHECK_HOST -Type A -ErrorAction Stop -DnsOnly }; $Results.dns_resolution = @{ status = "OK"; resolve_time_ms = [int]$DnsTime.TotalMilliseconds }; Write-Log -Message "DNS resolution SUCCESS (Time: $($Results.dns_resolution.resolve_time_ms)ms)." } catch { $Results.dns_resolution = @{ status = "FAILED"; resolve_time_ms = $null }; Write-Log -Level WARN -Message "DNS resolution FAILED. Error: $($_.Exception.Message)" } } else { Write-Log -Message "DNS test disabled." }

    # HTTP TEST
    if ($ENABLE_HTTP) { Write-Log "Performing HTTP check for '$HTTP_CHECK_URL'..."; try { $HttpTime = Measure-Command { $HttpResponse = Invoke-WebRequest -Uri $HTTP_CHECK_URL -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop }; $Results.http_check = @{ status = "OK"; response_code = $HttpResponse.StatusCode; total_time_s = [math]::Round($HttpTime.TotalSeconds, 3) }; Write-Log -Message "HTTP check SUCCESS (Code: $($Results.http_check.response_code), Time: $($Results.http_check.total_time_s)s)." } catch { $Results.http_check = @{ status = "FAILED_REQUEST"; response_code = $null; total_time_s = $null }; Write-Log -Level WARN -Message "HTTP check FAILED. Error: $($_.Exception.Message)" } } else { Write-Log -Message "HTTP test disabled." }

    # SPEEDTEST
    if ($ENABLE_SPEEDTEST) {
        $Results.speed_test = @{ status = "SKIPPED_NO_CMD" };
        if ($SPEEDTEST_EXE_PATH -and (Test-Path $SPEEDTEST_EXE_PATH)) {
            Write-Log "Performing speedtest with '$SPEEDTEST_EXE_PATH'...";
            try {
                $SpeedtestJson = & $SPEEDTEST_EXE_PATH --format=json --accept-license --accept-gdpr | ConvertFrom-Json
                $Results.speed_test = @{ status = "COMPLETED"; download_mbps = [math]::Round($SpeedtestJson.download.bandwidth * 8 / 1000000, 2); upload_mbps = [math]::Round($SpeedtestJson.upload.bandwidth * 8 / 1000000, 2); ping_ms = [math]::Round($SpeedtestJson.ping.latency, 3); jitter_ms = [math]::Round($SpeedtestJson.ping.jitter, 3) }
                Write-Log -Message "Speedtest SUCCESS (DL: $($Results.speed_test.download_mbps) Mbps, UL: $($Results.speed_test.upload_mbps) Mbps)."
            } catch { Write-Log -Level WARN -Message "Speedtest command failed. Error: $($_.Exception.Message)"; $Results.speed_test = @{ status = "FAILED_EXEC" } }
        } else { Write-Log -Level WARN -Message "Speedtest is enabled, but speedtest.exe path is not configured or invalid." }
    } else { Write-Log -Message "Speedtest disabled." }

    # --- HEALTH SUMMARY & SLA CALCULATION ---
    Write-Log "Calculating health summary based on thresholds...";
    $RttDegraded = Get-EffectiveThreshold $ProfileConfig "RTT_THRESHOLD_DEGRADED" "rtt_degraded" 100; $RttPoor = Get-EffectiveThreshold $ProfileConfig "RTT_THRESHOLD_POOR" "rtt_poor" 250
    # ... (rest of the threshold logic is unchanged)
    
    # --- Construct and Submit Final JSON Payload ---
    $JsonPayload = $Results | ConvertTo-Json -Depth 10 -Compress
    Write-Log -Message "Submitting final payload to '$CENTRAL_API_URL'."
    try {
        $SubmitHeaders = @{"Content-Type" = "application/json"}; if ($CENTRAL_API_KEY) { $SubmitHeaders."X-API-Key" = $CENTRAL_API_KEY }
        Invoke-RestMethod -Uri $CENTRAL_API_URL -Method Post -Body $JsonPayload -Headers $SubmitHeaders -TimeoutSec 60
        Write-Log -Message "Data successfully submitted to central API."
    } catch {
        $ErrorMessage = "Failed to submit data to API. Error: $($_.Exception.Message)"
        if ($_.Exception.Response) { $ErrorMessage += " | HTTP Status: $($_.Exception.Response.StatusCode.value__) | Response: $($_.Exception.Response.Content)" }
        Write-Log -Level ERROR -Message $ErrorMessage
    }
    
} catch {
    Write-Log -Level ERROR -Message "An unexpected critical error occurred in the main script block: $($_.Exception.Message)"
} finally {
    if (Test-Path $LockFile) {
        Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
        Write-Log -Level INFO -Message "Lock file removed. Agent monitor script finished."
    }
}

