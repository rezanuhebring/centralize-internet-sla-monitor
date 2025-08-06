# Distributed Internet SLA Monitor

This project provides a distributed system to monitor internet connection SLAs from multiple locations (Linux and Windows agents), sending data to a central server for aggregated display, historical logging, charting, and alerting. The central server application is designed to be run in a Docker container.

## Architecture

*   **Central Server (Dockerized):** Hosts the main dashboard, a central SQLite database (via Docker volume), and API endpoints for agents. Apache and PHP run inside the Docker container.
*   **Agent Machines (Linux/Windows):** Run monitoring scripts, perform tests based on centrally managed (or local fallback) profiles, and submit data to the central server API. Agents fetch their specific monitoring thresholds and configurations from the central server.

## Features

*   **Multi-Agent Support:** Monitor multiple ISP connections or client locations.
*   **Cross-Platform Agents:** Includes a Bash agent for Linux and a PowerShell agent template for Windows.
*   **Centralized Dashboard:** Web interface on the central server to view:
    *   Overall SLA averages for predefined agent types (e.g., "ISP", "Client").
    *   A list of all reporting agents with summary information (name, type, last reported details).
    *   Detailed metrics, historical SLA percentages, and Chart.js line graphs (RTT, Jitter, Speedtest) for individual selected agents.
*   **Comprehensive Monitoring (per agent):**
    *   Ping: Round Trip Time (RTT), Packet Loss, Jitter.
    *   DNS Resolution Time.
    *   HTTP Accessibility.
    *   Speedtest: Download speed, Upload speed, Speedtest Ping, Speedtest Jitter (Speedtest on Windows agent requires manual integration of `speedtest.exe`).
*   **SQLite Database Logging:** A central SQLite database stores all historical metrics from all agents, with proper indexing and WAL mode enabled.
*   **Dynamic Agent Profiling:**
    *   Agents self-identify with a unique `AGENT_IDENTIFIER` and `AGENT_TYPE`.
    *   The central server auto-creates a profile for new agents using configurable default thresholds.
    *   Agents fetch their specific monitoring thresholds (RTT, loss, jitter, speed, etc.), Teams Webhook URL, and alert hostname override from their profile on the central server.
*   **External Configuration:**
    *   **Central Server:** `central_server_package/app/sla_config.env.template` for general settings (dashboard refresh, default new-agent thresholds). Actual running config is on the host volume.
    *   **Agents:** `agent_config.env.template` (Linux) / `agent_config.ps1.template` (Windows) for agent identity and central API URL.
*   **Teams Notifications:** Agents (via their fetched profile config) can trigger Teams notifications if their *locally calculated* historical SLA (based on thresholds fetched from central) drops below target.
*   **CSV Export:** The `monitor_internet.sh` script (if run on the central server for its own connection, or by an agent locally) generates a CSV of its *own* recent data. The dashboard download link currently points to a generic `historical_sla_data.csv` which would typically be from the central server's own monitoring if active. Per-agent CSV download from the dashboard would require a dedicated PHP endpoint.
*   **Automated Setup Scripts:**
    *   `central_server_package/setup_central_server.sh`: Sets up Docker, host directories, initial DB/config on host, and launches the Docker Compose setup for the central application.
    *   `linux_agent_package/setup_agent_linux.sh`: For installing Linux agents.
    *   `windows_agent_package/setup_agent_windows.ps1`: For basic setup of Windows agents.

## Directory Structure (for this GitHub Repo)

internet-sla-monitor/
├── .gitignore
├── README.md
├── central_server_package/
│ ├── setup_central_server.sh (Run on Docker Host to setup Central App)
│ ├── Dockerfile (Builds the Central App Docker image)
│ ├── docker-compose.yml (Runs the Central App container)
│ └── app/ (Application source code for Central App)
│ ├── sla_config.env (Template for central server's /opt/sla_monitor/sla_config.env on host volume)
│ ├── index.html (Main Dashboard)
│ ├── get_sla_stats.php (PHP: Provides data to dashboard)
│ └── api/ (API Endpoints)
│ ├── submit_metrics.php (PHP: Agents POST data here)
│ └── get_profile_config.php (PHP: Agents GET their config here)
├── linux_agent_package/
│ ├── setup_agent_linux.sh
│ ├── monitor_internet.sh (Agent script)
│ └── agent_config.env.template (Template for agent's /opt/sla_monitor/agent_config.env)
└── windows_agent_package/
├── setup_agent_windows.ps1
├── Monitor-InternetAgent.ps1 (Agent script)
└── agent_config.ps1.template (Template for agent's C:\SLA_Monitor_Agent\agent_config.ps1)


## Prerequisites

*   **Central Server Host:** Linux machine with `sudo` access. Docker and Docker Compose will be installed by the setup script if not present.
*   **Linux Agent:** Ubuntu/Debian-based system, `sudo` access. Dependencies (curl, jq, bc, ping, dig, sqlite3, speedtest) will be installed by its setup script.
*   **Windows Agent:** Windows machine with PowerShell 5.1+, Administrator access for setup. **Ookla's `speedtest.exe` must be manually installed and added to PATH, or its path specified in `Monitor-InternetAgent.ps1`.**

## Setup Instructions

**I. Central Dashboard Server**

1.  Clone this repository (or copy the `central_server_package` directory) to your designated central server machine.
2.  Navigate into the `central_server_package` directory: `cd internet-sla-monitor/central_server_package`
3.  The `app/sla_config.env` file in this package is a template. The setup script will copy this to `/srv/sla_monitor/central_app_data/opt_sla_monitor/sla_config.env` on the host if it doesn't exist. You will edit the version on the host volume *after* setup for persistent configuration.
4.  Make the setup script executable: `chmod +x setup_central_server.sh`
5.  Run the setup script: `sudo ./setup_central_server.sh`
    *   This installs Docker/Compose, creates host volume directories, initializes the central SQLite DB and config on the host volume, builds the Docker image, and starts the container.
6.  **Customize Central Config (on Host Volume):**
    After setup, edit `/srv/sla_monitor/central_app_data/opt_sla_monitor/sla_config.env` on the Docker host for general settings like default thresholds for new agents.
7.  **Manually Add/Edit Agent/ISP Profiles in Central Database:**
    The central database is located at `/srv/sla_monitor/central_app_data/opt_sla_monitor/central_sla_data.sqlite` on the Docker host.
    ```bash
    sudo sqlite3 /srv/sla_monitor/central_app_data/opt_sla_monitor/central_sla_data.sqlite
    ```
    Use SQL `INSERT` or `UPDATE` commands on the `isp_profiles` table. Each agent that will report needs a corresponding entry here. The `submit_metrics.php` script will **auto-create a basic profile** if an agent reports with an unknown `agent_identifier`, using defaults specified in the central `sla_config.env`. You can then edit these auto-created profiles.
    *Example to pre-define a profile:*
    ```sql
    INSERT INTO isp_profiles (
        agent_name, agent_identifier, agent_type, network_interface_to_monitor, 
        sla_target_percentage, 
        rtt_degraded, rtt_poor, loss_degraded, loss_poor, 
        ping_jitter_degraded, ping_jitter_poor,
        dns_time_degraded, dns_time_poor, 
        http_time_degraded, http_time_poor,
        speedtest_dl_degraded, speedtest_dl_poor, 
        speedtest_ul_degraded, speedtest_ul_poor,
        teams_webhook_url, alert_hostname_override, notes, is_active
    ) VALUES (
        'Branch Office - WAN1', 'branch01_wan1_agent', 'ISP', 'eth1', 
        99.0, 
        150, 350, 2, 10, 
        30, 50,
        300, 800, 
        1.0, 2.5,
        60, 30, 
        20, 5, 
        'YOUR_TEAMS_URL_FOR_THIS_AGENT', 'BranchRouter', 'Primary connection for Branch Office.', 1
    );
    .quit
    ```
8.  **Firewall:** Ensure your host firewall allows port 80 (and 443 if you set up HTTPS via a reverse proxy).
9.  **Access Dashboard:** `http://<central_server_ip>/` (or your configured domain if using a reverse proxy).

**II. Linux Agent Machine**

1.  Copy the `linux_agent_package` directory (containing `setup_agent_linux.sh`, `monitor_internet.sh`, `agent_config.env.template`) to the Linux agent machine.
2.  Navigate into `linux_agent_package`.
3.  Copy `agent_config.env.template` to `agent_config.env`.
4.  **Edit `agent_config.env`:**
    *   Set `AGENT_IDENTIFIER` to a unique ID for this agent. This ID will be used by the central server to identify this agent and store its data. If this agent isn't pre-defined in the central DB, a profile will be auto-created using this identifier.
    *   Set `AGENT_TYPE` (e.g., "ISP" or "Client").
    *   Set `CENTRAL_API_URL` to `http://<central_server_ip>/api/submit_metrics.php` (replace `<central_server_ip>` with the actual IP or hostname of your central server).
    *   (Optional) Set `NETWORK_INTERFACE_TO_MONITOR` if this agent should use a specific network card for tests.
    *   (Optional) Set `CENTRAL_API_KEY` if you implement API key security on the central server.
5.  Make setup script executable: `chmod +x setup_agent_linux.sh`
6.  Run setup script: `sudo ./setup_agent_linux.sh`

**III. Windows Agent Machine**

1.  Copy the `windows_agent_package` directory to the Windows machine.
2.  Navigate into `windows_agent_package` using PowerShell.
3.  Copy `agent_config.ps1.template` to `agent_config.ps1`.
4.  **Edit `agent_config.ps1`:**
    *   Set `$AgentConfig.AGENT_IDENTIFIER`.
    *   Set `$AgentConfig.AGENT_TYPE`.
    *   Set `$AgentConfig.CENTRAL_API_URL`.
    *   (Optional) Set `$AgentConfig.NETWORK_INTERFACE_TO_MONITOR`.
    *   (Optional) Set `$AgentConfig.CENTRAL_API_KEY`.
5.  **Manually install Ookla's `speedtest.exe`** from their official website. Ensure it's in your system PATH or update the path explicitly in `Monitor-InternetAgent.ps1`. Run `speedtest.exe --accept-license --accept-gdpr` once from a command prompt or PowerShell.
6.  **Implement/Verify Speedtest Logic:** The `Monitor-InternetAgent.ps1` has a placeholder for calling `speedtest.exe`. You will need to uncomment and adapt the example code in that script to correctly execute `speedtest.exe --format=json` (or the equivalent for JSON output from your `speedtest.exe` version) and parse its output.
7.  Run the setup script from an **Administrator PowerShell**: `.\setup_agent_windows.ps1`

## Security Notes

*   **HTTPS for Dashboard/API:** Strongly recommended for the central server. Use a reverse proxy (Nginx, Traefik, Caddy) in front of the Docker container to handle SSL termination and certificates (e.g., from Let's Encrypt).
*   **API Key Authentication:** The provided PHP API scripts have comments indicating where API key checks should be implemented. This is a critical security step for production to ensure only authorized agents can submit data or fetch configurations.
*   Review and harden Apache and PHP configurations (e.g., `php.ini` settings like `display_errors = Off` for production) inside the Docker image if necessary, or by mounting custom config files.
*   Ensure firewall rules on the central server are restrictive, only allowing necessary ports (e.g., 80/443 for web, SSH).

## Troubleshooting

### Central Server Issues
*   **Docker Container Not Running:** Check the status with `sudo docker ps -a`. If the `sla_monitor_central_app` container is `Exited`, check its logs for errors: `sudo docker logs sla_monitor_central_app`.
*   **Dashboard Not Loading:**
    *   Ensure the container is running.
    *   Check host firewall rules to ensure port 80 (or your custom port) is allowed.
    *   Look for errors in the Apache error log on the host: `/srv/sla_monitor/central_app_data/apache_logs/error.log`.
*   **API Errors:**
    *   Check the central API log on the host: `/srv/sla_monitor/central_app_data/api_logs/sla_api.log`.
    *   Access PHP API endpoints directly in a browser or with `curl` for debugging JSON output or errors.
        *   `http://<central_server_ip>/api/get_profile_config.php?agent_id=<YOUR_AGENT_ID>`
        *   This should return the JSON profile for the agent or an error message.

### Agent Troubleshooting

**General Agent Issues:**
*   **Data Not Appearing on Dashboard:**
    1.  **Check Agent Logs First:** This is the most important step.
        *   **Linux:** `tail -f /var/log/internet_sla_monitor_agent.log`
        *   **Windows:** `Get-Content "C:\SLA_Monitor_Agent\internet_monitor_agent_windows.log" -Tail 10 -Wait`
    2.  **Look for "Failed to submit data" errors.** This usually points to a network issue or a problem with the `CENTRAL_API_URL`.
    3.  **Verify `CENTRAL_API_URL`:** Make sure the IP address or hostname is correct and that the agent machine can reach it. Use `ping <central_server_ip>` or `curl http://<central_server_ip>/api/submit_metrics.php` from the agent machine.
    4.  **Check `AGENT_IDENTIFIER`:** Ensure the `AGENT_IDENTIFIER` in the agent's config file matches exactly with an entry in the `isp_profiles` table on the central server. Remember that identifiers are case-sensitive.

**Windows Agent Specific Issues:**
*   **Script Fails to Run:**
    *   **Execution Policy:** PowerShell's execution policy might prevent the script from running. The scheduled task created by the setup script uses `-ExecutionPolicy Bypass`, but if you run it manually, you might need to open an Administrator PowerShell and run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` first.
    *   **Permissions:** Ensure the `C:\SLA_Monitor_Agent` directory and its contents are readable by the `SYSTEM` account, as that's what the scheduled task runs as.
*   **"Speedtest not found" or "FAILED_EXEC" in logs:**
    *   The `setup_agent_windows.ps1` script automatically installs Speedtest to `C:\SLA_Monitor_Agent\speedtest`.
    *   Verify that `speedtest.exe` exists in that directory.
    *   Check the `agent_config.ps1` file and ensure the `$SPEEDTEST_EXE_PATH` variable is set correctly. The setup script should do this automatically.
    *   Run `speedtest.exe` manually from a command prompt to ensure it works and that the license has been accepted.
*   **Scheduled Task Not Running:**
    *   Open "Task Scheduler" and find the "InternetSLAMonitorAgent" task.
    *   Check the "History" tab for any errors.
    *   Verify the task is configured to run as `NT AUTHORITY\SYSTEM` and that "Run with highest privileges" is checked.

**Linux Agent Specific Issues:**
*   **`jq: command not found` or other dependency errors:**
    *   Re-run the setup script `sudo ./setup_agent_linux.sh`. It is designed to install all necessary dependencies.
    *   If it fails, install them manually: `sudo apt-get update && sudo apt-get install -y curl jq bc dnsutils inetutils-ping sqlite3 speedtest-cli`.
*   **Permission Denied errors in log:**
    *   Ensure the agent was set up using `sudo`. The log file and configuration need correct ownership.
    *   Check permissions on `/opt/sla_monitor` and `/var/log/internet_sla_monitor_agent.log`. The user running the cron job (typically root) must have write access.
*   **Cron Job Not Running:**
    *   Check that the cron job exists: `sudo crontab -l`. You should see an entry for `monitor_internet.sh`.
    *   Check the system's cron logs (e.g., `/var/log/syslog` or `/var/log/cron.log`) for any errors related to the script execution.
