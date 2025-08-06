#!/bin/bash
# setup.sh - UNIFIED FINAL PRODUCTION SCRIPT
# Handles both fresh installs and data-preserving migration, and now
# includes secure API key generation for agent authentication.

# --- Configuration Variables ---
APP_SOURCE_SUBDIR="app"
PROJECT_DIR=$(pwd)

# Service Names
APP_SERVICE_NAME="sla_monitor_central_app"
NGINX_SERVICE_NAME="nginx"

# Host Data Paths
HOST_DATA_ROOT="/srv/sla_monitor/central_app_data"
HOST_OPT_SLA_MONITOR_DIR="${HOST_DATA_ROOT}/opt_sla_monitor"
HOST_API_LOGS_DIR="${HOST_DATA_ROOT}/api_logs"
HOST_APACHE_LOGS_DIR="${HOST_DATA_ROOT}/apache_logs"
HOST_CERTBOT_WEBROOT_DIR="${HOST_DATA_ROOT}/certbot-webroot"

# Project File Names
DOCKER_COMPOSE_FILE_NAME="docker-compose.yml"
DOCKERFILE_NAME="Dockerfile"
APACHE_CONFIG_DIR="docker/apache"
APACHE_CONFIG_FILE="000-default.conf"
NGINX_CONFIG_DIR="nginx/conf"
NGINX_CONFIG_FILE="default.conf"
SQLITE_DB_FILE_NAME="central_sla_data.sqlite"
SQLITE_DB_FILE_HOST_PATH="${HOST_OPT_SLA_MONITOR_DIR}/${SQLITE_DB_FILE_NAME}"
SLA_CONFIG_TEMPLATE_NAME="sla_config.env.template"
SLA_CONFIG_HOST_PATH="${HOST_OPT_SLA_MONITOR_DIR}/sla_config.env"

# --- Helper Functions ---
print_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
print_warn() { echo -e "\033[0;33m[WARN]\033[0m $1"; }
print_error() { echo -e "\033[0;31m[ERROR]\033[0m $1" >&2; }
print_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
print_highlight() { echo -e "\033[1;33m$1\033[0m"; }

# --- Main Setup Logic ---
clear
print_info "Starting UNIFIED Internet SLA Monitor Setup..."
if [ "$(id -u)" -ne 0 ]; then print_error "This script must be run with sudo: sudo $0"; exit 1; fi

# --- Step 0: Detect Mode (Fresh Install vs. Migration) ---
MIGRATION_MODE=false
if [ -d "${HOST_DATA_ROOT}" ]; then
    print_warn "Existing data found at ${HOST_DATA_ROOT}".
    print_warn "Entering MIGRATION mode. Your data will be preserved."
    MIGRATION_MODE=true
    
    if [ "$(docker ps -q -f name=^/${APP_SERVICE_NAME}$\)" ]; then
        print_info "Stopping the old running container..."
        if [ -f "${DOCKER_COMPOSE_FILE_NAME}" ]; then
             sudo docker-compose down
        else
             sudo docker stop "${APP_SERVICE_NAME}" && sudo docker rm "${APP_SERVICE_NAME}"
        fi
        print_info "Old container stopped."
    fi
else
    print_info "No existing data found. Proceeding with a FRESH INSTALLATION."
fi

# --- Step 1: Gather User Input for Secure Setup ---
print_info "This script will configure a secure setup using Nginx and Let's Encrypt."
read -p "Enter the domain name that points to this server (e.g., host.domain.com): " DOMAIN_NAME
if [ -z "$DOMAIN_NAME" ]; then print_error "Domain name cannot be empty. Aborting."; exit 1; fi

read -p "Enter your email address (for Let's Encrypt renewal notices): " EMAIL_ADDRESS
if [ -z "$EMAIL_ADDRESS" ]; then print_error "Email address cannot be empty. Aborting."; exit 1; fi

# --- Step 1b: Gather Dashboard Credentials ---
print_info "Please set up the credentials for the dashboard login."
read -p "Enter a username for the dashboard [admin]: " DASHBOARD_USERNAME
DASHBOARD_USERNAME=${DASHBOARD_USERNAME:-admin}
while true; do
    read -s -p "Enter a password for the dashboard: " DASHBOARD_PASSWORD
    echo
    read -s -p "Confirm the password: " DASHBOARD_PASSWORD_CONFIRM
    echo
    if [ "$DASHBOARD_PASSWORD" = "$DASHBOARD_PASSWORD_CONFIRM" ] && [ -n "$DASHBOARD_PASSWORD" ]; then
        break
    else
        print_error "Passwords do not match or are empty. Please try again."
    fi
done

# --- Step 2: Install System Dependencies ---
print_info "Updating package lists and checking dependencies..."
sudo apt-get update -y || { print_error "Apt update failed."; exit 1; }

# Install Docker, Docker Compose, Certbot, SQLite3
# Install Docker, Docker Compose, Certbot, SQLite3
if ! command -v docker &> /dev/null; then
    print_info "Installing Docker..."
    (
        sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common jq &&
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add - &&
        sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" -y &&
        sudo apt-get update -y &&
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io &&
        sudo systemctl start docker && sudo systemctl enable docker
    ) || { print_error "Docker installation failed"; exit 1; }
else
    print_info "Docker is already installed."
fi

if ! command -v docker-compose &> /dev/null; then
    print_info "Installing Docker Compose..."
    (
        LATEST_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r .tag_name)
        [ -z "$LATEST_COMPOSE_VERSION" ] && LATEST_COMPOSE_VERSION="v2.24.6"
        sudo curl -L "https://github.com/docker/compose/releases/download/${LATEST_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose &&
        sudo chmod +x /usr/local/bin/docker-compose
    ) || { print_error "Docker Compose download failed"; exit 1; }
else
    print_info "Docker Compose is already installed."
fi

if ! command -v certbot &> /dev/null || ! command -v sqlite3 &> /dev/null; then
    print_info "Installing Certbot and SQLite3..."
    sudo apt-get install -y certbot sqlite3 php-cli
else
    print_info "Certbot, SQLite3, and PHP CLI are already installed."
fi


# --- Step 3: Create Directories and Docker Files ---
print_info "Creating host directories and Docker configurations..."
sudo mkdir -p "${HOST_OPT_SLA_MONITOR_DIR}" "${HOST_API_LOGS_DIR}" "${HOST_APACHE_LOGS_DIR}" "${HOST_CERTBOT_WEBROOT_DIR}"
sudo touch "${HOST_API_LOGS_DIR}/sla_api.log"
mkdir -p "${APACHE_CONFIG_DIR}" "${NGINX_CONFIG_DIR}"

# Create Dockerfile, Apache Config, Docker Compose (no changes needed to these files)
tee "./${DOCKERFILE_NAME}" > /dev/null <<'EOF_DOCKERFILE'
FROM php:8.2-apache
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-dev libzip-dev zlib1g-dev sqlite3 curl jq bc git iputils-ping dnsutils && \
    docker-php-ext-install -j$(nproc) pdo pdo_sqlite zip && \
    a2enmod rewrite && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY ./docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf
WORKDIR /var/www/html
COPY ./app/ .
RUN chown -R www-data:www-data /var/www/html && chmod -R 755 /var/www/html
EXPOSE 80
EOF_DOCKERFILE
tee "./${APACHE_CONFIG_DIR}/${APACHE_CONFIG_FILE}" > /dev/null <<'EOF_APACHE_CONF'
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF_APACHE_CONF
tee "./${DOCKER_COMPOSE_FILE_NAME}" > /dev/null <<EOF_DOCKER_COMPOSE
version: '3.8'
services:
  ${APP_SERVICE_NAME}:
    build: { context: ., dockerfile: ${DOCKERFILE_NAME} }
    container_name: ${APP_SERVICE_NAME}
    restart: unless-stopped
    volumes:
      - ${HOST_OPT_SLA_MONITOR_DIR}:/opt/sla_monitor
      - ${HOST_API_LOGS_DIR}/sla_api.log:/var/log/sla_api.log
      - ${HOST_APACHE_LOGS_DIR}:/var/log/apache2
    environment: { APACHE_LOG_DIR: /var/log/apache2 }
    networks: [sla-monitor-network]
  ${NGINX_SERVICE_NAME}:
    image: nginx:latest
    container_name: ${NGINX_SERVICE_NAME}
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    volumes:
      - ./nginx/conf:/etc/nginx/conf.d
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - ${HOST_CERTBOT_WEBROOT_DIR}:/var/www/certbot
    depends_on: [${APP_SERVICE_NAME}]
    networks: [sla-monitor-network]
networks:
  sla-monitor-network:
    driver: bridge
EOF_DOCKER_COMPOSE

# --- Step 4: Phased Certificate Acquisition ---
print_info "Starting Phase 1: Acquiring SSL Certificate..."
tee "./${NGINX_CONFIG_DIR}/${NGINX_CONFIG_FILE}" > /dev/null <<EOF_NGINX_TEMP
server { listen 80; server_name ${DOMAIN_NAME}; location /.well-known/acme-challenge/ { root /var/www/certbot; } location / { return 404; } }
EOF_NGINX_TEMP
sudo docker-compose up -d ${NGINX_SERVICE_NAME}
if [ $? -ne 0 ]; then print_error "Failed to start temporary Nginx. Aborting."; exit 1; fi
sudo certbot certonly --webroot -w "${HOST_CERTBOT_WEBROOT_DIR}" -d "${DOMAIN_NAME}" --email "${EMAIL_ADDRESS}" --agree-tos --no-eff-email --force-renewal
if [ $? -ne 0 ]; then print_error "Certbot failed. Check DNS and firewall."; sudo docker-compose down; exit 1; fi
print_success "Certificate obtained successfully!"
sudo docker-compose down

# --- Step 5: Final Configuration and Launch ---
print_info "Starting Phase 2: Deploying final secure configuration..."
tee "./${NGINX_CONFIG_DIR}/${NGINX_CONFIG_FILE}" > /dev/null <<EOF_NGINX_FINAL
server { listen 80; server_name ${DOMAIN_NAME}; location /.well-known/acme-challenge/ { root /var/www/certbot; } location / { return 301 https://\$host\$request_uri; } }
server {
    listen 443 ssl http2; server_name ${DOMAIN_NAME};
    ssl_certificate /etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
    location / {
        proxy_pass http://${APP_SERVICE_NAME}:80;
        proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF_NGINX_FINAL
if [ ! -f /etc/letsencrypt/options-ssl-nginx.conf ]; then sudo curl -s https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf > ./options-ssl-nginx.conf; sudo mv ./options-ssl-nginx.conf /etc/letsencrypt/; fi
if [ ! -f /etc/letsencrypt/ssl-dhparams.pem ]; then sudo openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048; fi

# --- Step 6: Database, Config, and API Key Generation ---
API_KEY=""
if [ "${MIGRATION_MODE}" = false ]; then
    print_info "Initializing database and configuration for new installation..."
    sudo touch "${SQLITE_DB_FILE_HOST_PATH}"
    sudo sqlite3 "${SQLITE_DB_FILE_HOST_PATH}" "
        PRAGMA journal_mode=WAL;
        CREATE TABLE isp_profiles(id INTEGER PRIMARY KEY, agent_name TEXT NOT NULL, agent_identifier TEXT NOT NULL UNIQUE, agent_type TEXT DEFAULT 'Client', network_interface_to_monitor TEXT, sla_target_percentage REAL DEFAULT 99.9, rtt_degraded INTEGER DEFAULT 150, rtt_poor INTEGER DEFAULT 350, loss_degraded REAL DEFAULT 2, loss_poor REAL DEFAULT 10, ping_jitter_degraded REAL DEFAULT 30, ping_jitter_poor REAL DEFAULT 50, dns_time_degraded INTEGER DEFAULT 300, dns_time_poor INTEGER DEFAULT 800, http_time_degraded REAL DEFAULT 1.5, http_time_poor REAL DEFAULT 3.0, speedtest_dl_degraded REAL DEFAULT 50, speedtest_dl_poor REAL DEFAULT 20, speedtest_ul_degraded REAL DEFAULT 10, speedtest_ul_poor REAL DEFAULT 3, teams_webhook_url TEXT, alert_hostname_override TEXT, notes TEXT, is_active INTEGER DEFAULT 1, last_heard_from TEXT, last_reported_hostname TEXT, last_reported_source_ip TEXT);
        CREATE TABLE sla_metrics(
            id INTEGER PRIMARY KEY,
            isp_profile_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            overall_connectivity TEXT,
            avg_rtt_ms REAL,
            avg_loss_percent REAL,
            avg_jitter_ms REAL,
            dns_status TEXT,
            dns_resolve_time_ms INTEGER,
            http_status TEXT,
            http_response_code INTEGER,
            http_total_time_s REAL,
            speedtest_status TEXT,
            speedtest_download_mbps REAL,
            speedtest_upload_mbps REAL,
            speedtest_ping_ms REAL,
            speedtest_jitter_ms REAL,
            wifi_status TEXT,
            wifi_ssid TEXT,
            wifi_bssid TEXT,
            wifi_signal_strength_percent INTEGER,
            wifi_channel INTEGER,
            wifi_band TEXT,
            detailed_health_summary TEXT,
            sla_met_interval INTEGER,
            FOREIGN KEY (isp_profile_id) REFERENCES isp_profiles(id) ON DELETE CASCADE,
            UNIQUE(isp_profile_id, timestamp)
        );
        CREATE INDEX IF NOT EXISTS idx_isp_profiles_agent_identifier ON isp_profiles (agent_identifier);
        CREATE INDEX IF NOT EXISTS idx_sla_metrics_timestamp ON sla_metrics (timestamp);
        CREATE INDEX IF NOT EXISTS idx_sla_metrics_isp_profile_id ON sla_metrics (isp_profile_id);
    "
    
    API_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    PASSWORD_HASH=$(php -r "echo password_hash('$DASHBOARD_PASSWORD', PASSWORD_DEFAULT);")
    print_info "Generating new configuration file..."
    sudo cp "./${APP_SOURCE_SUBDIR}/${SLA_CONFIG_TEMPLATE_NAME}" "${SLA_CONFIG_HOST_PATH}"
    sudo sed -i "s/CENTRAL_API_KEY=.*/CENTRAL_API_KEY=${API_KEY}/" "${SLA_CONFIG_HOST_PATH}"
    echo "DASHBOARD_USERNAME=${DASHBOARD_USERNAME}" | sudo tee -a "${SLA_CONFIG_HOST_PATH}" > /dev/null
    echo "DASHBOARD_PASSWORD_HASH=${PASSWORD_HASH}" | sudo tee -a "${SLA_CONFIG_HOST_PATH}" > /dev/null

else
    print_info "Existing database found. Checking for schema updates..."
    COLUMNS_EXIST=$(sudo sqlite3 "${SQLITE_DB_FILE_HOST_PATH}" "SELECT count(*) FROM pragma_table_info('sla_metrics') WHERE name IN ('wifi_status', 'wifi_ssid');")
    if [ "$COLUMNS_EXIST" -eq 0 ]; then
        print_info "Adding new Wi-Fi monitoring columns to the sla_metrics table..."
        sudo sqlite3 "${SQLITE_DB_FILE_HOST_PATH}" "ALTER TABLE sla_metrics ADD COLUMN wifi_status TEXT; ALTER TABLE sla_metrics ADD COLUMN wifi_ssid TEXT; ALTER TABLE sla_metrics ADD COLUMN wifi_bssid TEXT; ALTER TABLE sla_metrics ADD COLUMN wifi_signal_strength_percent INTEGER; ALTER TABLE sla_metrics ADD COLUMN wifi_channel INTEGER; ALTER TABLE sla_metrics ADD COLUMN wifi_band TEXT;"
    else
        print_info "Wi-Fi columns already exist. No schema changes needed."
    fi

    if [ -f "${SLA_CONFIG_HOST_PATH}" ]; then
        API_KEY=$(grep "^CENTRAL_API_KEY=" "${SLA_CONFIG_HOST_PATH}" | cut -d'=' -f2)
        if [ -z "$API_KEY" ]; then
            print_warn "API Key not found in existing config. Generating a new one."
            API_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
            sudo echo -e "\nCENTRAL_API_KEY=${API_KEY}" >> "${SLA_CONFIG_HOST_PATH}"
        fi
        if ! grep -q "^DASHBOARD_USERNAME=" "${SLA_CONFIG_HOST_PATH}"; then
            print_warn "Dashboard credentials not found. Adding them now."
            PASSWORD_HASH=$(php -r "echo password_hash('$DASHBOARD_PASSWORD', PASSWORD_DEFAULT);")
            echo "DASHBOARD_USERNAME=${DASHBOARD_USERNAME}" | sudo tee -a "${SLA_CONFIG_HOST_PATH}" > /dev/null
            echo "DASHBOARD_PASSWORD_HASH=${PASSWORD_HASH}" | sudo tee -a "${SLA_CONFIG_HOST_PATH}" > /dev/null
        fi
    else
        print_warn "Config file not found! Creating one with a new API key and credentials."
        API_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
        PASSWORD_HASH=$(php -r "echo password_hash('$DASHBOARD_PASSWORD', PASSWORD_DEFAULT);")
        sudo cp "./${APP_SOURCE_SUBDIR}/${SLA_CONFIG_TEMPLATE_NAME}" "${SLA_CONFIG_HOST_PATH}"
        sudo sed -i "s/CENTRAL_API_KEY=.*/CENTRAL_API_KEY=${API_KEY}/" "${SLA_CONFIG_HOST_PATH}"
        echo "DASHBOARD_USERNAME=${DASHBOARD_USERNAME}" | sudo tee -a "${SLA_CONFIG_HOST_PATH}" > /dev/null
        echo "DASHBOARD_PASSWORD_HASH=${PASSWORD_HASH}" | sudo tee -a "${SLA_CONFIG_HOST_PATH}" > /dev/null
    fi
fi


print_info "Setting final data permissions..."
sudo chown -R root:www-data "${HOST_DATA_ROOT}"
sudo chmod -R 770 "${HOST_DATA_ROOT}"
sudo chmod 660 "${HOST_API_LOGS_DIR}/sla_api.log"
sudo chmod 660 "${SQLITE_DB_FILE_HOST_PATH}"
sudo chmod 660 "${SLA_CONFIG_HOST_PATH}"

# --- Step 7: Build and Launch Final Stack ---
print_info "Building and starting the final, secure application stack..."
sudo docker-compose up --build -d
if [ $? -eq 0 ]; then
    print_success "Deployment complete!"
    sudo docker-compose ps
    echo
    print_info "--------------------------------------------------------------------"
    print_success "Dashboard available at: https://${DOMAIN_NAME}"
    print_warn "Login with username '${DASHBOARD_USERNAME}' and the password you provided."
    print_warn "Your agents must use the following API Key in their configuration:"
    print_highlight "API Key: ${API_KEY}"
    print_info "--------------------------------------------------------------------"
else
    print_error "Failed to start the final Docker stack. Check logs using:"
    print_error "sudo docker-compose logs ${APP_SERVICE_NAME}"
    print_error "sudo docker-compose logs ${NGINX_SERVICE_NAME}"
    exit 1
fi