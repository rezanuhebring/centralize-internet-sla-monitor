# =========================================================================
# STAGE 1: Builder
# This stage installs build-time dependencies and compiles the PHP extensions.
# These dependencies will NOT be included in the final image.
# =========================================================================
FROM php:8.2-apache AS builder

LABEL stage="builder"

ENV DEBIAN_FRONTEND=noninteractive

# Install system libraries required to build the PHP extensions.
# We only need the '-dev' packages here.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For pdo_sqlite
    libsqlite3-dev \
    # For zip
    libzip-dev \
    zlib1g-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Compile the required PHP extensions.
# We do NOT need the 'sqlite3' extension, as 'pdo_sqlite' provides the
# necessary functionality for interacting with SQLite databases via PDO.
RUN docker-php-ext-install -j$(nproc) \
    pdo \
    pdo_sqlite \
    zip

# The compiled .so files are now available to be copied to the next stage.

# =========================================================================
# STAGE 2: Final Production Image
# This stage builds the final, lean image. It copies the compiled extensions
# from the 'builder' stage and installs only runtime dependencies.
# =========================================================================
FROM php:8.2-apache

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime system dependencies and common tools in a single layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Runtime library for pdo_sqlite/sqlite3
    sqlite3 \
    # Common CLI tools
    curl \
    jq \
    bc \
    git \
    iputils-ping \
    dnsutils \
    procps \
    nano \
    less \
    # Dependencies for Ookla Speedtest CLI
    ca-certificates \
    gnupg \
    && \
    # --- Install Ookla Speedtest CLI ---
    echo "----> Installing Ookla Speedtest CLI..." && \
    curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash && \
    apt-get install -y speedtest && \
    # --- Final Cleanup ---
    echo "----> Cleaning up apt cache..." && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy the compiled PHP extensions from the 'builder' stage.
COPY --from=builder /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/

# Enable the copied extensions in php.ini.
RUN docker-php-ext-enable pdo pdo_sqlite zip

# Enable common Apache modules.
RUN a2enmod rewrite headers ssl expires

# --- Application Setup ---

# Create a directory for your custom Apache config.
# You will need to create this file locally.
# Example: ./docker/apache/000-default.conf
COPY ./docker/apache/000-default.conf /etc/apache2/sites-available/000-default.conf

# Set the web root as the working directory.
WORKDIR /var/www/html

# Copy your application files.
COPY ./app/ .

# Set correct ownership and permissions for the web root.
RUN chown -R www-data:www-data /var/www/html && \
    find /var/www/html -type d -exec chmod 755 {} \;
    find /var/www/html -type f -exec chmod 644 {} \;

# Expose HTTP and HTTPS ports.
EXPOSE 80
EXPOSE 443

# Healthcheck to ensure the web server is responsive.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD curl -f http://localhost/index.html || exit 1