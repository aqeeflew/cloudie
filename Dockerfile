# Cloudie PHP frontend — Cloud Run image
# Apache + PHP 8.3 with pdo_mysql, gd, zip, plus google/cloud-storage via Composer.
FROM php:8.3-apache

# ---- System packages needed to build PHP extensions ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        libzip-dev \
        libpng-dev \
        libonig-dev \
        unzip \
        git \
    && docker-php-ext-install pdo_mysql zip gd \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---- Composer (from the official Composer image) ----
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# ---- Recommended PHP production settings ----
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
# Allow uploads up to our app limit (50MB) + headroom
RUN { \
        echo "upload_max_filesize = 60M"; \
        echo "post_max_size = 60M"; \
        echo "memory_limit = 256M"; \
        echo "pdo_mysql.default_socket = /cloudsql/cloudie-499914:asia-southeast1:cloudie-db"; \
        echo "mysqli.default_socket = /cloudsql/cloudie-499914:asia-southeast1:cloudie-db"; \
    } > "$PHP_INI_DIR/conf.d/cloudie.ini"

# Enable mod_rewrite (handy if you add pretty URLs later)
RUN a2enmod rewrite

WORKDIR /var/www/html

# Install PHP dependencies first (better build caching)
COPY composer.json ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader

# Copy the application (page files + includes/)
COPY . .

# Cloud Run provides $PORT (default 8080). Apache must listen on it.
# We substitute it at container start so it works whatever PORT is set to.
RUN printf '#!/bin/sh\nset -e\nsed -i "s/Listen 80\$/Listen ${PORT:-8080}/" /etc/apache2/ports.conf\nsed -i "s/:80>/:${PORT:-8080}>/" /etc/apache2/sites-available/000-default.conf\nexec apache2-foreground\n' > /usr/local/bin/cloudie-start \
    && chmod +x /usr/local/bin/cloudie-start

CMD ["cloudie-start"]