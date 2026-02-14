FROM php:7.4-fpm-bullseye AS base

WORKDIR /var/www/html

RUN apt-get update && apt-get install -y --no-install-recommends \
    mariadb-client \
    zlib1g-dev \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libxpm-dev \
    libmagickwand-dev \
    zip \
    libzip-dev \
    vim \
    netcat-openbsd \
    iputils-ping \
    wget \
    python3 \
    cron \
    && docker-php-ext-configure gd \
		--with-freetype \
		--with-jpeg \
		--with-xpm \
    && docker-php-ext-install pdo_mysql zip gd soap \
    && pecl install imagick \
    && docker-php-ext-enable imagick \
    && rm -rf /var/lib/apt/lists/*

COPY . /var/www/html

# Setup Laravel scheduler to run as root for privesc demonstration
RUN echo '* * * * * root cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1' >> /etc/crontab

RUN chown -R www-data:www-data /var/www/html/
RUN find /var/www/html/ -type d -exec chmod 755 {} \;
RUN find /var/www/html/ -type f -exec chmod 644 {} \;
RUN chgrp -R www-data /var/www/html/storage /var/www/html/public/uploads /var/www/html/bootstrap/cache
RUN chmod -R ug+rwx /var/www/html/storage /var/www/html/public/uploads /var/www/html/bootstrap/cache

CMD service cron start && php-fpm
