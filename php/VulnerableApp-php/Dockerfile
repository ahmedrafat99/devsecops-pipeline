FROM php:8.2-apache-bookworm
LABEL maintainer="KSASAN preetkaran20@gmail.com"

RUN a2enmod rewrite

COPY src/ /var/www/html/VulnerableApp-php/
COPY static/ /var/www/html/VulnerableApp-php/
COPY resources/ /var/www/html/VulnerableApp-php/resources
COPY vulnerablehtaccess/ /var/www/html/VulnerableApp-php/images/specialimages

RUN chmod -R 777 /var/www/html/

EXPOSE 80