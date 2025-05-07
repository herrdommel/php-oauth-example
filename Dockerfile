FROM php:7.4.33-apache

# Copy app files from the app directory.
COPY ./src /var/www/html

# Switch to a non-privileged user (defined in the base image) that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/
USER www-data

# Expose changed port
#EXPOSE 80
