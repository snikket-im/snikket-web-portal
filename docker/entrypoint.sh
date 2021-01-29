#!/bin/sh

export SNIKKET_WEB_DOMAIN="$SNIKKET_DOMAIN"

exec hypercorn -b "127.0.0.1:5765" 'snikket_web:create_app()'
