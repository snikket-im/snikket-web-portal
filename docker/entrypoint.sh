#!/bin/sh

export SNIKKET_WEB_DOMAIN="$SNIKKET_DOMAIN"

exec hypercorn -b "0.0.0.0:8000" 'snikket_web:create_app()'
