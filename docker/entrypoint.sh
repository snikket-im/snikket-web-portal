#!/bin/sh

if [ -z "$SNIKKET_DOMAIN" ]; then
  echo "Please provide SNIKKET_DOMAIN";
  exit 1;
fi

if [ -z "$PROSODY_ENDPOINT" ]; then
  echo "Please provide PROSODY_ENDPOINT";
  exit 1;
fi

if [ -z "$SECRET_KEY" ]; then
  echo "Please provide SECRET_KEY";
fi

exec hypercorn -b "0.0.0.0:8000" snikket_web:app
