# Please see example.env for a detailed list of supported environment
# variables as well as their semantics.

# NOTE: this file is not meant for production use. Due to the non-constant
# secret key, each server restart will log out all users from the web portal.

import secrets
SNIKKET_WEB_SECRET_KEY = secrets.token_urlsafe(nbytes=32)
SNIKKET_WEB_PROSODY_ENDPOINT = "http://localhost:5280"
SNIKKET_WEB_DOMAIN = "localhost"
# SNIKKET_WEB_AVATAR_CACHE_TTL = 1800
