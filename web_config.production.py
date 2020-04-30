# REQUIRED SETTINGS
# =================

# Secret key used to guard forms and sessions.
#
# This must be both reasonably constant and secret. If the secret gets
# compromised, you can change it (without having to worry about the "constant"
# requirement).
#
# if not constant:
# - sessions will be lost on each server restart
#
# if not secret:
# - users may be able to forge sessions
# - attackers may be able to execute things on a properly authenticated user’s
#   behalf.
# - other bad things.
import os
import sys
import secrets

try:
    SECRET_KEY = os.environ['SECRET_KEY']
except KeyError:
    print('SECRET_KEY was not provided. It will be automatically generated. '
          'To avoid losing sessions on each server restart, please provide '
          'a SECRET_KEY.',
          file=sys.stderr)

SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(nbytes=32))

# URL (without trailing /) of the prosody HTTP server.
#
# This must be set for anything to work correctly.
#
# NOTE: If this does not point at localhost, it MUST use https. Otherwise,
# passwords will be transmitted in plaintext through insecure channels.
try:
    PROSODY_ENDPOINT = os.environ['PROSODY_ENDPOINT']
except KeyError as e:
    print(f'Environment variable {e} must be set for the web portal to work',
          file=sys.stderr)
    sys.exit(2)

# The domain name of the Snikket server
#
# This must be set for login to work correctly.
try:
    SNIKKET_DOMAIN = os.environ['SNIKKET_DOMAIN']
except KeyError as e:
    print(f'Environment variable {e} must be set for the web portal to work',
          file=sys.stderr)
    sys.exit(2)


# OPTIONAL SETTINGS
# =================

# How long browers may cache avatars
#
# Setting this to zero forces browsers to check if their locally cached copy
# of an avatar is still up-to-date on every request; if it is, the avatar is
# not re-transferred.
#
# AVATAR_CACHE_TTL = 1800

# Which languages to offer
#
# Generally, the web portal will offer all languages it has available. There
# is little point in restricting this, unless if you’re in a situation where
# the release you’re on has a terrible translation of a specific language
# and not offering that language at all is better than having that terrible
# translation.
#
# LANGUAGES = ["de", "en"]
