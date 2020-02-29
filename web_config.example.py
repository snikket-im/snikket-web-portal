import secrets

# NOTE: change this to a constant, but secret value. 
# if not constant:
# - sessions will be lost on each server restart
# if not secret:
# - users may be able to forge sessions
SECRET_KEY = secrets.token_urlsafe(nbytes=32)

# URL (without trailing /) of the prosody HTTP server.
PROSODY_ENDPOINT = "http://localhost:5280"
