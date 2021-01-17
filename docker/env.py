import os
import secrets
import sys

_secret_key_path = "/etc/snikket-web-portal/secret_key"

if "SNIKKET_WEB_SECRET_KEY" in os.environ:
    print("Using SNIKKET_WEB_SECRET_KEY from environment")
else:
    try:
        with open(_secret_key_path, "r") as f:
            SNIKKET_WEB_SECRET_KEY = f.read()
        print("Restored SNIKKET_WEB_SECRET_KEY from", _secret_key_path)
    except FileNotFoundError:
        print("Generating SNIKKET_WEB_SECRET_KEY ...")
        SNIKKET_WEB_SECRET_KEY = secrets.token_urlsafe(nbytes=32)
        old_mask = os.umask(0o077)
        with open(_secret_key_path, "x") as f:
            f.write(SNIKKET_WEB_SECRET_KEY)
        os.umask(old_mask)
        print("SNIKKET_WEB_SECRET_KEY persisted to", _secret_key_path)

# Ensure that the above output is printed, even if nothing else is.
sys.stdout.flush()
sys.stderr.flush()
