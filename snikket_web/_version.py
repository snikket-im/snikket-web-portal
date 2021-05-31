import os
import subprocess

version = "(unknown)"

if os.path.exists(".app_version"):
    with open(".app_version") as f:
        version = f.read().strip()
elif os.path.exists(".git"):
    try:
        version = subprocess.check_output([
            "git", "describe", "--always"
        ]).strip().decode("utf8")
    except OSError:
        version = "dev (unknown)"
