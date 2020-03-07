version_info = (0, 1, 0, "a0")
version = (
    ".".join(map(str, version_info[:3])) +
    (f"-{version_info[3]}" if version_info[3] else "")
)
