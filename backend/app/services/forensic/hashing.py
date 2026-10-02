import hashlib


def calculate_sha256(data: bytes) -> str:
    """Calculate lowercase hexadecimal SHA-256 hash of byte data."""
    return hashlib.sha256(data).hexdigest()


def calculate_md5(data: bytes) -> str:
    """Calculate lowercase hexadecimal MD5 hash of byte data."""
    return hashlib.md5(data).hexdigest()
