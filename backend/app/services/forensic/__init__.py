"""Forensic email parsing engine for MAILSENTINEL."""

from app.services.forensic.eml_parser import parse_eml_bytes
from app.services.forensic.hashing import calculate_md5, calculate_sha256
from app.services.forensic.msg_parser import parse_msg_bytes
from app.services.forensic.parser import parse_email
from app.services.forensic.persistence import persist_forensic_data

__all__ = [
    "parse_email",
    "parse_eml_bytes",
    "parse_msg_bytes",
    "persist_forensic_data",
    "calculate_sha256",
    "calculate_md5",
]
