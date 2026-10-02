import os
from app.schemas.email_analysis import ParsedEmailData
from app.services.forensic.eml_parser import parse_eml_bytes
from app.services.forensic.msg_parser import parse_msg_bytes

# OLE Compound File Binary Format magic bytes used by Outlook .msg files
OLE_CFBF_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def parse_email(raw_bytes: bytes, filename: str) -> ParsedEmailData:
    """Main entry point for forensic email parsing.

    Inspects file extension and byte signature to dispatch to the appropriate
    deterministic parser (.eml or .msg).
    """
    if not raw_bytes:
        raise ValueError("Cannot parse empty file: 0 bytes received")

    ext = os.path.splitext(filename)[1].lower()

    # Detect .msg by extension or OLE magic bytes
    if ext == ".msg" or raw_bytes.startswith(OLE_CFBF_HEADER):
        return parse_msg_bytes(raw_bytes, filename)

    # Detect .eml by extension or standard MIME / header structure
    if ext == ".eml" or b":" in raw_bytes[:1024]:
        return parse_eml_bytes(raw_bytes, filename)

    raise ValueError(
        f"Unsupported email format for '{filename}'. Only .eml and .msg files are supported."
    )
