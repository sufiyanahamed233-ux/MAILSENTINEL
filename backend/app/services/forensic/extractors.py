import ipaddress
import os
import re
import urllib.parse
from email.utils import parseaddr

# Regex for IPv4 addresses
IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# Regex candidate pattern for IPv6 addresses (verified strictly by ipaddress.IPv6Address)
IPV6_PATTERN = re.compile(r"\b[0-9a-fA-F:]{2,39}\b")


# Regex for URL extraction in text/html
URL_PATTERN = re.compile(
    r"https?://(?:[a-zA-Z0-9\-._~%!$&'()*+,;=]+(?::[a-zA-Z0-9\-._~%!$&'()*+,;=]+)?@)?"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
    r"(?::[0-9]{1,5})?(?:/[^\s<>\"'{}|\\^`\[\]]*)?",
    re.IGNORECASE,
)

# Domain validation pattern
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def extract_domain_from_email(email_str: str | None) -> str | None:
    """Extract and lowercase domain part from an email address or 'Name <email>' string."""
    if not email_str:
        return None
    _, addr = parseaddr(email_str)
    if not addr and "@" in email_str:
        addr = email_str.strip().strip("<>\"'")
    if "@" in addr:
        domain = addr.split("@")[-1].strip().lower()
        if domain and "." in domain and not domain.endswith("."):
            return domain
    return None


def extract_ips(text: str) -> list[tuple[str, int]]:
    """Extract valid unique IPv4 and IPv6 addresses from text preserving first-seen order.

    Returns:
        List of tuples: (ip_address_string, ip_version_int)
    """
    if not text:
        return []

    found_ips: list[tuple[str, int]] = []
    seen: set[str] = set()

    # IPv4 candidates
    for candidate in IPV4_PATTERN.findall(text):
        try:
            ip_obj = ipaddress.IPv4Address(candidate)
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                found_ips.append((ip_str, 4))
        except ValueError:
            continue

    # IPv6 candidates
    for candidate in IPV6_PATTERN.findall(text):
        try:
            ip_obj = ipaddress.IPv6Address(candidate)
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                found_ips.append((ip_str, 6))
        except ValueError:
            continue

    return found_ips


def normalize_url(raw_url: str) -> tuple[str, str, str | None, str | None, str | None] | None:
    """Parse and normalize a URL.

    Returns:
        tuple of (original_url, normalized_url, domain, scheme, path) or None if invalid.
    """
    raw_url = raw_url.strip().rstrip(".,;)>]\"'")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except Exception:
        return None

    scheme = parsed.scheme.lower() if parsed.scheme else None
    if scheme not in ("http", "https"):
        return None

    netloc = parsed.netloc.lower()
    if not netloc:
        return None

    # Separate host and port
    host = parsed.hostname.lower() if parsed.hostname else netloc
    path = parsed.path if parsed.path else "/"
    query = f"?{parsed.query}" if parsed.query else ""

    # Normalized URL: lowercase scheme + host, standard path and query, no fragment
    normalized = f"{scheme}://{netloc}{path}{query}"

    return (raw_url, normalized, host, scheme, path)


def extract_urls(text: str) -> list[dict[str, str | None]]:
    """Extract, normalize, and deduplicate all URLs found in text."""
    if not text:
        return []

    urls: list[dict[str, str | None]] = []
    seen_normalized: set[str] = set()

    for match in URL_PATTERN.finditer(text):
        candidate = match.group(0)
        norm_result = normalize_url(candidate)
        if norm_result:
            orig, norm, domain, scheme, path = norm_result
            if norm not in seen_normalized:
                seen_normalized.add(norm)
                urls.append(
                    {
                        "url": orig,
                        "normalized_url": norm,
                        "domain": domain,
                        "scheme": scheme,
                        "path": path,
                    }
                )

    return urls


def extract_domains(candidates: list[str]) -> list[str]:
    """Validate, clean, and deduplicate domain strings including base domains."""
    domains: list[str] = []
    seen: set[str] = set()

    def add_domain(dom: str) -> None:
        if dom and dom not in seen:
            if DOMAIN_PATTERN.match(dom):
                try:
                    ipaddress.ip_address(dom)
                    return  # Skip pure IPs
                except ValueError:
                    pass
                seen.add(dom)
                domains.append(dom)

    for item in candidates:
        if not item:
            continue
        cleaned = item.strip().lower().rstrip(".,:;\"'/")
        if ":" in cleaned:
            cleaned = cleaned.split(":")[0]
        add_domain(cleaned)
        # Also extract parent registered domain (e.g. login.phish.com -> phish.com)
        parts = cleaned.split(".")
        if len(parts) > 2 and len(parts[-1]) >= 2:
            add_domain(".".join(parts[-2:]))

    return domains



def sanitize_filename(filename: str | None) -> str:
    """Sanitize attachment filename to prevent path traversal attacks."""
    if not filename:
        return "unnamed_attachment"
    # Take basename only
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes and non-printable characters
    sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", base).strip()
    return sanitized if sanitized else "unnamed_attachment"
