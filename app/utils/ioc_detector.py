import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_REGEX = re.compile(
    r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$"
)

MD5_REGEX = re.compile(r"^[A-Fa-f0-9]{32}$")
SHA1_REGEX = re.compile(r"^[A-Fa-f0-9]{40}$")
SHA256_REGEX = re.compile(r"^[A-Fa-f0-9]{64}$")


def detect_ioc(value: str):
    value = value.strip()

    # IPv4 / IPv6
    try:
        ip = ipaddress.ip_address(value)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass

    # URL
    parsed = urlparse(value)

    if parsed.scheme in ("http", "https") and parsed.netloc:
        return "url"

    # Domain
    if DOMAIN_REGEX.match(value):
        return "domain"

    # Hashes
    if MD5_REGEX.match(value):
        return "md5"

    if SHA1_REGEX.match(value):
        return "sha1"

    if SHA256_REGEX.match(value):
        return "sha256"

    return "unknown"
