import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)

BLOCKED_NAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "169.254.169.254",
}

BLOCKED_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
)

def normalize_domain(raw: str) -> str:
    if not raw:
        raise ValueError("Le domaine est vide.")

    value = raw.strip().lower()

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    else:
        value = value.split("/")[0].split("?")[0].split("#")[0]

    value = value.strip(". ")

    if not value:
        raise ValueError("Domaine invalide.")

    if value in BLOCKED_NAMES or any(value.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        raise ValueError("Domaine interdit ou non public.")

    try:
        ipaddress.ip_address(value)
        raise ValueError("La V5 accepte uniquement des noms de domaine, pas des adresses IP.")
    except ValueError as exc:
        if "La V5 accepte" in str(exc):
            raise

    if not DOMAIN_RE.match(value):
        raise ValueError("Format de domaine invalide.")

    return value

def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except ValueError:
        return False
