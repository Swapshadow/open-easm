from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from app.services.network_guard import resolve_ips, build_guard_finding

def _parse_cert_datetime(value: str):
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None

def _name_tuple_to_dict(name_tuple):
    data = {}
    for item in name_tuple:
        for key, value in item:
            data[key] = value
    return data

def audit_tls(hostname: str, port: int = 443) -> dict:
    findings = []
    guard = resolve_ips(hostname)
    result = {
        "hostname": hostname,
        "port": port,
        "guard": guard,
        "available": False,
        "cert": None,
        "findings": findings,
    }

    guard_finding = build_guard_finding(hostname, guard)
    if guard_finding:
        findings.append(guard_finding)
        return result

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

        subject = _name_tuple_to_dict(cert.get("subject", []))
        issuer = _name_tuple_to_dict(cert.get("issuer", []))
        not_before = _parse_cert_datetime(cert.get("notBefore", ""))
        not_after = _parse_cert_datetime(cert.get("notAfter", ""))
        now = datetime.now(timezone.utc)

        days_remaining = None
        expired = None
        if not_after:
            days_remaining = (not_after - now).days
            expired = days_remaining < 0

        san = []
        for typ, value in cert.get("subjectAltName", []):
            if typ == "DNS":
                san.append(value)

        cert_data = {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "days_remaining": days_remaining,
            "expired": expired,
            "san": san,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
        }

        result["available"] = True
        result["cert"] = cert_data

        if expired:
            findings.append({
                "severity": "critical",
                "category": "TLS",
                "title": f"Certificat TLS expiré sur {hostname}",
                "description": "Le certificat présenté par le serveur HTTPS est expiré.",
                "recommendation": "Renouveler immédiatement le certificat.",
                "applies_to": ["web"],
            })
        elif days_remaining is not None and days_remaining <= 15:
            findings.append({
                "severity": "high",
                "category": "TLS",
                "title": f"Certificat TLS proche de l'expiration sur {hostname}",
                "description": f"Le certificat expire dans {days_remaining} jours.",
                "recommendation": "Planifier le renouvellement du certificat.",
                "applies_to": ["web"],
            })
        elif days_remaining is not None and days_remaining <= 30:
            findings.append({
                "severity": "medium",
                "category": "TLS",
                "title": f"Certificat TLS à renouveler prochainement sur {hostname}",
                "description": f"Le certificat expire dans {days_remaining} jours.",
                "recommendation": "Prévoir le renouvellement avant expiration.",
                "applies_to": ["web"],
            })

        if san and hostname not in san and not any(_matches_wildcard(hostname, entry) for entry in san):
            findings.append({
                "severity": "high",
                "category": "TLS",
                "title": f"Nom {hostname} absent du SAN",
                "description": "La cible auditée ne semble pas présente dans les noms alternatifs du certificat.",
                "recommendation": "Utiliser un certificat contenant le nom audité dans le SAN.",
                "applies_to": ["web"],
            })

        return result

    except ssl.SSLCertVerificationError as exc:
        findings.append({
            "severity": "high",
            "category": "TLS",
            "title": f"Erreur de validation du certificat TLS sur {hostname}",
            "description": str(exc),
            "recommendation": "Vérifier la chaîne de certification, le nom du certificat et sa validité.",
            "applies_to": ["web"],
        })
    except Exception as exc:
        findings.append({
            "severity": "info",
            "category": "TLS",
            "title": f"HTTPS/TLS non disponible ou inaccessible sur {hostname}",
            "description": str(exc),
            "recommendation": "À vérifier uniquement si cette cible doit exposer un service HTTPS public.",
            "applies_to": ["web"],
        })

    return result

def _matches_wildcard(domain: str, pattern: str) -> bool:
    if not pattern.startswith("*."):
        return False
    suffix = pattern[1:]
    return domain.endswith(suffix) and domain.count(".") == pattern.count(".")
