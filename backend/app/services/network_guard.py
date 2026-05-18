from __future__ import annotations

import dns.resolver
from app.validators import is_public_ip

TIMEOUT = 4.0

def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    r.timeout = TIMEOUT
    return r

def resolve_ips(hostname: str) -> dict:
    result = {
        "hostname": hostname,
        "ips": [],
        "public_ips": [],
        "blocked_ips": [],
        "safe_for_outbound_checks": False,
        "error": None,
    }

    ips = []

    for record_type in ("A", "AAAA"):
        try:
            answers = _resolver().resolve(hostname, record_type)
            ips.extend([str(r).strip() for r in answers])
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
            break
        except Exception as exc:
            if not result["error"]:
                result["error"] = str(exc)

    result["ips"] = sorted(set(ips))
    result["public_ips"] = [ip for ip in result["ips"] if is_public_ip(ip)]
    result["blocked_ips"] = [ip for ip in result["ips"] if not is_public_ip(ip)]

    result["safe_for_outbound_checks"] = bool(result["public_ips"]) and not result["blocked_ips"]
    return result

def build_guard_finding(hostname: str, guard: dict) -> dict | None:
    if guard.get("safe_for_outbound_checks"):
        return None

    if guard.get("blocked_ips"):
        return {
            "severity": "info",
            "category": "Garde-fous",
            "title": f"Contrôle actif léger bloqué pour {hostname}",
            "description": f"La cible résout vers au moins une IP non publique ou interdite : {', '.join(guard.get('blocked_ips', []))}. Les tests HTTP/TLS ont été volontairement bloqués.",
            "recommendation": "Vérifier que le domaine audité est un domaine public. Ce garde-fou limite les risques SSRF et les audits de ressources internes.",
            "applies_to": ["web", "tls"],
        }

    return {
        "severity": "info",
        "category": "Garde-fous",
        "title": f"Contrôle actif léger non lancé pour {hostname}",
        "description": "La cible ne résout pas vers une IP publique exploitable pour les contrôles HTTP/TLS.",
        "recommendation": "Ce comportement est normal si le domaine n'héberge pas de service web public.",
        "applies_to": ["web", "tls"],
    }
