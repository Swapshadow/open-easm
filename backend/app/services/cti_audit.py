from __future__ import annotations

import dns.resolver
import ipaddress

TIMEOUT = 3.0

DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]

def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    r.timeout = TIMEOUT
    return r

def _reverse_ipv4(ip: str) -> str | None:
    try:
        obj = ipaddress.ip_address(ip)
        if obj.version != 4:
            return None
        return ".".join(reversed(ip.split(".")))
    except ValueError:
        return None

def check_dnsbl(ip: str) -> list[dict]:
    rev = _reverse_ipv4(ip)
    results = []
    if not rev:
        return [{"zone": "dnsbl", "status": "not_supported", "detail": "IPv6 non testée par les DNSBL IPv4 utilisées."}]

    for zone in DNSBL_ZONES:
        query = f"{rev}.{zone}"
        try:
            answers = _resolver().resolve(query, "A")
            values = [str(a) for a in answers]
            results.append({"zone": zone, "status": "listed", "values": values})
        except dns.resolver.NXDOMAIN:
            results.append({"zone": zone, "status": "not_listed", "values": []})
        except dns.resolver.NoAnswer:
            results.append({"zone": zone, "status": "not_listed", "values": []})
        except Exception as exc:
            results.append({"zone": zone, "status": "error", "error": str(exc)})
    return results

def audit_cti(ip_inventory: dict, domain: str) -> dict:
    ip_results_all = []
    ip_results_display = []
    findings = []

    # Check core exposure + non-public is not checked + limited supporting.
    candidates = []
    for item in ip_inventory.get("unique_ips", []):
        if not item.get("is_public"):
            continue
        if item.get("scope") in ("core_exposure", "supporting_exposure"):
            candidates.append(item)

    # Avoid huge CTI output for Microsoft/Mail providers. Still keeps counts.
    checked = 0
    listed_count = 0
    error_count = 0
    not_listed_count = 0
    skipped_provider_count = len([i for i in ip_inventory.get("unique_ips", []) if i.get("scope") == "third_party_provider"])

    for item in candidates[:40]:
        ip = item["ip"]
        checks = check_dnsbl(ip)
        checked += 1
        row = {"ip": ip, "scope": item.get("scope"), "hostnames": item.get("hostnames", []), "checks": checks}
        ip_results_all.append(row)

        listed = [c for c in checks if c.get("status") == "listed"]
        errors = [c for c in checks if c.get("status") == "error"]
        if listed:
            listed_count += 1
            ip_results_display.append(row)
            findings.append({
                "severity": "high",
                "category": "CTI",
                "title": f"IP listée dans une DNSBL : {ip}",
                "description": f"L'IP {ip} apparaît dans au moins une liste de réputation : " + ", ".join(c["zone"] for c in listed),
                "recommendation": "Vérifier la réputation de l'IP, l'usage mail éventuel et ouvrir une procédure de délégitimation si nécessaire.",
                "applies_to": ["cti", "reputation"],
            })
        elif errors:
            error_count += 1
            ip_results_display.append(row)
        else:
            not_listed_count += 1

    # If nothing suspicious, show only a compact sample to avoid UI flooding.
    if not ip_results_display and ip_results_all:
        ip_results_display = ip_results_all[:5]

    return {
        "domain": domain,
        "summary": {
            "checked": checked,
            "listed": listed_count,
            "not_listed": not_listed_count,
            "errors": error_count,
            "skipped_third_party_provider_ips": skipped_provider_count,
        },
        "ip_reputation": ip_results_display,
        "ip_reputation_all": ip_results_all,
        "leak_monitoring": {
            "status": "not_performed_public_mode",
            "reason": "La recherche de fuites d'identifiants est réservée à un mode avec preuve de propriété du domaine.",
        },
        "compromised_assets": {
            "status": "not_performed_public_mode",
            "reason": "La corrélation IOC avancée nécessite des sources CTI authentifiées ou un mode domaine vérifié.",
        },
        "findings": findings,
        "note": "CTI léger basé sur DNSBL publiques IPv4. Les IP de prestataires tiers sont résumées pour éviter le bruit.",
    }
