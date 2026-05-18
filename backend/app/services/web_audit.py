from __future__ import annotations

import httpx

from app.services.network_guard import resolve_ips, build_guard_finding

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "medium",
        "recommendation": "Activer HSTS pour forcer l'utilisation de HTTPS.",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "medium",
        "recommendation": "Définir une CSP adaptée pour réduire les risques XSS.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "low",
        "recommendation": "Ajouter X-Frame-Options ou frame-ancestors dans la CSP.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "recommendation": "Ajouter X-Content-Type-Options: nosniff.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "recommendation": "Ajouter une politique Referrer-Policy adaptée.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "recommendation": "Ajouter Permissions-Policy pour limiter les API navigateur exposées.",
    },
}

async def audit_web_target(hostname: str) -> dict:
    findings = []
    guard = resolve_ips(hostname)

    result = {
        "hostname": hostname,
        "guard": guard,
        "http": None,
        "https": None,
        "reachable": False,
        "best_scheme": None,
        "security_headers": {},
        "findings": findings,
    }

    guard_finding = build_guard_finding(hostname, guard)
    if guard_finding:
        findings.append(guard_finding)
        return result

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=True) as client:
        http_result = await _fetch(client, f"http://{hostname}")
        https_result = await _fetch(client, f"https://{hostname}")

    result["http"] = http_result
    result["https"] = https_result
    result["reachable"] = bool(http_result["reachable"] or https_result["reachable"])
    result["best_scheme"] = "https" if https_result["reachable"] else ("http" if http_result["reachable"] else None)

    best = https_result if https_result["reachable"] else http_result

    if result["reachable"]:
        if not https_result["reachable"]:
            findings.append({
                "severity": "medium",
                "category": "Web",
                "title": f"HTTPS inaccessible sur {hostname}",
                "description": "Un service web répond, mais HTTPS n'est pas accessible ou présente une erreur.",
                "recommendation": "Publier le service web en HTTPS avec un certificat valide.",
                "applies_to": ["web"],
            })

        if http_result["reachable"] and https_result["reachable"]:
            final_url = http_result.get("final_url") or ""
            if final_url.startswith("http://"):
                findings.append({
                    "severity": "medium",
                    "category": "Web",
                    "title": f"HTTP ne redirige pas vers HTTPS sur {hostname}",
                    "description": "Le service HTTP reste accessible sans redirection vers HTTPS.",
                    "recommendation": "Mettre en place une redirection permanente HTTP vers HTTPS.",
                    "applies_to": ["web"],
                })

        headers = {k.lower(): v for k, v in best.get("headers", {}).items()}
        for key, meta in SECURITY_HEADERS.items():
            present = key in headers
            result["security_headers"][meta["name"]] = {
                "present": present,
                "value": headers.get(key),
            }
            if not present:
                findings.append({
                    "severity": meta["severity"],
                    "category": "Web",
                    "title": f"Header absent sur {hostname} : {meta['name']}",
                    "description": f"L'en-tête {meta['name']} n'a pas été détecté.",
                    "recommendation": meta["recommendation"],
                    "applies_to": ["web"],
                })
    else:
        findings.append({
            "severity": "info",
            "category": "Web",
            "title": f"Service web inaccessible sur {hostname}",
            "description": "Aucun service HTTP/HTTPS exploitable n'a été joint.",
            "recommendation": "À vérifier uniquement si cette cible doit exposer un service web public.",
            "applies_to": ["web"],
        })

    return result

async def audit_web_targets(domain: str) -> dict:
    targets = [domain]
    www = f"www.{domain}"
    if www not in targets:
        targets.append(www)

    results = []
    findings = []

    for target in targets:
        item = await audit_web_target(target)
        results.append(item)
        findings.extend(item.get("findings", []))

    reachable_targets = [r for r in results if r.get("reachable")]

    return {
        "domain": domain,
        "targets": results,
        "reachable_targets": reachable_targets,
        "has_web": bool(reachable_targets),
        "findings": findings,
    }

async def _fetch(client: httpx.AsyncClient, url: str) -> dict:
    try:
        response = await client.get(url)
        return {
            "url": url,
            "reachable": True,
            "status_code": response.status_code,
            "final_url": str(response.url),
            "headers": dict(response.headers),
            "error": None,
        }
    except Exception as exc:
        return {
            "url": url,
            "reachable": False,
            "status_code": None,
            "final_url": None,
            "headers": {},
            "error": str(exc),
        }
