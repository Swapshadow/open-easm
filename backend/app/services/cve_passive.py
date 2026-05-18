from __future__ import annotations

import re

KNOWN_PASSIVE = [
    {
        "product": "apache",
        "version": "2.4.49",
        "cve": "CVE-2021-41773",
        "severity": "critical",
        "description": "Apache HTTP Server 2.4.49 est associé à une faille de path traversal/RCE selon configuration.",
        "recommendation": "Vérifier immédiatement la version réelle et appliquer les correctifs. Ne pas conclure sans confirmation serveur.",
    },
    {
        "product": "apache",
        "version": "2.4.50",
        "cve": "CVE-2021-42013",
        "severity": "critical",
        "description": "Apache HTTP Server 2.4.50 est associé à une correction incomplète de CVE-2021-41773.",
        "recommendation": "Vérifier immédiatement la version réelle et appliquer les correctifs. Ne pas conclure sans confirmation serveur.",
    },
]

OUTDATED_HINTS = [
    {
        "pattern": r"php/7\.",
        "severity": "high",
        "title": "PHP 7.x détecté passivement",
        "description": "PHP 7.x est obsolète. Cette détection repose sur les headers HTTP et doit être confirmée.",
        "recommendation": "Vérifier la version réelle et planifier une migration vers une version supportée.",
    },
    {
        "pattern": r"microsoft-iis/7\.|microsoft-iis/8\.",
        "severity": "high",
        "title": "Ancienne version IIS détectée passivement",
        "description": "Une ancienne génération de Microsoft IIS semble apparaître dans les headers HTTP.",
        "recommendation": "Vérifier la version réelle de Windows Server/IIS et le niveau de correctifs.",
    },
    {
        "pattern": r"apache/2\.2",
        "severity": "high",
        "title": "Apache 2.2 détecté passivement",
        "description": "Apache 2.2 est obsolète. Cette détection repose sur les headers HTTP et doit être confirmée.",
        "recommendation": "Vérifier la version réelle et planifier une mise à jour vers une version supportée.",
    },
]

def _headers_text(web_result: dict) -> list[dict]:
    observations = []
    for target in web_result.get("targets", []):
        host = target.get("hostname")
        for scheme in ("http", "https"):
            data = target.get(scheme) or {}
            headers = data.get("headers") or {}
            if not headers:
                continue
            text = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()
            observations.append({
                "hostname": host,
                "scheme": scheme,
                "text": text,
                "server": headers.get("server") or headers.get("Server"),
                "x_powered_by": headers.get("x-powered-by") or headers.get("X-Powered-By"),
            })
    return observations

def detect_passive_cves(web_result: dict) -> dict:
    observations = _headers_text(web_result)
    items = []
    findings = []

    for obs in observations:
        text = obs["text"]

        for rule in KNOWN_PASSIVE:
            product = rule["product"]
            version = rule["version"]
            if product in text and version in text:
                item = {
                    "hostname": obs["hostname"],
                    "scheme": obs["scheme"],
                    "type": "cve_potentielle_passive",
                    "technology": f"{product} {version}",
                    "cve": rule["cve"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "confidence": "medium",
                    "evidence": f"Header passif observé : Server={obs.get('server')} X-Powered-By={obs.get('x_powered_by')}",
                }
                items.append(item)
                findings.append({
                    "severity": rule["severity"],
                    "category": "CVE potentielles",
                    "title": f"{rule['cve']} potentielle sur {obs['hostname']}",
                    "description": rule["description"] + " Détection passive uniquement.",
                    "recommendation": rule["recommendation"],
                    "applies_to": ["web", "vulnerability"],
                })

        for hint in OUTDATED_HINTS:
            if re.search(hint["pattern"], text):
                item = {
                    "hostname": obs["hostname"],
                    "scheme": obs["scheme"],
                    "type": "obsolescence_potentielle",
                    "technology": hint["title"],
                    "cve": None,
                    "severity": hint["severity"],
                    "description": hint["description"],
                    "recommendation": hint["recommendation"],
                    "confidence": "low",
                    "evidence": f"Header passif observé : Server={obs.get('server')} X-Powered-By={obs.get('x_powered_by')}",
                }
                items.append(item)
                findings.append({
                    "severity": hint["severity"],
                    "category": "CVE potentielles",
                    "title": f"{hint['title']} sur {obs['hostname']}",
                    "description": hint["description"],
                    "recommendation": hint["recommendation"],
                    "applies_to": ["web", "vulnerability"],
                })

    return {
        "items": items,
        "count": len(items),
        "findings": findings,
        "note": "Détection passive basée sur headers HTTP. Les CVE sont potentielles et doivent être confirmées par un audit autorisé.",
    }
