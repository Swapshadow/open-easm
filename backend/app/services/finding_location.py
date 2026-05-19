from __future__ import annotations

import re

def _first_match(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            value = match.group(1).strip().strip(".")
            if value.startswith("25."):
                return None
            if "%" in value or "/" in value:
                return None
            return value
    return None

def infer_location(finding: dict, domain: str) -> dict:
    title = str(finding.get("title", ""))
    desc = str(finding.get("description", ""))
    category = str(finding.get("category", "Autre"))
    text = f"{title} {desc}"

    # Special handling: passive source availability is not a vulnerable hostname.
    if category.lower().startswith("sous-domaines") and "source passive" in title.lower():
        src = "crt.sh"
        if "hackertarget" in title.lower() or "hackertarget" in desc.lower():
            src = "HackerTarget"
        elif "certspotter" in title.lower() or "certspotter" in desc.lower():
            src = "CertSpotter"
        return {
            "hostname": domain,
            "record": None,
            "control": "Découverte passive des sous-domaines",
            "path": f"Source passive : {src}",
            "display": f"Source passive : {src}",
        }

    hostname = _first_match([
        r"\bsur\s+([a-z0-9._-]+\.[a-z]{2,})",
        r"\bpour\s+([a-z0-9._-]+\.[a-z]{2,})",
        r"\b([a-z0-9._-]+\." + re.escape(domain) + r")\b",
    ], text) or domain

    record = None
    control = category
    path = None

    if category.lower().startswith("messagerie"):
        control = "Messagerie"
        if "DMARC" in title.upper() or "DMARC" in desc.upper():
            record = f"_dmarc.{domain} TXT"
        elif "SPF" in title.upper() or "SPF" in desc.upper():
            record = f"{domain} TXT SPF"
        elif "MX" in title.upper() or "MX" in desc.upper():
            record = f"{domain} MX"

    elif category.lower() == "dns":
        control = "DNS"
        if "CAA" in title.upper():
            record = f"{domain} CAA"
        elif "A/AAAA" in title.upper() or "résolution" in title.lower():
            record = f"{hostname} A/AAAA"
        elif "NS" in title.upper():
            record = f"{domain} NS"

    elif category.lower() in ("web", "tls", "tls/ssl"):
        if "Header absent" in title or "en-tête" in desc:
            control = "Headers HTTP"
        elif "HTTPS" in title.upper() or "TLS" in title.upper():
            control = "HTTPS/TLS"
        else:
            control = "Web"

    elif "cti" in category.lower():
        control = "CTI / Réputation"
    elif "cve" in category.lower():
        control = "CVE potentielle passive"
    elif "inventaire ip" in category.lower():
        control = "Inventaire IP"

    if "Header absent" in title and ":" in title:
        header = title.split(":")[-1].strip()
        if header:
            path = f"{hostname} -> header {header}"

    display = path or record or hostname
    return {
        "hostname": hostname,
        "record": record,
        "control": control,
        "path": path,
        "display": display,
    }

def enrich_findings_locations(findings: list[dict], domain: str) -> list[dict]:
    enriched = []
    for finding in findings:
        item = dict(finding)
        item["location"] = item.get("location") or infer_location(item, domain)
        enriched.append(item)
    return enriched
