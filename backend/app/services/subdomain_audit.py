from __future__ import annotations

import httpx
import dns.resolver

COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "autodiscover", "autoconfig",
    "ns1", "ns2", "dns1", "dns2",
    "vpn", "ssl-vpn", "remote", "portal", "portail", "sso", "auth", "login",
    "intranet", "extranet", "admin", "api", "app", "apps",
    "support", "helpdesk", "glpi", "ticket", "tickets",
    "cloud", "cdn", "static", "assets",
    "ftp", "sftp", "files", "secure", "monitoring", "zabbix",
    "mailinblack", "owa", "exchange", "m365", "office365",
    "sig", "cart", "grc", "gta", "netbox",
]

def _normalize_name(name: str, domain: str) -> str | None:
    name = (name or "").strip().lower().strip(".")
    if not name:
        return None
    if name.startswith("*."):
        name = name[2:]
    if name == domain:
        return None
    if name.endswith("." + domain):
        return name
    return None

def _resolve_exists(hostname: str) -> bool:
    r = dns.resolver.Resolver()
    r.lifetime = 2.5
    r.timeout = 2.5
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            answers = r.resolve(hostname, rtype)
            if answers:
                return True
        except Exception:
            continue
    return False

async def _source_crtsh(domain: str) -> tuple[list[str], str | None]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=14.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        found = set()
        for item in data:
            raw = item.get("name_value") or ""
            for name in raw.splitlines():
                clean = _normalize_name(name, domain)
                if clean:
                    found.add(clean)
        return sorted(found), None
    except Exception as exc:
        return [], str(exc)

async def _source_hackertarget(domain: str) -> tuple[list[str], str | None]:
    # Free public endpoint. Returns CSV lines: host,ip
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            text = response.text
        found = set()
        if "error" in text.lower() or "api count exceeded" in text.lower():
            return [], text[:200]
        for line in text.splitlines():
            host = line.split(",")[0].strip()
            clean = _normalize_name(host, domain)
            if clean:
                found.add(clean)
        return sorted(found), None
    except Exception as exc:
        return [], str(exc)

async def _source_certspotter(domain: str) -> tuple[list[str], str | None]:
    # Unauthenticated endpoint may be rate limited. Useful fallback when allowed.
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        found = set()
        for item in data:
            for name in item.get("dns_names", []) or []:
                clean = _normalize_name(name, domain)
                if clean:
                    found.add(clean)
        return sorted(found), None
    except Exception as exc:
        return [], str(exc)

def _fallback_dns(domain: str) -> list[str]:
    found = []
    for prefix in COMMON_SUBDOMAINS:
        host = f"{prefix}.{domain}"
        if _resolve_exists(host):
            found.append(host)
    return sorted(set(found))

async def discover_subdomains_ct(domain: str) -> dict:
    sources = {}
    all_found = set()
    findings = []

    for source_name, func in [
        ("crt.sh", _source_crtsh),
        ("HackerTarget hostsearch", _source_hackertarget),
        ("CertSpotter", _source_certspotter),
    ]:
        items, error = await func(domain)
        sources[source_name] = {"count": len(items), "error": error}
        all_found.update(items)
        if error:
            findings.append({
                "severity": "info",
                "category": "Sous-domaines",
                "title": f"Source passive indisponible ou limitée : {source_name}",
                "description": f"La source {source_name} n'a pas pu être utilisée complètement : {error}",
                "recommendation": "L'audit continue avec les autres sources et le fallback DNS.",
                "applies_to": ["web", "dns"],
            })

    fallback_subs = _fallback_dns(domain)
    sources["DNS fallback common names"] = {"count": len(fallback_subs), "error": None}
    all_found.update(fallback_subs)

    merged = sorted(all_found)

    if len(merged) > 500:
        findings.append({
            "severity": "info",
            "category": "Sous-domaines",
            "title": "Nombre important de sous-domaines",
            "description": f"{len(merged)} sous-domaines ont été trouvés. Le rapport affiche les 500 premiers.",
            "recommendation": "Analyser régulièrement la liste pour identifier les actifs oubliés ou non maîtrisés.",
            "applies_to": ["web", "dns"],
        })

    return {
        "domain": domain,
        "source": "crt.sh + HackerTarget + CertSpotter + DNS fallback",
        "sources": sources,
        "count": len(merged),
        "subdomains": merged[:500],
        "error": "; ".join([f"{k}: {v['error']}" for k, v in sources.items() if v.get("error")]) or None,
        "findings": findings,
    }
