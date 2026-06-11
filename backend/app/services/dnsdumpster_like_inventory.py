from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import httpx

from app.validators import is_public_ip

UNKNOWN = "Non détecté"
UNKNOWN_COUNTRY = "Unknown"
USER_AGENT = "OpenEASM-Beta-26.6 Defensive Audit"
HTTP_TIMEOUT = float(os.getenv("OPENEASM_HTTP_TIMEOUT", "8") or 8)
TLS_TIMEOUT = float(os.getenv("OPENEASM_TLS_TIMEOUT", "8") or 8)
MAX_HOSTS = int(os.getenv("OPENEASM_HOST_INVENTORY_MAX_HOSTS", "200") or 200)
CONCURRENCY = int(os.getenv("OPENEASM_HOST_INVENTORY_CONCURRENCY", "10") or 10)
SCAN_ALL_SUBDOMAINS = os.getenv("OPENEASM_SCAN_ALL_SUBDOMAINS", "true").lower() in {"1", "true", "yes", "on"}
PASSIVE_DB_ENABLED = os.getenv("OPENEASM_PASSIVE_DB_ENABLED", "false").lower() in {"1", "true", "yes", "on"}

COUNTRY_NAMES = {
    "FR": "France",
    "US": "United States",
    "GB": "United Kingdom",
    "DE": "Germany",
    "ES": "Spain",
    "IT": "Italy",
    "NL": "Netherlands",
    "BE": "Belgium",
    "CH": "Switzerland",
    "CA": "Canada",
    "IE": "Ireland",
    "LU": "Luxembourg",
    "PT": "Portugal",
}


def env_enabled() -> bool:
    return os.getenv("OPENEASM_DNSDUMPSTER_LIKE_ENABLED", "true").lower() in {"1", "true", "yes", "on"}


async def build_dnsdumpster_like_inventory(
    domain: str,
    dns_result: dict,
    mail_result: dict,
    subdomains_result: dict,
    ip_inventory: dict,
    service_scan: dict | None = None,
) -> dict:
    """Build a DNSDumpster-like view from observed OpenEASM data.

    HTTP/HTTPS/TLS fingerprints are first-class sources. Nmap is merged as a
    complementary source only; missing Nmap output never suppresses web evidence.
    """
    if not env_enabled():
        return _empty(domain, enabled=False)

    a_hosts = _a_record_hosts(domain, dns_result, subdomains_result, ip_inventory)
    mx_hosts = _mx_records(mail_result)
    ns_hosts = _ns_records(dns_result)
    txt_records = _txt_records(dns_result)

    all_for_revip = defaultdict(set)
    for item in a_hosts:
        for ip in item.get("ips", []):
            if is_public_ip(ip):
                all_for_revip[ip].add(item["host"])

    sem = asyncio.Semaphore(max(1, CONCURRENCY))
    asn_cache: dict[str, dict] = {}

    async def enrich_host(item: dict, record_type: str = "a") -> dict:
        async with sem:
            return await _enrich_host(item, record_type, all_for_revip, asn_cache, service_scan or {})

    if os.getenv("OPENEASM_HOST_INVENTORY_ENABLED", "true").lower() not in {"1", "true", "yes", "on"}:
        hosts = [_host_skeleton(x, "a") for x in a_hosts[:MAX_HOSTS]]
        mx_records = [_record_skeleton(x, "mx") for x in mx_hosts]
        ns_records = [_record_skeleton(x, "ns") for x in ns_hosts]
    else:
        hosts = await asyncio.gather(*(enrich_host(item, "a") for item in a_hosts[:MAX_HOSTS]))
        mx_records = await asyncio.gather(*(enrich_host(item, "mx") for item in mx_hosts[:MAX_HOSTS]))
        ns_records = await asyncio.gather(*(enrich_host(item, "ns") for item in ns_hosts[:MAX_HOSTS]))

    system_locations = Counter(h.get("country") or UNKNOWN_COUNTRY for h in hosts if _public_ip(h.get("ip")))
    system_locations.update(h.get("country") or UNKNOWN_COUNTRY for h in mx_records + ns_records if _public_ip(h.get("ip")))

    hosting_counter: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for h in hosts + mx_records + ns_records:
        if not _public_ip(h.get("ip")):
            continue
        key = (
            h.get("asn") or UNKNOWN,
            h.get("network") or UNKNOWN,
            h.get("asn_name") or UNKNOWN,
            h.get("country") or UNKNOWN_COUNTRY,
        )
        hosting_counter[key].add(h.get("host") or h.get("ip"))
    hosting_networks = [
        {"asn": k[0], "network": k[1], "asn_name": k[2], "country": k[3], "count": len(v)}
        for k, v in sorted(hosting_counter.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ]

    services_banners = Counter()
    for h in hosts + mx_records + ns_records:
        for svc in h.get("open_services", []) or []:
            banner = svc.get("banner") or svc.get("service") or "unknown server"
            services_banners[banner or "unknown server"] += 1
        for nmap in h.get("nmap_services", []) or []:
            banner = _nmap_banner(nmap)
            if banner:
                services_banners[banner] += 1

    return {
        "enabled": True,
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "web_fingerprint_primary": True,
            "nmap_role": "complementary_appendix",
            "user_agent": USER_AGENT,
            "http_timeout_seconds": HTTP_TIMEOUT,
            "tls_timeout_seconds": TLS_TIMEOUT,
            "concurrency": CONCURRENCY,
            "passive_db_enabled": PASSIVE_DB_ENABLED,
            "passive_db_configured": _passive_configured(),
            "open_services_label": "Open Services from DB" if PASSIVE_DB_ENABLED and _passive_configured() else "Open Services observed",
        },
        "system_locations": dict(system_locations) or {UNKNOWN_COUNTRY: 0},
        "hosting_networks": hosting_networks,
        "services_banners": dict(services_banners),
        "a_records": [_a_record_row(h) for h in hosts],
        "mx_records": [_mx_record_row(h) for h in mx_records],
        "ns_records": [_ns_record_row(h) for h in ns_records],
        "txt_records": txt_records,
        "hosts": hosts,
        "guardrail_logs": [h for h in hosts + mx_records + ns_records if h.get("guardrail")],
        "notes": [
            "Nmap est une source complémentaire. Les services HTTP/HTTPS peuvent être détectés par fingerprint web même lorsque Nmap ne remonte pas de service.",
            "Les valeurs non observées sont marquées Non détecté ou Version non exposée, sans invention de technologie.",
        ],
    }


def _empty(domain: str, enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "domain": domain,
        "system_locations": {},
        "hosting_networks": [],
        "services_banners": {},
        "a_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
        "hosts": [],
    }


def _resolver(timeout: float = 4.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _resolve_ips(hostname: str) -> dict:
    ips: list[str] = []
    errors: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips.extend(str(a).strip().strip(".") for a in _resolver().resolve(hostname, rtype))
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            errors.append("NXDOMAIN")
            break
        except Exception as exc:
            errors.append(str(exc))
    ips = sorted(set(ips))
    return {
        "ips": ips,
        "public_ips": [ip for ip in ips if is_public_ip(ip)],
        "blocked_ips": [ip for ip in ips if not is_public_ip(ip)],
        "errors": sorted(set(errors)),
    }


def _a_record_hosts(domain: str, dns_result: dict, subdomains_result: dict, ip_inventory: dict) -> list[dict]:
    hosts: dict[str, dict] = {}

    def add(host: str, source: str):
        host = (host or "").strip().lower().strip(".")
        if not host:
            return
        hosts.setdefault(host, {"host": host, "sources": set(), "priority": None})["sources"].add(source)

    add(domain, "dns")
    add(f"www.{domain}", "dns")
    if SCAN_ALL_SUBDOMAINS:
        for sub in subdomains_result.get("subdomains", []) or []:
            if isinstance(sub, dict):
                add(sub.get("host") or sub.get("subdomain") or sub.get("name"), "subdomain_dataset")
            else:
                add(str(sub), "subdomain_dataset")
    for entry in ip_inventory.get("entries", []) or []:
        if entry.get("source") in {"subdomain", "root", "www", "web_target"}:
            add(entry.get("hostname"), entry.get("source") or "ip_inventory")

    out = []
    by_entry = {e.get("hostname"): e for e in ip_inventory.get("entries", []) or []}
    for host, data in sorted(hosts.items()):
        inv = by_entry.get(host) or {}
        resolved = {"ips": inv.get("ips") or [], "public_ips": inv.get("public_ips") or [], "blocked_ips": inv.get("blocked_ips") or [], "errors": inv.get("errors") or []}
        if not resolved["ips"]:
            resolved = _resolve_ips(host)
        out.append({"host": host, "ips": resolved["ips"], "public_ips": resolved["public_ips"], "blocked_ips": resolved["blocked_ips"], "errors": resolved["errors"], "sources": sorted(data["sources"] | {"dns"})})
    return out


def _mx_records(mail_result: dict) -> list[dict]:
    rows = []
    for raw in mail_result.get("mx", {}).get("values", []) or []:
        parts = str(raw).strip().split()
        if len(parts) >= 2:
            priority = _to_int(parts[0])
            host = parts[-1].strip(".").lower()
        else:
            priority = None
            host = str(raw).strip(".").lower()
        resolved = _resolve_ips(host) if host else {"ips": [], "public_ips": [], "blocked_ips": [], "errors": []}
        rows.append({"host": host, "priority": priority, **resolved, "sources": ["mx", "dns"]})
    return rows


def _ns_records(dns_result: dict) -> list[dict]:
    rows = []
    for host in dns_result.get("records", {}).get("NS", {}).get("values", []) or []:
        host = str(host).strip(".").lower()
        resolved = _resolve_ips(host)
        rows.append({"host": host, **resolved, "sources": ["ns", "dns"]})
    return rows


def _txt_records(dns_result: dict) -> list[dict]:
    rows = []
    for raw in dns_result.get("records", {}).get("TXT", {}).get("values", []) or []:
        value = str(raw).replace('" "', "").replace('"', "").strip()
        item = {"value": value, "type": "TXT", "sources": ["dns"]}
        if value.lower().startswith("v=spf1"):
            item["type"] = "SPF"
            item["spf"] = {
                "includes": re.findall(r"\binclude:([^\s]+)", value, flags=re.I)[:15],
                "ip4": re.findall(r"\bip4:([^\s]+)", value, flags=re.I)[:20],
                "ip6": re.findall(r"\bip6:([^\s]+)", value, flags=re.I)[:20],
                "providers": _spf_providers(value),
                "resolution_policy": "includes parsed only; no aggressive recursive resolution",
            }
        rows.append(item)
    return rows


def _spf_providers(value: str) -> list[str]:
    providers = []
    for inc in re.findall(r"\binclude:([^\s]+)", value, flags=re.I):
        host = inc.lower().strip(".")
        if "mailjet" in host:
            providers.append("Mailjet")
        elif "outlook" in host or "protection.outlook" in host:
            providers.append("Microsoft 365 / Exchange Online Protection")
        elif "mailinblack" in host:
            providers.append("Mailinblack")
        else:
            providers.append(host)
    return sorted(dict.fromkeys(providers))


async def _enrich_host(item: dict, record_type: str, revip: dict[str, set[str]], asn_cache: dict[str, dict], service_scan: dict) -> dict:
    host = item.get("host") or UNKNOWN
    public_ips = item.get("public_ips") or []
    blocked_ips = item.get("blocked_ips") or []
    ip = public_ips[0] if public_ips else (item.get("ips") or ["Not found"])[0] if item.get("ips") else "Not found"
    guardrail = None
    sources = set(item.get("sources") or [])

    if blocked_ips or (item.get("ips") and not public_ips):
        guardrail = {
            "status": "blocked_by_guard",
            "reason": "IP privée, réservée ou résolution mixte ; fingerprint HTTP/TLS bloqué.",
            "blocked_ips": blocked_ips or item.get("ips") or [],
        }
        sources.add("guardrail")

    asn = await _asn_for_ip(ip, asn_cache) if _public_ip(ip) else _asn_unknown()
    http_results: dict[str, dict] = {}
    open_services: list[dict] = []
    technologies: list[dict] = []
    tls = {}

    if _public_ip(ip) and not guardrail:
        http_results = await _fingerprint_http(host)
        for scheme, result in http_results.items():
            if result.get("reachable"):
                sources.add(f"{scheme}_fingerprint")
                banner = _server_banner(result.get("headers") or {})
                svc = {
                    "scheme": scheme,
                    "port": 443 if scheme == "https" else 80,
                    "service": scheme,
                    "banner": banner or "unknown server",
                    "title": result.get("title") or UNKNOWN,
                    "status_code": result.get("status_code"),
                    "final_url": result.get("final_url"),
                    "source": f"{scheme}_fingerprint",
                }
                open_services.append(svc)
                technologies.extend(_detect_technologies(result.get("headers") or {}, result.get("body_sample") or ""))
        if http_results.get("https", {}).get("reachable"):
            tls = await asyncio.to_thread(_fingerprint_tls, host)
            if tls and not tls.get("error"):
                sources.add("tls_certificate")

    nmap_services = _nmap_for_host(host, service_scan)
    if nmap_services:
        sources.add("nmap")
    technologies = _dedup_technologies(technologies)

    return {
        "host": host,
        "ip": ip,
        "ips": item.get("ips") or [],
        "asn": asn.get("asn") or UNKNOWN,
        "network": asn.get("network") or UNKNOWN,
        "asn_name": asn.get("asn_name") or UNKNOWN,
        "country": asn.get("country") or UNKNOWN_COUNTRY,
        "city": UNKNOWN,
        "provider": asn.get("provider") or UNKNOWN,
        "record_type": record_type,
        "priority": item.get("priority"),
        "open_services": open_services,
        "http": http_results.get("http") or {},
        "https": http_results.get("https") or {},
        "tls": tls or {},
        "technologies": technologies,
        "nmap_services": nmap_services,
        "revip_count": len(revip.get(ip, set())) if _public_ip(ip) else 0,
        "guardrail": guardrail,
        "resolution_errors": item.get("errors") or [],
        "sources": sorted(sources),
    }


def _host_skeleton(item: dict, record_type: str) -> dict:
    return {"host": item.get("host"), "ip": (item.get("public_ips") or item.get("ips") or ["Not found"])[0], "record_type": record_type, "open_services": [], "technologies": [], "nmap_services": [], "revip_count": 0, "sources": item.get("sources") or []}


def _record_skeleton(item: dict, record_type: str) -> dict:
    h = _host_skeleton(item, record_type)
    h["priority"] = item.get("priority")
    return h


async def _fingerprint_http(host: str) -> dict[str, dict]:
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True, verify=False, headers=headers, limits=limits) as client:
        http, https = await asyncio.gather(_fetch(client, f"http://{host}"), _fetch(client, f"https://{host}"))
    return {"http": http, "https": https}


async def _fetch(client: httpx.AsyncClient, url: str) -> dict:
    try:
        response = await client.get(url)
        content_type = response.headers.get("content-type", "")
        body = response.text[:180000] if "text" in content_type or "html" in content_type or not content_type else ""
        return {
            "url": url,
            "reachable": True,
            "status_code": response.status_code,
            "final_url": str(response.url),
            "headers": dict(response.headers),
            "title": _html_title(body),
            "body_sample": body[:50000],
            "error": None,
        }
    except Exception as exc:
        return {"url": url, "reachable": False, "status_code": None, "final_url": None, "headers": {}, "title": None, "body_sample": "", "error": str(exc)}


def _fingerprint_tls(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                parsed = _parse_tls_der(der) if der else {}
                parsed.update({
                    "tls_version": ssock.version() or UNKNOWN,
                    "cipher": ssock.cipher()[0] if ssock.cipher() else UNKNOWN,
                })
                return parsed
    except Exception as exc:
        return {"cn": UNKNOWN, "san": [], "issuer": UNKNOWN, "issuer_organization": UNKNOWN, "expires_at": UNKNOWN, "days_remaining": 0, "tls_version": UNKNOWN, "error": str(exc)}


def _parse_tls_der(der: bytes) -> dict:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der, default_backend())
        cn = UNKNOWN
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            pass
        issuer_cn = UNKNOWN
        issuer_org = UNKNOWN
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            pass
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            pass
        san = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san = san_ext.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        expires = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        return {
            "cn": cn or UNKNOWN,
            "san": san,
            "issuer": issuer_cn or UNKNOWN,
            "issuer_organization": issuer_org or UNKNOWN,
            "expires_at": expires.astimezone(timezone.utc).isoformat(),
            "days_remaining": max(0, (expires.astimezone(timezone.utc) - datetime.now(timezone.utc)).days),
        }
    except Exception as exc:
        return {"cn": UNKNOWN, "san": [], "issuer": UNKNOWN, "issuer_organization": UNKNOWN, "expires_at": UNKNOWN, "days_remaining": 0, "parse_error": str(exc)}


def _html_title(body: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", flags=re.I | re.S)
    if not match:
        return None
    title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip()
    return title[:220] or None


def _server_banner(headers: dict) -> str | None:
    for k, v in headers.items():
        if k.lower() == "server" and v:
            return str(v).strip()
    return None


def _detect_technologies(headers: dict, body: str) -> list[dict]:
    tech: list[dict] = []
    header_l = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    server = header_l.get("server", "")
    powered = header_l.get("x-powered-by", "")

    if server:
        if "microsoft-iis" in server.lower():
            version = _first_version(server)
            tech.append(_tech("Microsoft-IIS", version, "http_header", "high"))
            tech.append(_tech("IIS", version, "http_header", "high"))
            tech.append(_tech("Windows Server", None, "http_header", "medium", note="probable"))
        if "apache" in server.lower():
            tech.append(_tech("Apache HTTP Server", _version_after(server, "Apache/"), "http_header", "high"))
            if "win64" in server.lower() or "win32" in server.lower():
                tech.append(_tech("Windows Server", None, "http_header", "medium", note="probable"))
            openssl = re.search(r"OpenSSL/([0-9][^\s;)]+)", server, flags=re.I)
            if openssl:
                tech.append(_tech("OpenSSL", openssl.group(1), "http_header", "high"))
        if "nginx" in server.lower():
            tech.append(_tech("Nginx", _version_after(server, "nginx/"), "http_header", "high"))
    if powered:
        if "asp.net" in powered.lower():
            tech.append(_tech("ASP.NET", _first_version(powered), "http_header", "high"))
        php = re.search(r"PHP/?([0-9][^\s;]*)?", powered, flags=re.I)
        if php:
            tech.append(_tech("PHP", php.group(1), "http_header", "high"))

    body_l = (body or "").lower()
    patterns = [
        (r"jquery(?:\.min)?[-.]([0-9][0-9a-zA-Z.\-]*)\.js|jquery-([0-9][0-9a-zA-Z.\-]*)", "jQuery"),
        (r"jquery-ui(?:\.min)?[-.]([0-9][0-9a-zA-Z.\-]*)\.js|jquery-ui-([0-9][0-9a-zA-Z.\-]*)", "jQuery UI"),
        (r"bootstrap(?:\.bundle|\.min)?[-.]([0-9][0-9a-zA-Z.\-]*)\.(?:js|css)|bootstrap[/_-]([0-9][0-9a-zA-Z.\-]*)", "Bootstrap"),
    ]
    for regex, name in patterns:
        m = re.search(regex, body_l, flags=re.I)
        if m:
            tech.append(_tech(name, next((g for g in m.groups() if g), None), "html_body", "medium"))
        elif name.lower().replace(" ", "-") in body_l or name.lower().replace(" ", "") in body_l:
            tech.append(_tech(name, None, "html_body", "medium"))
    simple = [
        ("modernizr", "Modernizr"), ("onetrust", "OneTrust"), ("prettyphoto", "prettyPhoto"),
        ("platform.twitter.com", "Twitter"), ("widgets.js", "Twitter"), ("wp-content", "WordPress"),
        ("glpi", "GLPI"), ("zabbix", "Zabbix"), ("fortinet", "Fortinet"), ("fortigate", "Fortinet"),
        ("fortipam", "Fortinet"), ("fortiguard", "Fortinet"),
    ]
    for needle, name in simple:
        if needle in body_l:
            tech.append(_tech(name, None, "html_body", "medium"))
    return tech


def _tech(name: str, version: str | None, source: str, confidence: str, note: str | None = None) -> dict:
    item = {"name": name, "source": source, "confidence": confidence}
    if version:
        item["version"] = version.strip().strip("/;,)")
    if note:
        item["note"] = note
    return item


def _dedup_technologies(items: list[dict]) -> list[dict]:
    dedup = {}
    for t in items:
        key = (t.get("name"), t.get("version") or "")
        dedup[key] = t
    return list(dedup.values())


def _version_after(text: str, token: str) -> str | None:
    idx = text.lower().find(token.lower())
    if idx < 0:
        return None
    rest = text[idx + len(token):]
    m = re.match(r"([0-9][^\s;)]*)", rest)
    return m.group(1) if m else None


def _first_version(text: str) -> str | None:
    m = re.search(r"([0-9]+(?:\.[0-9A-Za-z_-]+)+)", text or "")
    return m.group(1) if m else None


async def _asn_for_ip(ip: str, cache: dict[str, dict]) -> dict:
    if ip in cache:
        return cache[ip]
    if not _public_ip(ip):
        cache[ip] = _asn_unknown()
        return cache[ip]
    try:
        import ipaddress
        obj = ipaddress.ip_address(ip)
        if obj.version == 4:
            qname = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:
            qname = ".".join(reversed(obj.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        answers = await asyncio.to_thread(lambda: list(_resolver(3.0).resolve(qname, "TXT")))
        raw = str(answers[0]).replace('"', "") if answers else ""
        parts = [p.strip() for p in raw.split("|")]
        asn_num = parts[0] if parts else ""
        network = parts[1] if len(parts) > 1 else UNKNOWN
        cc = parts[2] if len(parts) > 2 else ""
        as_name = parts[4] if len(parts) > 4 else UNKNOWN
        asn_name = f"{as_name}" if as_name.startswith("AS") else f"AS{asn_num} - {as_name}" if asn_num and as_name != UNKNOWN else UNKNOWN
        country = COUNTRY_NAMES.get(cc.upper(), cc.upper() or UNKNOWN_COUNTRY)
        provider = _provider_from_asn_name(asn_name)
        cache[ip] = {"asn": f"AS{asn_num}" if asn_num and not str(asn_num).startswith("AS") else asn_num or UNKNOWN, "network": network, "asn_name": asn_name, "country": country, "provider": provider}
    except Exception:
        cache[ip] = _asn_unknown()
    return cache[ip]


def _asn_unknown() -> dict:
    return {"asn": UNKNOWN, "network": UNKNOWN, "asn_name": UNKNOWN, "country": UNKNOWN_COUNTRY, "provider": UNKNOWN}


def _provider_from_asn_name(name: str) -> str:
    if not name or name == UNKNOWN:
        return UNKNOWN
    if " - " in name:
        tail = name.split(" - ", 1)[1]
    else:
        tail = name
    return tail.split(",")[0].strip() or UNKNOWN


def _nmap_for_host(host: str, service_scan: dict) -> list[dict]:
    rows = []
    for p in service_scan.get("open_ports", []) or []:
        if (p.get("hostname") or p.get("host") or "").lower() == host.lower():
            rows.append(p)
    return rows


def _nmap_banner(p: dict) -> str | None:
    product = p.get("product") or ""
    version = p.get("version") or ""
    name = p.get("name") or p.get("service") or ""
    return " ".join(x for x in [product or name, version] if x).strip() or None


def _a_record_row(h: dict) -> dict:
    return {k: h.get(k) for k in ["host", "ip", "asn", "network", "asn_name", "country", "open_services", "technologies", "revip_count", "sources", "guardrail"]}


def _mx_record_row(h: dict) -> dict:
    row = _a_record_row(h)
    row["priority"] = h.get("priority")
    return row


def _ns_record_row(h: dict) -> dict:
    return _a_record_row(h)


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value))
    except Exception:
        return None


def _public_ip(ip: str | None) -> bool:
    return bool(ip and ip != "Not found" and is_public_ip(ip))


def _passive_configured() -> bool:
    return bool(os.getenv("SHODAN_API_KEY") or (os.getenv("CENSYS_API_ID") and os.getenv("CENSYS_API_SECRET")) or os.getenv("SECURITYTRAILS_API_KEY"))
