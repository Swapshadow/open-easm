from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
import ssl
from collections import Counter, defaultdict
from datetime import datetime, timezone
from html import unescape
from typing import Any

import dns.resolver
import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.services.network_guard import resolve_ips

MAX_HOSTS = int(os.getenv("OPENEASM_ENRICH_MAX_HOSTS", "150"))
CONCURRENCY = int(os.getenv("OPENEASM_ENRICH_CONCURRENCY", "10"))
HTTP_TIMEOUT = float(os.getenv("OPENEASM_HTTP_TIMEOUT", "8.0"))
RDAP_TIMEOUT = float(os.getenv("OPENEASM_RDAP_TIMEOUT", "5.0"))
ENABLE_RDAP = os.getenv("OPENEASM_ENABLE_RDAP", "true").lower() in {"1", "true", "yes", "on"}

TECH_RULES = [
    ("Apache", re.compile(r"apache", re.I)),
    ("nginx", re.compile(r"nginx", re.I)),
    ("Microsoft-IIS", re.compile(r"microsoft-iis|\biis\b", re.I)),
    ("OpenSSL", re.compile(r"openssl", re.I)),
    ("PHP", re.compile(r"php", re.I)),
    ("ASP.NET", re.compile(r"asp\.net|x-aspnet", re.I)),
    ("jQuery", re.compile(r"jquery(?:[-.]|/)?([0-9][0-9A-Za-z_.-]*)?", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(?:[-.]|/)?([0-9][0-9A-Za-z_.-]*)?", re.I)),
    ("Modernizr", re.compile(r"modernizr", re.I)),
    ("OneTrust", re.compile(r"onetrust", re.I)),
    ("WordPress", re.compile(r"wp-content|wordpress", re.I)),
    ("GLPI", re.compile(r"\bglpi\b", re.I)),
    ("Zabbix", re.compile(r"zabbix", re.I)),
    ("Fortinet", re.compile(r"fortinet|fortigate|fortipam|fortiguard", re.I)),
    ("Apache Tomcat", re.compile(r"tomcat", re.I)),
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _domain_match(hostname: str, domain: str) -> bool:
    hostname = hostname.strip(".").lower()
    domain = domain.strip(".").lower()
    return hostname == domain or hostname.endswith("." + domain)


def _uniq(items: list[str]) -> list[str]:
    return sorted({str(item).strip().strip(".").lower() for item in items if item})


def _host_candidates(domain: str, subdomains_result: dict, ip_inventory: dict) -> list[dict[str, Any]]:
    by_host: dict[str, dict[str, Any]] = {}

    def add(hostname: str, source: str = "candidate", entry: dict | None = None) -> None:
        if not hostname or not _domain_match(hostname, domain):
            return
        hostname = hostname.strip(".").lower()
        item = by_host.setdefault(
            hostname,
            {
                "hostname": hostname,
                "sources": set(),
                "ips": set(),
                "public_ips": set(),
                "blocked_ips": set(),
                "cname_chain": [],
                "resolved_name": None,
            },
        )
        item["sources"].add(source)
        if entry:
            item["resolved_name"] = entry.get("resolved_name") or item.get("resolved_name")
            item["cname_chain"] = entry.get("cname_chain") or item.get("cname_chain") or []
            for ip in entry.get("ips", []) or []:
                item["ips"].add(ip)
            for ip in entry.get("public_ips", []) or []:
                item["public_ips"].add(ip)
            for ip in entry.get("blocked_ips", []) or []:
                item["blocked_ips"].add(ip)

    add(domain, "root")
    add(f"www.{domain}", "www")

    for sub in subdomains_result.get("subdomains", []) or []:
        add(str(sub), "subdomain")

    for entry in ip_inventory.get("entries", []) or []:
        add(entry.get("hostname"), entry.get("source") or "inventory", entry)

    for ip_item in ip_inventory.get("unique_ips", []) or []:
        if not isinstance(ip_item, dict):
            continue
        for host in ip_item.get("hostnames", []) or []:
            add(host, "ip_inventory")
            item = by_host.get(host.strip(".").lower())
            if item:
                if ip_item.get("is_public"):
                    item["public_ips"].add(ip_item.get("ip"))
                else:
                    item["blocked_ips"].add(ip_item.get("ip"))

    # Resolve missing candidates. This keeps the enrichment useful even when a
    # passive source discovered a hostname after the inventory cap was reached.
    for hostname, item in by_host.items():
        if item["ips"] or item["public_ips"] or item["blocked_ips"]:
            continue
        guard = resolve_ips(hostname)
        for ip in guard.get("ips", []) or []:
            item["ips"].add(ip)
        for ip in guard.get("public_ips", []) or []:
            item["public_ips"].add(ip)
        for ip in guard.get("blocked_ips", []) or []:
            item["blocked_ips"].add(ip)

    ordered = []
    for hostname in sorted(by_host):
        item = by_host[hostname]
        ordered.append(
            {
                "hostname": hostname,
                "sources": sorted(item["sources"]),
                "ips": sorted(item["ips"] or item["public_ips"] or item["blocked_ips"]),
                "public_ips": sorted(ip for ip in item["public_ips"] if ip),
                "blocked_ips": sorted(ip for ip in item["blocked_ips"] if ip),
                "cname_chain": item.get("cname_chain") or [],
                "resolved_name": item.get("resolved_name") or hostname,
            }
        )
    return ordered[:MAX_HOSTS]


def _reverse_for_cymru(ip: str) -> tuple[str, str]:
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com", "TXT"
    nibbles = address.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com", "TXT"


def _cymru_lookup(ip: str) -> dict[str, Any]:
    try:
        qname, rtype = _reverse_for_cymru(ip)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0
        resolver.timeout = 3.0
        answers = resolver.resolve(qname, rtype)
        raw = " ".join(str(a).strip('"') for a in answers)
        # Format: AS | BGP Prefix | CC | Registry | Allocated | AS Name
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) >= 5 and parts[0].lower() != "as":
            return {
                "asn": f"AS{parts[0]}",
                "network": parts[1] if len(parts) > 1 else None,
                "country": parts[2] if len(parts) > 2 else None,
                "registry": parts[3] if len(parts) > 3 else None,
                "allocated": parts[4] if len(parts) > 4 else None,
                "asn_name": parts[5] if len(parts) > 5 else None,
                "source": "Team Cymru",
            }
    except Exception as exc:
        return {"error": str(exc), "source": "Team Cymru"}
    return {"source": "Team Cymru"}


async def _rdap_lookup(client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
    if not ENABLE_RDAP:
        return {}
    try:
        response = await client.get(f"https://rdap.org/ip/{ip}")
        response.raise_for_status()
        data = response.json()
        return {
            "rdap_handle": data.get("handle"),
            "rdap_name": data.get("name"),
            "country": data.get("country"),
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "provider": data.get("name") or data.get("handle"),
            "rdap_source": "rdap.org",
        }
    except Exception as exc:
        return {"rdap_error": str(exc), "rdap_source": "rdap.org"}


async def _enrich_ips(ip_inventory: dict) -> dict[str, dict[str, Any]]:
    ip_meta: dict[str, dict[str, Any]] = {}
    ips = []
    for item in ip_inventory.get("unique_ips", []) or []:
        if isinstance(item, dict) and item.get("ip") and item.get("is_public"):
            ips.append(item["ip"])
    ips = sorted(set(ips))

    async with httpx.AsyncClient(timeout=RDAP_TIMEOUT, follow_redirects=True) as client:
        rdap_tasks = {ip: asyncio.create_task(_rdap_lookup(client, ip)) for ip in ips}
        for ip in ips:
            cymru = await asyncio.to_thread(_cymru_lookup, ip)
            rdap = await rdap_tasks[ip]
            merged = {**cymru, **{k: v for k, v in rdap.items() if v}}
            if rdap.get("country") and not merged.get("country"):
                merged["country"] = rdap["country"]
            if not merged.get("provider"):
                merged["provider"] = merged.get("asn_name") or merged.get("rdap_name")
            ip_meta[ip] = merged

    for item in ip_inventory.get("unique_ips", []) or []:
        if isinstance(item, dict) and item.get("ip") in ip_meta:
            item.update({k: v for k, v in ip_meta[item["ip"]].items() if v not in (None, "", [], {})})
    return ip_meta


def _title_from_html(text: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    if not match:
        return None
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:180] if title else None


def _detect_technologies(headers: dict[str, str], body: str) -> tuple[list[str], list[str]]:
    haystack = "\n".join([f"{k}: {v}" for k, v in headers.items()]) + "\n" + (body or "")[:200000]
    technologies = []
    banners = []
    server = headers.get("server") or headers.get("Server")
    powered = headers.get("x-powered-by") or headers.get("X-Powered-By")
    if server:
        banners.append(server)
    if powered:
        banners.append(powered)
    for name, pattern in TECH_RULES:
        match = pattern.search(haystack)
        if match:
            version = match.group(1) if match.groups() and match.group(1) else ""
            technologies.append(f"{name}:{version}" if version and name in {"jQuery", "Bootstrap"} else name)
    return sorted(set(technologies)), sorted(set(banners))


async def _fetch_http(client: httpx.AsyncClient, url: str, verify: bool = True) -> dict[str, Any]:
    try:
        response = await client.get(url, follow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        text = response.text[:250000] if response.text else ""
        technologies, banners = _detect_technologies(headers, text)
        return {
            "url": url,
            "reachable": True,
            "status_code": response.status_code,
            "final_url": str(response.url),
            "server": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "title": _title_from_html(text),
            "headers": {h: headers.get(h) for h in SECURITY_HEADERS if headers.get(h)},
            "technologies": technologies,
            "banners": banners,
            "error": None,
        }
    except Exception as exc:
        return {
            "url": url,
            "reachable": False,
            "status_code": None,
            "final_url": None,
            "server": None,
            "x_powered_by": None,
            "title": None,
            "headers": {},
            "technologies": [],
            "banners": [],
            "error": str(exc),
        }


def _name_attr(cert: x509.Certificate, oid: NameOID) -> str | None:
    try:
        attrs = cert.subject.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _issuer_attr(cert: x509.Certificate, oid: NameOID) -> str | None:
    try:
        attrs = cert.issuer.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _cert_datetime(cert: x509.Certificate, attr: str) -> datetime | None:
    try:
        value = getattr(cert, attr + "_utc")
    except Exception:
        value = getattr(cert, attr, None)
    if value and value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def _tls_certificate(hostname: str, port: int = 443) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
        if not der:
            return {"reachable": False, "error": "Aucun certificat présenté"}
        cert = x509.load_der_x509_certificate(der)
        san_dns = []
        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            san_dns = san.get_values_for_type(x509.DNSName)
        except Exception:
            san_dns = []
        not_after = _cert_datetime(cert, "not_valid_after")
        not_before = _cert_datetime(cert, "not_valid_before")
        days_remaining = None
        if not_after:
            days_remaining = (not_after - datetime.now(timezone.utc)).days
        return {
            "reachable": True,
            "tls_version": tls_version,
            "subject_cn": _name_attr(cert, NameOID.COMMON_NAME),
            "issuer_cn": _issuer_attr(cert, NameOID.COMMON_NAME),
            "issuer_org": _issuer_attr(cert, NameOID.ORGANIZATION_NAME),
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "days_remaining": days_remaining,
            "san_dns": san_dns[:80],
            "serial_number": str(cert.serial_number),
            "error": None,
        }
    except Exception as exc:
        return {"reachable": False, "error": str(exc)}


async def _enrich_host(host: dict[str, Any], ip_meta: dict[str, dict[str, Any]], sem: asyncio.Semaphore) -> dict[str, Any]:
    async with sem:
        hostname = host["hostname"]
        public_ips = host.get("public_ips", []) or []
        if not public_ips or host.get("blocked_ips"):
            host.update({
                "status": "skipped_by_guard",
                "reason": "Résolution non publique ou mixte ; enrichissement actif HTTP/TLS bloqué.",
                "http": None,
                "https": None,
                "tls_certificate": None,
                "technologies": [],
                "banners": [],
                "services": [],
            })
            return host

        limits = httpx.Limits(max_keepalive_connections=4, max_connections=8)
        timeout = httpx.Timeout(HTTP_TIMEOUT)
        async with httpx.AsyncClient(timeout=timeout, limits=limits, verify=False) as client:
            http_result, https_result = await asyncio.gather(
                _fetch_http(client, f"http://{hostname}", verify=False),
                _fetch_http(client, f"https://{hostname}", verify=False),
            )
        tls_cert = await asyncio.to_thread(_tls_certificate, hostname)

        all_tech = sorted(set((http_result.get("technologies") or []) + (https_result.get("technologies") or [])))
        all_banners = sorted(set((http_result.get("banners") or []) + (https_result.get("banners") or [])))
        ip_details = [ip_meta.get(ip, {}) | {"ip": ip} for ip in public_ips]
        countries = sorted({str(d.get("country")) for d in ip_details if d.get("country")})
        providers = sorted({str(d.get("provider") or d.get("asn_name")) for d in ip_details if d.get("provider") or d.get("asn_name")})
        networks = sorted({str(d.get("network") or d.get("rdap_name")) for d in ip_details if d.get("network") or d.get("rdap_name")})

        host.update({
            "status": "ok",
            "http": http_result,
            "https": https_result,
            "tls_certificate": tls_cert,
            "technologies": all_tech,
            "banners": all_banners,
            "title": https_result.get("title") or http_result.get("title"),
            "best_url": https_result.get("final_url") if https_result.get("reachable") else http_result.get("final_url"),
            "best_status": https_result.get("status_code") if https_result.get("reachable") else http_result.get("status_code"),
            "countries": countries,
            "providers": providers,
            "networks": networks,
            "ip_details": ip_details,
            "services": [],
        })
        return host


def _summary(hosts: list[dict[str, Any]], ip_inventory: dict) -> dict[str, Any]:
    locations = Counter()
    hosting = Counter()
    banners = Counter()
    techs = Counter()
    for item in ip_inventory.get("unique_ips", []) or []:
        if not isinstance(item, dict) or not item.get("is_public"):
            continue
        country = item.get("country") or "Unknown"
        locations[country] += 1
        network_label = " / ".join([x for x in [item.get("asn"), item.get("asn_name") or item.get("provider"), item.get("network")] if x])
        if network_label:
            hosting[network_label] += 1
    for host in hosts:
        for banner in host.get("banners", []) or []:
            banners[banner] += 1
        for tech in host.get("technologies", []) or []:
            techs[tech] += 1
    return {
        "host_count": len(hosts),
        "active_host_count": len([h for h in hosts if h.get("status") == "ok"]),
        "skipped_host_count": len([h for h in hosts if h.get("status") != "ok"]),
        "location_counts": dict(locations.most_common()),
        "hosting_networks": dict(hosting.most_common(40)),
        "service_banners": dict(banners.most_common(40)),
        "technology_counts": dict(techs.most_common(40)),
        "note": "Enrichissement DNSDumpster-like : ASN/hébergeur/localisation IP, titres HTTP, banners, technologies, certificats TLS et rattachement des services Nmap. Aucun exploit, bruteforce ou script intrusif.",
    }


async def enrich_public_hosts(domain: str, subdomains_result: dict, ip_inventory: dict) -> dict[str, Any]:
    ip_meta = await _enrich_ips(ip_inventory)
    candidates = _host_candidates(domain, subdomains_result, ip_inventory)
    sem = asyncio.Semaphore(CONCURRENCY)
    hosts = await asyncio.gather(*[_enrich_host(host, ip_meta, sem) for host in candidates]) if candidates else []
    return {
        "domain": domain,
        "version": "Beta 26.6",
        "mode": "dnsdumpster_like_public_host_enrichment",
        "max_hosts": MAX_HOSTS,
        "concurrency": CONCURRENCY,
        "hosts": list(hosts),
        "summary": _summary(list(hosts), ip_inventory),
    }


def attach_services_to_hosts(host_enrichment: dict, service_scan: dict) -> dict:
    by_host = {h.get("hostname"): h for h in host_enrichment.get("hosts", []) if isinstance(h, dict)}
    for port in service_scan.get("open_ports", []) or []:
        hostname = port.get("hostname")
        if not hostname or hostname not in by_host:
            continue
        service = {
            "port": port.get("port"),
            "protocol": port.get("protocol", "tcp"),
            "service": port.get("name") or port.get("service"),
            "product": port.get("product"),
            "version": port.get("version") or "Version non exposée",
            "cpe": port.get("cpe") or port.get("cpes") or [],
            "cves": port.get("cves") or [],
            "evidence": port.get("evidence"),
        }
        by_host[hostname].setdefault("services", []).append(service)

    service_banners = Counter((host_enrichment.get("summary") or {}).get("service_banners") or {})
    for port in service_scan.get("open_ports", []) or []:
        label = " ".join([str(x) for x in [port.get("product"), port.get("version")] if x]).strip()
        if not label:
            label = str(port.get("name") or port.get("service") or "unknown")
        service_banners[label] += 1
    host_enrichment.setdefault("summary", {})["service_banners"] = dict(service_banners.most_common(60))
    host_enrichment["summary"]["nmap_service_count"] = service_scan.get("count_open_ports", 0)
    return host_enrichment
