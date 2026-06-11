from __future__ import annotations

from copy import deepcopy
from typing import Any

UNKNOWN = "Non détecté"


def canonicalize_hosts(hosts: list[dict[str, Any]] | None, service_scan: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a display-safe canonical host inventory without deleting raw data.

    Only exact ``www.X`` aliases are folded into ``X``.  They are merged when
    resolution, ASN, web/Nmap services, HTTP titles and TLS certificate markers
    are equivalent. Divergent ``www`` entries remain first-class hosts.
    """
    raw_hosts = [deepcopy(h) for h in (hosts or []) if isinstance(h, dict)]
    by_host = {_host_name(h): h for h in raw_hosts if _host_name(h)}
    consumed: set[str] = set()
    canonical: list[dict[str, Any]] = []
    alias_map: dict[str, str] = {}

    for name in sorted(by_host):
        if name in consumed or name.startswith("www."):
            continue
        base = by_host[name]
        aliases: list[dict[str, Any]] = []
        www = f"www.{name}"
        if www in by_host and _equivalent(base, by_host[www]):
            aliases.append(by_host[www])
            consumed.add(www)
            alias_map[www] = name
        canonical.append(_merge_group(name, [base] + aliases))
        consumed.add(name)

    for name in sorted(by_host):
        if name in consumed:
            continue
        canonical.append(_merge_group(name, [by_host[name]]))
        consumed.add(name)

    raw_nmap = deepcopy((service_scan or {}).get("open_ports", []) or [])
    canonical_nmap = consolidate_nmap_services(raw_nmap, alias_map)
    by_canon = {h["canonical_host"]: h for h in canonical}
    for h in canonical:
        host = h["canonical_host"]
        nmap = [p for p in canonical_nmap if _port_host(p) == host]
        h["nmap_services"] = nmap
        h["services"] = _dedupe_dicts((h.get("open_services") or []) + nmap, _service_key)
        # Backwards-compatible display field names used by existing reports.
        h["host"] = host
        h["aliases"] = sorted(dict.fromkeys(h.get("aliases") or []))
    for port in canonical_nmap:
        host = _port_host(port)
        if host in by_canon:
            continue
        # Nmap-only host: keep it visible instead of dropping data.
        canonical.append(_merge_group(host, [{"host": host, "nmap_services": [port], "sources": ["nmap"]}]))

    aliases_count = sum(len(h.get("aliases") or []) for h in canonical)
    return {
        "canonical_hosts": canonical,
        "alias_map": alias_map,
        "aliases_count": aliases_count,
        "raw_hosts": raw_hosts,
        "raw_nmap_services": raw_nmap,
        "canonical_nmap_services": canonical_nmap,
        "summary": summarize_canonical_hosts(canonical, canonical_nmap),
    }


def consolidate_nmap_services(open_ports: list[dict[str, Any]] | None, alias_map: dict[str, str] | None = None) -> list[dict[str, Any]]:
    alias_map = alias_map or {}
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for raw in open_ports or []:
        if not isinstance(raw, dict):
            continue
        item = deepcopy(raw)
        raw_host = _port_host(item)
        host = alias_map.get(raw_host, raw_host)
        item["raw_hostname"] = raw_host
        item["hostname"] = host
        item["host"] = host
        key = (
            host,
            item.get("port"),
            item.get("protocol", "tcp"),
            item.get("name") or item.get("service"),
            item.get("product") or "",
            item.get("version") or "",
        )
        if key not in merged:
            item["aliases"] = [raw_host] if raw_host and raw_host != host else []
            item["raw_hosts"] = [raw_host] if raw_host else []
            merged[key] = item
        else:
            if raw_host and raw_host != host:
                merged[key].setdefault("aliases", []).append(raw_host)
            if raw_host:
                merged[key].setdefault("raw_hosts", []).append(raw_host)
            merged[key]["cves"] = _dedupe_dicts((merged[key].get("cves") or []) + (item.get("cves") or []), lambda c: c.get("cve") or str(c))
    out = []
    for item in merged.values():
        item["aliases"] = sorted(dict.fromkeys(item.get("aliases") or []))
        item["raw_hosts"] = sorted(dict.fromkeys(item.get("raw_hosts") or []))
        out.append(item)
    return sorted(out, key=lambda p: (_port_host(p), int(p.get("port") or 0), str(p.get("protocol") or "tcp")))


def summarize_canonical_hosts(hosts: list[dict[str, Any]], nmap_ports: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    http_services = 0
    technologies = set()
    asns = set()
    locations = set()
    http_without_nmap = 0
    for h in hosts or []:
        open_services = h.get("open_services") or []
        nmap = h.get("nmap_services") or []
        if open_services and not nmap:
            http_without_nmap += 1
        http_services += sum(1 for s in open_services if (s.get("scheme") or s.get("service")) in {"http", "https"})
        asn = h.get("asn")
        if asn and asn != UNKNOWN:
            asns.add(asn)
        country = h.get("country")
        if country and country != "Unknown":
            locations.add(country)
        for t in h.get("technologies") or []:
            if t.get("name"):
                technologies.add((t.get("name"), t.get("version") or ""))
    return {
        "canonical_hosts": len(hosts or []),
        "aliases_grouped": sum(len(h.get("aliases") or []) for h in hosts or []),
        "http_https_services": http_services,
        "nmap_services": len(nmap_ports or []),
        "technologies": len(technologies),
        "asn_networks": len(asns),
        "locations": len(locations),
        "http_hosts_without_nmap": http_without_nmap,
    }


def _merge_group(canonical_host: str, group: list[dict[str, Any]]) -> dict[str, Any]:
    primary = deepcopy(group[0]) if group else {"host": canonical_host}
    aliases = [_host_name(h) for h in group[1:] if _host_name(h)]
    raw_names = [_host_name(h) for h in group if _host_name(h)]
    services = _dedupe_dicts([s for h in group for s in (h.get("open_services") or [])], _service_key)
    nmap = _dedupe_dicts([s for h in group for s in (h.get("nmap_services") or [])], _nmap_key)
    tech = _dedupe_dicts([t for h in group for t in (h.get("technologies") or [])], lambda t: (t.get("name"), t.get("version") or ""))
    sources = sorted(dict.fromkeys([s for h in group for s in (h.get("sources") or [])]))
    ips = sorted(dict.fromkeys([ip for h in group for ip in (h.get("ips") or ([h.get("ip")] if h.get("ip") else [])) if ip]))
    primary.update({
        "canonical_host": canonical_host,
        "host": canonical_host,
        "aliases": aliases,
        "dedupe_reason": "same_ip_same_asn_same_services" if aliases else "canonical",
        "raw_hosts": raw_names,
        "ips": ips or primary.get("ips") or [],
        "open_services": services,
        "services": services + nmap,
        "nmap_services": nmap,
        "technologies": tech,
        "sources": sources,
    })
    return primary


def _equivalent(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return (
        _ip_sig(a) == _ip_sig(b)
        and (a.get("asn") or UNKNOWN) == (b.get("asn") or UNKNOWN)
        and _service_sig(a) == _service_sig(b)
        and _title_sig(a) == _title_sig(b)
        and _tls_sig(a) == _tls_sig(b)
    )


def _host_name(item: dict[str, Any]) -> str:
    return str(item.get("host") or item.get("hostname") or item.get("canonical_host") or "").strip().lower().strip(".")


def _port_host(item: dict[str, Any]) -> str:
    return str(item.get("hostname") or item.get("host") or "").strip().lower().strip(".")


def _ip_sig(h: dict[str, Any]) -> tuple[str, ...]:
    ips = h.get("ips") or ([h.get("ip")] if h.get("ip") else [])
    return tuple(sorted(str(ip) for ip in ips if ip and ip != "Not found"))


def _service_key(s: dict[str, Any]) -> tuple[Any, ...]:
    return (s.get("scheme") or s.get("service"), s.get("port"), s.get("banner") or "", s.get("title") or "", s.get("status_code") or "")


def _nmap_key(s: dict[str, Any]) -> tuple[Any, ...]:
    return (s.get("port"), s.get("protocol", "tcp"), s.get("name") or s.get("service"), s.get("product") or "", s.get("version") or "")


def _service_sig(h: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(sorted([_service_key(s) for s in (h.get("open_services") or [])] + [_nmap_key(s) for s in (h.get("nmap_services") or [])]))


def _title_sig(h: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    http = h.get("http") or {}
    https = h.get("https") or {}
    service_titles = tuple(sorted(str(s.get("title")) for s in h.get("open_services") or [] if s.get("title") and s.get("title") != UNKNOWN))
    return (str(http.get("title") or ""), str(https.get("title") or ""), service_titles)


def _tls_sig(h: dict[str, Any]) -> tuple[str, tuple[str, ...], str]:
    tls = h.get("tls") or {}
    return (str(tls.get("cn") or ""), tuple(sorted(str(x) for x in (tls.get("san") or []))), str(tls.get("issuer") or ""))


def _dedupe_dicts(items: list[Any], key_fn) -> list[dict[str, Any]]:
    out: dict[Any, dict[str, Any]] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        out[key_fn(item)] = deepcopy(item)
    return list(out.values())
