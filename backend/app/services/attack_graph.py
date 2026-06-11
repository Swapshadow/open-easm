from __future__ import annotations

from collections import Counter
from typing import Any

MAX_SUBDOMAINS = 120
MAX_IPS = 120
MAX_FINDINGS = 60
MAX_SERVICES = 100


def build_attack_graph(audit: dict[str, Any]) -> dict[str, Any]:
    """Build a defensive relationship graph for the Graph Explorer.

    The graph is intentionally explanatory, not offensive: it links domains,
    subdomains, public IPs, web targets, exposed services, CVE correlations and
    prioritized findings already produced by OpenEASM.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def add_node(node_id: str, label: str, node_type: str, **props: Any) -> str:
        if not node_id:
            return ""
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label or node_id,
                "type": node_type,
                "weight": 1,
                "properties": {},
            }
        else:
            nodes[node_id]["weight"] = int(nodes[node_id].get("weight", 1)) + 1
        nodes[node_id]["properties"].update({k: v for k, v in props.items() if v not in (None, "", [], {})})
        return node_id

    def add_edge(source: str, target: str, label: str, edge_type: str = "related", **props: Any) -> None:
        if not source or not target or source == target:
            return
        edge_id = f"{source}->{target}:{edge_type}:{label}"
        if edge_id not in edges:
            edges[edge_id] = {
                "id": edge_id,
                "source": source,
                "target": target,
                "label": label,
                "type": edge_type,
                "weight": 1,
                "properties": {},
            }
        else:
            edges[edge_id]["weight"] = int(edges[edge_id].get("weight", 1)) + 1
        edges[edge_id]["properties"].update({k: v for k, v in props.items() if v not in (None, "", [], {})})

    domain = audit.get("domain") or "domain"
    root_id = add_node(f"domain:{domain}", domain, "domain", score=(audit.get("score") or {}).get("score"))

    profile = audit.get("domain_profile") or {}
    if profile:
        profile_id = add_node(f"profile:{profile.get('label', 'profil')}", profile.get("label", "Profil"), "profile")
        add_edge(root_id, profile_id, "profil", "classified_as")

    canonical_hosts = audit.get("canonical_hosts") or (audit.get("dnsdumpster_like") or {}).get("canonical_hosts") or (audit.get("dnsdumpster_like") or {}).get("hosts") or []
    host_alias_map = {}
    for h in canonical_hosts[:MAX_SUBDOMAINS]:
        host = h.get("canonical_host") or h.get("host")
        if not host:
            continue
        host_id = add_node(
            f"domain:{host}",
            host,
            "domain" if host == domain else "subdomain",
            aliases=h.get("aliases") or [],
            ip=h.get("ip"),
            asn=h.get("asn"),
            services=len(h.get("open_services") or []) + len(h.get("nmap_services") or []),
            technologies=[t.get("name") for t in (h.get("technologies") or []) if t.get("name")],
        )
        add_edge(root_id, host_id, "host canonique", "canonical_host")
        for alias in h.get("aliases") or []:
            host_alias_map[alias] = host
        if h.get("ip"):
            ip_id = add_node(f"ip:{h.get('ip')}", h.get("ip"), "ip", asn=h.get("asn"), country=h.get("country"))
            add_edge(host_id, ip_id, "résout vers", "dns_resolution")
        for svc in (h.get("open_services") or [])[:4]:
            label = f"{svc.get('port')}/{svc.get('scheme') or svc.get('service')}"
            sid = add_node(f"service:{host}:{label}", label, "service", banner=svc.get("banner"), title=svc.get("title"))
            add_edge(host_id, sid, "HTTP(S)", "web_service")
        for tech in (h.get("technologies") or [])[:6]:
            name = tech.get("name")
            if name:
                tid = add_node(f"tech:{name}", name, "technology", version=tech.get("version"))
                add_edge(host_id, tid, "technologie", "uses_technology")

    dns = audit.get("dns") or {}
    for ip in (dns.get("public_ips") or [])[:MAX_IPS]:
        ip_id = add_node(f"ip:{ip}", ip, "ip", scope="dns_root")
        add_edge(root_id, ip_id, "résout vers", "dns_a")

    inventory = audit.get("ip_inventory") or {}
    ip_items = inventory.get("unique_ips") or inventory.get("display_ips") or []
    for item in ip_items[:MAX_IPS]:
        ip = item.get("ip") if isinstance(item, dict) else str(item)
        if not ip:
            continue
        ip_id = add_node(f"ip:{ip}", ip, "ip", scope=item.get("scope") if isinstance(item, dict) else None, sources=item.get("sources") if isinstance(item, dict) else None)
        add_edge(root_id, ip_id, "IP inventoriée", "inventory")
    scan = audit.get("service_scan") or {}
    for port in scan.get("open_ports", [])[:MAX_SERVICES]:
        host = host_alias_map.get((port.get("hostname") or port.get("host") or domain), port.get("hostname") or port.get("host") or domain)
        host_id = add_node(f"domain:{host}", host, "domain" if host == domain else "subdomain")
        service_label = f"{port.get('port')}/{port.get('protocol', 'tcp')} {port.get('name') or port.get('service') or 'service'}".strip()
        service_id = add_node(
            f"service:{host}:{port.get('port')}:{port.get('protocol', 'tcp')}",
            service_label,
            "service",
            product=port.get("product"),
            version=port.get("version"),
            evidence=port.get("evidence"),
        )
        add_edge(host_id, service_id, "expose", "exposes_service", port=port.get("port"))
        for cve in port.get("cves", []) or []:
            cve_id = add_node(
                f"cve:{cve.get('cve')}",
                cve.get("cve", "CVE"),
                "cve",
                severity=cve.get("severity"),
                cvss=cve.get("cvss"),
            )
            add_edge(service_id, cve_id, "corrélation CVE", "cve_correlation", confidence=cve.get("confidence"))

    for idx, finding in enumerate(sorted(audit.get("findings", []), key=lambda f: _severity_rank(f.get("severity")))[:MAX_FINDINGS]):
        title = finding.get("title") or finding.get("category") or "Constat"
        sev = finding.get("severity") or "info"
        finding_id = add_node(
            f"finding:{idx}:{abs(hash(title))}",
            title[:80],
            "finding",
            severity=sev,
            category=finding.get("category"),
            recommendation=finding.get("recommendation"),
        )
        loc = finding.get("location") or {}
        host = loc.get("hostname") or loc.get("host") or loc.get("domain") or domain
        host_id = add_node(f"domain:{host}", host, "domain" if host == domain else "subdomain")
        add_edge(host_id, finding_id, sev, "has_finding", severity=sev)

    type_counts = Counter(node.get("type") for node in nodes.values())
    severity_counts = Counter(
        str((node.get("properties") or {}).get("severity", "info"))
        for node in nodes.values()
        if node.get("type") in {"finding", "cve"}
    )

    return {
        "version": "v7.5",
        "domain": domain,
        "generated_from_audit_id": audit.get("id"),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "metrics": {
            "nodes": len(nodes),
            "edges": len(edges),
            "types": dict(type_counts),
            "severity": dict(severity_counts),
            "open_ports": scan.get("count_open_ports", 0),
            "service_cves": scan.get("count_cves", 0),
            "public_ips": inventory.get("public_ip_count", 0),
            "subdomains": (audit.get("subdomains") or {}).get("count", 0),
            "canonical_hosts": len(canonical_hosts or []),
            "aliases_grouped": sum(len(h.get("aliases") or []) for h in (canonical_hosts or [])),
        },
        "legend": {
            "domain": "Domaine racine",
            "subdomain": "Sous-domaine public",
            "ip": "Adresse IP publique",
            "web": "Service web observé",
            "service": "Port/service détecté par Nmap ou HTTP(S)",
            "technology": "Technologie détectée",
            "cve": "CVE corrélée sans exploitation",
            "finding": "Constat priorisé",
        },
    }


def _severity_rank(value: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(value).lower(), 5)
