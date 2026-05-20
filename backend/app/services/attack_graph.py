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

    dns = audit.get("dns") or {}
    for ip in (dns.get("public_ips") or [])[:MAX_IPS]:
        ip_id = add_node(f"ip:{ip}", ip, "ip", scope="dns_root")
        add_edge(root_id, ip_id, "résout vers", "dns_a")

    subdomains = (audit.get("subdomains") or {}).get("subdomains") or []
    for sub in subdomains[:MAX_SUBDOMAINS]:
        sub_id = add_node(f"domain:{sub}", sub, "subdomain")
        add_edge(root_id, sub_id, "sous-domaine", "subdomain")

    inventory = audit.get("ip_inventory") or {}
    ip_items = inventory.get("unique_ips") or inventory.get("display_ips") or []
    for item in ip_items[:MAX_IPS]:
        ip = item.get("ip") if isinstance(item, dict) else str(item)
        if not ip:
            continue
        ip_id = add_node(
            f"ip:{ip}",
            ip,
            "ip",
            scope=item.get("scope") if isinstance(item, dict) else None,
            sources=item.get("sources") if isinstance(item, dict) else None,
        )
        add_edge(root_id, ip_id, "IP inventoriée", "inventory")
        for host in (item.get("hostnames", []) if isinstance(item, dict) else [])[:12]:
            host_type = "domain" if host == domain else "subdomain"
            host_id = add_node(f"domain:{host}", host, host_type)
            add_edge(host_id, ip_id, "résout vers", "dns_resolution")

    for target in (audit.get("web") or {}).get("targets", [])[:MAX_SUBDOMAINS]:
        host = target.get("hostname")
        if not host:
            continue
        host_id = add_node(f"domain:{host}", host, "domain" if host == domain else "subdomain")
        add_edge(root_id, host_id, "cible web", "web_target")
        if target.get("reachable"):
            web_id = add_node(f"web:{host}", target.get("best_scheme") or host, "web", reachable=True)
            add_edge(host_id, web_id, "HTTP(S)", "web_service")
        guard = target.get("guard") or {}
        for ip in guard.get("public_ips", [])[:12]:
            ip_id = add_node(f"ip:{ip}", ip, "ip", source="web_guard")
            add_edge(host_id, ip_id, "résout vers", "web_resolution")

    scan = audit.get("service_scan") or {}
    for port in scan.get("open_ports", [])[:MAX_SERVICES]:
        host = port.get("hostname") or domain
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
        },
        "legend": {
            "domain": "Domaine racine",
            "subdomain": "Sous-domaine public",
            "ip": "Adresse IP publique",
            "web": "Service web observé",
            "service": "Port/service détecté par Nmap",
            "cve": "CVE corrélée sans exploitation",
            "finding": "Constat priorisé",
        },
    }


def _severity_rank(value: Any) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(value).lower(), 5)
