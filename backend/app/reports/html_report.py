from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
import re

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAX_TABLE_ROWS = 120
MAX_SUBDOMAINS = 150


class SafeHtml(str):
    """Marker for tiny internally generated HTML snippets."""


def safe_get(data: Any, path: str, default: Any = "") -> Any:
    """Safely read a dotted path from nested dictionaries/lists."""
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part, default)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else default
        else:
            return default
        if current is None:
            return default
    return current


def esc(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        value = str(value)
    return escape(str(value), quote=True)


def _slug_domain(domain: Any) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(domain or "unknown")).strip("._-")
    return (slug or "unknown").replace(".", "_")[:120]


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _join(value: Any, limit: int = 6) -> str:
    items = _as_list(value)
    rendered = [str(item) for item in items[:limit]]
    if len(items) > limit:
        rendered.append(f"+{len(items) - limit}")
    return ", ".join(rendered)


def _severity_key(value: Any) -> str:
    sev = str(value or "info").lower()
    if sev in {"critical", "critique", "blocker"}:
        return "critical"
    if sev in {"high", "haut", "elevated", "élevé", "eleve"}:
        return "high"
    if sev in {"medium", "moyen", "moderate"}:
        return "medium"
    if sev in {"low", "faible"}:
        return "low"
    return "info"


def severity_badge(severity: Any) -> str:
    key = _severity_key(severity)
    return SafeHtml(f'<span class="badge severity-{key}">{esc(severity or key)}</span>')


def _priority_for_severity(severity: Any) -> tuple[str, str]:
    key = _severity_key(severity)
    return {
        "critical": ("P1", "24-72h"),
        "high": ("P2", "7 jours"),
        "medium": ("P3", "30 jours"),
        "low": ("P4", "90 jours"),
        "info": ("P4", "Best effort"),
    }.get(key, ("P4", "Best effort"))


def progress_bar(value: Any, max_value: Any = 100, label: str = "") -> str:
    try:
        numeric = float(value or 0)
        maximum = float(max_value or 100)
    except (TypeError, ValueError):
        numeric, maximum = 0.0, 100.0
    pct = 0 if maximum <= 0 else max(0, min(100, numeric / maximum * 100))
    return (
        '<div class="progress-wrap">'
        f'<div class="progress-label"><span>{esc(label)}</span><strong>{esc(round(numeric, 1))} / {esc(round(maximum, 1))}</strong></div>'
        f'<div class="progress"><span style="width:{pct:.1f}%"></span></div>'
        '</div>'
    )


def render_table(headers: list[str], rows: list[list[Any]], empty: str = "Aucune donnée disponible.", max_rows: int = MAX_TABLE_ROWS) -> str:
    if not rows:
        return f'<p class="notice">{esc(empty)}</p>'
    visible = rows[:max_rows]
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in visible:
        cells = "".join(f"<td>{cell if isinstance(cell, SafeHtml) else esc(cell)}</td>" for cell in row)
        body.append(f"<tr>{cells}</tr>")
    note = ""
    if len(rows) > max_rows:
        note = f'<p class="notice">Affichage limité à {max_rows} lignes sur {len(rows)}. Liste complète disponible dans JSON/Excel.</p>'
    return f'<div class="table-scroll"><table class="table"><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>{note}'


def section(section_id: str, title: str, body: str, subtitle: str = "") -> str:
    return (
        f'<section id="{esc(section_id)}" class="section">'
        f'<div class="section-title"><span>{esc(section_id).zfill(2)}</span><h2>{esc(title)}</h2></div>'
        f'{f"<p class=\"section-subtitle\">{esc(subtitle)}</p>" if subtitle else ""}'
        f'{body}'
        '</section>'
    )


def _metric(label: str, value: Any, hint: str = "") -> str:
    return f'<div class="metric-card"><span>{esc(label)}</span><strong>{esc(value)}</strong>{f"<small>{esc(hint)}</small>" if hint else ""}</div>'


def _finding_sort_key(finding: dict) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(_severity_key(finding.get("severity")), 5)


def _build_executive_summary(audit: dict) -> str:
    risk = audit.get("executive_risk") or {}
    if risk.get("board_summary"):
        summary = esc(risk.get("board_summary"))
    else:
        domain = audit.get("domain", "domaine audité")
        score = safe_get(audit, "score.score", "N/A")
        findings = audit.get("findings") or []
        public_ips = safe_get(audit, "ip_inventory.public_ip_count", 0)
        subdomains = safe_get(audit, "subdomains.count", len(safe_get(audit, "subdomains.subdomains", [])))
        summary = (
            f"L'audit public défensif de {esc(domain)} présente un score global de {esc(score)} / 1000, "
            f"avec {esc(public_ips)} IP publiques, {esc(subdomains)} sous-domaines observés et {esc(len(findings))} constats. "
            "Les éléments ci-dessous priorisent les actions de réduction d'exposition sans exploitation active."
        )
    findings = audit.get("findings") or []
    sev_counts = Counter(_severity_key(f.get("severity")) for f in findings if isinstance(f, dict))
    strengths = []
    weaknesses = []
    if safe_get(audit, "tls_score.global_score", 0) and int(safe_get(audit, "tls_score.global_score", 0) or 0) >= 75:
        strengths.append("Posture TLS globalement robuste sur les cibles testées.")
    if not findings:
        strengths.append("Aucun constat consolidé n'a été remonté par les modules disponibles.")
    if sev_counts.get("critical") or sev_counts.get("high"):
        weaknesses.append(f"{sev_counts.get('critical', 0)} critique(s) et {sev_counts.get('high', 0)} élevé(s) à traiter en priorité.")
    if safe_get(audit, "service_scan.count_open_ports", 0):
        weaknesses.append("Des services exposés ont été identifiés par Nmap service/version/port non exploitant.")
    if not strengths:
        strengths.append("Inventaire EASM consolidé disponible pour piloter la remédiation.")
    if not weaknesses:
        weaknesses.append("Continuer la surveillance et vérifier les contrôles DNS, mail, web et TLS dans le temps.")
    return (
        f'<p class="lead">{summary}</p>'
        '<div class="two-col"><div class="cardlet"><h3>Points forts</h3><ul>'
        + "".join(f"<li>{esc(s)}</li>" for s in strengths)
        + '</ul></div><div class="cardlet"><h3>Points faibles</h3><ul>'
        + "".join(f"<li>{esc(w)}</li>" for w in weaknesses)
        + '</ul></div></div>'
    )


def _render_scoring(audit: dict) -> str:
    score = audit.get("score") or {}
    risk = audit.get("executive_risk") or {}
    pillars = risk.get("pillar_scores") or risk.get("pillars") or score.get("pillars") or {}
    rows = []
    if isinstance(pillars, dict):
        for name, data in pillars.items():
            if isinstance(data, dict):
                value = data.get("score", data.get("value", "N/A"))
                max_value = data.get("max_score", data.get("max", 100))
            else:
                value, max_value = data, 100
            rows.append([name, f"{value} / {max_value}"])
    return (
        progress_bar(score.get("score", 0), score.get("max_score", 1000), "Score global")
        + progress_bar(risk.get("overall_score", risk.get("score", 0)), risk.get("max_score", 100), "Score exécutif")
        + render_table(["Pilier", "Score"], rows, "Aucun score par pilier disponible.")
    )


def _render_action_plan(audit: dict) -> str:
    rows = []
    for finding in sorted([f for f in audit.get("findings", []) if isinstance(f, dict)], key=_finding_sort_key):
        priority, sla = _priority_for_severity(finding.get("severity"))
        rows.append([
            priority,
            severity_badge(finding.get("severity")),
            finding.get("category", ""),
            finding.get("applies_to") or finding.get("location") or finding.get("source") or "",
            finding.get("recommendation") or finding.get("remediation") or "À qualifier par l'équipe sécurité.",
            sla,
        ])
    return render_table(["Priorité", "Sévérité", "Catégorie", "Lieu/source", "Recommandation", "SLA cible"], rows)


def _render_findings(audit: dict) -> str:
    findings = sorted([f for f in audit.get("findings", []) if isinstance(f, dict)], key=_finding_sort_key)
    if not findings:
        return '<p class="notice">Aucun finding détaillé disponible.</p>'
    cards = []
    for finding in findings[:80]:
        proof = finding.get("evidence") or finding.get("proof") or finding.get("details") or ""
        cards.append(
            '<article class="finding">'
            f'<div class="finding-head"><h3>{esc(finding.get("title", "Finding"))}</h3>{severity_badge(finding.get("severity"))}</div>'
            f'<p>{esc(finding.get("description", ""))}</p>'
            '<dl class="finding-meta">'
            f'<dt>Catégorie</dt><dd>{esc(finding.get("category", ""))}</dd>'
            f'<dt>Localisation</dt><dd>{esc(finding.get("applies_to") or finding.get("location") or finding.get("source") or "")}</dd>'
            f'<dt>Recommandation</dt><dd>{esc(finding.get("recommendation") or finding.get("remediation") or "")}</dd>'
            f'{f"<dt>Preuve</dt><dd class=\"code\">{esc(proof)}</dd>" if proof else ""}'
            '</dl></article>'
        )
    note = '<p class="notice">Findings tronqués dans le HTML. Liste complète disponible dans JSON/Excel.</p>' if len(findings) > 80 else ""
    return "".join(cards) + note


def _render_dns(audit: dict) -> str:
    dns = audit.get("dns") or {}
    rows = [
        ["A", _join(dns.get("a_records") or dns.get("a") or dns.get("public_ips"))],
        ["AAAA", _join(dns.get("aaaa_records") or dns.get("aaaa"))],
        ["MX", _join(safe_get(audit, "mail.mx.values", []))],
        ["TXT", _join(dns.get("txt_records") or dns.get("txt"))],
        ["SPF", _join(dns.get("spf_records") or safe_get(audit, "mail.spf_records", []))],
        ["DMARC", _join(safe_get(audit, "mail.dmarc_records", []))],
        ["Erreurs", esc(dns.get("error") or safe_get(audit, "mail.error", ""))],
    ]
    return render_table(["Contrôle", "Valeurs"], rows)


def _render_mail(audit: dict) -> str:
    mail = audit.get("mail") or {}
    rows = [
        ["MX", _join(safe_get(mail, "mx.values", []))],
        ["SPF", _join(mail.get("spf_records", []))],
        ["DMARC", _join(mail.get("dmarc_records", []))],
        ["Recommandations", _join([f.get("recommendation") for f in audit.get("findings", []) if isinstance(f, dict) and str(f.get("category", "")).lower().startswith("mail")], 4)],
    ]
    return render_table(["Messagerie", "Détail"], rows)


def _render_web(audit: dict) -> str:
    rows = []
    for target in safe_get(audit, "web.targets", []):
        if not isinstance(target, dict):
            continue
        https = target.get("https") or {}
        http = target.get("http") or {}
        headers = https.get("headers") or http.get("headers") or target.get("headers") or {}
        rows.append([
            target.get("hostname"),
            http.get("status_code"),
            https.get("status_code"),
            https.get("final_url") or http.get("final_url"),
            "présent" if headers.get("strict-transport-security") or headers.get("Strict-Transport-Security") else "absent",
            "présent" if headers.get("content-security-policy") or headers.get("Content-Security-Policy") else "absent",
            "présent" if headers.get("x-frame-options") or headers.get("X-Frame-Options") else "absent",
            "présent" if headers.get("x-content-type-options") or headers.get("X-Content-Type-Options") else "absent",
            "présent" if headers.get("referrer-policy") or headers.get("Referrer-Policy") else "absent",
            "présent" if headers.get("permissions-policy") or headers.get("Permissions-Policy") else "absent",
        ])
    return render_table(["Cible", "HTTP", "HTTPS", "Final URL", "HSTS", "CSP", "XFO", "XCTO", "Referrer", "Permissions"], rows)


def _render_tls(audit: dict) -> str:
    rows = []
    for target in safe_get(audit, "tls.targets", []):
        if not isinstance(target, dict):
            continue
        rows.append([
            target.get("hostname") or target.get("target"),
            target.get("tls_version") or target.get("version") or target.get("negotiated_protocol"),
            target.get("not_after") or target.get("expires_at") or target.get("certificate_expiration"),
            _join(target.get("passed_checks") or target.get("passed")),
            _join(target.get("failed_checks") or target.get("failed")),
            target.get("hsts"),
        ])
    return progress_bar(safe_get(audit, "tls_score.global_score", 0), 100, "Score TLS") + render_table(["Cible", "TLS", "Expiration", "Passés", "Échoués", "HSTS"], rows)


def _render_subdomains(audit: dict) -> str:
    subs = safe_get(audit, "subdomains.subdomains", [])
    rows = []
    for item in _as_list(subs)[:MAX_SUBDOMAINS]:
        if isinstance(item, dict):
            rows.append([item.get("subdomain") or item.get("host") or item.get("name"), item.get("source") or safe_get(audit, "subdomains.source", "")])
        else:
            rows.append([item, safe_get(audit, "subdomains.source", "")])
    note = ""
    if len(_as_list(subs)) > MAX_SUBDOMAINS:
        note = f'<p class="notice">Affichage limité à {MAX_SUBDOMAINS} sous-domaines sur {len(_as_list(subs))}. Liste complète disponible dans JSON/Excel.</p>'
    return render_table(["Sous-domaine", "Source"], rows, "Aucun sous-domaine disponible.", max_rows=MAX_SUBDOMAINS) + note


def _render_ips(audit: dict) -> str:
    rows = []
    for item in safe_get(audit, "ip_inventory.display_ips", []) or safe_get(audit, "ip_inventory.unique_ips", []):
        if isinstance(item, dict):
            rows.append([item.get("ip"), item.get("scope") or item.get("classification"), _join(item.get("hostnames")), item.get("source"), item.get("provider_type") or item.get("ownership")])
        else:
            rows.append([item, "", "", "", ""])
    return render_table(["IP", "Périmètre", "Hostnames", "Source", "Cœur/prestataire/tiers"], rows)


def _render_nmap(audit: dict) -> str:
    rows = []
    for port in safe_get(audit, "service_scan.open_ports", []):
        if isinstance(port, dict):
            rows.append([port.get("host") or port.get("ip"), port.get("port"), port.get("protocol"), port.get("service"), port.get("product"), port.get("version"), _join(port.get("cpe") or port.get("cpes")), _join(port.get("cves"))])
    return '<p class="notice">Nmap service/version/port est utilisé en mode non exploitant.</p>' + render_table(["Host", "Port", "Proto", "Service", "Produit", "Version", "CPE", "CVE corrélées"], rows)


def _render_cves(audit: dict) -> str:
    cves = _as_list(safe_get(audit, "service_scan.cves", [])) + _as_list(safe_get(audit, "passive_cves.items", []))
    rows = []
    for cve in cves:
        if isinstance(cve, dict):
            rows.append([cve.get("cve") or cve.get("id") or cve.get("cve_id"), cve.get("product"), cve.get("version"), cve.get("severity"), cve.get("cvss"), cve.get("evidence") or cve.get("proof") or cve.get("source")])
        else:
            rows.append([cve, "", "", "", "", ""])
    return '<p class="notice">Corrélation de version uniquement : ce n’est pas une preuve d’exploitation.</p>' + render_table(["CVE ID", "Produit", "Version", "Sévérité", "CVSS", "Preuve de corrélation"], rows)


def _render_cti(audit: dict) -> str:
    rows = []
    for item in safe_get(audit, "cti.ip_reputation", []):
        if isinstance(item, dict):
            rows.append([item.get("dnsbl") or item.get("source"), item.get("status") or item.get("listed"), item.get("ip"), item.get("detail") or item.get("details")])
    return render_table(["DNSBL/source", "Statut", "IP", "Détail"], rows)


def _render_graph(audit: dict) -> str:
    graph = audit.get("attack_graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or graph.get("links") or []
    types = Counter(n.get("type", "unknown") for n in nodes if isinstance(n, dict))
    return (
        '<div class="metric-grid">'
        + _metric("Noeuds", len(nodes))
        + _metric("Relations", len(edges))
        + _metric("Types", ", ".join(f"{k}: {v}" for k, v in types.items()) or "N/A")
        + '</div><p class="notice">Le graphe interactif est disponible dans l’onglet Graph Explorer de l’application.</p>'
    )



def _render_dnsdumpster_like(audit: dict) -> str:
    dd = audit.get("dnsdumpster_like") or {}
    note = '<p class="notice"><strong>Nmap est une source complémentaire.</strong> Les services HTTP/HTTPS peuvent être détectés par fingerprint web même lorsque Nmap ne remonte pas de service.</p>'
    metrics = ('<div class="metric-grid">' + _metric("System Locations", len(dd.get("system_locations", {}) or {})) + _metric("Hosting / Networks", len(dd.get("hosting_networks", []) or [])) + _metric("Services / Banners", len(dd.get("services_banners", {}) or {})) + _metric("A Records enrichis", len(dd.get("a_records", []) or [])) + _metric("MX Records enrichis", len(dd.get("mx_records", []) or [])) + _metric("NS Records enrichis", len(dd.get("ns_records", []) or [])) + '</div>')
    return note + metrics


def _render_system_locations(audit: dict) -> str:
    rows = [[country, count] for country, count in (safe_get(audit, "dnsdumpster_like.system_locations", {}) or {}).items()]
    return render_table(["Country", "Count"], rows or [["Unknown", 0]])


def _render_hosting_networks(audit: dict) -> str:
    rows = [[h.get("asn"), h.get("network"), h.get("asn_name"), h.get("country"), h.get("count")] for h in safe_get(audit, "dnsdumpster_like.hosting_networks", []) or []]
    return render_table(["ASN", "Network", "ASN Name", "Country", "Hosts"], rows)


def _render_services_banners(audit: dict) -> str:
    rows = [[banner, count] for banner, count in (safe_get(audit, "dnsdumpster_like.services_banners", {}) or {}).items()]
    return render_table(["Banner", "Count"], rows)


def _render_a_records_filterable(audit: dict) -> str:
    records = safe_get(audit, "dnsdumpster_like.a_records", []) or []
    controls = """<div class="filters">
<input id="hostSearch" placeholder="Recherche host..." oninput="filterDnsdumpsterTable()">
<input id="asnFilter" placeholder="Filtre ASN..." oninput="filterDnsdumpsterTable()">
<input id="countryFilter" placeholder="Filtre pays..." oninput="filterDnsdumpsterTable()">
<input id="techFilter" placeholder="Filtre technologie..." oninput="filterDnsdumpsterTable()">
<input id="serviceFilter" placeholder="Filtre service/banner..." oninput="filterDnsdumpsterTable()">
<label><input id="webNoNmap" type="checkbox" onchange="filterDnsdumpsterTable()"> HTTP/HTTPS détecté mais Nmap vide</label>
<label><input id="guardOnly" type="checkbox" onchange="filterDnsdumpsterTable()"> Bloqué par garde-fou</label>
</div>"""
    headers = ["Host", "IP", "ASN", "Network", "ASN Name", "Country", "Open Services observed", "RevIP", "Sources"]
    rows = []
    for h in records:
        tech = _tech_text(h)
        services = _open_services_html(h)
        badges = _host_badges(h)
        detail = _host_detail_html(h)
        attrs = {"host": h.get("host", ""), "asn": h.get("asn", ""), "country": h.get("country", ""), "tech": tech, "service": _plain_services(h), "webnonmap": str(bool(h.get("open_services") and not h.get("nmap_services"))).lower(), "guard": str(bool(h.get("guardrail"))).lower()}
        attr_str = " ".join(f'data-{k}="{esc(v).lower()}"' for k, v in attrs.items())
        host_cell = SafeHtml(f'<details><summary>{esc(h.get("host"))} {badges}</summary>{detail}</details>')
        rows.append(SafeHtml(f'<tr {attr_str} class="dnsdumpster-row"><td>{host_cell}</td><td>{esc(h.get("ip"))}</td><td>{esc(h.get("asn"))}</td><td>{esc(h.get("network"))}</td><td>{esc(h.get("asn_name"))}</td><td>{esc(h.get("country"))}</td><td>{services}</td><td>{esc(h.get("revip_count", 0))}</td><td>{esc(", ".join(h.get("sources", []) or []))}</td></tr>'))
    if not rows:
        return controls + '<p class="notice">Aucun A record enrichi disponible.</p>'
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    return controls + f'<div class="table-scroll"><table id="dnsdumpsterTable" class="table"><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _render_mx_records(audit: dict) -> str:
    rows = []
    for h in safe_get(audit, "dnsdumpster_like.mx_records", []) or []:
        rows.append([h.get("priority"), h.get("host"), h.get("ip"), h.get("asn"), h.get("network"), h.get("asn_name"), h.get("country"), SafeHtml(_open_services_html(h)), _tech_text(h), _join(h.get("sources", []))])
    return render_table(["Priority", "Host", "IP", "ASN", "Network", "ASN Name", "Country", "Open Services observed", "Technologies", "Sources"], rows)


def _render_ns_records(audit: dict) -> str:
    rows = []
    for h in safe_get(audit, "dnsdumpster_like.ns_records", []) or []:
        rows.append([h.get("host"), h.get("ip"), h.get("asn"), h.get("network"), h.get("asn_name"), h.get("country"), SafeHtml(_open_services_html(h)), _join(h.get("sources", []))])
    return render_table(["Host", "IP", "ASN", "Network", "ASN Name", "Country", "Open Services observed", "Sources"], rows)


def _render_txt_records(audit: dict) -> str:
    rows = []
    for item in safe_get(audit, "dnsdumpster_like.txt_records", []) or []:
        spf = item.get("spf") or {}
        rows.append([item.get("type"), SafeHtml(f'<div class="code">{esc(item.get("value"))}</div>'), _join(spf.get("providers", []), 10), _join(spf.get("includes", []), 15), _join((spf.get("ip4", []) or []) + (spf.get("ip6", []) or []), 20)])
    return render_table(["Type", "Value", "SPF providers", "SPF includes", "SPF IPs"], rows)


def _render_host_inventory_detail(audit: dict) -> str:
    cards = []
    for h in safe_get(audit, "dnsdumpster_like.hosts", []) or []:
        cards.append(f"<details class=\"host-card\"><summary>{esc(h.get('host'))} - {esc(h.get('ip'))} {_host_badges(h)}</summary>{_host_detail_html(h)}</details>")
    return "".join(cards) or '<p class="notice">Aucun host inventory détaillé disponible.</p>'


def _host_badges(h: dict) -> str:
    badges = []
    if any(s.get("scheme") == "http" for s in h.get("open_services", []) or []): badges.append("HTTP")
    if any(s.get("scheme") == "https" for s in h.get("open_services", []) or []): badges.append("HTTPS")
    if (h.get("tls") or {}).get("cn") and (h.get("tls") or {}).get("cn") != "Non détecté": badges.append("TLS")
    if h.get("nmap_services"): badges.append("Nmap")
    if h.get("asn") and h.get("asn") != "Non détecté": badges.append("ASN")
    if h.get("technologies"): badges.append("Tech")
    if h.get("guardrail"): badges.append("Bloqué par garde-fou")
    if not h.get("open_services"): badges.append("Non détecté")
    return " ".join(f'<span class="badge mini">{esc(b)}</span>' for b in badges)


def _open_services_html(h: dict) -> str:
    services = h.get("open_services", []) or []
    if not services:
        return '<span class="badge mini">Bloqué par garde-fou</span>' if h.get("guardrail") else '<span class="badge mini">Non détecté</span>'
    parts = []
    for svc in services:
        text = f"{svc.get('scheme')}: {svc.get('banner') or svc.get('service') or 'unknown server'}"
        if svc.get("title") and svc.get("title") != "Non détecté": text += f"; title: {svc.get('title')}"
        parts.append(esc(text))
    tls = h.get("tls") or {}
    if tls.get("cn") and tls.get("cn") != "Non détecté": parts.append(f"cn: {esc(tls.get('cn'))}")
    tech = _tech_text(h)
    if tech: parts.append(f"tech: {esc(tech)}")
    return "<br>".join(parts)


def _plain_services(h: dict) -> str:
    return " ".join([str(s.get("banner") or s.get("service") or "") for s in h.get("open_services", []) or []])


def _tech_text(h: dict) -> str:
    out = []
    for t in h.get("technologies", []) or []:
        name = t.get("name") or ""
        if t.get("version"): name += f":{t.get('version')}"
        if t.get("note"): name += f" ({t.get('note')})"
        out.append(name)
    return ", ".join(dict.fromkeys(out))


def _host_detail_html(h: dict) -> str:
    tls = h.get("tls") or {}
    guard = h.get("guardrail") or {}
    data = [["DNS", h.get("host")], ["IP", h.get("ip")], ["ASN", h.get("asn")], ["Network", h.get("network")], ["ASN Name", h.get("asn_name")], ["Country", h.get("country")], ["Provider", h.get("provider")], ["HTTP", h.get("http", {}).get("status_code") or "Non détecté"], ["HTTPS", h.get("https", {}).get("status_code") or "Non détecté"], ["TLS", f"CN={tls.get('cn', 'Non détecté')} SAN={', '.join(tls.get('san', []) or [])} issuer={tls.get('issuer', 'Non détecté')} exp={tls.get('expires_at', 'Non détecté')}"], ["Technologies", _tech_text(h) or "Non détecté"], ["Nmap", _nmap_services_text(h) or "Non détecté par Nmap"], ["Sources", ", ".join(h.get("sources", []) or [])], ["Erreurs / garde-fous", guard.get("reason") or _join(h.get("resolution_errors", []))]]
    return render_table(["Champ", "Valeur"], data, max_rows=80)


def _nmap_services_text(h: dict) -> str:
    return "; ".join(f"{s.get('port')}/{s.get('protocol', 'tcp')} {s.get('name') or s.get('service') or ''} {s.get('product') or ''} {s.get('version') or 'Version non exposée'}".strip() for s in h.get("nmap_services", []) or [])

def _css() -> str:
    return """
:root{--bg:#07070a;--bg2:#09090d;--card:#101018;--card2:#151521;--red:#ff3045;--red2:#dc143c;--darkred:#65000b;--text:#f5f5f5;--muted:#a1a1aa;--border:rgba(255,48,69,.25);--green:#34d399;--orange:#fb923c}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 70% 0,rgba(220,20,60,.22),transparent 32%),linear-gradient(135deg,var(--bg),var(--bg2));color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial,sans-serif;line-height:1.55}.watermark{position:fixed;inset:auto -4vw 8vh auto;font-size:13vw;font-weight:900;letter-spacing:.08em;color:rgba(255,255,255,.025);transform:rotate(-10deg);pointer-events:none;z-index:0}.hero{position:relative;z-index:1;min-height:72vh;padding:72px 7vw 52px;border-bottom:1px solid var(--border);background:linear-gradient(120deg,rgba(255,48,69,.12),transparent 55%)}.hero:before{content:"";position:absolute;inset:24px;border:1px solid rgba(255,48,69,.18);border-radius:32px;pointer-events:none}.eyebrow{color:var(--red);text-transform:uppercase;letter-spacing:.28em;font-size:.78rem;font-weight:800}.hero h1{margin:.1em 0;font-size:clamp(3.6rem,9vw,8.8rem);line-height:.88;letter-spacing:-.08em}.hero h2{margin:0;color:#fff;font-size:clamp(1.15rem,2vw,2rem);font-weight:500}.hero-meta{display:flex;flex-wrap:wrap;gap:12px;margin:28px 0}.badge{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:999px;padding:5px 10px;background:rgba(255,48,69,.09);color:#fff;font-weight:800;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}.layout{position:relative;z-index:1;display:grid;grid-template-columns:280px minmax(0,1fr);gap:28px;padding:36px 5vw}.toc{position:sticky;top:20px;align-self:start;background:rgba(16,16,24,.86);backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:20px;padding:18px;max-height:calc(100vh - 40px);overflow:auto}.toc strong{display:block;margin-bottom:12px;color:#fff}.toc a{display:block;color:var(--muted);text-decoration:none;padding:8px 10px;border-radius:10px;font-size:.92rem}.toc a:hover{background:rgba(255,48,69,.12);color:#fff}.content{min-width:0}.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-top:28px}.metric-card,.cardlet{background:linear-gradient(180deg,var(--card),rgba(16,16,24,.76));border:1px solid var(--border);border-radius:18px;padding:18px;box-shadow:0 18px 50px rgba(0,0,0,.24)}.metric-card span{display:block;color:var(--muted);font-size:.82rem;text-transform:uppercase;letter-spacing:.08em}.metric-card strong{display:block;margin-top:7px;font-size:1.7rem;color:#fff}.metric-card small{color:var(--muted)}.section{margin:0 0 28px;padding:26px;background:rgba(16,16,24,.78);border:1px solid var(--border);border-radius:24px;box-shadow:0 20px 70px rgba(0,0,0,.26)}.section-title{display:flex;align-items:center;gap:14px;border-bottom:1px solid rgba(255,48,69,.18);padding-bottom:14px;margin-bottom:18px}.section-title span{color:var(--red);font-weight:900}.section h2{margin:0;color:#fff;font-size:1.55rem}.section-subtitle,.notice{color:var(--muted)}.lead{font-size:1.06rem;color:#e7e7e9}.two-col{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}.cardlet h3{margin-top:0;color:var(--red)}.table-scroll{overflow:auto;border:1px solid rgba(255,48,69,.16);border-radius:16px}.table{width:100%;border-collapse:collapse;min-width:760px;background:rgba(7,7,10,.55)}.table th,.table td{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.07);text-align:left;vertical-align:top}.table th{color:#fff;background:rgba(101,0,11,.5);font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}.table td{color:#d8d8dc;font-size:.9rem}.finding{border:1px solid rgba(255,48,69,.22);border-radius:18px;padding:18px;margin:14px 0;background:linear-gradient(135deg,rgba(255,48,69,.05),rgba(255,255,255,.02))}.finding-head{display:flex;justify-content:space-between;gap:12px;align-items:start}.finding h3{margin:0;color:#fff}.finding-meta{display:grid;grid-template-columns:140px 1fr;gap:8px 12px}.finding-meta dt{color:var(--red);font-weight:800}.finding-meta dd{margin:0;color:#dcdce1}.severity-critical{background:rgba(101,0,11,.88);border-color:rgba(255,48,69,.75)}.severity-high{background:rgba(220,20,60,.55)}.severity-medium{background:rgba(251,146,60,.28);border-color:rgba(251,146,60,.45)}.severity-low{background:rgba(161,161,170,.18)}.severity-info{background:rgba(59,130,246,.16);border-color:rgba(59,130,246,.35)}.progress-wrap{margin:14px 0}.progress-label{display:flex;justify-content:space-between;color:#fff;font-weight:800}.progress{height:12px;border:1px solid var(--border);border-radius:999px;background:#09090d;overflow:hidden}.progress span{display:block;height:100%;background:linear-gradient(90deg,var(--darkred),var(--red));border-radius:999px}.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#08080c;border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:8px;color:#f1f1f3;white-space:pre-wrap;word-break:break-word}.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:14px 0}.filters input{background:#08080c;color:#fff;border:1px solid var(--border);border-radius:12px;padding:10px}.filters label{color:#d8d8dc;font-size:.9rem}.badge.mini{font-size:.64rem;padding:3px 7px;margin:2px}.host-card{border:1px solid rgba(255,48,69,.2);border-radius:16px;margin:12px 0;padding:12px;background:rgba(7,7,10,.35)}details summary{cursor:pointer;color:#fff;font-weight:800}@media(max-width:880px){.layout{grid-template-columns:1fr}.toc{position:relative;top:0}.hero{padding:48px 6vw}.section{padding:20px}}@media print{body{background:#09090d}.toc{position:relative}.layout{display:block}.section{break-inside:avoid}}
"""


def generate_html_report(audit: dict) -> str:
    domain = audit.get("domain", "unknown")
    filename = f"open_easm_beta_{_slug_domain(domain)}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
    path = REPORT_DIR / filename
    now = datetime.now(timezone.utc).isoformat()
    score = audit.get("score") or {}
    risk = audit.get("executive_risk") or {}
    subdomains = safe_get(audit, "subdomains.subdomains", [])
    cve_count = (safe_get(audit, "passive_cves.count", 0) or 0) + (safe_get(audit, "service_scan.count_cves", 0) or 0)
    toc = [
        ("synthese", "Synthèse"), ("system_locations", "System Locations"), ("hosting_networks", "Hosting / Networks"),
        ("services_banners", "Services / Banners"), ("a_records", "A Records / Subdomains"),
        ("mx_records", "MX Records"), ("ns_records", "NS Records"), ("txt_records", "TXT Records"),
        ("host_inventory", "Host Inventory détaillé"), ("nmap", "Nmap en annexe"), ("cve", "CVE"),
        ("limites", "Limites et sources"),
    ]
    hero_metrics = (
        '<div class="metric-grid">'
        + _metric("Score global", f"{score.get('score', 'N/A')} / {score.get('max_score', 1000)}", score.get("level") or risk.get("risk_level") or "")
        + _metric("Niveau de risque", risk.get("risk_level") or score.get("level") or "N/A")
        + _metric("IP publiques", safe_get(audit, "ip_inventory.public_ip_count", 0))
        + _metric("Sous-domaines", safe_get(audit, "subdomains.count", len(_as_list(subdomains))))
        + _metric("Ports Nmap", safe_get(audit, "service_scan.count_open_ports", 0), "non exploitant")
        + _metric("CVE corrélées", cve_count, "corrélation de version")
        + '</div>'
    )
    limits = """
<ul>
<li>Audit public défensif uniquement.</li><li>Aucune exploitation, aucun bruteforce, aucun DoS et aucune extraction de données.</li>
<li>Les CVE sont basées sur des versions observables et ne constituent pas une preuve d'exploitation.</li>
<li>Les versions masquées ne sont pas corrélables de manière fiable.</li><li>Les backports Linux peuvent corriger une faille tout en conservant un numéro de version apparent.</li>
</ul>
"""
    html = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenEASM Beta - Rapport HTML - {esc(domain)}</title><style>{_css()}</style></head>
<body><div class="watermark">OPENEASM</div>
<header class="hero"><p class="eyebrow">OpenEASM Beta</p><h1>RAPPORT OPENEASM</h1><h2>External Attack Surface Management · Rapport d’exposition externe</h2>
<div class="hero-meta"><span class="badge">Domaine: {esc(domain)}</span><span class="badge">Généré: {esc(now)}</span><span class="badge">NON EXPLOITANT</span><span class="badge">Service/version/CVE défensif public</span></div>{hero_metrics}</header>
<main class="layout"><nav class="toc"><strong>Sommaire</strong>{''.join(f'<a href="#{sid}">{esc(label)}</a>' for sid, label in toc)}</nav><div class="content">
{section('synthese','Synthèse',_build_executive_summary(audit) + _render_dnsdumpster_like(audit))}
{section('system_locations','System Locations',_render_system_locations(audit))}
{section('hosting_networks','Hosting / Networks',_render_hosting_networks(audit))}
{section('services_banners','Services / Banners',_render_services_banners(audit))}
{section('a_records','A Records / Subdomains from dataset',_render_a_records_filterable(audit),'Table filtrable : host, ASN, pays, technologie, service, HTTP/HTTPS sans Nmap, garde-fou.')}
{section('mx_records','MX Records',_render_mx_records(audit))}
{section('ns_records','NS Records',_render_ns_records(audit))}
{section('txt_records','TXT Records',_render_txt_records(audit))}
{section('host_inventory','Host Inventory détaillé',_render_host_inventory_detail(audit))}
{section('nmap','Nmap en annexe',_render_nmap(audit),'Rappel : collecte non exploitante, sans scripts intrusifs.')}
{section('cve','CVE',_render_cves(audit))}
{section('limites','Limites et sources',limits)}
</div></main><script>
function filterDnsdumpsterTable(){{
 const table=document.getElementById('dnsdumpsterTable'); if(!table) return;
 const val=id=>(document.getElementById(id)?.value||'').toLowerCase();
 const host=val('hostSearch'), asn=val('asnFilter'), country=val('countryFilter'), tech=val('techFilter'), service=val('serviceFilter');
 const webNoNmap=document.getElementById('webNoNmap')?.checked; const guardOnly=document.getElementById('guardOnly')?.checked;
 table.querySelectorAll('tbody tr').forEach(tr=>{{
  let ok=true;
  if(host && !tr.dataset.host.includes(host)) ok=false;
  if(asn && !tr.dataset.asn.includes(asn)) ok=false;
  if(country && !tr.dataset.country.includes(country)) ok=false;
  if(tech && !tr.dataset.tech.includes(tech)) ok=false;
  if(service && !tr.dataset.service.includes(service)) ok=false;
  if(webNoNmap && tr.dataset.webnonmap!=='true') ok=false;
  if(guardOnly && tr.dataset.guard!=='true') ok=false;
  tr.style.display=ok?'':'none';
 }});
}}
</script></body></html>"""
    path.write_text(html, encoding="utf-8")
    return filename
