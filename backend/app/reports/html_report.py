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


def _css() -> str:
    return """
:root{--bg:#07070a;--bg2:#09090d;--card:#101018;--card2:#151521;--red:#ff3045;--red2:#dc143c;--darkred:#65000b;--text:#f5f5f5;--muted:#a1a1aa;--border:rgba(255,48,69,.25);--green:#34d399;--orange:#fb923c}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:radial-gradient(circle at 70% 0,rgba(220,20,60,.22),transparent 32%),linear-gradient(135deg,var(--bg),var(--bg2));color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Arial,sans-serif;line-height:1.55}.watermark{position:fixed;inset:auto -4vw 8vh auto;font-size:13vw;font-weight:900;letter-spacing:.08em;color:rgba(255,255,255,.025);transform:rotate(-10deg);pointer-events:none;z-index:0}.hero{position:relative;z-index:1;min-height:72vh;padding:72px 7vw 52px;border-bottom:1px solid var(--border);background:linear-gradient(120deg,rgba(255,48,69,.12),transparent 55%)}.hero:before{content:"";position:absolute;inset:24px;border:1px solid rgba(255,48,69,.18);border-radius:32px;pointer-events:none}.eyebrow{color:var(--red);text-transform:uppercase;letter-spacing:.28em;font-size:.78rem;font-weight:800}.hero h1{margin:.1em 0;font-size:clamp(3.6rem,9vw,8.8rem);line-height:.88;letter-spacing:-.08em}.hero h2{margin:0;color:#fff;font-size:clamp(1.15rem,2vw,2rem);font-weight:500}.hero-meta{display:flex;flex-wrap:wrap;gap:12px;margin:28px 0}.badge{display:inline-flex;align-items:center;border:1px solid var(--border);border-radius:999px;padding:5px 10px;background:rgba(255,48,69,.09);color:#fff;font-weight:800;font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}.layout{position:relative;z-index:1;display:grid;grid-template-columns:280px minmax(0,1fr);gap:28px;padding:36px 5vw}.toc{position:sticky;top:20px;align-self:start;background:rgba(16,16,24,.86);backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:20px;padding:18px;max-height:calc(100vh - 40px);overflow:auto}.toc strong{display:block;margin-bottom:12px;color:#fff}.toc a{display:block;color:var(--muted);text-decoration:none;padding:8px 10px;border-radius:10px;font-size:.92rem}.toc a:hover{background:rgba(255,48,69,.12);color:#fff}.content{min-width:0}.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-top:28px}.metric-card,.cardlet{background:linear-gradient(180deg,var(--card),rgba(16,16,24,.76));border:1px solid var(--border);border-radius:18px;padding:18px;box-shadow:0 18px 50px rgba(0,0,0,.24)}.metric-card span{display:block;color:var(--muted);font-size:.82rem;text-transform:uppercase;letter-spacing:.08em}.metric-card strong{display:block;margin-top:7px;font-size:1.7rem;color:#fff}.metric-card small{color:var(--muted)}.section{margin:0 0 28px;padding:26px;background:rgba(16,16,24,.78);border:1px solid var(--border);border-radius:24px;box-shadow:0 20px 70px rgba(0,0,0,.26)}.section-title{display:flex;align-items:center;gap:14px;border-bottom:1px solid rgba(255,48,69,.18);padding-bottom:14px;margin-bottom:18px}.section-title span{color:var(--red);font-weight:900}.section h2{margin:0;color:#fff;font-size:1.55rem}.section-subtitle,.notice{color:var(--muted)}.lead{font-size:1.06rem;color:#e7e7e9}.two-col{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}.cardlet h3{margin-top:0;color:var(--red)}.table-scroll{overflow:auto;border:1px solid rgba(255,48,69,.16);border-radius:16px}.table{width:100%;border-collapse:collapse;min-width:760px;background:rgba(7,7,10,.55)}.table th,.table td{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.07);text-align:left;vertical-align:top}.table th{color:#fff;background:rgba(101,0,11,.5);font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}.table td{color:#d8d8dc;font-size:.9rem}.finding{border:1px solid rgba(255,48,69,.22);border-radius:18px;padding:18px;margin:14px 0;background:linear-gradient(135deg,rgba(255,48,69,.05),rgba(255,255,255,.02))}.finding-head{display:flex;justify-content:space-between;gap:12px;align-items:start}.finding h3{margin:0;color:#fff}.finding-meta{display:grid;grid-template-columns:140px 1fr;gap:8px 12px}.finding-meta dt{color:var(--red);font-weight:800}.finding-meta dd{margin:0;color:#dcdce1}.severity-critical{background:rgba(101,0,11,.88);border-color:rgba(255,48,69,.75)}.severity-high{background:rgba(220,20,60,.55)}.severity-medium{background:rgba(251,146,60,.28);border-color:rgba(251,146,60,.45)}.severity-low{background:rgba(161,161,170,.18)}.severity-info{background:rgba(59,130,246,.16);border-color:rgba(59,130,246,.35)}.progress-wrap{margin:14px 0}.progress-label{display:flex;justify-content:space-between;color:#fff;font-weight:800}.progress{height:12px;border:1px solid var(--border);border-radius:999px;background:#09090d;overflow:hidden}.progress span{display:block;height:100%;background:linear-gradient(90deg,var(--darkred),var(--red));border-radius:999px}.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#08080c;border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:8px;color:#f1f1f3;white-space:pre-wrap;word-break:break-word}@media(max-width:880px){.layout{grid-template-columns:1fr}.toc{position:relative;top:0}.hero{padding:48px 6vw}.section{padding:20px}}@media print{body{background:#09090d}.toc{position:relative}.layout{display:block}.section{break-inside:avoid}}
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
        ("synthese", "Synthèse exécutive"), ("scoring", "Scoring"), ("plan", "Plan d’action priorisé"),
        ("findings", "Findings"), ("dns", "DNS"), ("messagerie", "Messagerie"), ("web", "Web / Headers"),
        ("tls", "TLS / SSL"), ("subdomains", "Sous-domaines"), ("ips", "IP publiques"),
        ("nmap", "Nmap service/version/port"), ("cve", "CVE"), ("cti", "CTI / réputation"),
        ("graph", "Graph Explorer"), ("limites", "Limites et responsabilité"),
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
{section('synthese','Synthèse exécutive',_build_executive_summary(audit))}
{section('scoring','Scoring',_render_scoring(audit),'Scores consolidés et jauges visuelles CSS.')}
{section('plan','Plan d’action priorisé',_render_action_plan(audit))}
{section('findings','Findings détaillés',_render_findings(audit))}
{section('dns','DNS',_render_dns(audit))}
{section('messagerie','Messagerie',_render_mail(audit))}
{section('web','Web / Headers',_render_web(audit))}
{section('tls','TLS / SSL',_render_tls(audit))}
{section('subdomains','Sous-domaines',_render_subdomains(audit))}
{section('ips','IP publiques',_render_ips(audit))}
{section('nmap','Nmap service/version/port',_render_nmap(audit),'Rappel : collecte non exploitante, sans scripts intrusifs.')}
{section('cve','CVE',_render_cves(audit))}
{section('cti','CTI / réputation',_render_cti(audit))}
{section('graph','Graph Explorer',_render_graph(audit))}
{section('limites','Limites et responsabilité',limits)}
</div></main></body></html>"""
    path.write_text(html, encoding="utf-8")
    return filename
