from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Flowable,
    Image as RLImage,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

PAGE_BG = colors.HexColor("#F6F1E6")
INK = colors.HexColor("#17120D")
MUTED = colors.HexColor("#61584D")
RED = colors.HexColor("#B00020")
RED_DARK = colors.HexColor("#65000B")
GOLD = colors.HexColor("#B8871B")
GOLD_DARK = colors.HexColor("#7B5500")
GOLD_LIGHT = colors.HexColor("#FFE2A0")
CARD = colors.HexColor("#FFFDF7")
CARD_ALT = colors.HexColor("#FFF4D6")
BORDER = colors.HexColor("#D7BB74")
ROW_ALT = colors.HexColor("#FFF8E7")
WHITE = colors.white
GREEN = colors.HexColor("#1F8F5F")
ORANGE = colors.HexColor("#D06B00")

MAX_CELL_CHARS = 260
MAX_LONG_CELL_CHARS = 420


class ScoreGauge(Flowable):
    def __init__(self, value: float, max_value: float = 1000, width: float = 5.7 * cm, height: float = 0.72 * cm):
        super().__init__()
        self.value = max(0, min(float(value or 0), float(max_value or 1000)))
        self.max_value = float(max_value or 1000)
        self.width = width
        self.height = height

    def draw(self):
        pct = self.value / self.max_value if self.max_value else 0
        c = self.canv
        c.setFillColor(colors.HexColor("#E7D8B2"))
        c.roundRect(0, 0, self.width, self.height, 5, fill=1, stroke=0)
        fill_color = GREEN if pct >= 0.75 else ORANGE if pct >= 0.5 else RED
        c.setFillColor(fill_color)
        c.roundRect(0, 0, max(0.18 * cm, self.width * pct), self.height, 5, fill=1, stroke=0)
        c.setStrokeColor(BORDER)
        c.roundRect(0, 0, self.width, self.height, 5, fill=0, stroke=1)


class SeverityLegend(Flowable):
    def __init__(self, counts: dict, width: float = 25.5 * cm, height: float = 0.95 * cm):
        super().__init__()
        self.counts = counts or {}
        self.width = width
        self.height = height

    def draw(self):
        palette = [
            ("critical", RED_DARK),
            ("high", RED),
            ("medium", GOLD),
            ("low", GOLD_DARK),
            ("info", MUTED),
        ]
        total = sum(int(self.counts.get(k, 0) or 0) for k, _ in palette) or 1
        x = 0
        c = self.canv
        for key, color in palette:
            count = int(self.counts.get(key, 0) or 0)
            w = max(0.7 * cm, self.width * count / total) if count else 0.55 * cm
            c.setFillColor(color)
            c.roundRect(x, 0.22 * cm, w, 0.38 * cm, 3, fill=1, stroke=0)
            c.setFillColor(INK)
            c.setFont("Helvetica", 6.7)
            c.drawString(x, 0, f"{key}: {count}")
            x += w + 0.28 * cm


def generate_pdf_report(audit: dict) -> str:
    """Generate a DNSDumpster-like PDF where Nmap is an appendix."""
    filename = f"open_easm_beta_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = REPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=1.1 * cm,
        leftMargin=1.1 * cm,
        topMargin=1.35 * cm,
        bottomMargin=1.05 * cm,
        title=f"OpenEASM Beta - {audit['domain']}",
        author="OpenEASM",
        subject="DNSDumpster-like External Attack Surface Management defensive audit",
    )

    styles = _styles()
    story = []
    dd = audit.get("dnsdumpster_like", {}) or {}
    risk = audit.get("executive_risk", {}) or {}
    scan = audit.get("service_scan", {}) or {}

    story.append(_cover_block(audit, styles))
    story.append(Spacer(1, 0.20 * cm))
    story.append(_kpi_cards(audit, styles))
    story.append(Spacer(1, 0.18 * cm))
    story.append(Paragraph("Page de synthèse", styles["Section"]))
    story.append(_callout(str(risk.get("board_summary") or _conclusion(audit)), styles, tone="neutral"))
    story.append(Spacer(1, 0.14 * cm))
    story.append(_callout("Nmap est une source complémentaire. Les services HTTP/HTTPS peuvent être détectés par fingerprint web même lorsque Nmap ne remonte pas de service.", styles, tone="safe"))
    story.append(Spacer(1, 0.18 * cm))
    story.append(_dnsdumpster_summary_table(dd, styles))

    story.append(PageBreak())
    story.append(Paragraph("System Locations", styles["Section"]))
    story.append(_system_locations_table(dd, styles))
    story.append(Spacer(1, 0.22 * cm))
    story.append(Paragraph("Hosting / Networks", styles["Section"]))
    story.append(_hosting_networks_table(dd, styles))
    story.append(Spacer(1, 0.22 * cm))
    story.append(Paragraph("Services / Banners", styles["Section"]))
    story.append(_services_banners_table(dd, styles))

    story.append(PageBreak())
    story.append(Paragraph("A Records / Subdomains from dataset", styles["Section"]))
    story.append(_dnsdumpster_hosts_table(dd.get("a_records", []), styles, limit=70))

    story.append(PageBreak())
    story.append(Paragraph("MX Records", styles["Section"]))
    story.append(_dnsdumpster_hosts_table(dd.get("mx_records", []), styles, limit=60, mx=True))
    story.append(Spacer(1, 0.22 * cm))
    story.append(Paragraph("NS Records", styles["Section"]))
    story.append(_dnsdumpster_hosts_table(dd.get("ns_records", []), styles, limit=60))
    story.append(Spacer(1, 0.22 * cm))
    story.append(Paragraph("TXT Records", styles["Section"]))
    story.append(_txt_records_table(dd, styles))

    story.append(PageBreak())
    story.append(Paragraph("Host Inventory détaillé", styles["Section"]))
    story.append(_host_inventory_detail(dd, styles, limit=40))

    story.append(PageBreak())
    story.append(Paragraph("Annexe — Nmap service/version", styles["Section"]))
    story.append(_callout(str(scan.get("note") or "Nmap service/version/port uniquement, sans exploitation."), styles, tone="safe"))
    story.append(Spacer(1, 0.16 * cm))
    story.append(_nmap_table(audit, styles, limit=80))

    story.append(PageBreak())
    story.append(Paragraph("Annexe — CVE", styles["Section"]))
    story.append(_cve_table(audit, styles, limit=80))
    story.append(Spacer(1, 0.22 * cm))
    story.append(Paragraph("Limites et sources", styles["Section"]))
    story.append(_limits_sources_table(audit, dd, styles))

    doc.build(story, onFirstPage=_decorate_page, onLaterPages=_decorate_page)
    return filename


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("CoverTitle", parent=base["Title"], textColor=RED_DARK, fontSize=29, leading=33, alignment=TA_LEFT, spaceAfter=3))
    base.add(ParagraphStyle("CoverSubtitle", parent=base["BodyText"], textColor=MUTED, fontSize=10.3, leading=14, spaceAfter=4))
    base.add(ParagraphStyle("Section", parent=base["Heading2"], textColor=RED_DARK, fontSize=15.2, leading=18, spaceBefore=5, spaceAfter=7))
    base.add(ParagraphStyle("SectionSmall", parent=base["Heading3"], textColor=GOLD_DARK, fontSize=11.0, leading=13, spaceBefore=3, spaceAfter=5))
    base.add(ParagraphStyle("Body", parent=base["BodyText"], textColor=INK, fontSize=8.5, leading=12))
    base.add(ParagraphStyle("Cell", parent=base["BodyText"], textColor=INK, fontSize=6.8, leading=8.3))
    base.add(ParagraphStyle("CellSmall", parent=base["BodyText"], textColor=INK, fontSize=6.15, leading=7.35))
    base.add(ParagraphStyle("HeaderCell", parent=base["BodyText"], textColor=RED_DARK, fontSize=6.8, leading=8.2, fontName="Helvetica-Bold"))
    return base


def _cover_block(audit: dict, styles):
    domain = audit.get("domain", "N/A")
    created = audit.get("created_at", datetime.utcnow().isoformat())
    logo_path = Path(__file__).resolve().parents[1] / "static" / "assets" / "cyborg.png"
    left = []
    if logo_path.exists():
        left.append(RLImage(str(logo_path), width=2.05 * cm, height=1.55 * cm))
    left.extend([
        Paragraph("OPEN EASM BETA", styles["CoverTitle"]),
        Paragraph("Rapport professionnel d'exposition externe", styles["CoverSubtitle"]),
    ])
    right = Paragraph(
        f"<b>Domaine</b> : {escape(str(domain))}<br/><b>Génération</b> : {escape(str(created))}<br/><b>Mode</b> : audit défensif public, service/version/CVE non exploitant<br/><b>Livrables</b> : PDF, Excel, JSON",
        styles["CoverSubtitle"],
    )
    t = Table([[left, right]], colWidths=[15.8 * cm, 9.8 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.9, BORDER),
        ("LINEBEFORE", (1, 0), (1, 0), 0.7, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 13),
        ("RIGHTPADDING", (0, 0), (-1, -1), 13),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _kpi_cards(audit: dict, styles):
    score = audit.get("score", {}) or {}
    risk = audit.get("executive_risk", {}) or {}
    scan = audit.get("service_scan", {}) or {}
    items = [
        ("Score global", f"{score.get('score', 'N/A')} / {score.get('max_score', 1000)}", score.get("level", "N/A")),
        ("Risque exécutif", f"{risk.get('overall_score', 'N/A')} / {risk.get('max_score', 100)}", risk.get("risk_level", "N/A")),
        ("Surface publique", f"{audit.get('ip_inventory', {}).get('public_ip_count', 0)} IP", f"{audit.get('subdomains', {}).get('count', 0)} sous-domaines"),
        ("Nmap", f"{scan.get('count_open_ports', 0)} ports", f"{scan.get('count_cves', 0)} CVE corrélées"),
    ]
    row = [Paragraph(f"<b>{escape(str(label))}</b><br/><font size='15' color='#65000B'><b>{escape(str(value))}</b></font><br/><font color='#7B5500'>{escape(str(note))}</font>", styles["Body"]) for label, value, note in items]
    t = Table([row], colWidths=[6.25 * cm] * 4)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _score_panel(audit: dict, styles):
    score = audit.get("score", {}) or {}
    risk = audit.get("executive_risk", {}) or {}
    left = [Paragraph("Lecture rapide", styles["SectionSmall"]), Paragraph(_p_text(_conclusion(audit), MAX_LONG_CELL_CHARS), styles["Body"])]
    right = [
        Paragraph("Score global", styles["SectionSmall"]),
        ScoreGauge(score.get("score", 0), score.get("max_score", 1000)),
        Spacer(1, 0.12 * cm),
        Paragraph(f"Niveau : <b>{escape(str(score.get('level', 'N/A')))}</b> | Posture : <b>{escape(str(risk.get('posture', 'N/A')))}</b>", styles["Body"]),
    ]
    t = Table([[left, right]], colWidths=[13.0 * cm, 12.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _risk_overview(risk: dict, styles):
    rows = [["Pilier", "Score", "Niveau", "Risque", "Constats", "Recommandation"]]
    for p in risk.get("pillars", []) or []:
        score = p.get("score", "N/A")
        rows.append([p.get("label", ""), f"{score} / 100" if score != "N/A" else "N/A", p.get("level", ""), p.get("risk", ""), str(p.get("findings_count", 0)), p.get("recommendation", "")])
    if len(rows) == 1:
        rows.append(["Scoring", "N/A", "Indisponible", "N/A", "0", "Relancer un audit complet."])
    return _table(rows, [4.4 * cm, 2.6 * cm, 3.7 * cm, 4.1 * cm, 2.2 * cm, 8.5 * cm], styles=styles)


def _actions_table(audit: dict, styles, limit: int = 16):
    rows = [["Priorité", "Sévérité", "Catégorie", "Lieu / source", "Action recommandée", "SLA"]]
    findings = sorted(audit.get("findings", []), key=lambda x: _sev_order(x.get("severity", "info")))[:limit]
    for f in findings:
        sev = f.get("severity", "info")
        rows.append([_priority_label(sev), sev, f.get("category", ""), _loc(f.get("location", {})), f.get("recommendation") or f.get("title", ""), _sla_for(sev)])
    if len(rows) == 1:
        rows.append(["Info", "info", "Aucun", "N/A", "Aucun constat prioritaire.", "Suivi"])
    return _table(rows, [2.5 * cm, 2.2 * cm, 3.1 * cm, 5.3 * cm, 10.1 * cm, 2.3 * cm], small=True, styles=styles)


def _findings_table(audit: dict, styles, limit: int = 30):
    rows = [["Sévérité", "Catégorie", "Lieu / source", "Description", "Recommandation"]]
    for f in sorted(audit.get("findings", []), key=lambda x: _sev_order(x.get("severity", "info")))[:limit]:
        rows.append([f.get("severity", ""), f.get("category", ""), _loc(f.get("location", {})), f.get("description", ""), f.get("recommendation", "")])
    if len(rows) == 1:
        rows.append(["info", "Aucun", "N/A", "Aucun constat notable.", "Maintenir la surveillance."])
    return _table(rows, [2.1 * cm, 3.1 * cm, 5.2 * cm, 8.0 * cm, 8.2 * cm], small=True, styles=styles)


def _subdomains_table(audit: dict, styles, limit: int = 80):
    sub = audit.get("subdomains", {}) or {}
    values = sub.get("subdomains") or []
    rows = [["Sous-domaine", "Source"]]
    for name in values[:limit]:
        rows.append([name, sub.get("source", "passif")])
    if len(values) > limit:
        rows.append([f"... {len(values) - limit} sous-domaines supplémentaires masqués dans le PDF", "Voir export JSON/Excel"])
    if len(rows) == 1:
        rows.append(["Aucun", sub.get("source", "passif")])
    return _table(rows, [18.0 * cm, 7.0 * cm], small=True, styles=styles)


def _ip_table(audit: dict, styles, limit: int = 80):
    rows = [["IP", "Périmètre", "Hostnames"]]
    inv = audit.get("ip_inventory", {}) or {}
    values = inv.get("unique_ips") or inv.get("display_ips") or []
    for item in values[:limit]:
        rows.append([item.get("ip", ""), item.get("scope", ""), ", ".join(item.get("hostnames", [])[:5])])
    if len(values) > limit:
        rows.append(["...", f"{len(values) - limit} IP supplémentaires masquées", "Voir export JSON/Excel"])
    if len(rows) == 1:
        rows.append(["Aucune", "N/A", "N/A"])
    return _table(rows, [4.0 * cm, 4.0 * cm, 17.0 * cm], small=True, styles=styles)


def _nmap_table(audit: dict, styles, limit: int = 80):
    scan = audit.get("service_scan", {}) or {}
    rows = [["Hôte", "Port", "Service", "Produit", "Version", "CVE", "Sévérité"]]
    ports = scan.get("open_ports", []) or []
    for port in ports[:limit]:
        cves = port.get("cves", []) or []
        if cves:
            for cve in cves[:4]:
                rows.append([_host(port), f"{port.get('port', '')}/{port.get('protocol', 'tcp')}", _service(port), port.get("product", ""), port.get("version", ""), cve.get("cve", ""), cve.get("severity", "")])
        else:
            rows.append([_host(port), f"{port.get('port', '')}/{port.get('protocol', 'tcp')}", _service(port), port.get("product", ""), port.get("version") or "Version non exposée", "", ""])
    if len(ports) > limit:
        rows.append(["...", "", "", "", f"{len(ports) - limit} ports supplémentaires masqués", "Voir export JSON/Excel", ""])
    if len(rows) == 1:
        rows.append(["Aucun", "", "", "", "", "", scan.get("note", "Aucun port ouvert détecté ou Nmap indisponible.")])
    return _table(rows, [4.4 * cm, 2.2 * cm, 2.9 * cm, 4.2 * cm, 3.5 * cm, 3.4 * cm, 2.5 * cm], small=True, styles=styles)



def _dnsdumpster_summary_table(dd: dict, styles):
    rows = [["Section", "Volume"]]
    rows.extend([
        ["System Locations", str(len(dd.get("system_locations", {}) or {}))],
        ["Hosting / Networks", str(len(dd.get("hosting_networks", []) or []))],
        ["Services / Banners", str(len(dd.get("services_banners", {}) or {}))],
        ["A Records enrichis", str(len(dd.get("a_records", []) or []))],
        ["MX Records enrichis", str(len(dd.get("mx_records", []) or []))],
        ["NS Records enrichis", str(len(dd.get("ns_records", []) or []))],
        ["TXT Records", str(len(dd.get("txt_records", []) or []))],
    ])
    return _table(rows, [15.0 * cm, 5.0 * cm], styles=styles)


def _system_locations_table(dd: dict, styles):
    rows = [["Country", "Count"]]
    for country, count in (dd.get("system_locations", {}) or {}).items():
        rows.append([country, str(count)])
    if len(rows) == 1:
        rows.append(["Unknown", "0"])
    return _table(rows, [16.0 * cm, 4.0 * cm], styles=styles)


def _hosting_networks_table(dd: dict, styles):
    rows = [["ASN", "Network", "ASN Name", "Country", "Hosts"]]
    for h in dd.get("hosting_networks", []) or []:
        rows.append([h.get("asn"), h.get("network"), h.get("asn_name"), h.get("country"), h.get("count")])
    if len(rows) == 1:
        rows.append(["Non détecté", "Non détecté", "Non détecté", "Unknown", "0"])
    return _table(rows, [3.0 * cm, 4.2 * cm, 11.8 * cm, 3.0 * cm, 2.0 * cm], small=True, styles=styles)


def _services_banners_table(dd: dict, styles):
    rows = [["Banner", "Count"]]
    for banner, count in (dd.get("services_banners", {}) or {}).items():
        rows.append([banner, str(count)])
    if len(rows) == 1:
        rows.append(["Non détecté", "0"])
    return _table(rows, [17.0 * cm, 3.0 * cm], styles=styles)


def _dnsdumpster_hosts_table(records: list, styles, limit: int = 70, mx: bool = False):
    headers = (["Priority"] if mx else []) + ["Host", "IP", "ASN", "Network", "ASN Name", "Country", "Open Services observed", "RevIP", "Sources"]
    rows = [headers]
    for h in (records or [])[:limit]:
        base = [h.get("host"), h.get("ip"), h.get("asn"), h.get("network"), h.get("asn_name"), h.get("country"), _open_services_line(h), h.get("revip_count", 0), ", ".join(h.get("sources", []) or [])]
        rows.append(([h.get("priority")] if mx else []) + base)
    if len(records or []) > limit:
        rows.append((["..."] if mx else []) + [f"{len(records)-limit} lignes supplémentaires", "Voir JSON/Excel", "", "", "", "", "", "", ""])
    if len(rows) == 1:
        rows.append(([""] if mx else []) + ["Aucun", "Not found", "Non détecté", "Non détecté", "Non détecté", "Unknown", "Non détecté", "0", ""])
    widths = ([1.8 * cm] if mx else []) + [4.2 * cm, 2.8 * cm, 2.4 * cm, 3.4 * cm, 5.2 * cm, 2.5 * cm, 7.4 * cm, 1.7 * cm, 2.7 * cm]
    scale = 25.5 * cm / sum(widths)
    widths = [w * scale for w in widths]
    return _table(rows, widths, small=True, styles=styles)


def _txt_records_table(dd: dict, styles):
    rows = [["Type", "Value", "SPF providers", "SPF includes/ip"]]
    for item in dd.get("txt_records", []) or []:
        spf = item.get("spf") or {}
        rows.append([item.get("type"), item.get("value"), ", ".join(spf.get("providers", []) or []), "; ".join((spf.get("includes", []) or []) + (spf.get("ip4", []) or []) + (spf.get("ip6", []) or []))])
    if len(rows) == 1:
        rows.append(["TXT", "Non détecté", "", ""])
    return _table(rows, [2.1 * cm, 14.4 * cm, 4.0 * cm, 5.0 * cm], small=True, styles=styles)


def _host_inventory_detail(dd: dict, styles, limit: int = 40):
    rows = [["Host", "IP / ASN", "HTTP/HTTPS/TLS", "Technologies", "Nmap"]]
    for h in (dd.get("hosts", []) or [])[:limit]:
        tls = h.get("tls") or {}
        tls_txt = f"cn: {tls.get('cn', 'Non détecté')}; issuer: {tls.get('issuer', 'Non détecté')}; exp: {tls.get('expires_at', 'Non détecté')}"
        rows.append([
            h.get("host"),
            f"{h.get('ip')} | {h.get('asn')} | {h.get('network')} | {h.get('country')}",
            f"{_open_services_line(h)}; {tls_txt}",
            _tech_line(h),
            _nmap_line(h) or "Non détecté par Nmap",
        ])
    if len(rows) == 1:
        rows.append(["Aucun", "", "", "", ""])
    return _table(rows, [4.3 * cm, 5.3 * cm, 7.4 * cm, 5.0 * cm, 3.5 * cm], small=True, styles=styles)


def _cve_table(audit: dict, styles, limit: int = 80):
    cves = (audit.get("service_scan", {}) or {}).get("cves", []) or []
    rows = [["CVE", "Host", "Service", "Version", "Sévérité", "Preuve"]]
    for c in cves[:limit]:
        rows.append([c.get("cve"), c.get("hostname") or c.get("host"), c.get("service") or c.get("product"), c.get("version") or "Version non exposée", c.get("severity"), c.get("evidence")])
    if len(rows) == 1:
        rows.append(["Aucune", "", "", "", "", "Aucune CVE corrélée par version exposée."])
    return _table(rows, [3.0 * cm, 4.0 * cm, 4.0 * cm, 3.5 * cm, 2.5 * cm, 8.5 * cm], small=True, styles=styles)


def _limits_sources_table(audit: dict, dd: dict, styles):
    policy = dd.get("policy", {}) or {}
    rows = [["Point", "Détail"]]
    rows.extend([
        ["Sources", "DNS, sous-domaines passifs/fallback, ASN Team Cymru, HTTP/HTTPS fingerprint, TLS certificate, Nmap en annexe."],
        ["HTTP", f"User-Agent: {policy.get('user_agent', 'OpenEASM-Beta-26.6 Defensive Audit')} ; timeout {policy.get('http_timeout_seconds', 8)} s ; concurrence {policy.get('concurrency', 10)}."],
        ["Garde-fous", "Aucun exploit, aucun bruteforce, aucun DoS, aucun NSE intrusif ; cibles privées/réservées ou mixtes bloquées."],
        ["Nmap", "Source complémentaire seulement. Une absence Nmap ne masque pas un service HTTP/HTTPS observé."],
        ["Données passives", "Optionnelles via clés API ; aucune donnée inventée si non configuré."],
        ["Non détecté", "Les informations absentes restent Non détecté / Version non exposée / Non détecté par Nmap."],
    ])
    return _table(rows, [5.0 * cm, 20.5 * cm], styles=styles)


def _open_services_line(h: dict) -> str:
    parts = []
    for svc in h.get("open_services", []) or []:
        seg = f"{svc.get('scheme')}: {svc.get('banner') or svc.get('service') or 'unknown server'}"
        if svc.get("title") and svc.get("title") != "Non détecté":
            seg += f"; title: {svc.get('title')}"
        parts.append(seg)
    tls = h.get("tls") or {}
    if tls.get("cn") and tls.get("cn") != "Non détecté":
        parts.append(f"cn: {tls.get('cn')}")
    tech = _tech_line(h)
    if tech and tech != "Non détecté":
        parts.append(f"tech: {tech}")
    return "; ".join(parts) or ("Bloqué par garde-fou" if h.get("guardrail") else "Non détecté")


def _tech_line(h: dict) -> str:
    out = []
    for t in h.get("technologies", []) or []:
        name = t.get("name") or ""
        if t.get("version"):
            name += f":{t.get('version')}"
        if t.get("note"):
            name += f" ({t.get('note')})"
        out.append(name)
    return ", ".join(dict.fromkeys(out)) or "Non détecté"


def _nmap_line(h: dict) -> str:
    parts = []
    for s in h.get("nmap_services", []) or []:
        parts.append(f"{s.get('port')}/{s.get('protocol', 'tcp')} {s.get('name') or s.get('service') or ''} {s.get('product') or ''} {s.get('version') or 'Version non exposée'}".strip())
    return "; ".join(parts)

def _callout(text: str, styles, tone: str = "neutral"):
    bg = colors.HexColor("#ECFFF5") if tone == "safe" else CARD_ALT
    bar = GREEN if tone == "safe" else GOLD
    table = Table([[Paragraph(_p_text(text, MAX_LONG_CELL_CHARS), styles["Body"])]], colWidths=[25.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("LINEBEFORE", (0, 0), (0, 0), 4.0, bar),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return table


def _table(data, col_widths, small=False, header=True, styles=None):
    styles = styles or _styles()
    cell_style = styles["CellSmall" if small else "Cell"]
    header_style = styles["HeaderCell"]
    converted = []
    for r, row in enumerate(data):
        new_row = []
        for value in row:
            style = header_style if header and r == 0 else cell_style
            max_chars = MAX_LONG_CELL_CHARS if r == 0 else MAX_CELL_CHARS
            new_row.append(Paragraph(_p_text(value, max_chars), style))
        converted.append(new_row)

    table = LongTable(converted, colWidths=col_widths, repeatRows=1 if header else 0, splitByRow=1)
    ts = [
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("GRID", (0, 0), (-1, -1), 0.28, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4.3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.3),
        ("TOPPADDING", (0, 0), (-1, -1), 3.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.8),
    ]
    if header:
        ts += [("BACKGROUND", (0, 0), (-1, 0), CARD_ALT), ("LINEBELOW", (0, 0), (-1, 0), 0.7, GOLD)]
    for r in range(1 if header else 0, len(data)):
        if r % 2 == 0:
            ts.append(("BACKGROUND", (0, r), (-1, r), ROW_ALT))
    table.setStyle(TableStyle(ts))
    return table


def _decorate_page(canvas: Canvas, doc):
    width, height = landscape(A4)
    canvas.saveState()
    canvas.setFillColor(PAGE_BG)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)
    canvas.setFillColor(RED_DARK)
    canvas.rect(0, height - 1.0 * cm, width, 1.0 * cm, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, height - 1.04 * cm, width, 0.04 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(GOLD_LIGHT)
    canvas.drawString(1.1 * cm, height - 0.66 * cm, "OPENEASM BETA")
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#F8E9BE"))
    canvas.drawRightString(width - 1.1 * cm, height - 0.66 * cm, "Audit externe défensif - service/version/CVE non exploitant")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(width - 1.1 * cm, 0.55 * cm, f"Page {doc.page}")
    canvas.restoreState()


def _conclusion(audit):
    return (
        f"Le domaine {audit.get('domain')} obtient un score de {audit.get('score', {}).get('score')} / 1000. "
        f"Profil : {audit.get('domain_profile', {}).get('label', 'N/A')}. "
        f"Surface observée : {audit.get('ip_inventory', {}).get('public_ip_count', 0)} IP publiques, "
        f"{audit.get('subdomains', {}).get('count', 0)} sous-domaines, "
        f"{audit.get('service_scan', {}).get('count_open_ports', 0)} ports ouverts Nmap et "
        f"{audit.get('service_scan', {}).get('count_cves', 0)} CVE corrélées par service/version. "
        "Les résultats sont priorisés pour faciliter la décision et la correction opérationnelle."
    )


def _p_text(value: Any, max_chars: int = MAX_CELL_CHARS) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\r", "").strip()
    if len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return escape(text).replace("\n", "<br/>")


def _host(port: dict) -> str:
    return str(port.get("hostname") or port.get("host") or port.get("ip") or "")


def _service(port: dict) -> str:
    return str(port.get("name") or port.get("service") or "")


def _loc(loc):
    if not isinstance(loc, dict):
        return ""
    return loc.get("display") or loc.get("path") or loc.get("record") or loc.get("hostname") or loc.get("control") or ""


def _sev_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(sev).lower(), 5)


def _priority_label(sev):
    return {"critical": "P1 immédiat", "high": "P2 prioritaire", "medium": "P3 planifié", "low": "P4 amélioration", "info": "Information"}.get(str(sev).lower(), "Information")


def _sla_for(sev):
    return {"critical": "< 5 jours", "high": "< 15 jours", "medium": "< 30 jours", "low": "< 90 jours", "info": "Suivi"}.get(str(sev).lower(), "Suivi")
