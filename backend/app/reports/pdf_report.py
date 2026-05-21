from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Flowable,
    Image as RLImage,
    KeepTogether,
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
RED_SOFT = colors.HexColor("#F6D7D9")
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
        subject="External Attack Surface Management defensive audit",
    )

    styles = _styles()
    story = []
    risk = audit.get("executive_risk", {}) or {}
    score = audit.get("score", {}) or {}
    scan = audit.get("service_scan", {}) or {}
    graph = audit.get("attack_graph", {}) or {}

    story.append(_cover_block(audit, styles))
    story.append(Spacer(1, 0.30 * cm))
    story.append(_kpi_cards(audit, styles))
    story.append(Spacer(1, 0.18 * cm))
    story.append(_score_panel(audit, styles))
    story.append(Spacer(1, 0.25 * cm))

    story.append(Paragraph("Synthèse exécutive", styles["Section"]))
    story.append(_callout(str(risk.get("board_summary") or _conclusion(audit)), styles, tone="neutral"))
    story.append(Spacer(1, 0.20 * cm))

    story.append(Paragraph("Plan d'action priorisé", styles["Section"]))
    story.append(_actions_table(audit, styles, limit=12))

    story.append(PageBreak())
    story.append(Paragraph("Vue de risque par pilier", styles["Section"]))
    story.append(_risk_overview(risk, styles))
    story.append(Spacer(1, 0.22 * cm))
    story.append(SeverityLegend(score.get("by_severity", {})))
    story.append(Spacer(1, 0.28 * cm))
    story.append(Paragraph("Constats prioritaires localisés", styles["Section"]))
    story.append(_findings_table(audit, styles, limit=26))

    story.append(PageBreak())
    story.append(Paragraph("Cartographie de l'exposition", styles["Section"]))
    graph_rows = [
        ["Indicateur", "Valeur", "Lecture"],
        ["Noeuds Graph Explorer", str((graph.get("metrics") or {}).get("nodes", 0)), "Domaines, sous-domaines, IP, services, CVE et constats"],
        ["Relations", str((graph.get("metrics") or {}).get("edges", 0)), "Liens DNS, exposition web, ports, CVE et constats"],
        ["IP publiques", str(audit.get("ip_inventory", {}).get("public_ip_count", 0)), "Surface réseau publique observée"],
        ["Sous-domaines", str(audit.get("subdomains", {}).get("count", 0)), "Découverte passive"],
        ["Ports Nmap", str(scan.get("count_open_ports", 0)), "Service/version/port, non exploitant"],
    ]
    story.append(_table(graph_rows, [5.2 * cm, 3.7 * cm, 16.6 * cm], styles=styles))
    story.append(Spacer(1, 0.25 * cm))

    cols = [[Paragraph("Sous-domaines publics", styles["SectionSmall"]), _subdomains_table(audit, styles, limit=38)], [Paragraph("Inventaire IP", styles["SectionSmall"]), _ip_table(audit, styles, limit=38)]]
    story.append(Table([cols], colWidths=[12.8 * cm, 12.8 * cm], style=[("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 8)]))

    story.append(PageBreak())
    story.append(Paragraph("Nmap service / version / CVE", styles["Section"]))
    story.append(_callout(
        "Contrôle non exploitant : identification des ports ouverts, services et versions. La corrélation CVE est effectuée côté OpenEASM à partir des versions détectées. Aucun exploit, bruteforce, DoS ou script intrusif n'est exécuté.",
        styles,
        tone="safe",
    ))
    story.append(Spacer(1, 0.16 * cm))
    story.append(_nmap_table(audit, styles, limit=60))

    story.append(PageBreak())
    story.append(Paragraph("Annexes : portée, limites et responsabilité", styles["Section"]))
    limits = [
        ["Point", "Détail"],
        ["Nature de l'audit", "Audit public défensif d'exposition externe. Les résultats sont issus d'informations visibles publiquement."],
        ["Nmap", str(scan.get("note", "Service/version/port uniquement, sans exploitation."))],
        ["CVE", "Une CVE n'est affichée que si la version détectée permet une corrélation raisonnable. Une version masquée ne doit pas générer de faux positif."],
        ["Versions masquées", "OpenEASM indique 'version non exposée' et recommande une vérification interne via inventaire serveur, EDR, gestion de parc ou paquet système."],
        ["Backports", "Les distributions Linux peuvent intégrer des correctifs de sécurité sans changer le numéro de version amont."],
        ["Responsabilité", "L'utilisateur doit disposer d'un droit, d'une autorisation explicite ou d'un motif légitime de sécurité informatique."],
    ]
    story.append(_table(limits, [5.2 * cm, 20.3 * cm], styles=styles))

    doc.build(story, onFirstPage=_decorate_page, onLaterPages=_decorate_page)
    return filename


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("CoverTitle", parent=base["Title"], textColor=RED_DARK, fontSize=29, leading=33, alignment=TA_LEFT, spaceAfter=3))
    base.add(ParagraphStyle("CoverSubtitle", parent=base["BodyText"], textColor=MUTED, fontSize=10.3, leading=14, spaceAfter=4))
    base.add(ParagraphStyle("Eyebrow", parent=base["BodyText"], textColor=GOLD_DARK, fontSize=7.5, leading=9, fontName="Helvetica-Bold", spaceAfter=2))
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
        f"<b>Domaine</b> : {escape(domain)}<br/><b>Génération</b> : {escape(str(created))}<br/><b>Mode</b> : audit défensif public, service/version/CVE non exploitant<br/><b>Livrables</b> : PDF, Excel, JSON",
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
    row = []
    for label, value, note in items:
        row.append(Paragraph(f"<b>{escape(str(label))}</b><br/><font size='15' color='#65000B'><b>{escape(str(value))}</b></font><br/><font color='#7B5500'>{escape(str(note))}</font>", styles["Body"]))
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
    left = [Paragraph("Lecture rapide", styles["SectionSmall"]), Paragraph(_conclusion(audit), styles["Body"])]
    right = [Paragraph("Score global", styles["SectionSmall"]), ScoreGauge(score.get("score", 0), score.get("max_score", 1000)), Spacer(1, 0.12 * cm), Paragraph(f"Niveau : <b>{escape(str(score.get('level', 'N/A')))}</b> | Posture : <b>{escape(str(risk.get('posture', 'N/A')))}</b>", styles["Body"])]
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


def _subdomains_table(audit: dict, styles, limit: int = 40):
    sub = audit.get("subdomains", {}) or {}
    rows = [["Sous-domaine", "Source"]]
    for name in (sub.get("subdomains") or [])[:limit]:
        rows.append([name, sub.get("source", "passif")])
    if len(rows) == 1:
        rows.append(["Aucun", sub.get("source", "passif")])
    return _table(rows, [8.8 * cm, 3.4 * cm], small=True, styles=styles)


def _ip_table(audit: dict, styles, limit: int = 40):
    rows = [["IP", "Périmètre", "Hostnames"]]
    inv = audit.get("ip_inventory", {}) or {}
    for item in (inv.get("unique_ips") or inv.get("display_ips") or [])[:limit]:
        rows.append([item.get("ip", ""), item.get("scope", ""), ", ".join(item.get("hostnames", [])[:4])])
    if len(rows) == 1:
        rows.append(["Aucune", "N/A", "N/A"])
    return _table(rows, [3.2 * cm, 2.7 * cm, 6.6 * cm], small=True, styles=styles)


def _nmap_table(audit: dict, styles, limit: int = 70):
    scan = audit.get("service_scan", {}) or {}
    rows = [["Hôte", "Port", "Service", "Produit", "Version", "CVE", "Sévérité"]]
    for port in scan.get("open_ports", [])[:limit]:
        cves = port.get("cves", []) or []
        if cves:
            for cve in cves:
                rows.append([port.get("hostname", ""), f"{port.get('port', '')}/{port.get('protocol', 'tcp')}", port.get("name", ""), port.get("product", ""), port.get("version", ""), cve.get("cve", ""), cve.get("severity", "")])
        else:
            rows.append([port.get("hostname", ""), f"{port.get('port', '')}/{port.get('protocol', 'tcp')}", port.get("name", ""), port.get("product", ""), port.get("version") or "Version non exposée", "", ""])
    if len(rows) == 1:
        rows.append(["Aucun", "", "", "", "", "", scan.get("note", "Aucun port ouvert détecté ou Nmap indisponible.")])
    return _table(rows, [4.4 * cm, 2.2 * cm, 2.9 * cm, 4.2 * cm, 3.5 * cm, 3.4 * cm, 2.5 * cm], small=True, styles=styles)


def _callout(text: str, styles, tone: str = "neutral"):
    bg = colors.HexColor("#ECFFF5") if tone == "safe" else CARD_ALT
    bar = GREEN if tone == "safe" else GOLD
    table = Table([[Paragraph(escape(text), styles["Body"])]], colWidths=[25.5 * cm])
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
            new_row.append(Paragraph(escape(str(value if value is not None else "")).replace("\n", "<br/>"), style))
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
