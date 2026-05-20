from __future__ import annotations

from pathlib import Path
from datetime import datetime
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
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
from reportlab.pdfgen.canvas import Canvas

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

PAGE_BG = colors.HexColor("#F8F4E8")
INK = colors.HexColor("#17120D")
MUTED = colors.HexColor("#5E5750")
RED = colors.HexColor("#E50914")
RED_DARK = colors.HexColor("#7F0008")
GOLD = colors.HexColor("#B8871B")
GOLD_LIGHT = colors.HexColor("#FFE29A")
CARD = colors.HexColor("#FFFDF7")
CARD_ALT = colors.HexColor("#FFF7E0")
BORDER = colors.HexColor("#D9BE7E")
ROW_ALT = colors.HexColor("#FFF9EA")
WHITE = colors.white


def generate_pdf_report(audit: dict) -> str:
    filename = f"open_easm_v7_5_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = REPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=1.15 * cm,
        leftMargin=1.15 * cm,
        topMargin=1.35 * cm,
        bottomMargin=1.15 * cm,
        title=f"OpenEASM V7.5 - {audit['domain']}",
    )

    styles = _styles()
    story = []
    domain = audit.get("domain", "N/A")
    score = audit.get("score", {}) or {}
    risk = audit.get("executive_risk", {}) or {}
    scan = audit.get("service_scan", {}) or {}
    graph = audit.get("attack_graph", {}) or {}

    story.append(_hero_block(audit, styles))
    story.append(Spacer(1, 0.28 * cm))

    kpis = [
        ("Score global", f"{score.get('score', 'N/A')} / {score.get('max_score', 1000)}", score.get("level", "N/A")),
        ("Risque executif", f"{risk.get('overall_score', 'N/A')} / {risk.get('max_score', 100)}", risk.get("risk_level", "N/A")),
        ("Surface exposee", f"{audit.get('ip_inventory', {}).get('public_ip_count', 0)} IP", f"{audit.get('subdomains', {}).get('count', 0)} sous-domaines"),
        ("Nmap", f"{scan.get('count_open_ports', 0)} ports", f"{scan.get('count_cves', 0)} CVE"),
    ]
    story.append(_kpi_cards(kpis, styles))
    story.append(Spacer(1, 0.30 * cm))

    story.append(Paragraph("Synthese direction", styles["Section"]))
    story.append(Paragraph(str(risk.get("board_summary", _conclusion(audit))), styles["Body"]))
    story.append(Spacer(1, 0.18 * cm))

    story.append(_risk_overview(risk, styles))
    story.append(Spacer(1, 0.25 * cm))

    story.append(Paragraph("Plan d'action priorise", styles["Section"]))
    story.append(_actions_table(audit, styles))

    story.append(PageBreak())
    story.append(Paragraph("Constats priorises avec localisation", styles["Section"]))
    story.append(_findings_table(audit, styles))

    story.append(PageBreak())
    story.append(Paragraph("Cartographie de l'exposition", styles["Section"]))
    graph_rows = [
        ["Indicateur", "Valeur", "Lecture"],
        ["Noeuds Graph Explorer", str((graph.get("metrics") or {}).get("nodes", 0)), "Domaines, IP, services, CVE et constats"],
        ["Relations", str((graph.get("metrics") or {}).get("edges", 0)), "Liens DNS, exposition web, ports, CVE"],
        ["IP publiques", str(audit.get("ip_inventory", {}).get("public_ip_count", 0)), "Surface reseau publique observee"],
        ["Sous-domaines", str(audit.get("subdomains", {}).get("count", 0)), "Decouverte passive"],
    ]
    story.append(_table(graph_rows, [5.5 * cm, 4 * cm, 16 * cm], styles=styles))
    story.append(Spacer(1, 0.25 * cm))

    story.append(Paragraph("Sous-domaines publics", styles["SectionSmall"]))
    story.append(_subdomains_table(audit, styles))
    story.append(Spacer(1, 0.22 * cm))

    story.append(Paragraph("Inventaire IP", styles["SectionSmall"]))
    story.append(_ip_table(audit, styles))

    story.append(PageBreak())
    story.append(Paragraph("Nmap service / version / CVE - non exploitant", styles["Section"]))
    story.append(Paragraph(
        "Controle limite a l'identification des ports ouverts, services et versions. La correlation CVE est realisee cote OpenEASM a partir des versions detectees. Aucun exploit, bruteforce, DoS ou script intrusif n'est execute.",
        styles["Body"],
    ))
    story.append(Spacer(1, 0.18 * cm))
    story.append(_nmap_table(audit, styles))

    story.append(PageBreak())
    story.append(Paragraph("Portee, limites et responsabilite", styles["Section"]))
    limits = [
        ["Point", "Detail"],
        ["Nature de l'audit", "Audit public defensif d'exposition externe."],
        ["Nmap", str(scan.get("note", "Service/version/port uniquement, sans exploitation."))],
        ["CVE", "Une CVE n'est affichee que si la version detectee permet une correlation raisonnable. Une version masquee ne doit pas generer de faux positif."],
        ["Responsabilite", "L'utilisateur doit disposer d'un droit, d'une autorisation explicite ou d'un motif legitime de securite informatique."],
    ]
    story.append(_table(limits, [5.0 * cm, 20.5 * cm], styles=styles))

    doc.build(story, onFirstPage=_decorate_page, onLaterPages=_decorate_page)
    return filename


def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("HeroTitle", parent=base["Title"], textColor=RED_DARK, fontSize=28, leading=32, alignment=TA_LEFT, spaceAfter=3))
    base.add(ParagraphStyle("HeroSubtitle", parent=base["BodyText"], textColor=MUTED, fontSize=10.5, leading=14, spaceAfter=4))
    base.add(ParagraphStyle("Eyebrow", parent=base["BodyText"], textColor=GOLD, fontSize=7.5, leading=9, fontName="Helvetica-Bold", spaceAfter=2))
    base.add(ParagraphStyle("Section", parent=base["Heading2"], textColor=RED_DARK, fontSize=15.5, leading=18, spaceBefore=5, spaceAfter=7))
    base.add(ParagraphStyle("SectionSmall", parent=base["Heading3"], textColor=GOLD, fontSize=11.5, leading=14, spaceBefore=4, spaceAfter=5))
    base.add(ParagraphStyle("Body", parent=base["BodyText"], textColor=INK, fontSize=8.8, leading=12.2))
    base.add(ParagraphStyle("Cell", parent=base["BodyText"], textColor=INK, fontSize=6.9, leading=8.4))
    base.add(ParagraphStyle("CellSmall", parent=base["BodyText"], textColor=INK, fontSize=6.2, leading=7.4))
    base.add(ParagraphStyle("HeaderCell", parent=base["BodyText"], textColor=RED_DARK, fontSize=6.9, leading=8.2, fontName="Helvetica-Bold"))
    base.add(ParagraphStyle("KpiLabel", parent=base["BodyText"], textColor=MUTED, fontSize=7.2, leading=9, fontName="Helvetica-Bold", alignment=TA_CENTER))
    base.add(ParagraphStyle("KpiValue", parent=base["BodyText"], textColor=RED_DARK, fontSize=15, leading=17, fontName="Helvetica-Bold", alignment=TA_CENTER))
    base.add(ParagraphStyle("KpiNote", parent=base["BodyText"], textColor=GOLD, fontSize=7.1, leading=9, alignment=TA_CENTER))
    return base


def _hero_block(audit: dict, styles):
    domain = audit.get("domain", "N/A")
    date = audit.get("created_at", datetime.utcnow().isoformat())
    logo_path = Path(__file__).resolve().parents[1] / "static" / "assets" / "cyborg.png"
    logo_block = [Paragraph("OPENEASM V7.5", styles["HeroTitle"])]
    if logo_path.exists():
        logo_block.insert(0, RLImage(str(logo_path), width=1.8 * cm, height=1.9 * cm))
    data = [[
        logo_block,
        Paragraph("Rapport d'exposition externe - audit defensif service/version/CVE non exploitant", styles["HeroSubtitle"]),
        Paragraph(f"Domaine audite : <b>{escape(domain)}</b><br/>Generation : {escape(str(date))}<br/>Livrable : PDF executif et technique", styles["HeroSubtitle"]),
    ]]
    t = Table(data, colWidths=[7.2 * cm, 10 * cm, 8.6 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def _kpi_cards(items, styles):
    row = []
    for label, value, note in items:
        row.append(Paragraph(f"<para alignment='center'><b>{escape(str(label))}</b><br/><font size='16' color='#7F0008'><b>{escape(str(value))}</b></font><br/><font color='#B8871B'>{escape(str(note))}</font></para>", styles["Body"]))
    table = Table([row], colWidths=[6.3 * cm] * 4)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return table


def _risk_overview(risk: dict, styles):
    rows = [["Pilier", "Score", "Niveau", "Risque", "Constats"]]
    for p in risk.get("pillars", []) or []:
        score = p.get("score", "N/A")
        rows.append([p.get("label", ""), f"{score} / 100" if score != "N/A" else "N/A", p.get("level", ""), p.get("risk", ""), str(p.get("findings_count", 0))])
    if len(rows) == 1:
        rows.append(["Scoring", "N/A", "Indisponible", "N/A", "0"])
    return _table(rows, [5.2 * cm, 3 * cm, 5 * cm, 6 * cm, 3 * cm], styles=styles)


def _actions_table(audit: dict, styles):
    rows = [["Priorite", "Severite", "Categorie", "Lieu / source", "Action recommandee", "SLA"]]
    findings = sorted(audit.get("findings", []), key=lambda x: _sev_order(x.get("severity", "info")))[:18]
    for f in findings:
        sev = f.get("severity", "info")
        rows.append([_priority_label(sev), sev, f.get("category", ""), _loc(f.get("location", {})), f.get("recommendation") or f.get("title", ""), _sla_for(sev)])
    if len(rows) == 1:
        rows.append(["Info", "info", "Aucun", "N/A", "Aucun constat prioritaire.", "Suivi"])
    return _table(rows, [2.3 * cm, 2.2 * cm, 3.2 * cm, 5.4 * cm, 9.8 * cm, 2.3 * cm], small=True, styles=styles)


def _findings_table(audit: dict, styles):
    rows = [["Severite", "Categorie", "Lieu / source", "Description", "Recommandation"]]
    for f in sorted(audit.get("findings", []), key=lambda x: _sev_order(x.get("severity", "info")))[:28]:
        rows.append([f.get("severity", ""), f.get("category", ""), _loc(f.get("location", {})), f.get("description", ""), f.get("recommendation", "")])
    if len(rows) == 1:
        rows.append(["info", "Aucun", "N/A", "Aucun constat notable.", "Maintenir la surveillance."])
    return _table(rows, [2.1 * cm, 3.1 * cm, 5.4 * cm, 8 * cm, 8 * cm], small=True, styles=styles)


def _subdomains_table(audit: dict, styles):
    sub = audit.get("subdomains", {}) or {}
    rows = [["Sous-domaine", "Source", "Note"]]
    for name in (sub.get("subdomains") or [])[:80]:
        rows.append([name, sub.get("source", "passif"), ""])
    if sub.get("error"):
        rows.append(["Source limitee", "crt.sh / passif", str(sub.get("error"))[:320]])
    if len(rows) == 1:
        rows.append(["Aucun", sub.get("source", "passif"), "Aucun sous-domaine affiche."])
    return _table(rows, [8 * cm, 6 * cm, 11.5 * cm], small=True, styles=styles)


def _ip_table(audit: dict, styles):
    rows = [["IP", "Perimetre", "Sources", "Hostnames"]]
    inv = audit.get("ip_inventory", {}) or {}
    for item in (inv.get("unique_ips") or inv.get("display_ips") or [])[:65]:
        rows.append([item.get("ip", ""), item.get("scope", ""), ", ".join(item.get("sources", [])), ", ".join(item.get("hostnames", [])[:6])])
    if len(rows) == 1:
        rows.append(["Aucune", "N/A", "N/A", "N/A"])
    return _table(rows, [4.2 * cm, 3.6 * cm, 4.5 * cm, 13.2 * cm], small=True, styles=styles)


def _nmap_table(audit: dict, styles):
    scan = audit.get("service_scan", {}) or {}
    rows = [["Hote", "Port", "Service", "Produit", "Version", "CVE", "Severite"]]
    for port in scan.get("open_ports", [])[:80]:
        cves = port.get("cves", []) or []
        if cves:
            for cve in cves:
                rows.append([port.get("hostname", ""), f"{port.get('port', '')}/{port.get('protocol', 'tcp')}", port.get("name", ""), port.get("product", ""), port.get("version", ""), cve.get("cve", ""), cve.get("severity", "")])
        else:
            rows.append([port.get("hostname", ""), f"{port.get('port', '')}/{port.get('protocol', 'tcp')}", port.get("name", ""), port.get("product", ""), port.get("version") or "Version non exposee", "", ""])
    if len(rows) == 1:
        rows.append(["Aucun", "", "", "", "", "", scan.get("note", "Aucun port ouvert detecte ou Nmap indisponible.")])
    return _table(rows, [4.5 * cm, 2.4 * cm, 3 * cm, 4.4 * cm, 3.3 * cm, 3.4 * cm, 2.3 * cm], small=True, styles=styles)


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
        ("LEFTPADDING", (0, 0), (-1, -1), 4.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4.5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
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
    canvas.rect(0, height - 1.04 * cm, width, 0.035 * cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(GOLD_LIGHT)
    canvas.drawString(1.15 * cm, height - 0.66 * cm, "OPENEASM V7.5")
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#F8E9BE"))
    canvas.drawRightString(width - 1.15 * cm, height - 0.66 * cm, "Audit defensif externe - non exploitant")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(width - 1.15 * cm, 0.62 * cm, f"Page {doc.page}")
    canvas.restoreState()


def _conclusion(audit):
    return (
        f"Le domaine {audit.get('domain')} obtient un score de {audit.get('score', {}).get('score')} / 1000. "
        f"Le profil detecte est {audit.get('domain_profile', {}).get('label', 'N/A')}. "
        f"L'audit recense {audit.get('ip_inventory', {}).get('public_ip_count', 0)} IP publiques, "
        f"{audit.get('subdomains', {}).get('count', 0)} sous-domaines, "
        f"{audit.get('passive_cves', {}).get('count', 0)} CVE potentielles passives et "
        f"{audit.get('service_scan', {}).get('count_cves', 0)} CVE issues de la correlation service/version. "
        "Les constats sont localises pour faciliter la correction operationnelle."
    )


def _loc(loc):
    if not isinstance(loc, dict):
        return ""
    return loc.get("display") or loc.get("path") or loc.get("record") or loc.get("hostname") or loc.get("control") or ""


def _sev_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(sev).lower(), 5)


def _priority_label(sev):
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "Info"}.get(str(sev).lower(), "Info")


def _sla_for(sev):
    return {"critical": "< 5 j", "high": "< 15 j", "medium": "< 30 j", "low": "< 90 j", "info": "Suivi"}.get(str(sev).lower(), "Suivi")
