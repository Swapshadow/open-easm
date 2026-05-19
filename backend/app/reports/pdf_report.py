from __future__ import annotations

from pathlib import Path
from datetime import datetime
from html import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, PageBreak, KeepTogether
from reportlab.pdfgen.canvas import Canvas

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

BLACK = colors.HexColor("#F8F4E8")
CHARCOAL = colors.HexColor("#FFFFFF")
ROW_DARK = colors.HexColor("#FFF8E8")
RED = colors.HexColor("#E50914")
RED_DARK = colors.HexColor("#7F0008")
GOLD = colors.HexColor("#D4AF37")
GOLD_LIGHT = colors.HexColor("#FFE29A")
WHITE = colors.HexColor("#17120D")
MUTED = colors.HexColor("#5E5750")

def generate_pdf_report(audit: dict) -> str:
    filename = f"open_easm_v6_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = REPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=1.15*cm,
        leftMargin=1.15*cm,
        topMargin=1.35*cm,
        bottomMargin=1.15*cm,
        title=f"OpenEASM Alpha - {audit['domain']}",
    )

    styles = _styles()
    story = []

    story.append(Paragraph("OPENEASM ALPHA", styles["Hero"]))
    story.append(Paragraph("Rapport d'exposition externe - audit public non intrusif", styles["Subtitle"]))
    story.append(Spacer(1, 0.22*cm))

    kpi = [
        ["Domaine", audit.get("domain"), "Score", f"{audit.get('score', {}).get('score')} / 1000", "Niveau", audit.get("score", {}).get("level", "N/A")],
        ["Profil", audit.get("domain_profile", {}).get("label", "N/A"), "TLS/SSL", f"{audit.get('tls_score', {}).get('global_score')} / 100", "IP publiques", str(audit.get("ip_inventory", {}).get("public_ip_count", 0))],
        ["Sous-domaines", str(audit.get("subdomains", {}).get("count", 0)), "CVE passives", str(audit.get("passive_cves", {}).get("count", 0)), "Mode", audit.get("mode", "")],
    ]
    story.append(_table(kpi, [3.0*cm, 5.1*cm, 3.0*cm, 4.2*cm, 3.0*cm, 5.0*cm], header=False, styles=styles))
    story.append(Spacer(1, 0.35*cm))


    risk = audit.get("executive_risk", {}) or {}
    story.append(Paragraph("Executive Risk Overview", styles["Section"]))
    story.append(Paragraph(str(risk.get("board_summary", "Scoring exécutif indisponible.")), styles["Body"]))
    risk_rows = [["Indicateur", "Valeur"], ["Score exécutif", f"{risk.get('overall_score', 'N/A')} / {risk.get('max_score', 100)}"], ["Niveau de risque", risk.get("risk_level", "N/A")], ["Posture", risk.get("posture", "N/A")]]
    story.append(_table(risk_rows, [6.0*cm, 20.0*cm], small=True, styles=styles))
    story.append(Spacer(1, 0.22*cm))

    pillar_rows = [["Pilier", "Score", "Niveau", "Risque", "Constats"]]
    for p in risk.get("pillars", []) or []:
        pillar_rows.append([p.get("label", ""), f"{p.get('score', 'N/A')} / 100", p.get("level", ""), p.get("risk", ""), str(p.get("findings_count", 0))])
    story.append(_table(pillar_rows, [5.0*cm, 3.0*cm, 5.0*cm, 4.0*cm, 3.0*cm], small=True, styles=styles))
    story.append(Spacer(1, 0.22*cm))

    story.append(Paragraph("Synthese executive", styles["Section"]))
    story.append(Paragraph(_conclusion(audit), styles["Body"]))
    story.append(Spacer(1, 0.22*cm))

    story.append(Paragraph("Plan d'action priorise", styles["Section"]))
    action_rows = [["Priorite", "Severite", "Categorie", "Lieu / source", "Constat", "SLA"]]
    for f in sorted(audit.get("findings", []), key=lambda x: _sev_order(x.get("severity", "info")))[:16]:
        loc = f.get("location", {})
        sev = f.get("severity", "info")
        action_rows.append([_priority_label(sev), sev, f.get("category", ""), _loc(loc), f.get("title", ""), _sla_for(sev)])
    story.append(_table(action_rows, [2.2*cm, 2.1*cm, 2.8*cm, 6.2*cm, 8.0*cm, 2.2*cm], small=True, styles=styles))

    story.append(PageBreak())
    story.append(Paragraph("Constats priorises avec localisation", styles["Section"]))
    finding_rows = [["Severite", "Categorie", "Lieu / source", "Description", "Recommandation"]]
    for f in sorted(audit.get("findings", []), key=lambda x: _sev_order(x.get("severity", "info")))[:24]:
        loc = f.get("location", {})
        finding_rows.append([f.get("severity", ""), f.get("category", ""), _loc(loc), f.get("description", ""), f.get("recommendation", "")])
    story.append(_table(finding_rows, [2.1*cm, 2.9*cm, 5.4*cm, 8.0*cm, 8.0*cm], small=True, styles=styles))

    story.append(PageBreak())
    story.append(Paragraph("Sous-domaines publics", styles["Section"]))
    sub = audit.get("subdomains", {})
    sub_rows = [["Sous-domaine", "Source", "Note"]]
    for name in sub.get("subdomains", [])[:80]:
        sub_rows.append([name, sub.get("source", ""), ""])
    if sub.get("error"):
        sub_rows.append(["Source limitee", "crt.sh / source passive", str(sub.get("error"))[:350]])
    story.append(_table(sub_rows, [7.0*cm, 7.0*cm, 12.0*cm], small=True, styles=styles))

    story.append(Spacer(1, 0.25*cm))
    story.append(Paragraph("Inventaire IP", styles["Section"]))
    ip_rows = [["IP", "Perimetre", "Sources", "Hostnames"]]
    for item in audit.get("ip_inventory", {}).get("unique_ips", [])[:60]:
        ip_rows.append([item.get("ip", ""), item.get("scope", ""), ", ".join(item.get("sources", [])), ", ".join(item.get("hostnames", [])[:5])])
    story.append(_table(ip_rows, [4.1*cm, 3.5*cm, 4.2*cm, 14.2*cm], small=True, styles=styles))

    story.append(PageBreak())
    story.append(Paragraph("Portee et limites", styles["Section"]))
    story.append(Paragraph(
        "Ce rapport est issu d'un audit public non intrusif : DNS, messagerie, TLS, headers web, inventaire IP, CTI leger et CVE potentielles passives. "
        "Aucun scan de ports, aucune exploitation, aucun bruteforce et aucune verification intrusive de CVE ne sont realises.",
        styles["Body"]
    ))

    doc.build(story, onFirstPage=_decorate_page, onLaterPages=_decorate_page)
    return filename

def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("Hero", parent=base["Title"], textColor=GOLD_LIGHT, fontSize=25, leading=29, spaceAfter=4))
    base.add(ParagraphStyle("Subtitle", parent=base["Heading2"], textColor=WHITE, fontSize=13, leading=17, spaceAfter=10))
    base.add(ParagraphStyle("Section", parent=base["Heading2"], textColor=GOLD_LIGHT, fontSize=13.5, leading=16, spaceBefore=9, spaceAfter=6))
    base.add(ParagraphStyle("Body", parent=base["BodyText"], textColor=WHITE, fontSize=8.8, leading=12))
    base.add(ParagraphStyle("Cell", parent=base["BodyText"], textColor=WHITE, fontSize=6.7, leading=8.2))
    base.add(ParagraphStyle("CellSmall", parent=base["BodyText"], textColor=WHITE, fontSize=6.1, leading=7.4))
    base.add(ParagraphStyle("HeaderCell", parent=base["BodyText"], textColor=GOLD_LIGHT, fontSize=6.8, leading=8.2, fontName="Helvetica-Bold"))
    return base

def _decorate_page(canvas: Canvas, doc):
    width, height = landscape(A4)
    canvas.saveState()
    canvas.setFillColor(BLACK)
    canvas.rect(0, 0, width, height, fill=1, stroke=0)
    canvas.setFillColor(RED_DARK)
    canvas.rect(0, height-1.0*cm, width, 1.0*cm, fill=1, stroke=0)
    canvas.setFillColor(GOLD)
    canvas.rect(0, height-1.04*cm, width, 0.035*cm, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(GOLD_LIGHT)
    canvas.drawString(1.15*cm, height-0.66*cm, "OPENEASM ALPHA")
    canvas.setFillColor(MUTED)
    canvas.drawRightString(width-1.15*cm, 0.62*cm, f"Page {doc.page}")
    canvas.restoreState()

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
        ("BACKGROUND", (0,0), (-1,-1), BLACK),
        ("GRID", (0,0), (-1,-1), 0.30, GOLD),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]
    if header:
        ts += [
            ("BACKGROUND", (0,0), (-1,0), CHARCOAL),
            ("TEXTCOLOR", (0,0), (-1,0), GOLD_LIGHT),
        ]
    else:
        for col in range(0, len(data[0]), 2):
            ts += [("BACKGROUND", (col,0), (col,-1), CHARCOAL)]
    for r in range(1 if header else 0, len(data)):
        if r % 2 == 0:
            ts.append(("BACKGROUND", (0,r), (-1,r), ROW_DARK))
    table.setStyle(TableStyle(ts))
    return table

def _conclusion(audit):
    return (
        f"Le domaine {audit.get('domain')} obtient un score de {audit.get('score', {}).get('score')} / 1000. "
        f"Le profil detecte est {audit.get('domain_profile', {}).get('label', 'N/A')}. "
        f"L'audit recense {audit.get('ip_inventory', {}).get('public_ip_count', 0)} IP publiques, "
        f"{audit.get('subdomains', {}).get('count', 0)} sous-domaines et "
        f"{audit.get('passive_cves', {}).get('count', 0)} CVE potentielles passives. "
        "Les constats sont localises pour faciliter la correction operationnelle."
    )

def _loc(loc):
    if not isinstance(loc, dict):
        return ""
    return loc.get("display") or loc.get("path") or loc.get("record") or loc.get("hostname") or loc.get("control") or ""

def _sev_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)

def _priority_label(sev):
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "Info"}.get(sev, "Info")

def _sla_for(sev):
    return {"critical": "< 5 j", "high": "< 15 j", "medium": "< 30 j", "low": "< 90 j", "info": "Suivi"}.get(sev, "Suivi")
