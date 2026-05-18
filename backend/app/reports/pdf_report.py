from __future__ import annotations

from pathlib import Path
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

def generate_pdf_report(audit: dict) -> str:
    filename = f"open_easm_v4_3_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = REPORT_DIR / filename

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=1.5*cm,
        leftMargin=1.5*cm,
        topMargin=1.5*cm,
        bottomMargin=1.5*cm,
        title=f"Open EASM V4.3 - {audit['domain']}",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="Hero",
        parent=styles["Title"],
        textColor=colors.HexColor("#E50914"),
        fontSize=24,
        leading=30,
        spaceAfter=18,
    ))
    styles.add(ParagraphStyle(
        name="Section",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#111111"),
        fontSize=15,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="BodySmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
    ))

    story = []

    story.append(Paragraph("Open EASM V4.3", styles["Hero"]))
    story.append(Paragraph(f"Rapport d'exposition externe — {audit['domain']}", styles["Heading2"]))
    story.append(Paragraph(f"Date : {audit['created_at']}", styles["BodyText"]))
    story.append(Spacer(1, 0.4*cm))

    score = audit.get("score", {})
    tls = audit.get("tls_score", {})
    profile = audit.get("domain_profile", {})

    summary_data = [
        ["Indicateur", "Valeur"],
        ["Score global", f"{score.get('score')} / {score.get('max_score')} ({score.get('level')})"],
        ["Profil", profile.get("label", "N/A")],
        ["Score TLS/SSL", f"{tls.get('global_score')} / 100 ({tls.get('global_level')})"],
        ["IP publiques", str(audit.get("ip_inventory", {}).get("public_ip_count", 0))],
        ["Sous-domaines publics", str(audit.get("subdomains", {}).get("count", 0))],
        ["CVE potentielles passives", str(audit.get("passive_cves", {}).get("count", 0))],
    ]
    story.append(_table(summary_data))
    story.append(Spacer(1, 0.4*cm))

    story.append(Paragraph("Synthèse exécutive", styles["Section"]))
    story.append(Paragraph(_conclusion(audit), styles["BodyText"]))

    story.append(Paragraph("Constats prioritaires", styles["Section"]))
    findings = sorted(audit.get("findings", []), key=lambda f: _sev_order(f.get("severity", "info")))[:15]
    if findings:
        data = [["Sévérité", "Catégorie", "Constat", "Recommandation"]]
        for f in findings:
            data.append([
                f.get("severity", ""),
                f.get("category", ""),
                f.get("title", ""),
                f.get("recommendation", ""),
            ])
        story.append(_table(data, small=True))
    else:
        story.append(Paragraph("Aucun constat prioritaire détecté.", styles["BodyText"]))

    story.append(PageBreak())
    story.append(Paragraph("Inventaire IP", styles["Section"]))
    ip_rows = [["IP", "Publique", "Sources", "Hostnames"]]
    for item in audit.get("ip_inventory", {}).get("unique_ips", [])[:50]:
        ip_rows.append([
            item.get("ip"),
            str(item.get("is_public")),
            ", ".join(item.get("sources", [])),
            ", ".join(item.get("hostnames", [])[:5]),
        ])
    story.append(_table(ip_rows, small=True))

    story.append(Paragraph("Portée et limites", styles["Section"]))
    story.append(Paragraph(
        "Audit public non intrusif : DNS, messagerie, TLS, web headers, www automatique, Certificate Transparency, inventaire IP, CTI léger par DNSBL IPv4_3 et CVE potentielles passives sur headers HTTP. Aucun scan de ports, aucune exploitation, aucun bruteforce, aucune vérification intrusive de CVE.",
        styles["BodyText"]
    ))

    doc.build(story)
    return filename

def _conclusion(audit: dict) -> str:
    return (
        f"Le domaine {audit['domain']} obtient un score de {audit['score']['score']} / 1000. "
        f"Le profil détecté est : {audit.get('domain_profile', {}).get('label', 'N/A')}. "
        f"L'inventaire observe {audit.get('ip_inventory', {}).get('public_ip_count', 0)} IP publiques, "
        f"{audit.get('subdomains', {}).get('count', 0)} sous-domaines publics et "
        f"{audit.get('passive_cves', {}).get('count', 0)} CVE potentielles passives. "
        "Les résultats doivent être confirmés par une analyse autorisée pour les actions critiques."
    )

def _sev_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)

def _table(data, small=False):
    style = TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#111111")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor("#D4AF37")),
        ("GRID", (0,0), (-1,-1), 0.35, colors.HexColor("#B8860B")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 7 if small else 9),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ])
    t = Table(data, repeatRows=1)
    t.setStyle(style)
    return t
