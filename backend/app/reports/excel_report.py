from __future__ import annotations

from pathlib import Path
from datetime import datetime
import json
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

BLACK = "F8F4E8"
ROW_DARK = "FFF8E8"
CHARCOAL = "FFFFFF"
RED = "E50914"
GOLD = "D4AF37"
GOLD_LIGHT = "8A5D00"
WHITE = "17120D"
MUTED = "5E5750"
BORDER = "8A6F1D"

SEVERITY_FILL = {
    "critical": "7F0008",
    "high": "E50914",
    "medium": "D4AF37",
    "low": "8A6F1D",
    "info": "555555",
}

def generate_excel_report(audit: dict) -> str:
    wb = Workbook()
    ws = wb.active
    ws.title = "Executive Summary"
    _executive_summary(ws, audit)
    _sheet_executive_risk(wb, audit)

    _sheet_action_plan(wb, audit)
    _sheet_findings(wb, audit)
    _sheet_subdomains(wb, audit)
    _sheet_ip_inventory(wb, audit)
    _sheet_web_targets(wb, audit)
    _sheet_headers(wb, audit)
    _sheet_tls_score(wb, audit)
    _sheet_dns(wb, audit)
    _sheet_mail(wb, audit)
    _sheet_cti(wb, audit)
    _sheet_passive_cves(wb, audit)
    _sheet_patching_sla(wb, audit)
    _sheet_passive_sources(wb, audit)
    _sheet_guards(wb, audit)
    _sheet_raw_summary(wb, audit)

    filename = f"open_easm_v6_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    path = REPORT_DIR / filename
    wb.save(path)
    return filename

def _executive_summary(ws, audit):
    _paint_background(ws, rows=34, cols=10)
    ws.merge_cells("A1:J2")
    c = ws["A1"]
    c.value = "OPENEASM ALPHA - RAPPORT D'EXPOSITION EXTERNE"
    c.font = Font(bold=True, size=18, color=GOLD_LIGHT)
    c.fill = PatternFill("solid", fgColor=BLACK)
    c.alignment = Alignment(horizontal="center", vertical="center")

    score = audit.get("score", {})
    tls = audit.get("tls_score", {})
    profile = audit.get("domain_profile", {})
    ip = audit.get("ip_inventory", {})
    sub = audit.get("subdomains", {})

    rows = [
        ("Domaine audité", audit.get("domain")),
        ("Date audit", audit.get("created_at")),
        ("Mode", audit.get("mode")),
        ("Profil détecté", profile.get("label")),
        ("Score global", f"{score.get('score')} / {score.get('max_score')}"),
        ("Niveau global", score.get("level")),
        ("Score TLS/SSL", f"{tls.get('global_score')} / 100 ({tls.get('global_level')})"),
        ("IP publiques", ip.get("public_ip_count", 0)),
        ("IP coeur exposition", ip.get("core_public_ip_count", 0)),
        ("IP prestataires tiers", ip.get("third_party_provider_ip_count", 0)),
        ("Sous-domaines publics", sub.get("count", 0)),
        ("CVE potentielles passives", audit.get("passive_cves", {}).get("count", 0)),
    ]

    row = 4
    for k, v in rows:
        ws.cell(row, 1, k)
        ws.cell(row, 2, v)
        ws.cell(row, 1).font = Font(bold=True, color=GOLD_LIGHT)
        ws.cell(row, 2).font = Font(color=WHITE)
        ws.cell(row, 1).fill = PatternFill("solid", fgColor=CHARCOAL)
        ws.cell(row, 2).fill = PatternFill("solid", fgColor=BLACK)
        row += 1

    ws.merge_cells("D4:J14")
    ws["D4"] = _conclusion(audit)
    ws["D4"].font = Font(color=WHITE, size=12)
    ws["D4"].alignment = Alignment(wrap_text=True, vertical="top")
    ws["D4"].fill = PatternFill("solid", fgColor=CHARCOAL)

    row = 18
    ws.cell(row, 1, "Répartition des constats")
    ws.cell(row, 1).font = Font(bold=True, color=GOLD_LIGHT, size=14)
    row += 2
    ws.cell(row, 1, "Criticité")
    ws.cell(row, 2, "Nombre")
    _header_row(ws, row, 2)
    for label, key in [("Critique","critical"),("Élevée","high"),("Moyenne","medium"),("Faible","low"),("Information","info")]:
        row += 1
        ws.cell(row, 1, label)
        ws.cell(row, 2, score.get("by_severity", {}).get(key, 0))
        ws.cell(row, 1).fill = PatternFill("solid", fgColor=SEVERITY_FILL.get(key, "555555"))
        ws.cell(row, 1).font = Font(bold=True, color=BLACK if key == "medium" else WHITE)
        ws.cell(row, 2).fill = PatternFill("solid", fgColor=CHARCOAL)
        ws.cell(row, 2).font = Font(color=WHITE, bold=True)

    ws.merge_cells("D18:J25")
    ws["D18"] = (
        "Portée : audit public non intrusif. Les constats sont localisés pour permettre une correction opérationnelle. "
        "Les onglets techniques contiennent les sous-domaines, IP, DNS, messagerie, TLS, CTI, sources passives et garde-fous."
    )
    ws["D18"].font = Font(color=MUTED)
    ws["D18"].alignment = Alignment(wrap_text=True, vertical="top")
    ws["D18"].fill = PatternFill("solid", fgColor=BLACK)

    _format_sheet(ws, freeze=None)


def _sheet_executive_risk(wb, audit):
    ws = wb.create_sheet("Executive Risk")
    risk = audit.get("executive_risk", {}) or {}

    rows = [
        ["Score exécutif", f"{risk.get('overall_score', 'N/A')} / {risk.get('max_score', 100)}"],
        ["Niveau de risque", risk.get("risk_level", "N/A")],
        ["Posture", risk.get("posture", "N/A")],
        ["Profil", risk.get("profile", "N/A")],
        ["Synthèse direction", risk.get("board_summary", "")],
        ["Méthode", risk.get("method", "")],
    ]
    _table_sheet(ws, "EXECUTIVE RISK OVERVIEW", ["Indicateur", "Valeur"], rows)

    start = len(rows) + 8
    ws.cell(start, 1, "Piliers de risque")
    ws.cell(start, 1).font = Font(bold=True, color=GOLD_LIGHT, size=14)

    headers = ["Pilier", "Score", "Niveau", "Risque", "Constats", "Critique/Élevé", "Recommandation"]
    for col, h in enumerate(headers, 1):
        ws.cell(start + 1, col, h)
    _header_row(ws, start + 1, len(headers))

    for idx, p in enumerate(risk.get("pillars", []) or [], start + 2):
        values = [p.get("label"), p.get("score"), p.get("level"), p.get("risk"), p.get("findings_count"), p.get("critical_high_count"), p.get("recommendation")]
        for col, val in enumerate(values, 1):
            ws.cell(idx, col, _excel_value(val))
            ws.cell(idx, col).font = Font(color=WHITE)
            ws.cell(idx, col).fill = PatternFill("solid", fgColor=BLACK if idx % 2 else ROW_DARK)

    _format_sheet(ws)


def _sheet_action_plan(wb, audit):
    ws = wb.create_sheet("Plan Action")
    headers = ["Priorité", "Sévérité", "Catégorie", "Lieu / Source", "Constat", "Action recommandée", "SLA cible", "Applicabilité"]
    rows = []
    for f in sorted(audit.get("findings", []), key=lambda x: _severity_order(x.get("severity", "info"))):
        loc = f.get("location", {})
        sev = f.get("severity", "info")
        rows.append([
            _priority_label(sev),
            sev,
            f.get("category", ""),
            _loc(loc),
            f.get("title", ""),
            f.get("recommendation", ""),
            _sla_for(sev),
            ", ".join(f.get("applies_to", [])),
        ])
    _table_sheet(ws, "PLAN D'ACTION PRIORISÉ", headers, rows or [["-", "-", "-", "-", "Aucun constat", "-", "-", "-"]])

def _sheet_findings(wb, audit):
    ws = wb.create_sheet("Constats")
    headers = ["Sévérité", "Catégorie", "Lieu / Source", "Hostname", "Contrôle", "Record", "Titre", "Description", "Recommandation", "Applicabilité"]
    rows = []
    for f in sorted(audit.get("findings", []), key=lambda x: _severity_order(x.get("severity", "info"))):
        loc = f.get("location", {})
        rows.append([
            f.get("severity"),
            f.get("category"),
            _loc(loc),
            loc.get("hostname"),
            loc.get("control"),
            loc.get("record"),
            f.get("title"),
            f.get("description"),
            f.get("recommendation"),
            ", ".join(f.get("applies_to", [])),
        ])
    _table_sheet(ws, "CONSTATS PRIORISÉS AVEC LOCALISATION", headers, rows)

def _sheet_subdomains(wb, audit):
    ws = wb.create_sheet("Sous-domaines")
    sub = audit.get("subdomains", {})
    entries = audit.get("ip_inventory", {}).get("entries", [])
    ip_map = {}
    for e in entries:
        if e.get("source") == "subdomain":
            ip_map[e.get("hostname")] = ", ".join(e.get("ips", []))
    rows = []
    for name in sub.get("subdomains", []):
        rows.append([name, ip_map.get(name, ""), sub.get("source"), sub.get("error") or ""])
    _table_sheet(ws, "SOUS-DOMAINES PUBLICS", ["Sous-domaine", "IP résolues", "Source globale", "Erreur source éventuelle"], rows or [["Aucun", "", sub.get("source"), sub.get("error")]])

def _sheet_ip_inventory(wb, audit):
    ws = wb.create_sheet("Inventaire IP")
    headers = ["IP", "Publique", "Périmètre", "Sources", "Hostnames", "Résolution/CNAME"]
    rows = []
    for item in audit.get("ip_inventory", {}).get("unique_ips", []):
        rows.append([
            item.get("ip"),
            item.get("is_public"),
            item.get("scope"),
            ", ".join(item.get("sources", [])),
            "\n".join(item.get("hostnames", [])),
            "\n".join(item.get("resolved_names", [])),
        ])
    _table_sheet(ws, "INVENTAIRE IP COMPLET", headers, rows)

def _sheet_web_targets(wb, audit):
    ws = wb.create_sheet("Cibles Web")
    headers = ["Hostname", "Joignable", "Schéma", "IP publiques", "IP bloquées", "HTTP", "HTTPS", "URL finale HTTPS"]
    rows = []
    for t in audit.get("web", {}).get("targets", []):
        http = t.get("http") or {}
        https = t.get("https") or {}
        guard = t.get("guard") or {}
        rows.append([
            t.get("hostname"),
            t.get("reachable"),
            t.get("best_scheme"),
            ", ".join(guard.get("public_ips", [])),
            ", ".join(guard.get("blocked_ips", [])),
            f"reachable={http.get('reachable')} status={http.get('status_code')} url={http.get('final_url')}",
            f"reachable={https.get('reachable')} status={https.get('status_code')} url={https.get('final_url')}",
            https.get("final_url"),
        ])
    _table_sheet(ws, "CIBLES WEB", headers, rows)

def _sheet_headers(wb, audit):
    ws = wb.create_sheet("Headers HTTP")
    headers = ["Hostname", "Schéma", "Header", "Présent", "Valeur"]
    rows = []
    for t in audit.get("web", {}).get("targets", []):
        for scheme in ("http", "https"):
            data = t.get(scheme) or {}
            sec = data.get("security_headers") or t.get("security_headers") or {}
            if isinstance(sec, dict):
                for h, v in sec.items():
                    if isinstance(v, dict):
                        rows.append([t.get("hostname"), scheme, h, v.get("present"), v.get("value")])
            raw = data.get("headers") or {}
            if isinstance(raw, dict):
                for h, v in raw.items():
                    rows.append([t.get("hostname"), scheme, h, True, v])
    _table_sheet(ws, "HEADERS HTTP ET SÉCURITÉ", headers, rows)

def _sheet_tls_score(wb, audit):
    ws = wb.create_sheet("TLS SSL")
    headers = ["Hostname", "Score", "Niveau", "TLS disponible", "Version", "Expiration jours", "Issuer", "Contrôles"]
    rows = []
    for t in audit.get("tls_score", {}).get("targets", []):
        rows.append([t.get("hostname"), t.get("score"), t.get("level"), t.get("tls_available"), t.get("tls_version"), t.get("days_remaining"), _excel_value(t.get("issuer")), "\n".join(t.get("checks", []))])
    _table_sheet(ws, "TLS / SSL AVANCÉ", headers, rows)

def _sheet_dns(wb, audit):
    ws = wb.create_sheet("DNS")
    rows = []
    for typ, data in audit.get("dns", {}).get("records", {}).items():
        rows.append([typ, data.get("status"), "\n".join(data.get("values", [])), data.get("error")])
    _table_sheet(ws, "DNS", ["Type", "Statut", "Valeurs", "Erreur"], rows)

def _sheet_mail(wb, audit):
    ws = wb.create_sheet("Messagerie")
    rows = [
        ["MX", "\n".join(audit.get("mail", {}).get("mx", {}).get("values", []))],
        ["DMARC", "\n".join(audit.get("mail", {}).get("dmarc_records", []))],
        ["SPF", "\n".join(audit.get("dns", {}).get("spf_records", []))],
    ]
    _table_sheet(ws, "MESSAGERIE", ["Contrôle", "Valeur"], rows)

def _sheet_cti(wb, audit):
    ws = wb.create_sheet("CTI")
    headers = ["IP", "Périmètre", "Hostnames", "Zone", "Statut", "Valeurs / Erreur"]
    rows = []
    for ipr in audit.get("cti", {}).get("ip_reputation_all", audit.get("cti", {}).get("ip_reputation", [])):
        for check in ipr.get("checks", []):
            rows.append([
                ipr.get("ip"), ipr.get("scope"), ", ".join(ipr.get("hostnames", [])),
                check.get("zone"), check.get("status"),
                ", ".join(check.get("values", [])) if check.get("values") else check.get("error") or check.get("detail") or ""
            ])
    _table_sheet(ws, "CTI / RÉPUTATION", headers, rows)

def _sheet_passive_cves(wb, audit):
    ws = wb.create_sheet("CVE Passives")
    headers = ["Hostname", "Schéma", "Type", "Technologie", "CVE", "Sévérité", "Confiance", "Description", "Preuve", "Recommandation"]
    rows = []
    for item in audit.get("passive_cves", {}).get("items", []):
        rows.append([item.get("hostname"), item.get("scheme"), item.get("type"), item.get("technology"), item.get("cve"), item.get("severity"), item.get("confidence"), item.get("description"), item.get("evidence"), item.get("recommendation")])
    _table_sheet(ws, "CVE POTENTIELLES PASSIVES", headers, rows or [["Aucun", "", "", "", "", "", "", "Aucune CVE passive détectée via headers HTTP.", "", "Confirmer par audit autorisé si nécessaire."]])

def _sheet_patching_sla(wb, audit):
    ws = wb.create_sheet("SLA")
    headers = ["ID", "Sévérité", "Catégorie", "Lieu / Source", "Constat", "Détecté le", "SLA jours", "Échéance", "Statut"]
    finding_by_title = {f.get("title"): f for f in audit.get("findings", [])}
    rows = []
    for item in audit.get("patching_sla", {}).get("items", []):
        f = finding_by_title.get(item.get("title"), {})
        rows.append([item.get("id"), item.get("severity"), item.get("category"), _loc(f.get("location", {})), item.get("title"), item.get("detected_at"), item.get("sla_days"), item.get("due_at"), item.get("status")])
    _table_sheet(ws, "SLA PATCHING / TRAITEMENT", headers, rows)

def _sheet_passive_sources(wb, audit):
    ws = wb.create_sheet("Sources Passives")
    sub = audit.get("subdomains", {})
    rows = []
    sources = sub.get("sources", {})
    if isinstance(sources, dict):
        for name, data in sources.items():
            rows.append([name, data.get("count"), data.get("error")])
    else:
        rows.append([sub.get("source"), sub.get("count"), sub.get("error")])
    _table_sheet(ws, "SOURCES PASSIVES SOUS-DOMAINES", ["Source", "Nombre", "Erreur"], rows)

def _sheet_guards(wb, audit):
    ws = wb.create_sheet("Garde-fous")
    rows = [[k, str(v)] for k, v in audit.get("safety", {}).items()]
    rows.append(["Note", "Les contrôles HTTP/TLS sont bloqués lorsqu'une cible ne résout pas vers une IP publique ou résout vers une IP privée/réservée."])
    _table_sheet(ws, "GARDE-FOUS", ["Contrôle", "Valeur"], rows)

def _sheet_raw_summary(wb, audit):
    ws = wb.create_sheet("Résumé Brut")
    rows = [
        ["id", audit.get("id")],
        ["domain", audit.get("domain")],
        ["created_at", audit.get("created_at")],
        ["score", json.dumps(audit.get("score", {}), ensure_ascii=False)],
        ["domain_profile", json.dumps(audit.get("domain_profile", {}), ensure_ascii=False)],
        ["subdomains_summary", json.dumps({k:v for k,v in audit.get("subdomains", {}).items() if k != "subdomains"}, ensure_ascii=False)],
        ["ip_inventory_summary", json.dumps({k:v for k,v in audit.get("ip_inventory", {}).items() if k not in ("entries","unique_ips")}, ensure_ascii=False)],
    ]
    _table_sheet(ws, "RÉSUMÉ BRUT JSON", ["Clé", "Valeur"], rows)


def _excel_value(value):
    """Convert complex Python objects into Excel-compatible strings."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (dict, list, tuple, set)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            return str(value)
    return str(value)

def _table_sheet(ws, title, headers, rows):
    _paint_background(ws, rows=max(len(rows) + 8, 20), cols=max(len(headers), 8))
    ws.merge_cells(start_row=1, start_column=1, end_row=2, end_column=max(len(headers), 8))
    ws["A1"] = title
    ws["A1"].font = Font(bold=True, size=16, color=GOLD_LIGHT)
    ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws["A1"].fill = PatternFill("solid", fgColor=BLACK)

    start_row = 4
    for col, header in enumerate(headers, 1):
        cell = ws.cell(start_row, col, header)
        cell.font = Font(bold=True, color=GOLD_LIGHT)
        cell.fill = PatternFill("solid", fgColor=CHARCOAL)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    for r_idx, row in enumerate(rows, start_row + 1):
        for c_idx, value in enumerate(row, 1):
            cell = ws.cell(r_idx, c_idx, _excel_value(value))
            cell.font = Font(color=WHITE)
            cell.fill = PatternFill("solid", fgColor=BLACK if r_idx % 2 else ROW_DARK)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            if c_idx <= 2 and str(value).lower() in SEVERITY_FILL:
                sev = str(value).lower()
                cell.fill = PatternFill("solid", fgColor=SEVERITY_FILL[sev])
                cell.font = Font(bold=True, color=BLACK if sev == "medium" else WHITE)

    if rows:
        end_row = start_row + len(rows)
        end_col = len(headers)
        ref = f"A{start_row}:{get_column_letter(end_col)}{end_row}"
        try:
            tab = Table(displayName=_safe_table_name(title), ref=ref)
            tab.tableStyleInfo = TableStyleInfo(name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False, showRowStripes=False, showColumnStripes=False)
            ws.add_table(tab)
        except Exception:
            pass

    ws.freeze_panes = f"A{start_row+1}"
    _format_sheet(ws)

def _paint_background(ws, rows=40, cols=10):
    for row in range(1, rows + 1):
        for col in range(1, cols + 1):
            ws.cell(row, col).fill = PatternFill("solid", fgColor=BLACK)

def _header_row(ws, row, max_col):
    for col in range(1, max_col + 1):
        cell = ws.cell(row=row, column=col)
        cell.font = Font(bold=True, color=GOLD_LIGHT)
        cell.fill = PatternFill("solid", fgColor=CHARCOAL)
        cell.alignment = Alignment(horizontal="center")

def _format_sheet(ws, freeze="A5"):
    border = Border(
        left=Side(style="thin", color=BORDER),
        right=Side(style="thin", color=BORDER),
        top=Side(style="thin", color=BORDER),
        bottom=Side(style="thin", color=BORDER),
    )
    for row in ws.iter_rows():
        max_height = 18
        for cell in row:
            cell.border = border
            if cell.value is not None:
                cell.alignment = Alignment(wrap_text=True, vertical="top")
                max_height = max(max_height, min(90, 15 + len(str(cell.value if cell.value is not None else '')) // 55 * 12))
        ws.row_dimensions[row[0].row].height = max_height
    for column_cells in ws.columns:
        length = 0
        col = get_column_letter(column_cells[0].column)
        for cell in column_cells:
            if cell.value is not None:
                length = max(length, min(len(str(cell.value if cell.value is not None else '')), 58))
        ws.column_dimensions[col].width = max(14, min(46, length + 2))
    if freeze:
        ws.freeze_panes = freeze
    ws.sheet_view.showGridLines = False

def _safe_table_name(title):
    safe = "".join(ch for ch in title.title() if ch.isalnum())[:24]
    return safe or "OpenEasmTable"

def _loc(loc):
    if not isinstance(loc, dict):
        return ""
    return loc.get("display") or loc.get("path") or loc.get("record") or loc.get("hostname") or loc.get("control") or ""

def _conclusion(audit):
    return (
        f"Le domaine {audit.get('domain')} obtient un score de {audit.get('score', {}).get('score')} / 1000. "
        f"Profil : {audit.get('domain_profile', {}).get('label', 'N/A')}. "
        f"IP publiques : {audit.get('ip_inventory', {}).get('public_ip_count', 0)}. "
        f"Sous-domaines : {audit.get('subdomains', {}).get('count', 0)}. "
        f"Score TLS : {audit.get('tls_score', {}).get('global_score', 0)} / 100. "
        "Les constats sont priorisés et localisés pour faciliter le plan d'action."
    )

def _severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)

def _priority_label(sev):
    return {"critical": "P1 immédiat", "high": "P2 prioritaire", "medium": "P3 planifié", "low": "P4 amélioration", "info": "Information"}.get(sev, "Information")

def _sla_for(sev):
    return {"critical": "< 5 jours", "high": "< 15 jours", "medium": "< 30 jours", "low": "< 90 jours", "info": "Suivi"}.get(sev, "Suivi")
