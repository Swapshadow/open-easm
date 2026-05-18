from __future__ import annotations

from pathlib import Path
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SEVERITY_FILL = {
    "critical": "7F1D1D",
    "high": "DC2626",
    "medium": "F97316",
    "low": "FACC15",
    "info": "64748B",
}

def generate_excel_report(audit: dict) -> str:
    wb = Workbook()
    ws = wb.active
    ws.title = "Synthèse exécutive"
    _executive_summary(ws, audit)

    _sheet_findings(wb, audit)
    _sheet_ip_inventory(wb, audit)
    _sheet_web_targets(wb, audit)
    _sheet_tls_score(wb, audit)
    _sheet_passive_cves(wb, audit)
    _sheet_cti(wb, audit)
    _sheet_patching_sla(wb, audit)
    _sheet_subdomains(wb, audit)
    _sheet_dns(wb, audit)
    _sheet_mail(wb, audit)
    _sheet_tls_raw(wb, audit)
    _sheet_guards(wb, audit)

    filename = f"open_easm_v4_3_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    path = REPORT_DIR / filename
    wb.save(path)
    return filename

def _executive_summary(ws, audit):
    _title(ws, "Rapport Open EASM V4.3")

    _kv(ws, 3, "Domaine audité", audit["domain"])
    _kv(ws, 4, "Date audit", audit["created_at"])
    _kv(ws, 5, "Mode", audit["mode"])
    _kv(ws, 6, "Profil détecté", audit["domain_profile"]["label"])
    _kv(ws, 7, "Score global", f'{audit["score"]["score"]} / {audit["score"]["max_score"]}')
    _kv(ws, 8, "Niveau global", audit["score"]["level"])
    _kv(ws, 9, "Score TLS/SSL", f'{audit["tls_score"]["global_score"]} / 100 ({audit["tls_score"]["global_level"]})')
    _kv(ws, 10, "IP publiques inventoriées", audit["ip_inventory"].get("public_ip_count"))
    _kv(ws, 11, "CVE potentielles passives", audit["passive_cves"].get("count"))
    _kv(ws, 12, "Cibles web joignables", ", ".join(audit["domain_profile"].get("reachable_web_targets", [])) or "Aucune")

    ws["A14"] = "Lecture exécutive"
    ws["A14"].font = Font(bold=True)
    ws["B14"] = build_conclusion(audit)
    ws["B14"].alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[14].height = 110

    ws["A16"] = "Criticité"
    ws["B16"] = "Nombre"
    _header_row(ws, 16, 2)
    severities = [
        ("Critique", "critical"),
        ("Élevée", "high"),
        ("Moyenne", "medium"),
        ("Faible", "low"),
        ("Information", "info"),
    ]
    row = 17
    for label, key in severities:
        ws.cell(row=row, column=1, value=label)
        ws.cell(row=row, column=2, value=audit["score"]["by_severity"].get(key, 0))
        row += 1

    ws["A24"] = "Portée et limites"
    ws["A24"].font = Font(bold=True)
    ws["B24"] = (
        "Audit public non intrusif : DNS, messagerie, TLS, web headers, www automatique, "
        "Certificate Transparency, inventaire IP, CTI léger par DNSBL IPv4_3 et CVE potentielles passives sur headers HTTP. "
        "Aucun scan de ports, aucune exploitation, aucun bruteforce, aucune vérification intrusive de CVE."
    )
    ws["B24"].alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[24].height = 85

    _format_table(ws)

def build_conclusion(audit: dict) -> str:
    score = audit["score"]["score"]
    profile_label = audit["domain_profile"]["label"]
    profile_explanation = audit["domain_profile"]["explanation"]
    sub_count = audit.get("subdomains", {}).get("count", 0)
    ip_count = audit.get("ip_inventory", {}).get("public_ip_count", 0)
    cve_count = audit.get("passive_cves", {}).get("count", 0)
    tls_score = audit.get("tls_score", {}).get("global_score", 0)

    base = (
        f"Profil détecté : {profile_label}. {profile_explanation} "
        f"Sous-domaines identifiés passivement : {sub_count}. "
        f"IP publiques inventoriées : {ip_count}. "
        f"Score TLS/SSL : {tls_score}/100. "
        f"CVE potentielles passives : {cve_count}. "
    )

    if score >= 850:
        return base + "L'exposition externe observée est globalement maîtrisée sur les contrôles réalisés en V4.3."
    if score >= 700:
        return base + "L'exposition externe est correcte mais plusieurs améliorations sont recommandées, notamment sur DNS, messagerie, TLS ou headers web."
    if score >= 500:
        return base + "L'exposition externe présente plusieurs faiblesses à traiter. Les corrections doivent être priorisées selon les niveaux de criticité."
    return base + "L'exposition externe présente un niveau de risque important sur les contrôles réalisés. Un plan d'action prioritaire est recommandé."

def _sheet_findings(wb, audit):
    ws = wb.create_sheet("Constats priorisés")
    headers = ["Sévérité", "Catégorie", "Titre", "Description", "Recommandation", "Applicabilité"]
    ws.append(headers)
    _header(ws)

    ordered = sorted(audit["findings"], key=lambda f: _severity_order(f.get("severity", "info")))
    for f in ordered:
        ws.append([
            f.get("severity"),
            f.get("category"),
            f.get("title"),
            f.get("description"),
            f.get("recommendation"),
            ", ".join(f.get("applies_to", [])),
        ])
        row = ws.max_row
        sev = f.get("severity", "info")
        ws.cell(row=row, column=1).fill = PatternFill("solid", fgColor=SEVERITY_FILL.get(sev, "64748B"))
        ws.cell(row=row, column=1).font = Font(color="FFFFFF", bold=True)

    _format_table(ws)

def _sheet_ip_inventory(wb, audit):
    ws = wb.create_sheet("Inventaire IP")
    headers = ["IP", "Publique", "Sources", "Hostnames liés"]
    ws.append(headers)
    _header(ws)
    for item in audit.get("ip_inventory", {}).get("unique_ips", []):
        ws.append([
            item.get("ip"),
            item.get("is_public"),
            ", ".join(item.get("sources", [])),
            "\n".join(item.get("hostnames", [])),
        ])
    _format_table(ws)

def _sheet_web_targets(wb, audit):
    ws = wb.create_sheet("Cibles web")
    headers = ["Hostname", "IP publiques", "IP bloquées", "HTTP", "HTTPS", "URL finale HTTPS", "Meilleur schéma"]
    ws.append(headers)
    _header(ws)

    for target in audit["web"].get("targets", []):
        http = target.get("http") or {}
        https = target.get("https") or {}
        guard = target.get("guard") or {}
        ws.append([
            target.get("hostname"),
            ", ".join(guard.get("public_ips", [])),
            ", ".join(guard.get("blocked_ips", [])),
            f"reachable={http.get('reachable')} status={http.get('status_code')}",
            f"reachable={https.get('reachable')} status={https.get('status_code')}",
            https.get("final_url"),
            target.get("best_scheme"),
        ])

    _format_table(ws)

def _sheet_tls_score(wb, audit):
    ws = wb.create_sheet("TLS SSL avancé")
    headers = ["Hostname", "Score", "Niveau", "TLS disponible", "Version négociée", "Expiration jours", "Contrôles"]
    ws.append(headers)
    _header(ws)
    for t in audit.get("tls_score", {}).get("targets", []):
        ws.append([
            t.get("hostname"),
            t.get("score"),
            t.get("level"),
            t.get("tls_available"),
            t.get("tls_version"),
            t.get("days_remaining"),
            "\n".join(t.get("checks", [])),
        ])
    _format_table(ws)

def _sheet_passive_cves(wb, audit):
    ws = wb.create_sheet("CVE potentielles")
    headers = ["Hostname", "Schéma", "Type", "Technologie", "CVE", "Sévérité", "Confiance", "Description", "Preuve", "Recommandation"]
    ws.append(headers)
    _header(ws)
    for item in audit.get("passive_cves", {}).get("items", []):
        ws.append([
            item.get("hostname"),
            item.get("scheme"),
            item.get("type"),
            item.get("technology"),
            item.get("cve"),
            item.get("severity"),
            item.get("confidence"),
            item.get("description"),
            item.get("evidence"),
            item.get("recommendation"),
        ])
    if not audit.get("passive_cves", {}).get("items"):
        ws.append(["Aucun", "", "", "", "", "", "", "Aucune CVE passive détectée via headers HTTP.", "", "Confirmer par un audit autorisé si nécessaire."])
    _format_table(ws)

def _sheet_cti(wb, audit):
    ws = wb.create_sheet("CTI réputation")
    headers = ["IP", "Zone", "Statut", "Valeurs / Erreur"]
    ws.append(headers)
    _header(ws)
    for ip_result in audit.get("cti", {}).get("ip_reputation", []):
        ip = ip_result.get("ip")
        for check in ip_result.get("checks", []):
            ws.append([
                ip,
                check.get("zone"),
                check.get("status"),
                ", ".join(check.get("values", [])) if check.get("values") else check.get("error") or check.get("detail") or "",
            ])
    ws.append([])
    ws.append(["Fuites d'identifiants", audit.get("cti", {}).get("leak_monitoring", {}).get("status"), audit.get("cti", {}).get("leak_monitoring", {}).get("reason"), ""])
    _format_table(ws)

def _sheet_patching_sla(wb, audit):
    ws = wb.create_sheet("SLA patching")
    headers = ["ID", "Sévérité", "Catégorie", "Constat", "Détecté le", "SLA jours", "Échéance cible", "Statut", "Recommandation"]
    ws.append(headers)
    _header(ws)
    for item in audit.get("patching_sla", {}).get("items", []):
        ws.append([
            item.get("id"),
            item.get("severity"),
            item.get("category"),
            item.get("title"),
            item.get("detected_at"),
            item.get("sla_days"),
            item.get("due_at"),
            item.get("status"),
            item.get("recommendation"),
        ])
    _format_table(ws)

def _sheet_subdomains(wb, audit):
    ws = wb.create_sheet("Sous-domaines")
    headers = ["Source", "Sous-domaine"]
    ws.append(headers)
    _header(ws)

    sub = audit.get("subdomains", {})
    for name in sub.get("subdomains", []):
        ws.append([sub.get("source"), name])

    if not sub.get("subdomains"):
        ws.append([sub.get("source"), "Aucun sous-domaine trouvé ou source indisponible."])

    _format_table(ws)

def _sheet_dns(wb, audit):
    ws = wb.create_sheet("DNS")
    headers = ["Type", "Statut", "Valeurs", "Erreur"]
    ws.append(headers)
    _header(ws)

    for typ, data in audit["dns"]["records"].items():
        ws.append([
            typ,
            data.get("status"),
            "\n".join(data.get("values", [])),
            data.get("error"),
        ])

    ws.append([])
    ws.append(["SPF détecté", "\n".join(audit["dns"].get("spf_records", []))])
    _format_table(ws)

def _sheet_mail(wb, audit):
    ws = wb.create_sheet("Messagerie")
    headers = ["Contrôle", "Statut/Valeur"]
    ws.append(headers)
    _header(ws)

    ws.append(["MX", "\n".join(audit["mail"]["mx"].get("values", []))])
    ws.append(["DMARC", "\n".join(audit["mail"].get("dmarc_records", []))])
    _format_table(ws)

def _sheet_tls_raw(wb, audit):
    ws = wb.create_sheet("TLS brut")
    headers = ["Hostname", "Disponible", "Expiration", "Jours restants", "Issuer", "SAN", "TLS", "Cipher"]
    ws.append(headers)
    _header(ws)

    for tls in audit.get("tls", {}).get("targets", []):
        cert = tls.get("cert") or {}
        issuer = cert.get("issuer") or {}
        ws.append([
            tls.get("hostname"),
            tls.get("available"),
            cert.get("not_after"),
            cert.get("days_remaining"),
            issuer.get("organizationName") or issuer.get("commonName"),
            "\n".join(cert.get("san", [])) if cert.get("san") else "",
            cert.get("tls_version"),
            cert.get("cipher"),
        ])

    _format_table(ws)

def _sheet_guards(wb, audit):
    ws = wb.create_sheet("Garde-fous")
    headers = ["Contrôle", "Valeur"]
    ws.append(headers)
    _header(ws)

    guards = audit.get("safety", {})
    for key, value in guards.items():
        ws.append([key, str(value)])

    ws.append(["Note", "Les contrôles HTTP/TLS sont bloqués lorsqu'une cible ne résout pas vers une IP publique ou résout vers une IP privée/réservée."])
    _format_table(ws)

def _severity_order(sev):
    return {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }.get(sev, 5)

def _title(ws, text):
    ws["A1"] = text
    ws["A1"].font = Font(bold=True, size=18, color="FFFFFF")
    ws["A1"].fill = PatternFill("solid", fgColor="1E293B")
    ws.merge_cells("A1:D1")
    ws["A1"].alignment = Alignment(horizontal="center")

def _kv(ws, row, key, value):
    ws.cell(row=row, column=1, value=key)
    ws.cell(row=row, column=2, value=value)
    ws.cell(row=row, column=1).font = Font(bold=True)
    ws.cell(row=row, column=1).fill = PatternFill("solid", fgColor="E2E8F0")

def _header(ws):
    _header_row(ws, 1, ws.max_column)

def _header_row(ws, row, max_col):
    for col in range(1, max_col + 1):
        cell = ws.cell(row=row, column=col)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="334155")
        cell.alignment = Alignment(horizontal="center")

def _format_table(ws):
    border = Border(
        left=Side(style="thin", color="CBD5E1"),
        right=Side(style="thin", color="CBD5E1"),
        top=Side(style="thin", color="CBD5E1"),
        bottom=Side(style="thin", color="CBD5E1"),
    )
    for row in ws.iter_rows():
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")
            cell.border = border
    _autosize(ws)

def _autosize(ws):
    for column_cells in ws.columns:
        length = 0
        col = get_column_letter(column_cells[0].column)
        for cell in column_cells:
            if cell.value:
                length = max(length, min(len(str(cell.value)), 90))
        ws.column_dimensions[col].width = max(14, length + 2)
