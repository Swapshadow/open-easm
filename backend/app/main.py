from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4
import traceback
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.validators import normalize_domain
from app.services.dns_audit import audit_dns, audit_mail
from app.services.tls_audit import audit_tls
from app.services.web_audit import audit_web_targets
from app.services.subdomain_audit import discover_subdomains_ct
from app.services.domain_profile import classify_domain, adjust_findings_for_profile
from app.services.scoring import collect_findings, compute_score
from app.services.rate_limit import check_rate_limit
from app.services.ip_inventory import build_ip_inventory
from app.services.tls_scoring import score_tls
from app.services.cve_passive import detect_passive_cves
from app.services.cti_audit import audit_cti
from app.services.patching_sla import build_patching_sla
from app.services.finding_location import enrich_findings_locations
from app.reports.excel_report import generate_excel_report
from app.reports.json_report import generate_json_report
from app.reports.pdf_report import generate_pdf_report
from app.database import init_db_with_retry, get_db
from app.services.storage import save_audit, list_audits, get_audit_record, dashboard_stats, compare_latest, delete_audit, delete_all_audits, delete_domain_audits
from app.services.domain_verification import start_verification, check_verification, get_domain_status, list_verified_domains, delete_verification, serialize_verification
from app.services.diagnostics import build_system_diagnostics, test_export_dependencies
from app.services.executive_risk import build_executive_risk

app = FastAPI(
    title="OpenEASM Alpha",
    description="OpenEASM Alpha : outil EASM public non intrusif avec scoring exécutif, rapports et constats localisés.",
    version="alpha",
)



@app.on_event("startup")
def startup_event():
    init_db_with_retry()



@app.exception_handler(Exception)
async def openeasm_unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Erreur interne OpenEASM pendant le traitement.",
            "error": str(exc),
            "type": exc.__class__.__name__,
        },
    )

AUDITS: dict[str, dict] = {}
REPORT_DIR = Path("/app/reports")

class AuditRequest(BaseModel):
    domain: str = Field(..., description="Nom de domaine à auditer, exemple : example.com")
    accepted_terms: bool = Field(False, description="L'utilisateur confirme être autorisé ou rester dans le cadre non intrusif.")

class DomainVerificationRequest(BaseModel):
    domain: str = Field(..., description="Nom de domaine à vérifier, exemple : example.com")

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "openeasm-alpha"}

@app.post("/api/audit")
async def create_audit(payload: AuditRequest, request: Request, db=Depends(get_db)):
    if not payload.accepted_terms:
        raise HTTPException(
            status_code=400,
            detail="Vous devez accepter l'usage responsable avant de lancer l'audit.",
        )

    client_host = request.client.host if request.client else "unknown"
    rate = check_rate_limit(client_host)
    if not rate["allowed"]:
        raise HTTPException(
            status_code=429,
            detail=f"Trop d'audits lancés. Réessayez dans {rate['retry_after']} secondes.",
        )

    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    created_at = datetime.now(timezone.utc).isoformat()
    verification_status = get_domain_status(db, domain)

    dns_result = audit_dns(domain)
    mail_result = audit_mail(domain)
    web_result = await audit_web_targets(domain)

    tls_targets = []
    for target in [domain, f"www.{domain}"]:
        tls_targets.append(audit_tls(target))

    tls_result = {
        "domain": domain,
        "targets": tls_targets,
        "findings": [f for t in tls_targets for f in t.get("findings", [])],
    }

    subdomains_result = await discover_subdomains_ct(domain)
    ip_inventory = build_ip_inventory(domain, dns_result, mail_result, web_result, subdomains_result)
    tls_score = score_tls(tls_result, web_result)
    passive_cves = detect_passive_cves(web_result)
    cti_result = audit_cti(ip_inventory, domain)

    raw_findings = collect_findings(
        dns_result,
        mail_result,
        tls_result,
        web_result,
        subdomains_result,
        ip_inventory,
        tls_score,
        passive_cves,
        cti_result,
    )
    domain_profile = classify_domain(dns_result, mail_result, web_result)
    findings = adjust_findings_for_profile(raw_findings, domain_profile)
    findings = enrich_findings_locations(findings, domain)
    legacy_score = compute_score(findings, domain_profile)
    patching_sla = build_patching_sla(findings, created_at)
    executive_risk = build_executive_risk(findings, domain_profile, tls_score, ip_inventory, subdomains_result, passive_cves, cti_result)
    score = executive_risk.get('global_score', legacy_score)

    audit_id = str(uuid4())
    audit = {
        "id": audit_id,
        "domain": domain,
        "created_at": created_at,
        "mode": "public_non_intrusive_alpha",
        "verification": verification_status,
        "domain_profile": domain_profile,
        "dns": dns_result,
        "mail": mail_result,
        "tls": tls_result,
        "tls_score": tls_score,
        "web": web_result,
        "subdomains": subdomains_result,
        "ip_inventory": ip_inventory,
        "passive_cves": passive_cves,
        "cti": cti_result,
        "patching_sla": patching_sla,
        "executive_risk": executive_risk,
        "legacy_score": legacy_score,
        "findings": findings,
        "score": score,
        "safety": {
            "accepted_terms": payload.accepted_terms,
            "client": client_host,
            "rate_limit": rate,
            "anti_ssrf": "HTTP/TLS only if target resolves to public IPs and no blocked IP.",
            "active_scan": "disabled",
            "nmap": "disabled",
            "cve_scan": "passive_headers_only",
            "leak_search": "disabled_public_mode",
        },
        "report_filename": None,
        "json_filename": None,
    }

    audit["report_errors"] = []
    try:
        report_filename = generate_excel_report(audit)
        audit["report_filename"] = report_filename
    except Exception as exc:
        audit["report_errors"].append(f"Excel: {exc}")

    try:
        json_filename = generate_json_report(audit)
        audit["json_filename"] = json_filename
    except Exception as exc:
        audit["report_errors"].append(f"JSON: {exc}")

    try:
        pdf_filename = generate_pdf_report(audit)
        audit["pdf_filename"] = pdf_filename
    except Exception as exc:
        audit["report_errors"].append(f"PDF: {exc}")

    AUDITS[audit_id] = audit
    save_audit(db, audit)

    return {
        "id": audit_id,
        "domain": domain,
        "mode": audit["mode"],
        "verification": verification_status,
        "created_at": audit["created_at"],
        "domain_profile": domain_profile,
        "score": audit["score"],
        "executive_risk": executive_risk,
        "tls_score": tls_score,
        "findings": audit["findings"],
        "subdomains": {
            "source": subdomains_result.get("source"),
            "count": subdomains_result.get("count"),
            "subdomains": subdomains_result.get("subdomains", [])[:80],
            "error": subdomains_result.get("error"),
        },
        "ip_inventory": {
            "public_ip_count": ip_inventory.get("public_ip_count"),
            "total_ip_count": ip_inventory.get("total_ip_count"),
            "unique_ips": ip_inventory.get("display_ips", ip_inventory.get("unique_ips", []))[:100],
            "core_public_ip_count": ip_inventory.get("core_public_ip_count", 0),
            "third_party_provider_ip_count": ip_inventory.get("third_party_provider_ip_count", 0),
            "total_ip_count": ip_inventory.get("total_ip_count", 0),
        },
        "passive_cves": {
            "count": passive_cves.get("count"),
            "items": passive_cves.get("items", [])[:30],
            "note": passive_cves.get("note"),
        },
        "cti": {
            "summary": cti_result.get("summary", {}),
            "ip_reputation": cti_result.get("ip_reputation", [])[:30],
            "leak_monitoring": cti_result.get("leak_monitoring"),
            "note": cti_result.get("note"),
        },
        "patching_sla": {
            "sla_policy": patching_sla.get("sla_policy"),
            "items": patching_sla.get("items", [])[:30],
            "note": patching_sla.get("note"),
        },
        "web_targets": [
            {
                "hostname": t.get("hostname"),
                "reachable": t.get("reachable"),
                "best_scheme": t.get("best_scheme"),
                "public_ips": (t.get("guard") or {}).get("public_ips", []),
                "blocked_ips": (t.get("guard") or {}).get("blocked_ips", []),
                "http_status": (t.get("http") or {}).get("status_code"),
                "https_status": (t.get("https") or {}).get("status_code"),
                "https_final_url": (t.get("https") or {}).get("final_url"),
            }
            for t in web_result.get("targets", [])
        ],
        "report_url": f"/api/reports/{audit_id}/excel",
        "json_url": f"/api/reports/{audit_id}/json",
        "pdf_url": f"/api/reports/{audit_id}/pdf",
        "report_errors": audit.get("report_errors", []),
        "summary": {
            "dns_public_ips": audit["dns"].get("public_ips", []),
            "spf_records": audit["dns"].get("spf_records", []),
            "mx_records": audit["mail"]["mx"].get("values", []),
            "dmarc_records": audit["mail"].get("dmarc_records", []),
            "has_web": web_result.get("has_web"),
            "reachable_web_targets": domain_profile.get("reachable_web_targets", []),
            "subdomain_count": subdomains_result.get("count", 0),
            "public_ip_count": ip_inventory.get("public_ip_count", 0),
            "core_public_ip_count": ip_inventory.get("core_public_ip_count", 0),
            "third_party_provider_ip_count": ip_inventory.get("third_party_provider_ip_count", 0),
            "passive_cve_count": passive_cves.get("count", 0),
            "tls_score": tls_score.get("global_score"),
            "tls_level": tls_score.get("global_level"),
            "executive_score": executive_risk.get("overall_score"),
            "executive_risk": executive_risk.get("risk_level"),
        },
    }

@app.get("/api/audits")
async def api_list_audits(limit: int = 50, domain: str | None = None, db=Depends(get_db)):
    records = list_audits(db, limit=limit, domain=domain)
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "created_at": r.created_at.isoformat(),
            "score": r.score,
            "level": r.level,
            "profile": r.profile,
            "public_ip_count": r.public_ip_count,
            "subdomain_count": r.subdomain_count,
            "passive_cve_count": r.passive_cve_count,
            "tls_score": r.tls_score,
        }
        for r in records
    ]

@app.get("/api/audits/{audit_id}")
async def get_audit(audit_id: str, db=Depends(get_db)):
    audit = AUDITS.get(audit_id)
    if audit:
        return audit
    record = get_audit_record(db, audit_id)
    if not record:
        raise HTTPException(status_code=404, detail="Audit introuvable.")
    return record.audit_json

@app.get("/api/dashboard")
async def api_dashboard(db=Depends(get_db)):
    return dashboard_stats(db)



@app.get("/api/system/diagnostics")
async def api_system_diagnostics(db=Depends(get_db)):
    return build_system_diagnostics(db)

@app.post("/api/system/export-test")
async def api_export_test():
    return test_export_dependencies(cleanup=True)

@app.get("/api/reports")
async def api_reports_center(limit: int = 100, domain: str | None = None, db=Depends(get_db)):
    records = list_audits(db, limit=limit, domain=domain)
    items = []
    for r in records:
        items.append({
            "id": r.id,
            "domain": r.domain,
            "created_at": r.created_at.isoformat(),
            "score": r.score,
            "level": r.level,
            "profile": r.profile,
            "excel_filename": r.excel_filename,
            "json_filename": r.json_filename,
            "pdf_filename": r.pdf_filename,
            "excel_exists": bool(r.excel_filename and (REPORT_DIR / r.excel_filename).exists()),
            "json_exists": bool(r.json_filename and (REPORT_DIR / r.json_filename).exists()),
            "pdf_exists": bool(r.pdf_filename and (REPORT_DIR / r.pdf_filename).exists()),
            "excel_url": f"/api/reports/{r.id}/excel",
            "json_url": f"/api/reports/{r.id}/json",
            "pdf_url": f"/api/reports/{r.id}/pdf",
        })
    return {
        "count": len(items),
        "items": items,
    }


@app.post("/api/domains/verification/start")
async def api_start_domain_verification(payload: DomainVerificationRequest, db=Depends(get_db)):
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record = start_verification(db, domain)
    return serialize_verification(record)

@app.post("/api/domains/{domain}/verification/check")
async def api_check_domain_verification(domain: str, db=Depends(get_db)):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record = check_verification(db, normalized)
    if not record:
        raise HTTPException(status_code=404, detail="Aucune vérification démarrée pour ce domaine.")
    return serialize_verification(record)

@app.get("/api/domains/verified")
async def api_list_verified_domains(db=Depends(get_db)):
    return [serialize_verification(r) for r in list_verified_domains(db)]

@app.get("/api/domains/{domain}/verification")
async def api_get_domain_verification(domain: str, db=Depends(get_db)):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return get_domain_status(db, normalized)

@app.delete("/api/domains/{domain}/verification")
async def api_delete_domain_verification(domain: str, db=Depends(get_db)):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    deleted = delete_verification(db, normalized)
    return {"domain": normalized, "deleted": deleted}


@app.get("/api/domains/{domain}/compare/latest")
async def api_compare_latest(domain: str, db=Depends(get_db)):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return compare_latest(db, normalized)


@app.delete("/api/audits/{audit_id}")
async def api_delete_audit(audit_id: str, db=Depends(get_db)):
    deleted = delete_audit(db, audit_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Audit introuvable.")
    AUDITS.pop(audit_id, None)
    return {"deleted": True, "audit_id": audit_id}

@app.delete("/api/audits")
async def api_delete_all_audits(db=Depends(get_db)):
    count = delete_all_audits(db)
    AUDITS.clear()
    return {"deleted": count}

@app.delete("/api/domains/{domain}/audits")
async def api_delete_domain_audits(domain: str, db=Depends(get_db)):
    try:
        normalized = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    count = delete_domain_audits(db, normalized)
    for audit_id, audit in list(AUDITS.items()):
        if audit.get("domain") == normalized:
            AUDITS.pop(audit_id, None)
    return {"domain": normalized, "deleted": count}


@app.get("/api/reports/{audit_id}/excel")
async def download_excel_report(audit_id: str, db=Depends(get_db)):
    audit = AUDITS.get(audit_id)
    if not audit:
        record = get_audit_record(db, audit_id)
        if record:
            audit = record.audit_json
        else:
            raise HTTPException(status_code=404, detail="Audit introuvable.")

    filename = audit.get("report_filename")
    if not filename:
        raise HTTPException(status_code=404, detail="Rapport introuvable.")

    path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier rapport introuvable.")

    return FileResponse(
        path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename=filename,
    )

@app.get("/api/reports/{audit_id}/json")
async def download_json_report(audit_id: str, db=Depends(get_db)):
    audit = AUDITS.get(audit_id)
    if not audit:
        record = get_audit_record(db, audit_id)
        if record:
            audit = record.audit_json
        else:
            raise HTTPException(status_code=404, detail="Audit introuvable.")

    filename = audit.get("json_filename")
    if not filename:
        raise HTTPException(status_code=404, detail="Rapport JSON introuvable.")

    path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier JSON introuvable.")

    return FileResponse(
        path,
        media_type="application/json",
        filename=filename,
    )

@app.get("/api/reports/{audit_id}/pdf")
async def download_pdf_report(audit_id: str, db=Depends(get_db)):
    audit = AUDITS.get(audit_id)
    if not audit:
        record = get_audit_record(db, audit_id)
        if record:
            audit = record.audit_json
        else:
            raise HTTPException(status_code=404, detail="Audit introuvable.")

    filename = audit.get("pdf_filename")
    if not filename:
        raise HTTPException(status_code=404, detail="Rapport PDF introuvable.")

    path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier PDF introuvable.")

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=filename,
    )

app.mount("/", StaticFiles(directory="/app/app/static", html=True), name="static")
