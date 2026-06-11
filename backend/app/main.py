from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.database import get_db, init_db_with_retry
from app.reports.excel_report import generate_excel_report
from app.reports.html_report import generate_html_report
from app.reports.json_report import generate_json_report
from app.reports.pdf_report import generate_pdf_report
from app.services.attack_graph import build_attack_graph
from app.services.cti_audit import audit_cti
from app.services.cve_passive import detect_passive_cves
from app.services.diagnostics import build_system_diagnostics, test_export_dependencies
from app.services.dns_audit import audit_dns, audit_mail
from app.services.domain_profile import adjust_findings_for_profile, classify_domain
from app.services.domain_verification import (
    check_verification,
    delete_verification,
    get_domain_status,
    list_verified_domains,
    serialize_verification,
    start_verification,
)
from app.services.executive_risk import build_executive_risk
from app.services.finding_location import enrich_findings_locations
from app.services.host_enrichment import attach_services_to_hosts, enrich_public_hosts
from app.services.ip_inventory import build_ip_inventory
from app.services.legal_terms import create_acceptance, legal_payload, validate_acceptance
from app.services.nmap_audit import audit_service_versions
from app.services.patching_sla import build_patching_sla
from app.services.rate_limit import check_rate_limit
from app.services.scoring import collect_findings, compute_score
from app.services.storage import (
    compare_latest,
    dashboard_stats,
    delete_all_audits,
    delete_audit,
    delete_domain_audits,
    get_audit_record,
    list_audits,
    save_audit,
)
from app.services.subdomain_audit import discover_subdomains_ct
from app.services.tls_audit import audit_tls
from app.services.tls_scoring import score_tls
from app.services.web_audit import audit_web_targets
from app.validators import normalize_domain

APP_VERSION = "OpenEASM Beta 26.6"
REPORT_DIR = Path("/app/reports")
AUDITS: dict[str, dict] = {}

app = FastAPI(
    title=APP_VERSION,
    description=(
        "OpenEASM Beta 26.6 : EASM défensif avec enrichissement DNSDumpster-like, "
        "ASN/hébergeur/localisation, scan service/version sur sous-domaines publics, "
        "Graph Explorer et rapports professionnels."
    ),
    version="26.6",
)


class AuditRequest(BaseModel):
    domain: str = Field(..., description="Nom de domaine à auditer, exemple : example.com")
    accepted_terms: bool = Field(False, description="Confirme le cadre autorisé et défensif.")
    terms_token: str | None = Field(None, description="Jeton d'acceptation juridique délivré par /api/legal/accept-terms.")


class LegalAcceptRequest(BaseModel):
    accepted: bool = Field(False, description="Confirme que l'utilisateur a lu et accepté les conditions.")
    terms_hash: str | None = Field(None, description="Hash SHA-256 du texte juridique affiché.")
    terms_version: str | None = Field(None, description="Version du règlement affiché.")


class DomainVerificationRequest(BaseModel):
    domain: str = Field(..., description="Nom de domaine à vérifier, exemple : example.com")


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


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "openeasm-beta", "version": "26.6", "edition": APP_VERSION}


@app.get("/api/legal/terms")
async def api_legal_terms():
    return legal_payload()


@app.post("/api/legal/accept-terms")
async def api_accept_terms(payload: LegalAcceptRequest, request: Request, db=Depends(get_db)):
    client_host = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    try:
        return create_acceptance(
            db,
            client_ip=client_host,
            user_agent=user_agent,
            accepted=payload.accepted,
            supplied_hash=payload.terms_hash,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/legal/status")
async def api_legal_status(token: str | None = None, db=Depends(get_db)):
    return validate_acceptance(db, token)


@app.post("/api/audit")
async def create_audit(payload: AuditRequest, request: Request, db=Depends(get_db)):
    if not payload.accepted_terms:
        raise HTTPException(status_code=400, detail="Vous devez accepter l'usage responsable avant de lancer l'audit.")

    legal_status = validate_acceptance(db, payload.terms_token)
    if not legal_status.get("accepted"):
        raise HTTPException(status_code=403, detail="Acceptation juridique obligatoire avant d'utiliser OpenEASM.")

    client_host = request.client.host if request.client else "unknown"
    rate = check_rate_limit(client_host)
    if not rate["allowed"]:
        raise HTTPException(status_code=429, detail=f"Trop d'audits lancés. Réessayez dans {rate['retry_after']} secondes.")

    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    created_at = datetime.now(timezone.utc).isoformat()
    verification_status = get_domain_status(db, domain)

    dns_result = audit_dns(domain)
    mail_result = audit_mail(domain)
    web_result = await audit_web_targets(domain)
    subdomains_result = await discover_subdomains_ct(domain)
    ip_inventory = build_ip_inventory(domain, dns_result, mail_result, web_result, subdomains_result)

    tls_targets = [audit_tls(target) for target in [domain, f"www.{domain}"]]
    tls_result = {
        "domain": domain,
        "targets": tls_targets,
        "findings": [f for t in tls_targets for f in t.get("findings", [])],
    }
    tls_score = score_tls(tls_result, web_result)
    passive_cves = detect_passive_cves(web_result)
    cti_result = audit_cti(ip_inventory, domain)

    service_scan = await asyncio.to_thread(audit_service_versions, domain, ip_inventory)
    host_enrichment = await enrich_public_hosts(domain, subdomains_result, ip_inventory)
    host_enrichment = attach_services_to_hosts(host_enrichment, service_scan)

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
        service_scan,
    )
    domain_profile = classify_domain(dns_result, mail_result, web_result)
    findings = adjust_findings_for_profile(raw_findings, domain_profile)
    findings = enrich_findings_locations(findings, domain)
    legacy_score = compute_score(findings, domain_profile)
    patching_sla = build_patching_sla(findings, created_at)
    executive_risk = build_executive_risk(findings, domain_profile, tls_score, ip_inventory, subdomains_result, passive_cves, cti_result)
    score = executive_risk.get("global_score", legacy_score)

    audit_id = str(uuid4())
    audit = {
        "id": audit_id,
        "product": APP_VERSION,
        "domain": domain,
        "created_at": created_at,
        "mode": "public_defensive_beta_26_6_dnsdumpster_like",
        "verification": verification_status,
        "domain_profile": domain_profile,
        "dns": dns_result,
        "mail": mail_result,
        "tls": tls_result,
        "tls_score": tls_score,
        "web": web_result,
        "subdomains": subdomains_result,
        "ip_inventory": ip_inventory,
        "host_enrichment": host_enrichment,
        "passive_cves": passive_cves,
        "service_scan": service_scan,
        "cti": cti_result,
        "patching_sla": patching_sla,
        "executive_risk": executive_risk,
        "legacy_score": legacy_score,
        "findings": findings,
        "score": score,
        "safety": {
            "accepted_terms": payload.accepted_terms,
            "legal_acceptance": legal_status,
            "client": client_host,
            "rate_limit": rate,
            "anti_ssrf": "HTTP/TLS/Nmap only if target resolves to public IPs and no blocked IP.",
            "active_scan": "enabled_light_service_version_all_public_subdomains",
            "nmap": service_scan.get("mode"),
            "cve_scan": "passive_headers_and_nmap_service_version_correlation",
            "leak_search": "disabled_public_mode",
        },
        "report_filename": None,
        "json_filename": None,
        "pdf_filename": None,
        "html_filename": None,
    }

    audit["attack_graph"] = build_attack_graph(audit)
    audit["report_errors"] = []
    for label, key, generator in [
        ("Excel", "report_filename", generate_excel_report),
        ("JSON", "json_filename", generate_json_report),
        ("PDF", "pdf_filename", generate_pdf_report),
        ("HTML", "html_filename", generate_html_report),
    ]:
        try:
            audit[key] = generator(audit)
        except Exception as exc:
            audit["report_errors"].append(f"{label}: {exc}")

    AUDITS[audit_id] = audit
    save_audit(db, audit)

    return {
        "id": audit_id,
        "domain": domain,
        "version": "26.6",
        "mode": audit["mode"],
        "verification": verification_status,
        "created_at": audit["created_at"],
        "domain_profile": domain_profile,
        "score": audit["score"],
        "executive_risk": executive_risk,
        "findings": audit["findings"],
        "subdomains": {
            "source": subdomains_result.get("source"),
            "count": subdomains_result.get("count"),
            "subdomains": subdomains_result.get("subdomains", [])[:120],
            "error": subdomains_result.get("error"),
        },
        "ip_inventory": {
            "public_ip_count": ip_inventory.get("public_ip_count"),
            "total_ip_count": ip_inventory.get("total_ip_count"),
            "unique_ips": ip_inventory.get("display_ips", ip_inventory.get("unique_ips", []))[:120],
            "location_counts": ip_inventory.get("location_counts", {}),
            "hosting_networks": ip_inventory.get("hosting_networks", {}),
            "core_public_ip_count": ip_inventory.get("core_public_ip_count", 0),
            "third_party_provider_ip_count": ip_inventory.get("third_party_provider_ip_count", 0),
        },
        "host_enrichment": {
            "summary": host_enrichment.get("summary", {}),
            "hosts": host_enrichment.get("hosts", [])[:120],
            "note": host_enrichment.get("summary", {}).get("note"),
        },
        "service_scan": {
            "enabled": service_scan.get("enabled"),
            "mode": service_scan.get("mode"),
            "count_open_ports": service_scan.get("count_open_ports", 0),
            "count_cves": service_scan.get("count_cves", 0),
            "elapsed_seconds": service_scan.get("elapsed_seconds", 0),
            "targets": service_scan.get("targets", [])[:120],
            "open_ports": service_scan.get("open_ports", [])[:200],
            "cves": service_scan.get("cves", [])[:100],
            "note": service_scan.get("note"),
        },
        "report_url": f"/api/reports/{audit_id}/excel",
        "json_url": f"/api/reports/{audit_id}/json",
        "pdf_url": f"/api/reports/{audit_id}/pdf",
        "html_url": f"/api/reports/{audit_id}/html",
        "graph_url": f"/api/audits/{audit_id}/graph",
        "attack_graph": audit.get("attack_graph", {}),
        "report_errors": audit.get("report_errors", []),
        "summary": {
            "subdomain_count": subdomains_result.get("count", 0),
            "public_ip_count": ip_inventory.get("public_ip_count", 0),
            "host_enrichment_active": host_enrichment.get("summary", {}).get("active_host_count", 0),
            "service_open_port_count": service_scan.get("count_open_ports", 0),
            "service_cve_count": service_scan.get("count_cves", 0),
            "service_scan_elapsed_seconds": service_scan.get("elapsed_seconds", 0),
            "locations": host_enrichment.get("summary", {}).get("location_counts", {}),
            "hosting_networks": host_enrichment.get("summary", {}).get("hosting_networks", {}),
            "service_banners": host_enrichment.get("summary", {}).get("service_banners", {}),
            "technologies": host_enrichment.get("summary", {}).get("technology_counts", {}),
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


@app.get("/api/audits/{audit_id}/graph")
async def api_audit_graph(audit_id: str, db=Depends(get_db)):
    audit = AUDITS.get(audit_id)
    if not audit:
        record = get_audit_record(db, audit_id)
        if not record:
            raise HTTPException(status_code=404, detail="Audit introuvable.")
        audit = record.audit_json
    return audit.get("attack_graph") or build_attack_graph(audit)


@app.get("/api/graph/latest")
async def api_latest_graph(db=Depends(get_db)):
    records = list_audits(db, limit=1)
    if not records:
        return {"available": False, "message": "Aucun audit disponible."}
    audit = records[0].audit_json
    return {"available": True, "audit_id": records[0].id, "graph": audit.get("attack_graph") or build_attack_graph(audit)}


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
        html_filename = r.html_filename or (r.audit_json or {}).get("html_filename")
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
            "html_filename": html_filename,
            "excel_exists": bool(r.excel_filename and (REPORT_DIR / r.excel_filename).exists()),
            "json_exists": bool(r.json_filename and (REPORT_DIR / r.json_filename).exists()),
            "pdf_exists": bool(r.pdf_filename and (REPORT_DIR / r.pdf_filename).exists()),
            "html_exists": bool(html_filename and (REPORT_DIR / html_filename).exists()),
            "excel_url": f"/api/reports/{r.id}/excel",
            "json_url": f"/api/reports/{r.id}/json",
            "pdf_url": f"/api/reports/{r.id}/pdf",
            "html_url": f"/api/reports/{r.id}/html",
        })
    return {"count": len(items), "items": items}


@app.post("/api/domains/verification/start")
async def api_start_domain_verification(payload: DomainVerificationRequest, db=Depends(get_db)):
    try:
        domain = normalize_domain(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return serialize_verification(start_verification(db, domain))


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


def _load_audit(audit_id: str, db):
    audit = AUDITS.get(audit_id)
    record = None
    if not audit:
        record = get_audit_record(db, audit_id)
        if not record:
            raise HTTPException(status_code=404, detail="Audit introuvable.")
        audit = record.audit_json
    return audit, record


@app.get("/api/reports/{audit_id}/excel")
async def download_excel_report(audit_id: str, db=Depends(get_db)):
    audit, _ = _load_audit(audit_id, db)
    filename = audit.get("report_filename")
    if not filename:
        raise HTTPException(status_code=404, detail="Rapport introuvable.")
    path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier rapport introuvable.")
    return FileResponse(path, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename=filename)


@app.get("/api/reports/{audit_id}/json")
async def download_json_report(audit_id: str, db=Depends(get_db)):
    audit, _ = _load_audit(audit_id, db)
    filename = audit.get("json_filename")
    if not filename:
        raise HTTPException(status_code=404, detail="Rapport JSON introuvable.")
    path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier JSON introuvable.")
    return FileResponse(path, media_type="application/json", filename=filename)


@app.get("/api/reports/{audit_id}/html")
async def download_html_report(audit_id: str, db=Depends(get_db)):
    audit, record = _load_audit(audit_id, db)
    filename = audit.get("html_filename") or (record.html_filename if record else None)
    path = REPORT_DIR / filename if filename else None
    if not filename or not path or not path.exists():
        try:
            filename = generate_html_report(audit)
            audit["html_filename"] = filename
            if audit_id in AUDITS:
                AUDITS[audit_id] = audit
            save_audit(db, audit)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Impossible de générer le rapport HTML: {exc}")
        path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier HTML introuvable.")
    return FileResponse(path, media_type="text/html", filename=filename)


@app.get("/api/reports/{audit_id}/pdf")
async def download_pdf_report(audit_id: str, db=Depends(get_db)):
    audit, _ = _load_audit(audit_id, db)
    filename = audit.get("pdf_filename")
    if not filename:
        raise HTTPException(status_code=404, detail="Rapport PDF introuvable.")
    path = REPORT_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Fichier PDF introuvable.")
    return FileResponse(path, media_type="application/pdf", filename=filename)


app.mount("/", StaticFiles(directory="/app/app/static", html=True), name="static")
