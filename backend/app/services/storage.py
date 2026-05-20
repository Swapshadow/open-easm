from __future__ import annotations

import hashlib
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from app.database import AuditRecord, FindingRecord, parse_dt

def finding_fingerprint(domain: str, finding: dict) -> str:
    raw = "|".join([
        domain.lower(),
        str(finding.get("category", "")),
        str(finding.get("title", "")),
        str(finding.get("applies_to", "")),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def save_audit(db: Session, audit: dict) -> None:
    created_at = parse_dt(audit["created_at"])
    score = audit.get("score", {})
    summary = {
        "public_ip_count": audit.get("ip_inventory", {}).get("public_ip_count", 0),
        "subdomain_count": audit.get("subdomains", {}).get("count", 0),
        "passive_cve_count": (audit.get("passive_cves", {}).get("count", 0) or 0) + (audit.get("service_scan", {}).get("count_cves", 0) or 0),
        "tls_score": audit.get("tls_score", {}).get("global_score", 0),
    }

    record = AuditRecord(
        id=audit["id"],
        domain=audit["domain"],
        created_at=created_at,
        mode=audit["mode"],
        score=score.get("score", 0),
        level=score.get("level", "N/A"),
        profile=audit.get("domain_profile", {}).get("label"),
        public_ip_count=summary["public_ip_count"],
        subdomain_count=summary["subdomain_count"],
        passive_cve_count=summary["passive_cve_count"],
        tls_score=summary["tls_score"],
        excel_filename=audit.get("report_filename"),
        json_filename=audit.get("json_filename"),
        pdf_filename=audit.get("pdf_filename"),
        audit_json=audit,
    )
    db.merge(record)

    for finding in audit.get("findings", []):
        fp = finding_fingerprint(audit["domain"], finding)
        existing = db.execute(
            select(FindingRecord).where(
                FindingRecord.domain == audit["domain"],
                FindingRecord.fingerprint == fp,
                FindingRecord.status == "open",
            )
        ).scalar_one_or_none()

        if existing:
            existing.finding_json = finding
            existing.created_at = created_at
            existing.severity = finding.get("severity", "info")
            existing.category = finding.get("category")
            existing.title = finding.get("title")
            existing.audit_id = audit["id"]
        else:
            db.add(FindingRecord(
                audit_id=audit["id"],
                domain=audit["domain"],
                created_at=created_at,
                severity=finding.get("severity", "info"),
                category=finding.get("category"),
                title=finding.get("title"),
                status="open",
                fingerprint=fp,
                finding_json=finding,
            ))

    db.commit()

def list_audits(db: Session, limit: int = 50, domain: str | None = None) -> list[AuditRecord]:
    stmt = select(AuditRecord).order_by(desc(AuditRecord.created_at)).limit(limit)
    if domain:
        stmt = select(AuditRecord).where(AuditRecord.domain == domain).order_by(desc(AuditRecord.created_at)).limit(limit)
    return list(db.execute(stmt).scalars())

def get_audit_record(db: Session, audit_id: str) -> AuditRecord | None:
    return db.get(AuditRecord, audit_id)

def get_latest_audits_for_domain(db: Session, domain: str, limit: int = 2) -> list[AuditRecord]:
    stmt = select(AuditRecord).where(AuditRecord.domain == domain).order_by(desc(AuditRecord.created_at)).limit(limit)
    return list(db.execute(stmt).scalars())

def dashboard_stats(db: Session) -> dict:
    audits = list_audits(db, limit=500)
    domains = sorted(set(a.domain for a in audits))
    latest_by_domain = {}
    for a in audits:
        if a.domain not in latest_by_domain:
            latest_by_domain[a.domain] = a

    latest = list(latest_by_domain.values())
    if latest:
        avg_score = round(sum(a.score for a in latest) / len(latest))
        total_ips = sum(a.public_ip_count or 0 for a in latest)
        total_subs = sum(a.subdomain_count or 0 for a in latest)
        total_cves = sum(a.passive_cve_count or 0 for a in latest)
    else:
        avg_score = total_ips = total_subs = total_cves = 0

    return {
        "domain_count": len(domains),
        "audit_count": len(audits),
        "average_latest_score": avg_score,
        "total_public_ips_latest": total_ips,
        "total_subdomains_latest": total_subs,
        "total_passive_cves_latest": total_cves,
        "latest": [
            {
                "id": a.id,
                "domain": a.domain,
                "created_at": a.created_at.isoformat(),
                "score": a.score,
                "level": a.level,
                "profile": a.profile,
                "public_ip_count": a.public_ip_count,
                "subdomain_count": a.subdomain_count,
                "passive_cve_count": a.passive_cve_count,
                "tls_score": a.tls_score,
            }
            for a in latest[:50]
        ],
    }

def compare_latest(db: Session, domain: str) -> dict:
    audits = get_latest_audits_for_domain(db, domain, 2)
    if len(audits) < 2:
        return {
            "available": False,
            "message": "Il faut au moins deux audits pour comparer.",
            "domain": domain,
        }

    current, previous = audits[0], audits[1]
    c_json = current.audit_json
    p_json = previous.audit_json

    def fp_set(audit_json):
        return {
            finding_fingerprint(audit_json["domain"], f): f
            for f in audit_json.get("findings", [])
        }

    c_find = fp_set(c_json)
    p_find = fp_set(p_json)

    new_keys = set(c_find) - set(p_find)
    fixed_keys = set(p_find) - set(c_find)
    persistent_keys = set(c_find) & set(p_find)

    c_ips = {i["ip"] for i in c_json.get("ip_inventory", {}).get("unique_ips", [])}
    p_ips = {i["ip"] for i in p_json.get("ip_inventory", {}).get("unique_ips", [])}

    return {
        "available": True,
        "domain": domain,
        "current": {
            "id": current.id,
            "created_at": current.created_at.isoformat(),
            "score": current.score,
        },
        "previous": {
            "id": previous.id,
            "created_at": previous.created_at.isoformat(),
            "score": previous.score,
        },
        "score_delta": current.score - previous.score,
        "new_findings": [c_find[k] for k in new_keys],
        "fixed_findings": [p_find[k] for k in fixed_keys],
        "persistent_findings": [c_find[k] for k in persistent_keys],
        "new_ips": sorted(c_ips - p_ips),
        "removed_ips": sorted(p_ips - c_ips),
    }


def delete_audit(db: Session, audit_id: str) -> bool:
    record = get_audit_record(db, audit_id)
    if not record:
        return False

    db.query(FindingRecord).filter(FindingRecord.audit_id == audit_id).delete(synchronize_session=False)
    db.delete(record)
    db.commit()
    return True

def delete_all_audits(db: Session) -> int:
    count = db.query(AuditRecord).count()
    db.query(FindingRecord).delete(synchronize_session=False)
    db.query(AuditRecord).delete(synchronize_session=False)
    db.commit()
    return count

def delete_domain_audits(db: Session, domain: str) -> int:
    records = list(db.execute(select(AuditRecord).where(AuditRecord.domain == domain)).scalars())
    ids = [r.id for r in records]
    if not ids:
        return 0
    db.query(FindingRecord).filter(FindingRecord.domain == domain).delete(synchronize_session=False)
    db.query(AuditRecord).filter(AuditRecord.domain == domain).delete(synchronize_session=False)
    db.commit()
    return len(ids)
