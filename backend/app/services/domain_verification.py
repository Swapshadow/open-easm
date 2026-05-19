from __future__ import annotations

import secrets
from datetime import datetime, timezone
import dns.resolver
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.database import VerifiedDomain

TIMEOUT = 4.0

def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    r.timeout = TIMEOUT
    return r

def _now():
    return datetime.now(timezone.utc)

def _clean_txt(value: str) -> str:
    return value.replace('" "', "").replace('"', "").strip()

def generate_token() -> str:
    return secrets.token_hex(16)

def get_verification_name(domain: str) -> str:
    return f"_easm-verification.{domain}"

def get_expected_value(token: str) -> str:
    return f"open-easm-verification={token}"

def start_verification(db: Session, domain: str) -> VerifiedDomain:
    existing = db.get(VerifiedDomain, domain)
    if existing and existing.status == "verified":
        return existing

    token = generate_token()
    record = existing or VerifiedDomain(domain=domain)
    record.token = token
    record.status = "pending"
    record.method = "dns_txt"
    record.verification_name = get_verification_name(domain)
    record.expected_value = get_expected_value(token)
    record.created_at = record.created_at or _now()
    record.verified_at = None
    record.last_checked_at = None
    record.last_error = None

    record = db.merge(record)
    db.commit()
    db.refresh(record)
    return record

def check_verification(db: Session, domain: str) -> VerifiedDomain | None:
    record = db.get(VerifiedDomain, domain)
    if not record:
        return None

    record.last_checked_at = _now()
    record.last_error = None

    try:
        answers = _resolver().resolve(record.verification_name, "TXT")
        values = [_clean_txt(str(a)) for a in answers]
        if record.expected_value in values:
            record.status = "verified"
            record.verified_at = _now()
        else:
            record.status = "pending"
            record.last_error = "TXT trouvé, mais valeur attendue absente. Valeurs vues : " + " | ".join(values)
    except Exception as exc:
        if record.status != "verified":
            record.status = "pending"
        record.last_error = str(exc)

    db.commit()
    db.refresh(record)
    return record

def get_domain_status(db: Session, domain: str) -> dict:
    record = db.get(VerifiedDomain, domain)
    if not record:
        return {"domain": domain, "status": "not_started", "verified": False}
    return serialize_verification(record)

def list_verified_domains(db: Session) -> list[VerifiedDomain]:
    stmt = select(VerifiedDomain).order_by(VerifiedDomain.created_at.desc())
    return list(db.execute(stmt).scalars())

def delete_verification(db: Session, domain: str) -> bool:
    record = db.get(VerifiedDomain, domain)
    if not record:
        return False
    db.delete(record)
    db.commit()
    return True

def serialize_verification(record: VerifiedDomain) -> dict:
    return {
        "domain": record.domain,
        "status": record.status,
        "verified": record.status == "verified",
        "method": record.method,
        "verification_name": record.verification_name,
        "expected_value": record.expected_value,
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "verified_at": record.verified_at.isoformat() if record.verified_at else None,
        "last_checked_at": record.last_checked_at.isoformat() if record.last_checked_at else None,
        "last_error": record.last_error,
    }
