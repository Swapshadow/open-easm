from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/reports/open_easm_dev.sqlite3")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

class AuditRecord(Base):
    __tablename__ = "audits"

    id = Column(String(64), primary_key=True, index=True)
    domain = Column(String(255), index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), index=True, nullable=False)
    mode = Column(String(80), nullable=False)
    score = Column(Integer, nullable=False)
    level = Column(String(40), nullable=False)
    profile = Column(String(120), nullable=True)
    public_ip_count = Column(Integer, default=0)
    subdomain_count = Column(Integer, default=0)
    passive_cve_count = Column(Integer, default=0)
    tls_score = Column(Integer, default=0)
    excel_filename = Column(String(255), nullable=True)
    json_filename = Column(String(255), nullable=True)
    pdf_filename = Column(String(255), nullable=True)
    audit_json = Column(JSON, nullable=False)

class FindingRecord(Base):
    __tablename__ = "findings"

    pk = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), index=True, nullable=False)
    severity = Column(String(30), index=True, nullable=False)
    category = Column(String(120), index=True, nullable=True)
    title = Column(Text, nullable=True)
    status = Column(String(40), index=True, default="open")
    fingerprint = Column(String(512), index=True, nullable=False)
    finding_json = Column(JSON, nullable=False)

def init_db_with_retry(retries: int = 30, delay: float = 2.0):
    last_error = None
    for _ in range(retries):
        try:
            Base.metadata.create_all(bind=engine)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(delay)
    raise last_error

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def parse_dt(value: str):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


class VerifiedDomain(Base):
    __tablename__ = "verified_domains"

    domain = Column(String(255), primary_key=True, index=True)
    token = Column(String(255), nullable=False)
    status = Column(String(40), index=True, default="pending")
    method = Column(String(40), default="dns_txt")
    verification_name = Column(String(255), nullable=False)
    expected_value = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)


class LegalAcceptance(Base):
    __tablename__ = "legal_acceptances"

    token = Column(String(64), primary_key=True, index=True)
    terms_version = Column(String(80), index=True, nullable=False)
    terms_hash = Column(String(128), nullable=False)
    accepted_at = Column(DateTime(timezone=True), index=True, nullable=False)
    client_ip = Column(String(128), nullable=True)
    user_agent = Column(Text, nullable=True)
