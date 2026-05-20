from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import LegalAcceptance

TERMS_VERSION = "v7.5-fr-2026-05-20"

LEGAL_WARNING_TEXT = """AVERTISSEMENT JURIDIQUE ET CONDITIONS D’UTILISATION D’OPENEASM V7.5

OpenEASM est un outil d’External Attack Surface Management destiné à aider les organisations à identifier leur exposition publique sur Internet.

L’outil peut réaliser des contrôles techniques limités tels que l’analyse DNS, l’analyse TLS/SSL, l’analyse des en-têtes HTTP, l’identification de ports ouverts, l’identification de services et versions exposés, ainsi que la corrélation non exploitante avec des vulnérabilités connues publiquement référencées sous forme de CVE.

OpenEASM ne réalise aucune exploitation volontaire de vulnérabilité, aucun contournement d’authentification, aucun bruteforce, aucune attaque par déni de service, aucune modification de données et aucune extraction frauduleuse de données.

En utilisant OpenEASM, je reconnais être seul responsable des domaines, sous-domaines, adresses IP ou services que je soumets à l’analyse.

Je certifie disposer d’un droit, d’une autorisation explicite ou d’un motif légitime de sécurité informatique pour analyser les ressources renseignées dans l’application.

Je reconnais que l’analyse de systèmes tiers sans autorisation peut engager ma responsabilité civile et pénale.

Je reconnais avoir été informé notamment des dispositions du Code pénal français relatives aux atteintes aux systèmes de traitement automatisé de données, notamment les articles 323-1, 323-2, 323-3 et 323-3-1.

Je comprends que :
- l’accès ou le maintien frauduleux dans un système de traitement automatisé de données est interdit ;
- le fait d’entraver ou de fausser le fonctionnement d’un système est interdit ;
- l’introduction, l’extraction, la reproduction, la transmission, la suppression ou la modification frauduleuse de données est interdite ;
- la mise à disposition ou l’utilisation d’outils informatiques sans motif légitime, notamment de recherche ou de sécurité informatique, peut également être sanctionnée.

En cochant la case ci-dessous, je déclare avoir lu, compris et accepté ces conditions d’utilisation. Je m’engage à utiliser OpenEASM uniquement dans un cadre légal, autorisé et défensif.
""".strip()

LEGAL_ARTICLES = [
    {
        "article": "Code pénal 323-1",
        "summary": "Accès ou maintien frauduleux dans un système de traitement automatisé de données.",
        "penalty": "3 ans d’emprisonnement et 100 000 € d’amende ; aggravation à 5 ans et 150 000 € en cas de suppression/modification de données ou altération du fonctionnement.",
    },
    {
        "article": "Code pénal 323-2",
        "summary": "Entrave ou fait de fausser le fonctionnement d’un système de traitement automatisé de données.",
        "penalty": "5 ans d’emprisonnement et 150 000 € d’amende.",
    },
    {
        "article": "Code pénal 323-3",
        "summary": "Introduction, extraction, détention, reproduction, transmission, suppression ou modification frauduleuse de données.",
        "penalty": "5 ans d’emprisonnement et 150 000 € d’amende.",
    },
    {
        "article": "Code pénal 323-3-1",
        "summary": "Importation, détention, offre, cession ou mise à disposition sans motif légitime d’un outil spécialement adapté à commettre les infractions 323-1 à 323-3.",
        "penalty": "Peines prévues pour l’infraction elle-même ou l’infraction la plus sévèrement réprimée.",
    },
]


def terms_hash() -> str:
    return hashlib.sha256(LEGAL_WARNING_TEXT.encode("utf-8")).hexdigest()


def legal_payload() -> dict:
    return {
        "app": "OpenEASM",
        "version": TERMS_VERSION,
        "hash": terms_hash(),
        "text": LEGAL_WARNING_TEXT,
        "articles": LEGAL_ARTICLES,
        "blocking": True,
        "requires_acceptance": True,
    }


def create_acceptance(db: Session, *, client_ip: str, user_agent: str, accepted: bool, supplied_hash: str | None) -> dict:
    current_hash = terms_hash()
    if not accepted:
        raise ValueError("Les conditions doivent être acceptées pour accéder à OpenEASM.")
    if supplied_hash and supplied_hash != current_hash:
        raise ValueError("La version des conditions affichées n’est plus à jour. Rechargez la page.")

    token = str(uuid4())
    now = datetime.now(timezone.utc)
    record = LegalAcceptance(
        token=token,
        terms_version=TERMS_VERSION,
        terms_hash=current_hash,
        accepted_at=now,
        client_ip=client_ip,
        user_agent=user_agent[:1000],
    )
    db.add(record)
    db.commit()
    return {
        "accepted": True,
        "token": token,
        "version": TERMS_VERSION,
        "hash": current_hash,
        "terms_version": TERMS_VERSION,
        "terms_hash": current_hash,
        "accepted_at": now.isoformat(),
    }


def validate_acceptance(db: Session, token: str | None) -> dict:
    if not token:
        return {"accepted": False, "reason": "missing_token", "version": TERMS_VERSION, "hash": terms_hash()}

    record = db.execute(
        select(LegalAcceptance).where(LegalAcceptance.token == token)
    ).scalar_one_or_none()

    if not record:
        return {"accepted": False, "reason": "unknown_token", "version": TERMS_VERSION, "hash": terms_hash()}

    current_hash = terms_hash()
    if record.terms_version != TERMS_VERSION or record.terms_hash != current_hash:
        return {"accepted": False, "reason": "terms_changed", "version": TERMS_VERSION, "hash": current_hash}

    return {
        "accepted": True,
        "version": record.terms_version,
        "hash": record.terms_hash,
        "accepted_at": record.accepted_at.isoformat() if record.accepted_at else None,
    }
