from __future__ import annotations

from datetime import datetime, timezone, timedelta

SLA_DAYS = {
    "critical": 5,
    "high": 15,
    "medium": 30,
    "low": 90,
    "info": None,
}

def build_patching_sla(findings: list[dict], now_iso: str | None = None) -> dict:
    if now_iso:
        now = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    else:
        now = datetime.now(timezone.utc)

    items = []
    for idx, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "info")
        sla = SLA_DAYS.get(severity)
        if sla is None:
            due = None
            status = "information"
        else:
            due_dt = now + timedelta(days=sla)
            due = due_dt.isoformat()
            status = "open_within_sla"

        items.append({
            "id": idx,
            "title": finding.get("title"),
            "category": finding.get("category"),
            "severity": severity,
            "detected_at": now.isoformat(),
            "sla_days": sla,
            "due_at": due,
            "status": status,
            "recommendation": finding.get("recommendation"),
        })

    return {
        "items": items,
        "sla_policy": {
            "critical": "< 5 jours",
            "high": "< 15 jours",
            "medium": "< 30 jours",
            "low": "< 90 jours",
            "info": "suivi informationnel",
        },
        "note": "La V5 prépare le suivi patching avec des SLA cibles. La mesure réelle de cadence de correction nécessite un historique serveur en base de données.",
    }
