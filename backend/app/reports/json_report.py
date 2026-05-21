from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def generate_json_report(audit: dict) -> str:
    """Export JSON complet enrichi avec des métadonnées de rapport Beta.

    Le JSON conserve l'audit complet pour rester compatible avec les usages existants,
    mais ajoute un bloc `report_metadata` exploitable par des outils tiers.
    """
    filename = f"open_easm_beta_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    path = REPORT_DIR / filename

    payload = deepcopy(audit)
    payload["report_metadata"] = {
        "product": "OpenEASM",
        "edition": "Beta",
        "report_profile": "professional_audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "report_scope": "External Attack Surface Management - audit defensif public",
        "non_exploit_policy": {
            "exploitation": False,
            "bruteforce": False,
            "dos": False,
            "intrusive_nse": False,
            "description": "Les CVE sont corrélées à partir des versions exposées. Aucune validation par exploitation n'est réalisée.",
        },
        "limitations": [
            "Une version masquée ne permet pas une corrélation CVE fiable.",
            "Les résultats dépendent des informations publiquement exposées au moment de l'audit.",
            "Les correctifs backportés par les distributions Linux peuvent rendre une version apparente non vulnérable.",
        ],
    }

    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, default=str)

    return filename
