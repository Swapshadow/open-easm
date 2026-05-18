from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("/app/reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

def generate_json_report(audit: dict) -> str:
    filename = f"open_easm_v4_3_{audit['domain'].replace('.', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    path = REPORT_DIR / filename

    with path.open("w", encoding="utf-8") as f:
        json.dump(audit, f, ensure_ascii=False, indent=2, default=str)

    return filename
