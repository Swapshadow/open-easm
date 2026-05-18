SEVERITY_WEIGHTS = {
    "critical": 200,
    "high": 120,
    "medium": 60,
    "low": 25,
    "info": 0,
}

def collect_findings(*sections: dict) -> list[dict]:
    findings = []
    for section in sections:
        findings.extend(section.get("findings", []))
    return findings

def compute_score(findings: list[dict], profile: dict | None = None) -> dict:
    penalty = 0
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    by_category = {}

    for finding in findings:
        severity = finding.get("severity", "info")
        category = finding.get("category", "Autre")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_category[category] = by_category.get(category, 0) + 1
        penalty += SEVERITY_WEIGHTS.get(severity, 0)

    score = max(0, 1000 - penalty)

    if score >= 850:
        level = "Bon"
    elif score >= 700:
        level = "Correct"
    elif score >= 500:
        level = "Moyen"
    else:
        level = "Faible"

    return {
        "score": score,
        "max_score": 1000,
        "level": level,
        "penalty": penalty,
        "by_severity": by_severity,
        "by_category": by_category,
        "profile_adjusted": True,
        "profile": profile.get("profile") if profile else None,
    }
