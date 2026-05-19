from __future__ import annotations

SEVERITY_PENALTY = {
    "critical": 38,
    "high": 24,
    "medium": 11,
    "low": 4,
    "info": 0,
}

PROFILE_WEIGHTS = {
    "web_et_messagerie": {
        "dns": 15, "mail": 20, "web": 15, "tls": 15, "surface": 15, "cti": 10, "cve": 10,
    },
    "web": {
        "dns": 18, "mail": 0, "web": 22, "tls": 20, "surface": 18, "cti": 12, "cve": 10,
    },
    "messagerie": {
        "dns": 20, "mail": 35, "web": 0, "tls": 0, "surface": 15, "cti": 20, "cve": 10,
    },
    "dns": {
        "dns": 40, "mail": 0, "web": 0, "tls": 0, "surface": 30, "cti": 30, "cve": 0,
    },
    "indetermine": {
        "dns": 25, "mail": 15, "web": 15, "tls": 15, "surface": 15, "cti": 10, "cve": 5,
    },
}

PILLARS = [
    {
        "id": "dns",
        "label": "DNS",
        "patterns": ["dns", "caa", "a/aaaa", "résolution"],
        "description": "Qualité des enregistrements publics et cohérence de la zone DNS.",
        "recommendation": "Corriger les enregistrements DNS faibles ou incohérents, notamment CAA, NS et résolutions non publiques.",
    },
    {
        "id": "mail",
        "label": "Messagerie",
        "patterns": ["messagerie", "mail", "dmarc", "spf", "mx", "dkim"],
        "description": "Protection du domaine contre l'usurpation, l'hameçonnage et les erreurs de routage mail.",
        "recommendation": "Renforcer SPF, DKIM et DMARC, puis viser progressivement une politique DMARC stricte.",
    },
    {
        "id": "web",
        "label": "Web",
        "patterns": ["web", "headers", "http", "header"],
        "description": "Sécurité des services web publics, redirections et en-têtes HTTP de sécurité.",
        "recommendation": "Corriger les headers HTTP manquants, forcer HTTPS et réduire les surfaces web non maîtrisées.",
    },
    {
        "id": "tls",
        "label": "TLS/SSL",
        "patterns": ["tls", "ssl", "certificat", "https"],
        "description": "Qualité des certificats, expiration, versions TLS et configuration HTTPS.",
        "recommendation": "Surveiller les expirations, garder TLS moderne et corriger les anomalies de certificat.",
    },
    {
        "id": "surface",
        "label": "Surface exposée",
        "patterns": ["inventaire ip", "sous-domaines", "surface", "ip publique", "ip privée"],
        "description": "Inventaire des IP, sous-domaines et actifs exposés sur Internet.",
        "recommendation": "Justifier chaque exposition, retirer les actifs non nécessaires et corriger les IP privées publiées.",
    },
    {
        "id": "cti",
        "label": "CTI / Réputation",
        "patterns": ["cti", "réputation", "reputation", "dnsbl", "blacklist"],
        "description": "Signaux de réputation et présence éventuelle dans des listes de blocage.",
        "recommendation": "Traiter les IP listées, vérifier les abus et documenter les faux positifs.",
    },
    {
        "id": "cve",
        "label": "CVE passives",
        "patterns": ["cve", "vulnérabilité", "vulnerability"],
        "description": "CVE potentielles déduites passivement des technologies exposées.",
        "recommendation": "Confirmer les versions réelles en interne et prioriser les corrections sur les actifs publics.",
    },
]

def _category_match(finding: dict, patterns: list[str]) -> bool:
    loc = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    haystack = " ".join([
        str(finding.get("category", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(loc.get("control", "")),
        str(loc.get("display", "")),
    ]).lower()
    return any(p.lower() in haystack for p in patterns)

def _confidence(finding: dict) -> str:
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    if any(x in title for x in ["dmarc", "spf", "mx", "caa", "header absent", "certificat"]):
        return "élevée"
    if "cve" in category or "passive" in title:
        return "moyenne"
    if "source passive" in title or "indisponible" in title:
        return "faible"
    return "moyenne"

def _score_from_findings(findings: list[dict], extra_penalty: int = 0) -> tuple[int, list[dict]]:
    evidence = []
    penalty = extra_penalty

    if extra_penalty:
        evidence.append({
            "label": "Pénalité contextuelle",
            "severity": "context",
            "points_lost": extra_penalty,
            "confidence": "moyenne",
            "reason": "Exposition ou signal contextuel défavorable.",
        })

    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        lost = SEVERITY_PENALTY.get(severity, 0)
        penalty += lost
        if lost:
            evidence.append({
                "label": finding.get("title", ""),
                "severity": severity,
                "points_lost": lost,
                "confidence": _confidence(finding),
                "reason": finding.get("description", ""),
                "location": _loc(finding),
            })

    return max(0, min(100, 100 - penalty)), evidence

def _level(score: int) -> str:
    if score >= 85:
        return "Maîtrisé"
    if score >= 70:
        return "Correct"
    if score >= 55:
        return "À surveiller"
    return "Risque élevé"

def _risk_label(score: int) -> str:
    if score >= 85:
        return "Faible"
    if score >= 70:
        return "Modéré"
    if score >= 55:
        return "Significatif"
    return "Élevé"

def _tech_level(score_1000: int) -> str:
    if score_1000 >= 850:
        return "Bon"
    if score_1000 >= 700:
        return "Correct"
    if score_1000 >= 550:
        return "Moyen"
    return "Faible"

def _sev_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(sev).lower(), 9)

def _loc(finding: dict) -> str:
    loc = finding.get("location") or {}
    if isinstance(loc, dict):
        return loc.get("display") or loc.get("path") or loc.get("record") or loc.get("hostname") or loc.get("control") or "N/A"
    return "N/A"

def build_executive_risk(
    findings: list[dict],
    domain_profile: dict,
    tls_score: dict,
    ip_inventory: dict,
    subdomains_result: dict,
    passive_cves: dict,
    cti_result: dict,
) -> dict:
    profile_name = domain_profile.get("profile") or "indetermine"
    weights = PROFILE_WEIGHTS.get(profile_name, PROFILE_WEIGHTS["indetermine"])

    pillars = []
    for pillar in PILLARS:
        pillar_id = pillar["id"]
        weight = weights.get(pillar_id, 0)
        applicability = "applicable" if weight > 0 else "non_applicable"
        pf = [f for f in findings if _category_match(f, pillar["patterns"])]

        extra = 0
        if applicability == "non_applicable":
            score = None
            evidence = []
        elif pillar_id == "tls":
            finding_score, evidence = _score_from_findings(pf)
            tls_global = tls_score.get("global_score")
            if isinstance(tls_global, (int, float)):
                score = round((finding_score + int(tls_global)) / 2)
                if tls_global < 60:
                    evidence.append({
                        "label": "Score TLS technique faible",
                        "severity": "context",
                        "points_lost": max(0, 100 - int(tls_global)),
                        "confidence": "élevée",
                        "reason": f"Score TLS calculé : {int(tls_global)} / 100.",
                    })
            else:
                score = finding_score
        else:
            if pillar_id == "surface":
                if ip_inventory.get("non_public_ips"):
                    extra += 25
                if (ip_inventory.get("core_public_ip_count") or 0) > 10:
                    extra += 8
                if (ip_inventory.get("third_party_provider_ip_count") or 0) > 25:
                    extra += 2
                if (subdomains_result.get("count") or 0) > 80:
                    extra += 5
            if pillar_id == "cti":
                summary = cti_result.get("summary") or {}
                if (summary.get("listed") or 0) > 0:
                    extra += 40
                if (summary.get("errors") or 0) > 0:
                    extra += 3
            if pillar_id == "cve":
                if (passive_cves.get("count") or 0) > 0:
                    extra += min(35, (passive_cves.get("count") or 0) * 10)
            score, evidence = _score_from_findings(pf, extra_penalty=extra)

        critical_high = sum(1 for f in pf if str(f.get("severity")).lower() in ("critical", "high"))
        pillars.append({
            "id": pillar_id,
            "label": pillar["label"],
            "weight": weight,
            "applicability": applicability,
            "score": score,
            "level": "Non applicable" if score is None else _level(score),
            "risk": "Non applicable" if score is None else _risk_label(score),
            "findings_count": len(pf),
            "critical_high_count": critical_high,
            "description": pillar["description"],
            "recommendation": pillar["recommendation"],
            "evidence": evidence[:10],
        })

    applicable = [p for p in pillars if p["applicability"] == "applicable" and isinstance(p["score"], int) and p["weight"] > 0]
    total_weight = sum(p["weight"] for p in applicable)
    overall = round(sum(p["score"] * p["weight"] for p in applicable) / total_weight) if total_weight else 0
    technical_score = max(0, min(1000, overall * 10))

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_category = {}
    penalty = 0
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        cat = str(finding.get("category", "Autre"))
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
        penalty += SEVERITY_PENALTY.get(sev, 0)

    sorted_findings = sorted(findings, key=lambda f: (_sev_rank(f.get("severity", "info")), str(f.get("category", "")), str(f.get("title", ""))))
    top_risks = []
    for f in sorted_findings:
        if len(top_risks) >= 5:
            break
        if str(f.get("severity", "info")).lower() in ("critical", "high", "medium"):
            top_risks.append({
                "severity": f.get("severity", "info"),
                "category": f.get("category", "Autre"),
                "title": f.get("title", ""),
                "location": _loc(f),
                "recommendation": f.get("recommendation", ""),
                "confidence": _confidence(f),
            })

    quick_wins = []
    for f in sorted_findings:
        text = f"{f.get('title','')} {f.get('description','')}".lower()
        if len(quick_wins) >= 5:
            break
        if any(word in text for word in ["header", "hsts", "dmarc", "spf", "caa", "expiration", "tls"]):
            quick_wins.append({
                "severity": f.get("severity", "info"),
                "title": f.get("title", ""),
                "location": _loc(f),
                "recommendation": f.get("recommendation", ""),
                "confidence": _confidence(f),
            })

    weakest = sorted([p for p in applicable], key=lambda p: p["score"])[:3]
    posture = _level(overall)
    risk = _risk_label(overall)
    weakest_text = ", ".join(f"{p['label']} ({p['score']}/100)" for p in weakest) if weakest else "aucun pilier applicable"

    return {
        "overall_score": overall,
        "max_score": 100,
        "technical_score": technical_score,
        "technical_max_score": 1000,
        "technical_level": _tech_level(technical_score),
        "posture": posture,
        "risk_level": risk,
        "board_summary": f"Posture globale {posture.lower()} avec un risque {risk.lower()}. Les piliers les plus faibles sont : {weakest_text}.",
        "profile": domain_profile.get("label"),
        "profile_id": profile_name,
        "pillars": pillars,
        "weakest_pillars": weakest,
        "top_risks": top_risks,
        "quick_wins": quick_wins,
        "method": "Score centralisé : moyenne pondérée des piliers applicables. Le score technique /1000 = score exécutif /100 × 10.",
        "global_score": {
            "score": technical_score,
            "max_score": 1000,
            "level": _tech_level(technical_score),
            "executive_score": overall,
            "executive_max_score": 100,
            "risk_level": risk,
            "penalty": penalty,
            "by_severity": by_severity,
            "by_category": by_category,
            "profile_adjusted": True,
            "profile": profile_name,
            "source": "executive_risk_engine_alpha",
        },
    }
