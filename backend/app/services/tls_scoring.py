from __future__ import annotations

def score_tls(tls_result: dict, web_result: dict) -> dict:
    per_target = []
    findings = []

    web_targets_by_host = {t.get("hostname"): t for t in web_result.get("targets", [])}

    for tls in tls_result.get("targets", []):
        host = tls.get("hostname")
        cert = tls.get("cert") or {}
        score = 100
        checks = []

        if not tls.get("available"):
            score -= 45
            checks.append("TLS indisponible ou non validé")
        else:
            checks.append("TLS disponible")

        if cert.get("expired") is True:
            score -= 70
            checks.append("Certificat expiré")
        elif cert.get("days_remaining") is not None:
            days = cert.get("days_remaining")
            if days <= 15:
                score -= 35
                checks.append("Certificat expire sous 15 jours")
            elif days <= 30:
                score -= 20
                checks.append("Certificat expire sous 30 jours")
            else:
                checks.append("Certificat non expiré")

        tls_version = cert.get("tls_version")
        if tls_version in ("TLSv1", "TLSv1.1"):
            score -= 35
            checks.append("Version TLS négociée ancienne")
        elif tls_version:
            checks.append(f"Version négociée : {tls_version}")

        web = web_targets_by_host.get(host) or {}
        headers = web.get("security_headers") or {}
        hsts = headers.get("Strict-Transport-Security", {})
        if web.get("reachable") and not hsts.get("present"):
            score -= 15
            checks.append("HSTS absent")

        http = web.get("http") or {}
        https = web.get("https") or {}
        if http.get("reachable") and https.get("reachable") and str(http.get("final_url", "")).startswith("http://"):
            score -= 15
            checks.append("HTTP ne redirige pas vers HTTPS")

        score = max(0, min(100, score))
        if score >= 85:
            level = "Bon"
        elif score >= 70:
            level = "Correct"
        elif score >= 50:
            level = "Moyen"
        else:
            level = "Faible"

        per_target.append({
            "hostname": host,
            "score": score,
            "level": level,
            "checks": checks,
            "tls_available": tls.get("available"),
            "tls_version": tls_version,
            "days_remaining": cert.get("days_remaining"),
            "issuer": cert.get("issuer"),
        })

        if score < 70:
            findings.append({
                "severity": "medium" if score >= 50 else "high",
                "category": "TLS/SSL",
                "title": f"Qualité TLS/SSL à améliorer sur {host}",
                "description": f"Score TLS/SSL calculé : {score}/100. Points observés : " + "; ".join(checks),
                "recommendation": "Vérifier la validité du certificat, la redirection HTTPS, HSTS et la configuration TLS.",
                "applies_to": ["web", "tls"],
            })

    if per_target:
        global_score = round(sum(t["score"] for t in per_target) / len(per_target))
    else:
        global_score = 0

    if global_score >= 85:
        global_level = "Bon"
    elif global_score >= 70:
        global_level = "Correct"
    elif global_score >= 50:
        global_level = "Moyen"
    else:
        global_level = "Faible"

    return {
        "global_score": global_score,
        "global_level": global_level,
        "targets": per_target,
        "findings": findings,
    }
