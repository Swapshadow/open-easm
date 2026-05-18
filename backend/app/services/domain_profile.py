from __future__ import annotations

def classify_domain(dns_result: dict, mail_result: dict, web_result: dict) -> dict:
    has_a = bool(dns_result.get("records", {}).get("A", {}).get("values") or dns_result.get("records", {}).get("AAAA", {}).get("values"))
    has_mx = bool(mail_result.get("mx", {}).get("values"))
    has_spf = bool(dns_result.get("spf_records"))
    has_dmarc = bool(mail_result.get("dmarc_records"))
    has_web = bool(web_result.get("has_web"))
    reachable_targets = [t.get("hostname") for t in web_result.get("reachable_targets", [])]

    if has_web and (has_mx or has_spf or has_dmarc):
        profile = "web_et_messagerie"
        label = "Domaine web + messagerie"
        explanation = "Le domaine présente des éléments web et des éléments de messagerie."
    elif has_web:
        profile = "web"
        label = "Domaine web"
        explanation = "Le domaine expose un service web sur au moins une cible testée, par exemple le domaine racine ou www."
    elif has_mx or has_spf or has_dmarc:
        profile = "messagerie"
        label = "Domaine messagerie uniquement"
        explanation = "Le domaine semble principalement utilisé pour la messagerie. L'absence de site web sur le domaine racine peut être volontaire."
    elif has_a:
        profile = "dns"
        label = "Domaine DNS uniquement"
        explanation = "Le domaine résout mais aucun service web ou messagerie notable n'a été confirmé."
    else:
        profile = "indetermine"
        label = "Profil indéterminé"
        explanation = "Le domaine n'expose pas suffisamment d'éléments pour déterminer un profil fiable."

    return {
        "profile": profile,
        "label": label,
        "explanation": explanation,
        "reachable_web_targets": reachable_targets,
        "signals": {
            "has_a_or_aaaa_on_root": has_a,
            "has_mx": has_mx,
            "has_spf": has_spf,
            "has_dmarc": has_dmarc,
            "has_web": has_web,
        },
    }

def adjust_findings_for_profile(findings: list[dict], profile: dict) -> list[dict]:
    adjusted = []
    profile_name = profile.get("profile")

    for finding in findings:
        item = dict(finding)
        applies_to = item.get("applies_to", [])

        if profile_name == "messagerie" and "web" in applies_to and "mail" not in applies_to:
            if item.get("severity") in ("critical", "high", "medium", "low"):
                item["original_severity"] = item["severity"]
                item["severity"] = "info"
                item["description"] = item.get("description", "") + " Ce constat a été reclassé en information car le domaine semble être utilisé principalement pour la messagerie."

        adjusted.append(item)

    return adjusted
