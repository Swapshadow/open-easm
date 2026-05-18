from __future__ import annotations

import dns.resolver
from app.validators import is_public_ip

TIMEOUT = 4.0

def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = TIMEOUT
    r.timeout = TIMEOUT
    return r

def query_records(domain: str, record_type: str) -> dict:
    resolver = _resolver()
    try:
        answers = resolver.resolve(domain, record_type)
        values = [str(r).strip() for r in answers]
        return {
            "record_type": record_type,
            "status": "ok",
            "values": values,
            "error": None,
        }
    except dns.resolver.NoAnswer:
        return {
            "record_type": record_type,
            "status": "no_answer",
            "values": [],
            "error": None,
        }
    except dns.resolver.NXDOMAIN:
        return {
            "record_type": record_type,
            "status": "nxdomain",
            "values": [],
            "error": "Le domaine n'existe pas.",
        }
    except Exception as exc:
        return {
            "record_type": record_type,
            "status": "error",
            "values": [],
            "error": str(exc),
        }

def extract_spf(txt_values: list[str]) -> list[str]:
    spf = []
    for value in txt_values:
        cleaned = value.replace('" "', "").replace('"', "").strip()
        if cleaned.lower().startswith("v=spf1"):
            spf.append(cleaned)
    return spf

def audit_dns(domain: str) -> dict:
    a = query_records(domain, "A")
    aaaa = query_records(domain, "AAAA")
    ns = query_records(domain, "NS")
    txt = query_records(domain, "TXT")
    caa = query_records(domain, "CAA")

    ips = a["values"] + aaaa["values"]
    public_ips = [ip for ip in ips if is_public_ip(ip)]
    non_public_ips = [ip for ip in ips if not is_public_ip(ip)]

    spf_records = extract_spf(txt["values"])

    return {
        "domain": domain,
        "records": {
            "A": a,
            "AAAA": aaaa,
            "NS": ns,
            "TXT": txt,
            "CAA": caa,
        },
        "resolved_ips": ips,
        "public_ips": public_ips,
        "non_public_ips": non_public_ips,
        "spf_records": spf_records,
        "findings": build_dns_findings(a, aaaa, ns, caa, spf_records, non_public_ips),
    }

def build_dns_findings(a: dict, aaaa: dict, ns: dict, caa: dict, spf_records: list[str], non_public_ips: list[str]) -> list[dict]:
    findings = []

    if not a["values"] and not aaaa["values"]:
        findings.append({
            "severity": "info",
            "category": "DNS",
            "title": "Aucune résolution A/AAAA sur le domaine racine",
            "description": "Le domaine racine ne semble pas résoudre vers une adresse IP publique.",
            "recommendation": "À vérifier uniquement si ce domaine doit héberger un site web. Si le site est sur www ou si le domaine est dédié à la messagerie, ce point peut être acceptable.",
            "applies_to": ["web", "dns"],
        })

    if non_public_ips:
        findings.append({
            "severity": "medium",
            "category": "DNS",
            "title": "Adresse IP non publique détectée",
            "description": f"Certaines résolutions pointent vers des IP non publiques : {', '.join(non_public_ips)}",
            "recommendation": "Vérifier que les enregistrements publics n'exposent pas d'adresses privées.",
            "applies_to": ["web", "dns"],
        })

    if not ns["values"]:
        findings.append({
            "severity": "medium",
            "category": "DNS",
            "title": "Serveurs NS non détectés",
            "description": "Aucun serveur de noms n'a été récupéré.",
            "recommendation": "Contrôler la configuration DNS du domaine.",
            "applies_to": ["mail", "web", "dns"],
        })

    if not caa["values"]:
        findings.append({
            "severity": "low",
            "category": "DNS",
            "title": "Enregistrement CAA absent",
            "description": "Aucun enregistrement CAA n'a été détecté.",
            "recommendation": "Ajouter un enregistrement CAA pour restreindre les autorités autorisées à émettre des certificats.",
            "applies_to": ["web", "mail", "dns"],
        })

    if not spf_records:
        findings.append({
            "severity": "high",
            "category": "Messagerie",
            "title": "SPF absent",
            "description": "Aucun enregistrement SPF n'a été détecté dans les TXT du domaine.",
            "recommendation": "Ajouter un enregistrement SPF adapté aux serveurs et prestataires d'envoi autorisés.",
            "applies_to": ["mail"],
        })
    elif len(spf_records) > 1:
        findings.append({
            "severity": "high",
            "category": "Messagerie",
            "title": "Plusieurs SPF détectés",
            "description": "Plusieurs enregistrements SPF ont été détectés, ce qui peut invalider la configuration SPF.",
            "recommendation": "Fusionner les SPF en un seul enregistrement TXT v=spf1.",
            "applies_to": ["mail"],
        })
    else:
        spf = spf_records[0].lower()
        if "+all" in spf:
            findings.append({
                "severity": "high",
                "category": "Messagerie",
                "title": "SPF trop permissif",
                "description": f"SPF détecté : {spf_records[0]}",
                "recommendation": "Éviter +all. Utiliser une politique de fin plus restrictive, par exemple -all ou ~all selon le contexte.",
                "applies_to": ["mail"],
            })
        elif spf.endswith("?all"):
            findings.append({
                "severity": "medium",
                "category": "Messagerie",
                "title": "SPF neutre",
                "description": f"SPF détecté : {spf_records[0]}",
                "recommendation": "Évaluer une politique plus explicite, par exemple ~all ou -all selon le contexte.",
                "applies_to": ["mail"],
            })

    return findings

def audit_mail(domain: str) -> dict:
    mx = query_records(domain, "MX")
    dmarc = query_records(f"_dmarc.{domain}", "TXT")

    dmarc_records = []
    for value in dmarc["values"]:
        cleaned = value.replace('" "', "").replace('"', "").strip()
        if cleaned.lower().startswith("v=dmarc1"):
            dmarc_records.append(cleaned)

    findings = []

    if not mx["values"]:
        findings.append({
            "severity": "info",
            "category": "Messagerie",
            "title": "MX absent",
            "description": "Aucun enregistrement MX n'a été détecté.",
            "recommendation": "À vérifier uniquement si le domaine doit recevoir des emails.",
            "applies_to": ["mail"],
        })

    if not dmarc_records:
        findings.append({
            "severity": "high",
            "category": "Messagerie",
            "title": "DMARC absent",
            "description": "Aucun enregistrement DMARC n'a été détecté.",
            "recommendation": "Publier un enregistrement DMARC, même en p=none dans une première phase d'observation.",
            "applies_to": ["mail"],
        })
    elif len(dmarc_records) > 1:
        findings.append({
            "severity": "high",
            "category": "Messagerie",
            "title": "Plusieurs DMARC détectés",
            "description": "Plusieurs enregistrements DMARC ont été détectés.",
            "recommendation": "Conserver un seul enregistrement DMARC valide.",
            "applies_to": ["mail"],
        })
    else:
        record = dmarc_records[0].lower()
        if "p=none" in record:
            findings.append({
                "severity": "medium",
                "category": "Messagerie",
                "title": "DMARC en mode observation",
                "description": f"DMARC détecté : {dmarc_records[0]}",
                "recommendation": "Après analyse des rapports, envisager une montée progressive vers quarantine puis reject.",
                "applies_to": ["mail"],
            })
        if "pct=" in record and "pct=100" not in record:
            findings.append({
                "severity": "low",
                "category": "Messagerie",
                "title": "DMARC appliqué partiellement",
                "description": f"DMARC détecté : {dmarc_records[0]}",
                "recommendation": "Vérifier si l'application partielle est volontaire. À terme, viser pct=100.",
                "applies_to": ["mail"],
            })
        if "rua=" not in record:
            findings.append({
                "severity": "low",
                "category": "Messagerie",
                "title": "DMARC sans adresse de rapport agrégé",
                "description": "L'enregistrement DMARC ne semble pas contenir de rua=.",
                "recommendation": "Ajouter rua=mailto:... pour recevoir les rapports agrégés DMARC.",
                "applies_to": ["mail"],
            })

    return {
        "domain": domain,
        "mx": mx,
        "dmarc": dmarc,
        "dmarc_records": dmarc_records,
        "findings": findings,
    }
