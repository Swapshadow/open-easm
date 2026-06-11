from __future__ import annotations

import dns.resolver
import ipaddress
from collections import defaultdict
from app.validators import is_public_ip

TIMEOUT = 3.5

RESOLVERS = [
    None,
    ["1.1.1.1", "1.0.0.1"],
    ["8.8.8.8", "8.8.4.4"],
    ["9.9.9.9", "149.112.112.112"],
]

THIRD_PARTY_HINTS = [
    "outlook.com", "office365.com", "protection.outlook.com", "microsoft.com",
    "mailinblack.com", "sitec.fr", "akamai", "cloudflare", "googlehosted",
]


def _resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=(nameservers is None))
    if nameservers:
        r.nameservers = nameservers
    r.lifetime = TIMEOUT
    r.timeout = TIMEOUT
    return r


def _query(hostname: str, rtype: str) -> tuple[list[str], list[str]]:
    values = []
    errors = []
    for ns in RESOLVERS:
        try:
            answers = _resolver(ns).resolve(hostname, rtype)
            values.extend([str(a).strip().strip(".") for a in answers])
            if values:
                break
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            errors.append("NXDOMAIN")
            break
        except Exception as exc:
            errors.append(str(exc))
    return sorted(set(values)), sorted(set(errors))


def _resolve_any(hostname: str) -> dict:
    all_errors = []
    cname_chain = []
    current = hostname.strip(".").lower()

    for _ in range(5):
        cnames, errors = _query(current, "CNAME")
        all_errors.extend(errors)
        if not cnames:
            break
        nxt = cnames[0].strip(".").lower()
        cname_chain.append(nxt)
        if nxt == current:
            break
        current = nxt

    a, e1 = _query(current, "A")
    aaaa, e2 = _query(current, "AAAA")
    all_errors.extend(e1)
    all_errors.extend(e2)

    ips = sorted(set(a + aaaa))
    return {
        "hostname": hostname,
        "resolved_name": current,
        "cname_chain": cname_chain,
        "ips": ips,
        "public_ips": [ip for ip in ips if is_public_ip(ip)],
        "blocked_ips": [ip for ip in ips if not is_public_ip(ip)],
        "errors": sorted(set(all_errors)),
    }


def _mx_hosts(mail_result: dict) -> list[str]:
    hosts = []
    for value in mail_result.get("mx", {}).get("values", []):
        parts = value.split()
        if len(parts) >= 2:
            hosts.append(parts[-1].strip(".").lower())
    return hosts


def _ns_hosts(dns_result: dict) -> list[str]:
    return [x.strip(".").lower() for x in dns_result.get("records", {}).get("NS", {}).get("values", [])]


def _is_third_party(hostname: str, resolved_name: str, sources: set[str]) -> bool:
    h = f"{hostname} {resolved_name}".lower()
    if "mx" in sources or "ns" in sources:
        return True
    if hostname.startswith(("autodiscover.", "mail.", "smtp.", "imap.", "pop.", "webmail.")):
        return True
    return any(hint in h for hint in THIRD_PARTY_HINTS)


def _scope_for(hostnames: set[str], resolved_names: set[str], sources: set[str], is_public: bool) -> str:
    if not is_public:
        return "non_public"
    if "root" in sources or "www" in sources or "web_target" in sources:
        return "core_exposure"
    sample_host = next(iter(hostnames), "")
    sample_resolved = next(iter(resolved_names), "")
    if _is_third_party(sample_host, sample_resolved, sources):
        return "third_party_provider"
    return "supporting_exposure"


def _cymru_qname(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = address.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def _asn_enrichment(ip: str) -> dict:
    """Passive ASN/provider enrichment via Team Cymru DNS.

    This is DNS-only, fast, and does not require an API key. It gives OpenEASM a
    DNSDumpster-like view: ASN, prefix/network, country and AS name/hoster.
    """
    if not is_public_ip(ip):
        return {}
    try:
        answers = _resolver(["1.1.1.1", "1.0.0.1"]).resolve(_cymru_qname(ip), "TXT")
        raw = " ".join(str(a).strip('"') for a in answers)
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) >= 5 and parts[0].lower() != "as":
            asn_name = parts[5] if len(parts) > 5 else ""
            return {
                "asn": f"AS{parts[0]}",
                "network": parts[1] if len(parts) > 1 else "",
                "country": parts[2] if len(parts) > 2 else "",
                "registry": parts[3] if len(parts) > 3 else "",
                "allocated": parts[4] if len(parts) > 4 else "",
                "asn_name": asn_name,
                "provider": asn_name,
                "geo_source": "Team Cymru DNS",
            }
    except Exception as exc:
        return {"geo_source": "Team Cymru DNS", "geo_error": str(exc)}
    return {"geo_source": "Team Cymru DNS"}


def build_ip_inventory(domain: str, dns_result: dict, mail_result: dict, web_result: dict, subdomains_result: dict, max_subdomains: int = 500) -> dict:
    hosts_by_source = defaultdict(set)

    hosts_by_source["root"].add(domain)
    hosts_by_source["www"].add(f"www.{domain}")

    for host in _mx_hosts(mail_result):
        hosts_by_source["mx"].add(host)

    for host in _ns_hosts(dns_result):
        hosts_by_source["ns"].add(host)

    for target in web_result.get("targets", []):
        host = target.get("hostname")
        if host:
            hosts_by_source["web_target"].add(host)

    for sub in subdomains_result.get("subdomains", [])[:max_subdomains]:
        hosts_by_source["subdomain"].add(sub)

    entries = []
    ip_to_hosts = defaultdict(lambda: {"sources": set(), "hostnames": set(), "is_public": True, "resolved_names": set()})

    for source, hosts in hosts_by_source.items():
        for host in sorted(hosts):
            resolved = _resolve_any(host)
            entry = {
                "source": source,
                "hostname": host,
                "resolved_name": resolved["resolved_name"],
                "cname_chain": resolved["cname_chain"],
                "ips": resolved["ips"],
                "public_ips": resolved["public_ips"],
                "blocked_ips": resolved["blocked_ips"],
                "errors": resolved["errors"],
            }
            entries.append(entry)

            for ip in resolved["ips"]:
                ip_to_hosts[ip]["sources"].add(source)
                ip_to_hosts[ip]["hostnames"].add(host)
                ip_to_hosts[ip]["resolved_names"].add(resolved["resolved_name"])
                if not is_public_ip(ip):
                    ip_to_hosts[ip]["is_public"] = False

    unique_ips = []
    for ip, data in sorted(ip_to_hosts.items()):
        scope = _scope_for(data["hostnames"], data["resolved_names"], data["sources"], data["is_public"])
        enrichment = _asn_enrichment(ip) if data["is_public"] else {}
        unique_ips.append({
            "ip": ip,
            "is_public": data["is_public"],
            "scope": scope,
            "sources": sorted(data["sources"]),
            "hostnames": sorted(data["hostnames"]),
            "resolved_names": sorted(data["resolved_names"]),
            **enrichment,
        })

    findings = []
    blocked = [ip for ip in unique_ips if not ip["is_public"]]
    if blocked:
        findings.append({
            "severity": "medium",
            "category": "Inventaire IP",
            "title": "IP non publique détectée dans l'inventaire",
            "description": "Une ou plusieurs résolutions DNS pointent vers des IP non publiques : " + ", ".join(i["ip"] for i in blocked),
            "recommendation": "Vérifier que la zone DNS publique n'expose pas d'adresses privées, réservées ou internes.",
            "applies_to": ["dns", "web"],
        })

    core = [i for i in unique_ips if i["scope"] == "core_exposure"]
    non_public = [i for i in unique_ips if i["scope"] == "non_public"]
    third_party = [i for i in unique_ips if i["scope"] == "third_party_provider"]
    supporting = [i for i in unique_ips if i["scope"] == "supporting_exposure"]

    location_counts = defaultdict(int)
    hosting_networks = defaultdict(int)
    for item in unique_ips:
        if not item.get("is_public"):
            continue
        if item.get("country"):
            location_counts[item["country"]] += 1
        label = " / ".join([x for x in [item.get("asn"), item.get("asn_name"), item.get("network")] if x])
        if label:
            hosting_networks[label] += 1

    return {
        "domain": domain,
        "entries": entries,
        "unique_ips": unique_ips,
        "display_ips": core + non_public + supporting[:80] + third_party[:80],
        "core_public_ips": core,
        "third_party_provider_ips": third_party,
        "supporting_ips": supporting,
        "non_public_ips": non_public,
        "public_ip_count": len([i for i in unique_ips if i["is_public"]]),
        "core_public_ip_count": len(core),
        "third_party_provider_ip_count": len(third_party),
        "total_ip_count": len(unique_ips),
        "location_counts": dict(sorted(location_counts.items())),
        "hosting_networks": dict(sorted(hosting_networks.items(), key=lambda kv: kv[1], reverse=True)),
        "findings": findings,
        "note": "Inventaire Beta 26.6 construit avec résolution DNS multi-résolveurs, CNAME, domaine racine, www, MX, NS, cibles web et sous-domaines. Les IP publiques sont enrichies en ASN, pays, réseau et hébergeur via Team Cymru DNS.",
    }
