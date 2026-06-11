from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any

from app.services.network_guard import resolve_ips

TOP_PORTS = os.getenv("OPENEASM_NMAP_TOP_PORTS", "1000")
HOST_TIMEOUT = os.getenv("OPENEASM_NMAP_HOST_TIMEOUT", "120s")
PROCESS_TIMEOUT = int(os.getenv("OPENEASM_NMAP_PROCESS_TIMEOUT", "300"))
SCAN_ALL_SUBDOMAINS = os.getenv("OPENEASM_SCAN_ALL_SUBDOMAINS", "true").lower() in {"1", "true", "yes", "on"}
MAX_TARGETS = int(os.getenv("OPENEASM_MAX_SERVICE_TARGETS", "150"))


def _version_tuple(value: str | None) -> tuple[int, ...]:
    if not value:
        return tuple()
    nums = re.findall(r"\d+", value)
    return tuple(int(n) for n in nums[:4])


def _version_eq(version: str | None, expected: str) -> bool:
    return _version_tuple(version) == _version_tuple(expected)


def _version_between(version: str | None, low: str, high: str) -> bool:
    current = _version_tuple(version)
    if not current:
        return False
    return _version_tuple(low) <= current <= _version_tuple(high)


def _rule(cve: str, technology: str, severity: str, cvss: float, confidence: str, description: str, recommendation: str) -> dict:
    return {
        "cve": cve,
        "technology": technology,
        "severity": severity,
        "cvss": cvss,
        "confidence": confidence,
        "description": description,
        "recommendation": recommendation,
    }


def correlate_service_cves(service: dict[str, Any]) -> list[dict[str, Any]]:
    """Conservative local CVE correlation from Nmap service/version output.

    No NSE exploit or vulnerability script is executed here. The mapping is intentionally
    small and exact/near-exact to avoid pretending to be a full vulnerability scanner.
    """
    product = str(service.get("product") or "")
    version = str(service.get("version") or "")
    name = str(service.get("name") or "")
    cpes = " ".join(service.get("cpe", []) or [])
    haystack = f"{name} {product} {version} {cpes}".lower()
    matches: list[dict[str, Any]] = []

    if "apache" in haystack and ("httpd" in haystack or "apache http" in haystack or name in {"http", "https"}):
        if _version_eq(version, "2.4.49"):
            matches.append(_rule("CVE-2021-41773", "Apache HTTP Server 2.4.49", "critical", 9.8, "élevée", "Apache HTTP Server 2.4.49 est associé à une traversée de chemin et, selon la configuration, une exécution de code distante.", "Mettre à jour Apache HTTP Server vers une version corrigée et vérifier la configuration des Alias/Require."))
        if _version_eq(version, "2.4.50"):
            matches.append(_rule("CVE-2021-42013", "Apache HTTP Server 2.4.50", "critical", 9.8, "élevée", "Apache HTTP Server 2.4.50 est associé à une traversée de chemin et, selon la configuration, une exécution de code distante.", "Mettre à jour Apache HTTP Server vers une version corrigée et vérifier la configuration des Alias/Require."))

    if "openssh" in haystack:
        if _version_between(version, "8.5", "9.7"):
            matches.append(_rule("CVE-2024-6387", "OpenSSH portable 8.5p1 à 9.7p1", "high", 8.1, "moyenne", "La version OpenSSH détectée peut correspondre à la plage concernée par regreSSHion sur certains systèmes Linux glibc. La condition exacte dépend du paquet et de la distribution.", "Confirmer la version paquet côté serveur et appliquer les correctifs OpenSSH/distribution."))
        if _version_between(version, "7.2", "7.7"):
            matches.append(_rule("CVE-2018-15473", "OpenSSH 7.2 à 7.7", "medium", 5.3, "moyenne", "Certaines versions OpenSSH 7.2 à 7.7 sont associées à une énumération d’utilisateurs.", "Mettre à jour OpenSSH et vérifier la configuration d’authentification SSH."))

    if "vsftpd" in haystack and _version_eq(version, "2.3.4"):
        matches.append(_rule("CVE-2011-2523", "vsftpd 2.3.4", "critical", 10.0, "élevée", "vsftpd 2.3.4 est connu pour une version backdoorée compromise.", "Retirer immédiatement cette version, reconstruire le serveur depuis une source saine et investiguer une compromission potentielle."))

    if "nginx" in haystack and _version_between(version, "1.3.13", "1.4.0"):
        matches.append(_rule("CVE-2013-2028", "nginx 1.3.13 à 1.4.0", "high", 7.5, "moyenne", "Certaines versions nginx 1.3.13 à 1.4.0 sont associées à une vulnérabilité de traitement chunked pouvant provoquer une exécution de code selon les conditions.", "Mettre à jour nginx vers une version maintenue par l’éditeur ou la distribution."))

    if ("openssl" in haystack or "ssl" in name.lower()) and re.search(r"\b1\.0\.1[a-f]?\b", version):
        matches.append(_rule("CVE-2014-0160", "OpenSSL 1.0.1 à 1.0.1f", "high", 7.5, "moyenne", "La version OpenSSL détectée peut correspondre à la plage Heartbleed. La confirmation dépend de la version exacte du paquet.", "Mettre à jour OpenSSL et renouveler les certificats/clefs si une exposition passée est confirmée."))

    if "microsoft-iis" in haystack or "microsoft iis" in haystack:
        if _version_eq(version, "6.0"):
            matches.append(_rule("CVE-2017-7269", "Microsoft IIS 6.0", "critical", 9.8, "moyenne", "IIS 6.0 avec WebDAV est associé à une vulnérabilité d’exécution de code distante. La présence de WebDAV doit être confirmée.", "Migrer vers une version supportée de Windows Server/IIS et désactiver WebDAV si non nécessaire."))

    if "apache tomcat" in haystack and _version_between(version, "9.0.0", "9.0.30"):
        matches.append(_rule("CVE-2020-1938", "Apache Tomcat 9.0.0 à 9.0.30", "high", 9.8, "faible", "La version Tomcat peut correspondre à la plage Ghostcat. L’exposition du connecteur AJP doit être confirmée.", "Mettre à jour Tomcat et désactiver ou restreindre le connecteur AJP."))

    for match in matches:
        match.update({
            "host": service.get("hostname"),
            "hostname": service.get("hostname"),
            "port": service.get("port"),
            "protocol": service.get("protocol"),
            "service": service.get("name"),
            "product": service.get("product"),
            "version": service.get("version"),
            "evidence": service.get("evidence"),
        })
    return matches


def _parse_nmap_xml(xml_text: str, hostname: str) -> tuple[list[dict[str, Any]], list[str]]:
    ports: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return [], [f"XML Nmap invalide : {exc}"]

    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            svc = port.find("service")
            svc_attrs = svc.attrib if svc is not None else {}
            cpes = [cpe.text.strip() for cpe in (svc.findall("cpe") if svc is not None else []) if cpe.text]
            product = svc_attrs.get("product") or ""
            version = svc_attrs.get("version") or ""
            service_name = svc_attrs.get("name") or "unknown"
            port_id = int(port.attrib.get("portid", "0"))
            entry = {
                "hostname": hostname,
                "port": port_id,
                "protocol": port.attrib.get("protocol", "tcp"),
                "state": "open",
                "name": service_name,
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": svc_attrs.get("extrainfo"),
                "ostype": svc_attrs.get("ostype"),
                "tunnel": svc_attrs.get("tunnel"),
                "method": svc_attrs.get("method"),
                "confidence": svc_attrs.get("conf"),
                "cpe": cpes,
                "cpes": cpes,
                "evidence": f"{hostname}:{port_id}/{port.attrib.get('protocol', 'tcp')} {service_name} {product} {version}".strip(),
            }
            entry["cves"] = correlate_service_cves(entry)
            ports.append(entry)
    return ports, errors


def _target_candidates(domain: str, ip_inventory: dict | None) -> list[str]:
    candidates: list[str] = [domain, f"www.{domain}"]
    inv = ip_inventory or {}
    source_items = inv.get("unique_ips", []) if SCAN_ALL_SUBDOMAINS else inv.get("core_public_ips", [])
    for item in source_items:
        if not isinstance(item, dict) or item.get("is_public") is False or item.get("scope") == "non_public":
            continue
        for host in item.get("hostnames", []) or []:
            if host and (host == domain or str(host).endswith("." + domain)):
                candidates.append(str(host).strip(".").lower())
    return sorted(dict.fromkeys(candidates))[:MAX_TARGETS]


def audit_service_versions(domain: str, ip_inventory: dict | None = None) -> dict[str, Any]:
    started = time.monotonic()
    nmap_path = shutil.which("nmap")
    result: dict[str, Any] = {
        "enabled": bool(nmap_path),
        "mode": "beta_26_6_all_public_subdomains_service_version_no_exploit",
        "tool": "nmap",
        "command_policy": f"-sS -sV --version-all --reason -Pn --max-retries 2 --host-timeout {HOST_TIMEOUT} --open --top-ports {TOP_PORTS or 'default'} -oX -",
        "scan_all_subdomains": SCAN_ALL_SUBDOMAINS,
        "max_targets": MAX_TARGETS,
        "targets": [],
        "open_ports": [],
        "cves": [],
        "findings": [],
        "count_open_ports": 0,
        "count_cves": 0,
        "elapsed_seconds": 0,
        "note": "Beta 26.6 : détection service/version sur les sous-domaines publics inventoriés. Scan SYN (-sS), fallback TCP connect (-sT) si nécessaire. Aucun exploit, bruteforce, DoS ou script NSE intrusif.",
    }

    if not nmap_path:
        result["note"] = "Nmap n'est pas installé dans le conteneur. Installez le paquet nmap ou reconstruisez l'image Docker."
        result["findings"].append({
            "severity": "info",
            "category": "Nmap service/version",
            "title": "Nmap non disponible",
            "description": "Le contrôle service/version/port n'a pas été exécuté car le binaire nmap est absent.",
            "recommendation": "Installer nmap dans l'image backend pour activer la détection CVE non exploitante.",
            "applies_to": ["surface", "cve"],
            "location": {"control": "nmap", "display": "backend"},
        })
        return result

    for hostname in _target_candidates(domain, ip_inventory):
        target = {"hostname": hostname, "status": "pending", "guard": None, "command": None, "open_ports": [], "cves": [], "error": None, "elapsed_seconds": 0}
        result["targets"].append(target)

        guard = resolve_ips(hostname)
        target["guard"] = guard
        if not guard.get("safe_for_outbound_checks"):
            target["status"] = "blocked_by_guard"
            target["error"] = "Résolution non publique ou mixte ; scan Nmap bloqué."
            continue

        cmd = [nmap_path, "-sS", "-sV", "--version-all", "--reason", "-Pn", "--max-retries", "2", "--host-timeout", HOST_TIMEOUT, "--open", "-oX", "-", hostname]
        if TOP_PORTS:
            cmd[-1:-1] = ["--top-ports", str(TOP_PORTS)]
        target["command"] = " ".join(cmd[1:])
        t0 = time.monotonic()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=PROCESS_TIMEOUT, check=False)
            target["elapsed_seconds"] = round(time.monotonic() - t0, 2)
            stderr = proc.stderr or ""
            stdout = proc.stdout or ""
            raw_socket_error = any(needle in stderr.lower() for needle in ["requires root privileges", "you requested a scan type which requires root privileges", "operation not permitted", "raw socket"])
            if raw_socket_error:
                fallback_cmd = cmd.copy()
                fallback_cmd[fallback_cmd.index("-sS")] = "-sT"
                target["command"] = " ".join(fallback_cmd[1:])
                target["fallback"] = "-sT"
                proc = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=PROCESS_TIMEOUT, check=False)
                target["elapsed_seconds"] = round(time.monotonic() - t0, 2)
                stderr = proc.stderr or ""
                stdout = proc.stdout or ""

            if proc.returncode not in (0, 1):
                target["status"] = "error"
                target["error"] = (stderr or stdout or "Erreur Nmap inconnue")[-1500:]
                continue

            ports, parse_errors = _parse_nmap_xml(stdout, hostname)
            target["open_ports"] = ports
            cves = [cve for p in ports for cve in p.get("cves", [])]
            target["cves"] = cves
            target["status"] = "ok"
            target["stderr_tail"] = stderr[-800:] if stderr else None
            if parse_errors:
                target["error"] = " | ".join(parse_errors)
            result["open_ports"].extend(ports)
            result["cves"].extend(cves)
        except subprocess.TimeoutExpired:
            target["elapsed_seconds"] = round(time.monotonic() - t0, 2)
            target["status"] = "timeout"
            target["error"] = f"Timeout Nmap après {PROCESS_TIMEOUT} secondes. Augmenter OPENEASM_NMAP_HOST_TIMEOUT/PROCESS_TIMEOUT ou réduire les cibles."
        except Exception as exc:
            target["elapsed_seconds"] = round(time.monotonic() - t0, 2)
            target["status"] = "error"
            target["error"] = str(exc)

    dedup = {}
    for cve in result["cves"]:
        key = f"{cve.get('hostname')}:{cve.get('port')}:{cve.get('cve')}"
        dedup[key] = cve
    result["cves"] = list(dedup.values())
    result["count_open_ports"] = len(result["open_ports"])
    result["count_cves"] = len(result["cves"])

    for cve in result["cves"]:
        result["findings"].append({
            "severity": cve.get("severity", "medium"),
            "category": "CVE Nmap service/version",
            "title": f"{cve.get('cve')} potentielle sur {cve.get('service')} {cve.get('version') or ''}".strip(),
            "description": f"Corrélation non exploitante depuis Nmap -sV : {cve.get('description')} Preuve observée : {cve.get('evidence')}",
            "recommendation": cve.get("recommendation") or "Confirmer la version côté serveur puis appliquer les correctifs éditeur.",
            "applies_to": ["surface", "cve"],
            "location": {"hostname": cve.get("hostname"), "control": "nmap -sV", "display": f"{cve.get('hostname')}:{cve.get('port')}/{cve.get('protocol')}"},
        })

    result["elapsed_seconds"] = round(time.monotonic() - started, 2)
    return result
