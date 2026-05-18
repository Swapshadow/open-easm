const runBtn = document.getElementById("runBtn");
const resetBtn = document.getElementById("resetBtn");
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
const clearAllBtn = document.getElementById("clearAllBtn");
const domainInput = document.getElementById("domain");
const termsBox = document.getElementById("termsBox");
const termsAcceptedInput = document.getElementById("termsAcceptedV4.3");
const termsStatus = document.getElementById("termsStatus");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");
const scoreBox = document.getElementById("score");
const levelBox = document.getElementById("level");
const profileBox = document.getElementById("profile");
const summaryBox = document.getElementById("summary");
const findingsBox = document.getElementById("findings");
const reportLink = document.getElementById("reportLink");
const pdfLink = document.getElementById("pdfLink");
const jsonLink = document.getElementById("jsonLink");
const subdomainsBox = document.getElementById("subdomains");
const subCount = document.getElementById("subCount");
const webTargetsBox = document.getElementById("webTargets");
const webTargetCount = document.getElementById("webTargetCount");
const historyBox = document.getElementById("history");
const dashboard = document.getElementById("dashboard");
const ipCount = document.getElementById("ipCount");
const ipInventoryBox = document.getElementById("ipInventory");
const ipInventoryNote = document.getElementById("ipInventoryNote");
const tlsScoreBadge = document.getElementById("tlsScoreBadge");
const tlsAdvancedBox = document.getElementById("tlsAdvanced");
const cveCount = document.getElementById("cveCount");
const passiveCvesBox = document.getElementById("passiveCves");
const ctiBox = document.getElementById("ctiBox");
const patchingBox = document.getElementById("patchingBox");
const comparisonCard = document.getElementById("comparisonCard");
const comparisonBox = document.getElementById("comparison");
const scoreDelta = document.getElementById("scoreDelta");
const startVerificationBtn = document.getElementById("startVerificationBtn");
const checkVerificationBtn = document.getElementById("checkVerificationBtn");
const deleteVerificationBtn = document.getElementById("deleteVerificationBtn");
const verificationBadge = document.getElementById("verificationBadge");
const verificationResult = document.getElementById("verificationResult");
const refreshVerifiedBtn = document.getElementById("refreshVerifiedBtn");
const verifiedDomainsBox = document.getElementById("verifiedDomains");

let termsAccepted = false;

runBtn.addEventListener("click", runAudit);
resetBtn.addEventListener("click", resetAudit);
refreshHistoryBtn.addEventListener("click", loadServerData);
clearAllBtn.addEventListener("click", clearAllAudits);
startVerificationBtn.addEventListener("click", startDomainVerification);
checkVerificationBtn.addEventListener("click", checkDomainVerification);
deleteVerificationBtn.addEventListener("click", deleteDomainVerification);
refreshVerifiedBtn.addEventListener("click", loadVerifiedDomains);

domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && termsAccepted) runAudit();
});

termsAcceptedInput.addEventListener("change", (e) => setTermsAccepted(e.target.checked));
termsBox.addEventListener("click", (e) => {
  if (e.target === termsAcceptedInput) return;
  setTermsAccepted(!termsAccepted);
});
termsBox.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    setTermsAccepted(!termsAccepted);
  }
});

setTermsAccepted(false);
loadServerData();
loadVerifiedDomains();

function setTermsAccepted(value) {
  termsAccepted = Boolean(value);
  termsAcceptedInput.checked = termsAccepted;
  termsBox.setAttribute("aria-pressed", String(termsAccepted));
  termsBox.classList.toggle("accepted", termsAccepted);
  runBtn.disabled = !termsAccepted;

  if (termsAccepted) {
    termsStatus.textContent = "Usage responsable accepté : vous pouvez lancer l’audit.";
    termsStatus.className = "terms-status ok";
  } else {
    termsStatus.textContent = "Usage responsable non accepté : le bouton d’audit est désactivé.";
    termsStatus.className = "terms-status ko";
  }
}

async function runAudit() {
  const domain = domainInput.value.trim();

  errorBox.classList.add("hidden");
  results.classList.add("hidden");

  if (!termsAccepted) {
    errorBox.textContent = "Vous devez accepter l'usage responsable avant de lancer l'audit.";
    errorBox.classList.remove("hidden");
    return;
  }

  loading.classList.remove("hidden");
  runBtn.disabled = true;
  runBtn.textContent = "Audit en cours...";

  try {
    const response = await fetch("/api/audit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Open-EASM-Version": "4.3.0"
      },
      body: JSON.stringify({ domain, accepted_terms: true }),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Erreur lors de l'audit.");

    renderResults(data);
    await loadComparison(data.domain);
    await loadServerData();
    await loadVerifiedDomains();
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  } finally {
    loading.classList.add("hidden");
    runBtn.disabled = !termsAccepted;
    runBtn.textContent = "Lancer l'audit";
  }
}

async function loadServerData() {
  try {
    const [dashRes, auditsRes] = await Promise.all([
      fetch("/api/dashboard"),
      fetch("/api/audits?limit=20")
    ]);
    if (dashRes.ok) renderDashboard(await dashRes.json());
    if (auditsRes.ok) renderHistory(await auditsRes.json());
  } catch {
    dashboard.innerHTML = "";
    historyBox.innerHTML = "<p class='notice'>Historique serveur indisponible.</p>";
  }
}


async function startDomainVerification() {
  const domain = domainInput.value.trim();
  if (!domain) {
    showError("Renseigne d’abord un domaine.");
    return;
  }
  try {
    const res = await fetch("/api/domains/verification/start", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({domain})
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Impossible de démarrer la vérification.");
    renderVerification(data);
    await loadVerifiedDomains();
  } catch (err) {
    showError(err.message);
  }
}

async function checkDomainVerification() {
  const domain = domainInput.value.trim();
  if (!domain) {
    showError("Renseigne d’abord un domaine.");
    return;
  }
  try {
    const res = await fetch(`/api/domains/${encodeURIComponent(domain)}/verification/check`, {method: "POST"});
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Impossible de vérifier le domaine.");
    renderVerification(data);
    await loadVerifiedDomains();
  } catch (err) {
    showError(err.message);
  }
}

async function deleteDomainVerification() {
  const domain = domainInput.value.trim();
  if (!domain) {
    showError("Renseigne d’abord un domaine.");
    return;
  }
  if (!confirm(`Supprimer la vérification DNS pour ${domain} ?`)) return;
  try {
    const res = await fetch(`/api/domains/${encodeURIComponent(domain)}/verification`, {method: "DELETE"});
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Impossible de supprimer la vérification.");
    verificationResult.classList.add("hidden");
    setVerificationBadge({status: "not_started"});
    await loadVerifiedDomains();
  } catch (err) {
    showError(err.message);
  }
}

function renderVerification(data) {
  setVerificationBadge(data);
  verificationResult.classList.remove("hidden");

  verificationResult.innerHTML = `
    <strong>Domaine : ${escapeHtml(data.domain)}</strong>
    <p>Statut : <strong>${escapeHtml(data.status)}</strong></p>
    <p>Ajoute cet enregistrement TXT dans ta zone DNS :</p>
    <code>${escapeHtml(data.verification_name)} TXT "${escapeHtml(data.expected_value)}"</code>
    ${data.verified_at ? `<p>Vérifié le : ${escapeHtml(new Date(data.verified_at).toLocaleString())}</p>` : ""}
    ${data.last_error ? `<p class="notice">Dernière erreur : ${escapeHtml(data.last_error)}</p>` : ""}
  `;
}

function setVerificationBadge(data) {
  const status = data.status || "not_started";
  verificationBadge.className = "pill";
  if (status === "verified") {
    verificationBadge.textContent = "Domaine vérifié";
    verificationBadge.classList.add("verified");
  } else if (status === "pending") {
    verificationBadge.textContent = "En attente DNS";
    verificationBadge.classList.add("pending");
  } else {
    verificationBadge.textContent = "Non démarrée";
    verificationBadge.classList.add("failed");
  }
}

async function loadVerifiedDomains() {
  try {
    const res = await fetch("/api/domains/verified");
    if (!res.ok) return;
    const data = await res.json();
    renderVerifiedDomains(data);
  } catch {
    verifiedDomainsBox.innerHTML = "<p class='notice'>Domaines vérifiés indisponibles.</p>";
  }
}

function renderVerifiedDomains(items) {
  verifiedDomainsBox.innerHTML = "";
  if (!items || items.length === 0) {
    verifiedDomainsBox.innerHTML = "<p class='notice'>Aucun domaine vérifié ou en attente.</p>";
    return;
  }

  for (const item of items) {
    const div = document.createElement("div");
    div.className = "history-item";
    div.innerHTML = `
      <div><strong>${escapeHtml(item.domain)}</strong><br>${escapeHtml(item.verification_name || "")}</div>
      <div>${escapeHtml(item.status)}<br>${item.verified ? "Vérifié" : "Non vérifié"}</div>
      <div>${escapeHtml(item.created_at ? new Date(item.created_at).toLocaleString() : "N/A")}</div>
      <div><button class="secondary small" data-domain="${escapeHtml(item.domain)}">Utiliser</button></div>
    `;
    div.querySelector("button").addEventListener("click", () => {
      domainInput.value = item.domain;
      renderVerification(item);
      window.scrollTo({top: 0, behavior: "smooth"});
    });
    verifiedDomainsBox.appendChild(div);
  }
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}


function renderDashboard(data) {
  dashboard.innerHTML = `
    <div class="kpi"><div class="label">Domaines</div><div class="value">${escapeHtml(data.domain_count || 0)}</div></div>
    <div class="kpi"><div class="label">Audits</div><div class="value">${escapeHtml(data.audit_count || 0)}</div></div>
    <div class="kpi"><div class="label">Score moyen</div><div class="value">${escapeHtml(data.average_latest_score || 0)}</div></div>
    <div class="kpi"><div class="label">IP publiques</div><div class="value">${escapeHtml(data.total_public_ips_latest || 0)}</div></div>
  `;
}

function renderHistory(items) {
  historyBox.innerHTML = "";
  if (!items || items.length === 0) {
    historyBox.innerHTML = "<p class='notice'>Aucun audit serveur enregistré.</p>";
    return;
  }

  for (const item of items) {
    const div = document.createElement("div");
    div.className = "history-item";
    div.innerHTML = `
      <div><strong>${escapeHtml(item.domain)}</strong><br>${escapeHtml(item.profile || "")}</div>
      <div>${escapeHtml(item.score)} / 1000<br>${escapeHtml(item.level)}</div>
      <div>TLS ${escapeHtml(item.tls_score ?? "N/A")} / 100<br>IP ${escapeHtml(item.public_ip_count ?? 0)}</div>
      <div>${escapeHtml(new Date(item.created_at).toLocaleString())}</div>
      <div><button class="danger small" data-audit-id="${escapeHtml(item.id)}">Supprimer</button></div>
    `;
    const btn = div.querySelector("button[data-audit-id]");
    btn.addEventListener("click", () => deleteAudit(item.id));
    historyBox.appendChild(div);
  }
}

async function deleteAudit(auditId) {
  if (!confirm("Supprimer cet audit de l'historique serveur ?")) return;
  try {
    const res = await fetch(`/api/audits/${encodeURIComponent(auditId)}`, { method: "DELETE" });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || "Suppression impossible.");
    }
    await loadServerData();
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  }
}

async function clearAllAudits() {
  if (!confirm("Supprimer TOUS les audits enregistrés dans PostgreSQL ?")) return;
  try {
    const res = await fetch("/api/audits", { method: "DELETE" });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || "Suppression impossible.");
    }
    await loadServerData();
    results.classList.add("hidden");
    comparisonCard.classList.add("hidden");
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  }
}

function renderResults(data) {
  scoreBox.textContent = `${data.score.score} / ${data.score.max_score}`;
  levelBox.textContent = data.score.level;
  profileBox.textContent = data.domain_profile.label;

  summaryBox.innerHTML = "";
  const items = [
    `Domaine : ${data.domain}`,
    `Mode : ${data.mode}`,
    `Vérification domaine : ${data.verification?.status || "not_started"}`,
    `Profil : ${data.domain_profile.label}`,
    `Analyse : ${data.domain_profile.explanation}`,
    `IP publiques domaine racine : ${(data.summary.dns_public_ips || []).join(", ") || "Non détectées"}`,
    `SPF : ${(data.summary.spf_records || []).join(" | ") || "Non détecté"}`,
    `MX : ${(data.summary.mx_records || []).join(" | ") || "Non détecté"}`,
    `DMARC : ${(data.summary.dmarc_records || []).join(" | ") || "Non détecté"}`,
    `Service web détecté : ${data.summary.has_web ? "oui" : "non"}`,
    `Cibles web joignables : ${(data.summary.reachable_web_targets || []).join(", ") || "Aucune"}`,
    `Sous-domaines publics : ${data.summary.subdomain_count || 0}`,
    `IP publiques inventoriées : ${data.summary.public_ip_count || 0}`,
    `IP cœur exposition : ${data.summary.core_public_ip_count || 0}`,
    `IP prestataires tiers : ${data.summary.third_party_provider_ip_count || 0}`,
    `Score TLS/SSL : ${data.summary.tls_score ?? "N/A"} / 100 (${data.summary.tls_level || "N/A"})`,
    `CVE potentielles passives : ${data.summary.passive_cve_count || 0}`,
  ];

  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    summaryBox.appendChild(li);
  }

  renderWebTargets(data.web_targets || []);
  renderIpInventory(data.ip_inventory || {});
  renderTlsAdvanced(data.tls_score || {});
  renderPassiveCves(data.passive_cves || {});
  renderCti(data.cti || {});
  renderPatching(data.patching_sla || {});
  renderSubdomains(data.subdomains || {});
  renderFindings(data.findings || []);

  reportLink.href = data.report_url;
  pdfLink.href = data.pdf_url;
  jsonLink.href = data.json_url;
  results.classList.remove("hidden");
}

async function loadComparison(domain) {
  try {
    const res = await fetch(`/api/domains/${encodeURIComponent(domain)}/compare/latest`);
    if (!res.ok) return;
    const data = await res.json();
    if (!data.available) {
      comparisonCard.classList.add("hidden");
      return;
    }
    comparisonCard.classList.remove("hidden");
    const delta = data.score_delta || 0;
    scoreDelta.textContent = `${delta >= 0 ? "+" : ""}${delta} pts`;
    comparisonBox.innerHTML = `
      <div class="target"><strong>Évolution du score</strong><span>Précédent : ${escapeHtml(data.previous.score)} / Actuel : ${escapeHtml(data.current.score)}</span></div>
      <div class="target"><strong>Nouveaux constats</strong><span>${escapeHtml((data.new_findings || []).length)}</span></div>
      <div class="target"><strong>Constats corrigés/disparus</strong><span>${escapeHtml((data.fixed_findings || []).length)}</span></div>
      <div class="target"><strong>IP nouvelles</strong><span>${escapeHtml((data.new_ips || []).join(", ") || "Aucune")}</span></div>
      <div class="target"><strong>IP disparues</strong><span>${escapeHtml((data.removed_ips || []).join(", ") || "Aucune")}</span></div>
    `;
  } catch {
    comparisonCard.classList.add("hidden");
  }
}

function renderWebTargets(targets) {
  webTargetsBox.innerHTML = "";
  webTargetCount.textContent = `${targets.length} cible(s)`;
  if (targets.length === 0) {
    webTargetsBox.innerHTML = "<p class='notice'>Aucune cible web testée.</p>";
    return;
  }
  for (const t of targets) {
    const div = document.createElement("div");
    div.className = "target";
    div.innerHTML = `
      <strong>${escapeHtml(t.hostname)}</strong>
      <span>Joignable : ${t.reachable ? "oui" : "non"} | Schéma : ${escapeHtml(t.best_scheme || "N/A")}</span>
      <span>IP publiques : ${(t.public_ips || []).map(escapeHtml).join(", ") || "Non détectées"}</span>
      <span>IP bloquées : ${(t.blocked_ips || []).map(escapeHtml).join(", ") || "Aucune"}</span>
      <span>HTTP : ${escapeHtml(t.http_status ?? "N/A")} | HTTPS : ${escapeHtml(t.https_status ?? "N/A")}</span>
      <span>URL finale HTTPS : ${escapeHtml(t.https_final_url || "N/A")}</span>
    `;
    webTargetsBox.appendChild(div);
  }
}

function renderIpInventory(inventory) {
  const ips = inventory.unique_ips || [];
  ipCount.textContent = `${inventory.core_public_ip_count || 0} IP cœur / ${inventory.total_ip_count || inventory.public_ip_count || 0} total`;
  ipInventoryBox.innerHTML = "";
  ipInventoryNote.textContent = `Affichage prioritaire : IP cœur exposition, IP non publiques et échantillon support/prestataires. Prestataires tiers détectés : ${inventory.third_party_provider_ip_count || 0}.`;

  if (ips.length === 0) {
    ipInventoryBox.innerHTML = "<p class='notice'>Aucune IP inventoriée.</p>";
    return;
  }

  const scopeLabels = {
    core_exposure: "Exposition principale",
    third_party_provider: "Prestataire tiers",
    supporting_exposure: "Support",
    non_public: "Non publique"
  };

  for (const item of ips) {
    const div = document.createElement("div");
    div.className = "target";
    div.innerHTML = `
      <strong>${escapeHtml(item.ip)} — ${escapeHtml(scopeLabels[item.scope] || item.scope || "N/A")}</strong>
      <span>Sources : ${(item.sources || []).map(escapeHtml).join(", ") || "N/A"}</span>
      <span>Hostnames : ${(item.hostnames || []).map(escapeHtml).join(", ") || "N/A"}</span>
      <span>Résolution/CNAME : ${(item.resolved_names || []).map(escapeHtml).join(", ") || "N/A"}</span>
    `;
    ipInventoryBox.appendChild(div);
  }
}

function renderTlsAdvanced(tls) {
  tlsScoreBadge.textContent = `${tls.global_score ?? "-"} / 100`;
  tlsAdvancedBox.innerHTML = "";
  const targets = tls.targets || [];
  if (targets.length === 0) {
    tlsAdvancedBox.innerHTML = "<p class='notice'>Aucun contrôle TLS avancé disponible.</p>";
    return;
  }
  for (const t of targets) {
    const div = document.createElement("div");
    div.className = "target";
    div.innerHTML = `
      <strong>${escapeHtml(t.hostname)} — ${escapeHtml(t.score)} / 100 (${escapeHtml(t.level)})</strong>
      <span>TLS : ${escapeHtml(t.tls_version || "N/A")} | Expiration : ${escapeHtml(t.days_remaining ?? "N/A")} jours</span>
      <span>Contrôles : ${(t.checks || []).map(escapeHtml).join(" ; ") || "N/A"}</span>
    `;
    tlsAdvancedBox.appendChild(div);
  }
}

function renderPassiveCves(cves) {
  const items = cves.items || [];
  cveCount.textContent = `${cves.count || 0} détectée(s)`;
  passiveCvesBox.innerHTML = "";
  if (items.length === 0) {
    passiveCvesBox.innerHTML = "<p class='notice'>Aucune CVE passive détectée via headers HTTP. Cela ne remplace pas un scan de vulnérabilités autorisé.</p>";
    return;
  }
  for (const item of items) {
    const div = document.createElement("div");
    div.className = "target";
    div.innerHTML = `
      <strong>${escapeHtml(item.hostname)} — ${escapeHtml(item.cve || item.technology || "Risque passif")}</strong>
      <span>Sévérité : ${escapeHtml(item.severity)} | Confiance : ${escapeHtml(item.confidence)}</span>
      <span>${escapeHtml(item.description || "")}</span>
      <span>Preuve : ${escapeHtml(item.evidence || "")}</span>
    `;
    passiveCvesBox.appendChild(div);
  }
}

function renderCti(cti) {
  ctiBox.innerHTML = "";

  const summary = cti.summary || {};
  const summaryDiv = document.createElement("div");
  summaryDiv.className = "target";
  summaryDiv.innerHTML = `
    <strong>Résumé CTI DNSBL</strong>
    <span>Vérifiées : ${escapeHtml(summary.checked ?? 0)} | Listées : ${escapeHtml(summary.listed ?? 0)} | Non listées : ${escapeHtml(summary.not_listed ?? 0)} | Erreurs : ${escapeHtml(summary.errors ?? 0)}</span>
    <span>IP prestataires tiers masquées du détail : ${escapeHtml(summary.skipped_third_party_provider_ips ?? 0)}</span>
  `;
  ctiBox.appendChild(summaryDiv);

  const ipRep = cti.ip_reputation || [];
  if (ipRep.length === 0) {
    const empty = document.createElement("div");
    empty.className = "target";
    empty.innerHTML = "<strong>Aucun signal CTI notable</strong><span>Aucune IP listée dans les DNSBL testées ou uniquement des résultats non critiques.</span>";
    ctiBox.appendChild(empty);
  } else {
    for (const ip of ipRep) {
      const statuses = (ip.checks || []).map(c => `${c.zone}: ${c.status}`).join(" ; ");
      const div = document.createElement("div");
      div.className = "target";
      div.innerHTML = `<strong>${escapeHtml(ip.ip)} — ${escapeHtml(ip.scope || "N/A")}</strong><span>${escapeHtml(statuses || "Aucun résultat")}</span><span>Hostnames : ${(ip.hostnames || []).map(escapeHtml).join(", ")}</span>`;
      ctiBox.appendChild(div);
    }
  }

  const leak = cti.leak_monitoring || {};
  const div = document.createElement("div");
  div.className = "target";
  div.innerHTML = `<strong>Fuites d’identifiants</strong><span>${escapeHtml(leak.status || "non exécuté")} — ${escapeHtml(leak.reason || "Réservé à un mode domaine vérifié.")}</span>`;
  ctiBox.appendChild(div);
}

function renderPatching(patching) {
  patchingBox.innerHTML = "";
  const policy = patching.sla_policy || {};
  const items = patching.items || [];
  const summary = document.createElement("div");
  summary.className = "target";
  summary.innerHTML = `
    <strong>Politique SLA cible</strong>
    <span>Critique : ${escapeHtml(policy.critical || "N/A")} | Élevé : ${escapeHtml(policy.high || "N/A")} | Moyen : ${escapeHtml(policy.medium || "N/A")} | Faible : ${escapeHtml(policy.low || "N/A")}</span>
    <span>${escapeHtml(patching.note || "")}</span>
  `;
  patchingBox.appendChild(summary);
  for (const item of items.slice(0, 8)) {
    const div = document.createElement("div");
    div.className = "target";
    div.innerHTML = `
      <strong>${escapeHtml(item.severity)} — ${escapeHtml(item.title || "")}</strong>
      <span>SLA : ${escapeHtml(item.sla_days ?? "info")} jour(s) | Échéance : ${escapeHtml(item.due_at || "N/A")}</span>
    `;
    patchingBox.appendChild(div);
  }
}

function renderSubdomains(sub) {
  const list = sub.subdomains || [];
  subCount.textContent = `${sub.count || 0} détecté(s)`;
  subdomainsBox.innerHTML = "";
  if (sub.error) {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = `Source indisponible : ${sub.error}`;
    subdomainsBox.appendChild(span);
    return;
  }
  if (list.length === 0) {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = "Aucun sous-domaine affiché";
    subdomainsBox.appendChild(span);
    return;
  }
  for (const name of list) {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = name;
    subdomainsBox.appendChild(span);
  }
}

function renderFindings(findings) {
  findingsBox.innerHTML = "";
  if (!findings || findings.length === 0) {
    findingsBox.innerHTML = "<p>Aucun constat notable sur les contrôles V4.3.</p>";
    return;
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
  for (const f of findings) {
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML = `
      <span class="sev ${escapeHtml(f.severity || "info")}">${escapeHtml(f.severity || "info")}</span>
      <h3>${escapeHtml(f.title || "")}</h3>
      <p><strong>Catégorie :</strong> ${escapeHtml(f.category || "N/A")}</p>
      <p>${escapeHtml(f.description || "")}</p>
      <p><strong>Recommandation :</strong> ${escapeHtml(f.recommendation || "")}</p>
    `;
    findingsBox.appendChild(div);
  }
}

function resetAudit() {
  domainInput.value = "";
  errorBox.classList.add("hidden");
  results.classList.add("hidden");
  loading.classList.add("hidden");
  comparisonCard.classList.add("hidden");
  domainInput.focus();
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (m) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
  }[m]));
}
