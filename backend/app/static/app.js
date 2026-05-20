
// -----------------------------------------------------------------------------
// OpenEASM V7.5 visual layer: Matrix 0/1 + premium meteors
// -----------------------------------------------------------------------------
(function(){
  function initMatrixRain(){
    const canvas=document.getElementById('matrixCanvas');
    if(!canvas||window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
    const ctx=canvas.getContext('2d'); let w=0,h=0,cols=0,drops=[]; const fs=15, chars=['0','1'];
    function resize(){const r=Math.min(window.devicePixelRatio||1,2);w=innerWidth;h=innerHeight;canvas.width=Math.floor(w*r);canvas.height=Math.floor(h*r);canvas.style.width=w+'px';canvas.style.height=h+'px';ctx.setTransform(r,0,0,r,0,0);cols=Math.floor(w/fs);drops=Array.from({length:cols},()=>Math.random()*-h);}
    function draw(){ctx.fillStyle='rgba(3,0,0,.085)';ctx.fillRect(0,0,w,h);ctx.font=fs+'px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';for(let i=0;i<drops.length;i++){const ch=chars[(Math.random()*2)|0];const x=i*fs,y=drops[i]*fs;ctx.fillStyle=Math.random()>.965?'rgba(255,226,154,.82)':'rgba(255,29,46,.34)';ctx.fillText(ch,x,y);if(y>h+Math.random()*1000)drops[i]=Math.random()*-40;drops[i]+=0.45+Math.random()*0.55;}requestAnimationFrame(draw)}
    addEventListener('resize',resize,{passive:true});resize();draw();
  }
  function initMeteors(){
    const layer=document.getElementById('meteorLayer');
    if(!layer||window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
    function spawn(){const m=document.createElement('span');m.className='meteor';const x=Math.random()*innerWidth+innerWidth*.15,y=Math.random()*innerHeight*.42-80,d=1.9+Math.random()*2.8,tail=90+Math.random()*170;m.style.left=x+'px';m.style.top=y+'px';m.style.setProperty('--duration',d+'s');m.style.setProperty('--tail',tail+'px');layer.appendChild(m);setTimeout(()=>m.remove(),d*1000+300)}
    function schedule(){spawn();setTimeout(schedule,1100+Math.random()*2600)} setTimeout(schedule,900);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',()=>{initMatrixRain();initMeteors();});else{initMatrixRain();initMeteors();}
})();

const runBtn = document.getElementById("runBtn");
const resetBtn = document.getElementById("resetBtn");
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");
const clearAllBtn = document.getElementById("clearAllBtn");
const domainInput = document.getElementById("domain");
const termsBox = document.getElementById("termsBox");
const termsAcceptedInput = document.getElementById("termsAcceptedV7");
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
const refreshDiagnosticsBtn = document.getElementById("refreshDiagnosticsBtn");
const testExportsBtn = document.getElementById("testExportsBtn");
const diagnosticsGrid = document.getElementById("diagnosticsGrid");
const exportTestResult = document.getElementById("exportTestResult");
const refreshReportsBtn = document.getElementById("refreshReportsBtn");
const reportsCenter = document.getElementById("reportsCenter");
const executiveRiskBox = document.getElementById("executiveRisk");
const executiveSummaryBox = document.getElementById("executiveSummary");
const pillarScoresBox = document.getElementById("pillarScores");
const topRisksBox = document.getElementById("topRisks");
const menuLinks = document.querySelectorAll("[data-page-link]");
const pages = document.querySelectorAll(".page");
const legalGate = document.getElementById("legalGate");
const legalText = document.getElementById("legalText");
const legalArticles = document.getElementById("legalArticles");
const legalAcceptCheckbox = document.getElementById("legalAcceptCheckbox");
const legalAcceptBtn = document.getElementById("legalAcceptBtn");
const legalGateStatus = document.getElementById("legalGateStatus");
const scanProgressFill = document.getElementById("scanProgressFill");
const scanProgressPercent = document.getElementById("scanProgressPercent");
const scanProgressStep = document.getElementById("scanProgressStep");
const scanElapsed = document.getElementById("scanElapsed");
const scanRemaining = document.getElementById("scanRemaining");
const serviceScanCount = document.getElementById("serviceScanCount");
const serviceScanBox = document.getElementById("serviceScanBox");
const reloadGraphBtn = document.getElementById("reloadGraphBtn");
const fitGraphBtn = document.getElementById("fitGraphBtn");
const graphStats = document.getElementById("graphStats");
const graphSvg = document.getElementById("graphSvg");
const graphStage = document.querySelector(".graph-stage");
const graphDetails = document.getElementById("graphDetails");


let termsAccepted = false;
let legalTerms = null;
let termsToken = localStorage.getItem("openeasm_terms_token") || "";
let progressTimer = null;
let progressStartedAt = 0;
let currentAuditId = null;
let currentGraph = null;

const SCAN_STEPS = [
  { at: 0, text: "Initialisation et garde-fous" },
  { at: 8, text: "Validation juridique et domaine" },
  { at: 18, text: "DNS, SPF, DMARC et MX" },
  { at: 32, text: "HTTP, headers et TLS/SSL" },
  { at: 48, text: "Sous-domaines et inventaire IP" },
  { at: 62, text: "Nmap service/version/port non exploitant" },
  { at: 80, text: "Corrélation CVE et scoring" },
  { at: 92, text: "Génération des rapports" },
];

async function fetchJsonSafe(url, options = {}) {
  const timeoutMs = options.timeoutMs || 0;
  const fetchOptions = { ...options };
  delete fetchOptions.timeoutMs;
  let timeoutId = null;
  if (timeoutMs > 0) {
    const controller = new AbortController();
    fetchOptions.signal = controller.signal;
    timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  }

  let response;
  try {
    response = await fetch(url, fetchOptions);
  } catch (err) {
    if (err && err.name === "AbortError") {
      throw new Error(`Délai dépassé pour ${url}. Vérifie les logs backend et l’état de PostgreSQL.`);
    }
    throw err;
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }

  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();

  let data = null;
  if (contentType.includes("application/json")) {
    try {
      data = text ? JSON.parse(text) : {};
    } catch (err) {
      throw new Error(`Réponse JSON invalide (${response.status}) : ${text.slice(0, 240)}`);
    }
  } else {
    // Fixes: Unexpected token 'I', "Internal S"... is not valid JSON
    const msg = text && text.trim()
      ? text.trim().slice(0, 500)
      : `Réponse non JSON du serveur (${response.status})`;
    if (!response.ok) {
      throw new Error(msg);
    }
    throw new Error(`Réponse non JSON inattendue : ${msg}`);
  }

  if (!response.ok) {
    throw new Error(data.detail || data.message || `Erreur HTTP ${response.status}`);
  }
  return data;
}


runBtn.addEventListener("click", runAudit);
resetBtn.addEventListener("click", resetAudit);
if (refreshDiagnosticsBtn) refreshDiagnosticsBtn.addEventListener("click", loadDiagnostics);
if (testExportsBtn) testExportsBtn.addEventListener("click", runExportTest);
if (refreshReportsBtn) refreshReportsBtn.addEventListener("click", loadReportsCenter);
if (reloadGraphBtn) reloadGraphBtn.addEventListener("click", loadLatestGraph);
if (fitGraphBtn) fitGraphBtn.addEventListener("click", () => { if (currentGraph) { renderGraphExplorer(currentGraph); centerGraphStage(); } });
menuLinks.forEach(btn => btn.addEventListener("click", () => showPage(btn.dataset.pageLink)));
refreshHistoryBtn.addEventListener("click", loadServerData);
clearAllBtn.addEventListener("click", clearAllAudits);
startVerificationBtn.addEventListener("click", startDomainVerification);
checkVerificationBtn.addEventListener("click", checkDomainVerification);
deleteVerificationBtn.addEventListener("click", deleteDomainVerification);
refreshVerifiedBtn.addEventListener("click", loadVerifiedDomains);

domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && termsAccepted) runAudit();
});

termsAcceptedInput.addEventListener("change", () => {
  termsAcceptedInput.checked = termsAccepted;
  if (!termsAccepted) showLegalGate();
});
termsBox.addEventListener("click", () => {
  if (!termsAccepted) showLegalGate();
});
termsBox.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    if (!termsAccepted) showLegalGate();
  }
});
if (legalAcceptCheckbox) {
  legalAcceptCheckbox.addEventListener("change", () => {
    legalAcceptBtn.disabled = !legalAcceptCheckbox.checked;
  });
}
if (legalAcceptBtn) legalAcceptBtn.addEventListener("click", acceptLegalTerms);
document.addEventListener("keydown", (e) => {
  if (legalGate && !legalGate.classList.contains("hidden") && e.key === "Escape") {
    e.preventDefault();
    e.stopPropagation();
  }
}, true);

setTermsAccepted(false);
initPageNavigation();
initLegalGate();
loadServerData();
loadVerifiedDomains();
loadDiagnostics();
loadReportsCenter();


function initPageNavigation() {
  const initial = (location.hash || "#audit").replace("#", "");
  showPage(["audit", "diagnostics", "reports"].includes(initial) ? initial : "audit", false);
  window.addEventListener("hashchange", () => {
    const page = (location.hash || "#audit").replace("#", "");
    showPage(["audit", "diagnostics", "reports"].includes(page) ? page : "audit", false);
  });
}

function showPage(page, updateHash = true) {
  pages.forEach(section => section.classList.toggle("active", section.id === `page-${page}`));
  menuLinks.forEach(btn => btn.classList.toggle("active", btn.dataset.pageLink === page));
  if (updateHash) history.replaceState(null, "", `#${page}`);
  if (page === "diagnostics") loadDiagnostics();
  if (page === "reports") loadReportsCenter();
  if (page === "graph" && !currentGraph) loadLatestGraph();
}

function setTermsAccepted(value) {
  termsAccepted = Boolean(value);
  if (termsAcceptedInput) {
    termsAcceptedInput.checked = termsAccepted;
    termsAcceptedInput.disabled = true;
  }
  if (termsBox) {
    termsBox.setAttribute("aria-pressed", String(termsAccepted));
    termsBox.classList.toggle("accepted", termsAccepted);
  }
  if (runBtn) runBtn.disabled = !termsAccepted;

  if (termsStatus) {
    if (termsAccepted) {
      termsStatus.textContent = "Avertissement juridique accepté : vous pouvez lancer l’audit V7.5.";
      termsStatus.className = "terms-status ok";
    } else {
      termsStatus.textContent = "Avertissement juridique non accepté : le bouton d’audit est désactivé.";
      termsStatus.className = "terms-status ko";
    }
  }
}

function showLegalGate() {
  if (!legalGate) return;
  legalGate.hidden = false;
  legalGate.style.removeProperty("display");
  legalGate.removeAttribute("aria-hidden");
  legalGate.classList.remove("hidden");
  document.body.classList.add("legal-locked");
}

function hideLegalGate(force = false) {
  if (!legalGate) return;
  legalGate.classList.add("hidden");
  legalGate.setAttribute("aria-hidden", "true");
  legalGate.hidden = true;
  if (force) legalGate.style.display = "none";
  document.body.classList.remove("legal-locked");
}

function completeLegalAcceptance() {
  setTermsAccepted(true);
  hideLegalGate(true);
  if (legalAcceptCheckbox) legalAcceptCheckbox.checked = true;
  if (legalAcceptBtn) legalAcceptBtn.disabled = true;
  showPage("audit", false);
  if (location.hash !== "#audit") history.replaceState(null, "", "#audit");
  requestAnimationFrame(() => {
    hideLegalGate(true);
    window.scrollTo({ top: 0, behavior: "smooth" });
  });
}

async function initLegalGate() {
  showLegalGate();
  try {
    legalTerms = await fetchJsonSafe("/api/legal/terms");
    renderLegalTerms(legalTerms);

    if (termsToken) {
      const status = await fetchJsonSafe(`/api/legal/status?token=${encodeURIComponent(termsToken)}`);
      if (status.valid || status.accepted) {
        completeLegalAcceptance();
        return;
      }
      termsToken = "";
      localStorage.removeItem("openeasm_terms_token");
    }

    setTermsAccepted(false);
    showLegalGate();
  } catch (err) {
    setTermsAccepted(false);
    showLegalGate();
    if (legalGateStatus) {
      legalGateStatus.textContent = `Impossible de charger l’avertissement juridique : ${err.message}`;
      legalGateStatus.className = "terms-status ko";
    }
  }
}

function renderLegalTerms(payload) {
  if (!payload) return;
  if (legalText) {
    legalText.textContent = payload.text || "Conditions indisponibles.";
  }
  if (legalArticles) {
    legalArticles.innerHTML = "";
    for (const article of payload.articles || []) {
      const div = document.createElement("div");
      div.className = "legal-article";
      div.innerHTML = `
        <strong>${escapeHtml(article.article || "Article")}</strong>
        <span>${escapeHtml(article.summary || "")}</span>
        <em>${escapeHtml(article.penalty || "")}</em>
      `;
      legalArticles.appendChild(div);
    }
  }
  if (legalGateStatus) {
    legalGateStatus.textContent = `Version du règlement : ${payload.version || "N/A"}`;
    legalGateStatus.className = "terms-status ko";
  }
}

async function acceptLegalTerms() {
  if (!legalTerms) {
    if (legalGateStatus) legalGateStatus.textContent = "Conditions non chargées.";
    return;
  }
  if (!legalAcceptCheckbox.checked) return;
  legalAcceptBtn.disabled = true;
  legalGateStatus.textContent = "Enregistrement de l’acceptation...";
  try {
    const data = await fetchJsonSafe("/api/legal/accept-terms", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-OpenEASM-Version": "v7.5" },
      body: JSON.stringify({ accepted: true, terms_hash: legalTerms.hash, terms_version: legalTerms.version }),
      timeoutMs: 15000,
    });
    const token = data.token || data.terms_token || data.acceptance_token;
    if (!token) throw new Error("Acceptation enregistrée, mais jeton backend absent. Recharge la page et vérifie /api/legal/accept-terms.");
    termsToken = token;
    localStorage.setItem("openeasm_terms_token", token);
    localStorage.setItem("openeasm_terms_version", data.terms_version || data.version || legalTerms.version || "");
    localStorage.setItem("openeasm_terms_hash", data.terms_hash || data.hash || legalTerms.hash || "");
    if (legalGateStatus) {
      legalGateStatus.textContent = "Acceptation enregistrée côté backend. Redirection vers OpenEASM...";
      legalGateStatus.className = "terms-status ok";
    }
    completeLegalAcceptance();
  } catch (err) {
    legalAcceptBtn.disabled = false;
    legalGateStatus.textContent = err.message || "Acceptation impossible.";
    legalGateStatus.className = "terms-status ko";
  }
}

async function runAudit() {
  const domain = domainInput.value.trim();

  errorBox.classList.add("hidden");
  results.classList.add("hidden");

  if (!termsAccepted || !termsToken) {
    errorBox.textContent = "Vous devez accepter l’avertissement juridique obligatoire avant de lancer l’audit.";
    errorBox.classList.remove("hidden");
    showLegalGate();
    return;
  }

  loading.classList.remove("hidden");
  runBtn.disabled = true;
  runBtn.textContent = "Audit en cours...";
  startAuditProgress();

  try {
    const data = await fetchJsonSafe("/api/audit", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-OpenEASM-Version": "v7.5"
      },
      body: JSON.stringify({ domain, accepted_terms: true, terms_token: termsToken }),
    });

    stopAuditProgress(true);
    renderResults(data);
    await loadComparison(data.domain);
    await loadServerData();
    await loadVerifiedDomains();
    await loadReportsCenter();
  } catch (err) {
    stopAuditProgress(false);
    errorBox.textContent = err.message || "Erreur inconnue pendant l'audit.";
    errorBox.classList.remove("hidden");
  } finally {
    loading.classList.add("hidden");
    runBtn.disabled = !termsAccepted;
    runBtn.textContent = "Lancer l'audit";
  }
}

function startAuditProgress() {
  progressStartedAt = Date.now();
  updateAuditProgress(0);
  clearInterval(progressTimer);
  progressTimer = setInterval(() => {
    const elapsed = Math.floor((Date.now() - progressStartedAt) / 1000);
    const estimatedTotal = 105;
    const percent = Math.min(94, Math.round((elapsed / estimatedTotal) * 100));
    updateAuditProgress(percent);
  }, 1000);
}

function updateAuditProgress(percent) {
  const safePercent = Math.max(0, Math.min(100, Number(percent) || 0));
  const elapsed = progressStartedAt ? Math.floor((Date.now() - progressStartedAt) / 1000) : 0;
  const estimatedTotal = 105;
  const remaining = Math.max(0, estimatedTotal - elapsed);
  const step = [...SCAN_STEPS].reverse().find(s => safePercent >= s.at) || SCAN_STEPS[0];

  if (scanProgressFill) scanProgressFill.style.width = `${safePercent}%`;
  if (scanProgressPercent) scanProgressPercent.textContent = `${safePercent}%`;
  if (scanProgressStep) scanProgressStep.textContent = step.text;
  if (scanElapsed) scanElapsed.textContent = formatDuration(elapsed);
  if (scanRemaining) scanRemaining.textContent = safePercent >= 100 ? "terminé" : formatDuration(remaining);
}

function stopAuditProgress(success) {
  clearInterval(progressTimer);
  progressTimer = null;
  updateAuditProgress(success ? 100 : 0);
  if (!success && scanProgressStep) scanProgressStep.textContent = "Audit interrompu";
}

function formatDuration(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}min ${r.toString().padStart(2, "0")}s`;
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



async function loadDiagnostics() {
  if (!diagnosticsGrid) return;
  diagnosticsGrid.innerHTML = "<p class='notice'>Diagnostic en cours...</p>";
  try {
    const data = await fetchJsonSafe("/api/system/diagnostics");
    renderDiagnostics(data);
  } catch (err) {
    diagnosticsGrid.innerHTML = `<div class="diag-item error-status"><strong>Diagnostic indisponible</strong><span>${escapeHtml(err.message)}</span></div>`;
  }
}

function renderDiagnostics(data) {
  diagnosticsGrid.innerHTML = "";
  const overall = document.createElement("div");
  overall.className = `diag-item ${statusClass(data.overall)}`;
  overall.innerHTML = `<strong>État global : ${escapeHtml(data.overall || "unknown")}</strong><span>Version ${escapeHtml(data.version || "N/A")} — ${escapeHtml(new Date(data.generated_at).toLocaleString())}</span>`;
  diagnosticsGrid.appendChild(overall);

  for (const item of data.items || []) {
    const div = document.createElement("div");
    div.className = `diag-item ${statusClass(item.status)}`;
    div.innerHTML = `
      <strong>${escapeHtml(item.name || "Contrôle")}</strong>
      <span>${escapeHtml(item.message || "")}</span>
      <small>${escapeHtml(item.status || "unknown")}</small>
    `;
    diagnosticsGrid.appendChild(div);
  }
}

async function runExportTest() {
  if (!exportTestResult) return;
  exportTestResult.classList.remove("hidden");
  exportTestResult.innerHTML = "<strong>Test exports en cours...</strong>";
  try {
    const data = await fetchJsonSafe("/api/system/export-test", { method: "POST" });
    const items = (data.items || []).map(i => `${i.name}: ${i.status}`).join(" | ");
    exportTestResult.innerHTML = `<strong>Résultat exports : ${escapeHtml(data.overall)}</strong><span>${escapeHtml(items)}</span>`;
    await loadDiagnostics();
  } catch (err) {
    exportTestResult.innerHTML = `<strong>Erreur test exports</strong><span>${escapeHtml(err.message)}</span>`;
  }
}

async function loadReportsCenter() {
  if (!reportsCenter) return;
  try {
    const data = await fetchJsonSafe("/api/reports?limit=50");
    renderReportsCenter(data.items || []);
  } catch (err) {
    reportsCenter.innerHTML = `<p class="notice">Centre de rapports indisponible : ${escapeHtml(err.message)}</p>`;
  }
}

function renderReportsCenter(items) {
  reportsCenter.innerHTML = "";
  if (!items.length) {
    reportsCenter.innerHTML = "<p class='notice'>Aucun rapport généré pour le moment.</p>";
    return;
  }

  for (const item of items) {
    const div = document.createElement("div");
    div.className = "report-row";
    div.innerHTML = `
      <div>
        <strong>${escapeHtml(item.domain)}</strong>
        <span>${escapeHtml(new Date(item.created_at).toLocaleString())} — Score ${escapeHtml(item.score)} / 1000 — ${escapeHtml(item.level || "")}</span>
      </div>
      <div class="report-actions">
        ${item.excel_exists ? `<a class="button-secondary small" href="${escapeHtml(item.excel_url)}" target="_blank">Excel</a>` : `<span class="report-missing">Excel manquant</span>`}
        ${item.pdf_exists ? `<a class="button-secondary small gold" href="${escapeHtml(item.pdf_url)}" target="_blank">PDF</a>` : `<span class="report-missing">PDF manquant</span>`}
        ${item.json_exists ? `<a class="button-secondary small" href="${escapeHtml(item.json_url)}" target="_blank">JSON</a>` : `<span class="report-missing">JSON manquant</span>`}
      </div>
    `;
    reportsCenter.appendChild(div);
  }
}

function statusClass(status) {
  if (status === "ok") return "ok-status";
  if (status === "warning") return "warning-status";
  if (status === "error") return "error-status";
  return "warning-status";
}


async function startDomainVerification() {
  const domain = domainInput.value.trim();
  if (!domain) {
    showError("Renseigne d’abord un domaine.");
    return;
  }
  try {
    const data = await fetchJsonSafe("/api/domains/verification/start", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({domain})
    });
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
    const data = await fetchJsonSafe(`/api/domains/${encodeURIComponent(domain)}/verification/check`, {method: "POST"});
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
    const data = await fetchJsonSafe(`/api/domains/${encodeURIComponent(domain)}/verification`, {method: "DELETE"});
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
    const data = await fetchJsonSafe("/api/domains/verified");
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


function renderExecutiveRisk(risk) {
  if (!executiveRiskBox || !pillarScoresBox || !topRisksBox) return;

  if (!risk || !risk.pillars) {
    executiveRiskBox.textContent = "N/A";
    executiveSummaryBox.textContent = "Scoring exécutif indisponible.";
    pillarScoresBox.innerHTML = "";
    topRisksBox.innerHTML = "";
    return;
  }

  executiveRiskBox.innerHTML = `
    <span class="executive-score">${escapeHtml(risk.overall_score)} / ${escapeHtml(risk.max_score || 100)}</span>
    <span class="executive-level">${escapeHtml(risk.risk_level)} — ${escapeHtml(risk.posture)}</span>
  `;
  executiveSummaryBox.textContent = risk.board_summary || "";

  pillarScoresBox.innerHTML = "";
  for (const pillar of risk.pillars || []) {
    const div = document.createElement("div");
    const pScore = pillar.score === null || pillar.score === undefined ? 'N/A' : pillar.score;
    div.className = `pillar-card ${pillar.applicability === 'non_applicable' ? 'pillar-na' : pillarClass(pillar.score)}`;
    div.innerHTML = `
      <div class="pillar-top">
        <strong>${escapeHtml(pillar.label)}</strong>
        <span>${escapeHtml(pScore)}${pScore === 'N/A' ? '' : ' / 100'}</span>
      </div>
      <div class="pillar-bar"><span style="width:${pillar.applicability === 'non_applicable' ? 0 : Math.max(0, Math.min(100, Number(pillar.score) || 0))}%"></span></div>
      <p>${escapeHtml(pillar.level)} — ${escapeHtml(pillar.findings_count)} constat(s), ${escapeHtml(pillar.critical_high_count)} critique/élevé.</p>
    `;
    pillarScoresBox.appendChild(div);
  }

  topRisksBox.innerHTML = "";
  const top = risk.top_risks || [];
  if (!top.length) {
    topRisksBox.innerHTML = "<p class='notice'>Aucun risque prioritaire de niveau moyen, élevé ou critique.</p>";
  } else {
    for (const item of top) {
      const div = document.createElement("div");
      div.className = "target";
      div.innerHTML = `
        <strong>${escapeHtml(item.severity)} — ${escapeHtml(item.title)}</strong>
        <span>Catégorie : ${escapeHtml(item.category || "N/A")}</span>
        <span>Lieu / source : ${escapeHtml(item.location || "N/A")}</span>
        <span>Action recommandée : ${escapeHtml(item.recommendation || "N/A")}</span>
      `;
      topRisksBox.appendChild(div);
    }
  }
}

function pillarClass(score) {
  const n = Number(score) || 0;
  if (n >= 85) return "pillar-good";
  if (n >= 70) return "pillar-ok";
  if (n >= 55) return "pillar-watch";
  return "pillar-bad";
}


function renderResults(data) {
  currentAuditId = data.id || null;
  currentGraph = data.attack_graph || null;
  if (currentGraph) renderGraphExplorer(currentGraph);
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
    `Ports ouverts détectés par Nmap : ${data.summary.service_open_port_count || 0}`,
    `CVE service/version détectées : ${data.summary.service_cve_count || 0}`,
    `Durée scan service/version : ${data.summary.service_scan_elapsed_seconds ?? "N/A"} s`,
  ];

  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    summaryBox.appendChild(li);
  }

  renderExecutiveRisk(data.executive_risk || {});
  renderWebTargets(data.web_targets || []);
  renderIpInventory(data.ip_inventory || {});
  renderTlsAdvanced(data.tls_score || {});
  renderPassiveCves(data.passive_cves || {});
  renderServiceScan(data.service_scan || {});
  renderCti(data.cti || {});
  renderPatching(data.patching_sla || {});
  renderSubdomains(data.subdomains || {});
  renderFindings(data.findings || []);

  reportLink.href = data.report_url;
  pdfLink.href = data.pdf_url;
  jsonLink.href = data.json_url;
  if (data.report_errors && data.report_errors.length) {
    const li = document.createElement("li");
    li.textContent = "Alerte exports : " + data.report_errors.join(" | ");
    summaryBox.appendChild(li);
  }
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

function renderServiceScan(scan) {
  if (!serviceScanBox || !serviceScanCount) return;
  const openPorts = scan.open_ports || [];
  const cves = scan.cves || [];
  serviceScanCount.textContent = `${scan.count_open_ports || openPorts.length || 0} port(s) | ${scan.count_cves || cves.length || 0} CVE`;
  serviceScanBox.innerHTML = "";

  const summary = document.createElement("div");
  summary.className = "target";
  summary.innerHTML = `
    <strong>Mode : ${escapeHtml(scan.mode || "service_version_light")}</strong>
    <span>${escapeHtml(scan.note || "Scan Nmap limité à la détection service/version/port, sans exploitation.")}</span>
    <span>Durée : ${escapeHtml(scan.elapsed_seconds ?? "N/A")} seconde(s)</span>
  `;
  serviceScanBox.appendChild(summary);

  if (!scan.enabled) {
    const disabled = document.createElement("div");
    disabled.className = "target";
    disabled.innerHTML = `<strong>Scan non exécuté</strong><span>${escapeHtml(scan.note || scan.error || "Nmap indisponible ou cible bloquée par les garde-fous.")}</span>`;
    serviceScanBox.appendChild(disabled);
    return;
  }

  const targets = scan.targets || [];
  if (targets.length) {
    for (const target of targets.slice(0, 8)) {
      const status = target.status || "unknown";
      const count = (target.open_ports || []).length;
      const div = document.createElement("div");
      div.className = "target";
      div.innerHTML = `
        <strong>Cible : ${escapeHtml(target.hostname || "N/A")} — ${escapeHtml(status)}</strong>
        <span>Ports ouverts détectés : ${escapeHtml(count)} | Durée : ${escapeHtml(target.elapsed_seconds ?? "N/A")} s</span>
        <span>Commande : nmap ${escapeHtml(target.command || scan.command_policy || "-sS -sV --version-all --reason")}</span>
        ${target.error ? `<span>Information : ${escapeHtml(target.error)}</span>` : ""}
      `;
      serviceScanBox.appendChild(div);
    }
  }

  if (openPorts.length === 0) {
    const empty = document.createElement("div");
    empty.className = "target";
    empty.innerHTML = "<strong>Aucun port ouvert détecté</strong><span>Vérifier le détail des cibles ci-dessus. En V7.2, le scan utilise -sS avec capability NET_RAW pour se rapprocher d’un nmap classique root, puis fallback -sT si nécessaire.</span>";
    serviceScanBox.appendChild(empty);
  }

  for (const port of openPorts.slice(0, 30)) {
    const related = cves.filter(c => String(c.host || c.hostname || "") === String(port.host || port.hostname || "") && Number(c.port) === Number(port.port));
    const div = document.createElement("div");
    div.className = "target";
    div.innerHTML = `
      <strong>${escapeHtml(port.host || port.hostname || "cible")} — ${escapeHtml(port.port)}/${escapeHtml(port.protocol || "tcp")}</strong>
      <span>Service : ${escapeHtml(port.service || "unknown")} | Produit : ${escapeHtml(port.product || "N/A")} | Version : ${escapeHtml(port.version || "N/A")}</span>
      <span>CPE : ${(port.cpes || []).map(escapeHtml).join(", ") || "Non détecté"}</span>
      <span>CVE corrélées : ${related.length ? related.map(c => `${c.cve} (${c.severity})`).join(" ; ") : "Aucune correspondance locale"}</span>
    `;
    serviceScanBox.appendChild(div);
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
  subCount.textContent = `${sub.count || list.length || 0} détecté(s)`;
  subdomainsBox.innerHTML = "";

  if (sub.error) {
    const error = document.createElement("div");
    error.className = "subdomain-warning";
    error.innerHTML = `<strong>Source passive limitée :</strong> ${escapeHtml(shortenText(sub.error, 260))}`;
    subdomainsBox.appendChild(error);
  }

  if (list.length === 0) {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = sub.error ? "Aucun sous-domaine affichable malgré les sources alternatives." : "Aucun sous-domaine affiché";
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
    findingsBox.innerHTML = "<p>Aucun constat notable sur les contrôles V7.</p>";
    return;
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

  for (const f of findings) {
    const loc = f.location || {};
    const locText = loc.display || loc.path || loc.record || loc.hostname || loc.control || "N/A";
    const div = document.createElement("div");
    div.className = "finding";
    div.innerHTML = `
      <span class="sev ${escapeHtml(f.severity || "info")}">${escapeHtml(f.severity || "info")}</span>
      <h3>${escapeHtml(f.title || "")}</h3>
      <p><strong>Catégorie :</strong> ${escapeHtml(f.category || "N/A")}</p>
      <p><strong>Lieu / source :</strong> ${escapeHtml(locText)}</p>
      <p>${escapeHtml(f.description || "")}</p>
      <p><strong>Recommandation :</strong> ${escapeHtml(f.recommendation || "")}</p>
    `;
    findingsBox.appendChild(div);
  }
}


async function loadLatestGraph() {
  if (!graphSvg || !graphStats) return;
  graphStats.innerHTML = "<span>Chargement du dernier graphe...</span>";
  try {
    const data = await fetchJsonSafe("/api/graph/latest");
    if (!data.available) {
      graphStats.innerHTML = "<span>Aucun audit disponible pour le Graph Explorer.</span>";
      graphSvg.innerHTML = "";
      graphDetails.innerHTML = "<strong>Sélection</strong><p>Lance un audit pour générer la cartographie relationnelle.</p>";
      return;
    }
    currentAuditId = data.audit_id || currentAuditId;
    currentGraph = data.graph || null;
    renderGraphExplorer(currentGraph);
  } catch (err) {
    graphStats.innerHTML = `<span>Graph indisponible : ${escapeHtml(err.message)}</span>`;
  }
}

function renderGraphExplorer(graph) {
  if (!graphSvg || !graphStats || !graphDetails) return;
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges) || !graph.nodes.length) {
    graphSvg.innerHTML = "";
    graphStats.innerHTML = "<span>Aucune donnée de graphe disponible.</span>";
    graphDetails.innerHTML = "<strong>Sélection</strong><p>Lance un audit pour générer la cartographie.</p>";
    return;
  }

  const nodes = graph.nodes.slice(0, 220).map(n => ({ ...n }));
  const nodeIds = new Set(nodes.map(n => n.id));
  const edges = graph.edges.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target)).slice(0, 440);
  const layout = computeGraphPositions(nodes, edges);
  const positions = layout.positions;
  const width = layout.width;
  const height = layout.height;

  graphStats.innerHTML = `
    <span><strong>${escapeHtml(graph.domain || "domaine")}</strong></span>
    <span>${escapeHtml(graph.metrics?.nodes ?? nodes.length)} nœuds</span>
    <span>${escapeHtml(graph.metrics?.edges ?? edges.length)} liens</span>
    <span>${escapeHtml(graph.metrics?.public_ips ?? 0)} IP publiques</span>
    <span>${escapeHtml(graph.metrics?.open_ports ?? 0)} ports Nmap</span>
    <span>${escapeHtml(graph.metrics?.service_cves ?? 0)} CVE service/version</span>
    <span>Vue V7.5 grand format</span>
  `;

  graphSvg.innerHTML = "";
  graphSvg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  graphSvg.setAttribute("width", String(width));
  graphSvg.setAttribute("height", String(height));
  graphSvg.style.width = `${width}px`;
  graphSvg.style.height = `${height}px`;

  const ns = "http://www.w3.org/2000/svg";
  const defs = document.createElementNS(ns, "defs");
  defs.innerHTML = `
    <marker id="arrowHead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
      <path d="M0,0 L0,6 L9,3 z" fill="rgba(255,255,255,.44)"></path>
    </marker>
    <filter id="nodeGlow" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="4" result="blur" />
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  `;
  graphSvg.appendChild(defs);

  const edgeLayer = document.createElementNS(ns, "g");
  edgeLayer.setAttribute("class", "graph-edges");
  graphSvg.appendChild(edgeLayer);

  const nodeLayer = document.createElementNS(ns, "g");
  nodeLayer.setAttribute("class", "graph-nodes");
  graphSvg.appendChild(nodeLayer);

  for (const edge of edges) {
    const a = positions.get(edge.source);
    const b = positions.get(edge.target);
    if (!a || !b) continue;
    const path = document.createElementNS(ns, "path");
    const midX = (a.x + b.x) / 2;
    const d = `M ${a.x} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x} ${b.y}`;
    path.setAttribute("d", d);
    path.setAttribute("class", `graph-edge ${edge.type || "related"}`);
    path.setAttribute("marker-end", "url(#arrowHead)");
    path.setAttribute("data-label", edge.label || "");
    edgeLayer.appendChild(path);
  }

  for (const node of nodes) {
    const p = positions.get(node.id);
    if (!p) continue;
    const group = document.createElementNS(ns, "g");
    group.setAttribute("class", `graph-node ${node.type || "unknown"}`);
    group.setAttribute("transform", `translate(${p.x}, ${p.y})`);
    group.setAttribute("tabindex", "0");

    const circle = document.createElementNS(ns, "circle");
    const radius = Math.max(8, Math.min(20, 8 + Number(node.weight || 1) * 1.4));
    circle.setAttribute("r", String(radius));
    circle.setAttribute("filter", "url(#nodeGlow)");
    group.appendChild(circle);

    const text = document.createElementNS(ns, "text");
    text.setAttribute("x", String(radius + 8));
    text.setAttribute("y", "4");
    text.textContent = shortenText(node.label || node.id, node.type === "finding" ? 48 : 34);
    group.appendChild(text);

    group.addEventListener("click", () => {
      graphSvg.querySelectorAll(".graph-node.selected").forEach(el => el.classList.remove("selected"));
      group.classList.add("selected");
      showGraphNodeDetails(node, graph, edges);
    });
    group.addEventListener("keydown", (evt) => {
      if (evt.key === "Enter" || evt.key === " ") {
        evt.preventDefault();
        group.dispatchEvent(new Event("click"));
      }
    });
    nodeLayer.appendChild(group);
  }

  graphDetails.innerHTML = `<strong>Graph Explorer V7.5</strong><p>${escapeHtml(graph.domain || "Domaine")} : cartographie grand format par colonnes. Clique sur un nœud pour afficher ses relations et propriétés. La zone du graphe a été élargie pour visualiser davantage de relations sans perdre la lisibilité.</p>`;
  centerGraphStage();
}

function computeGraphPositions(nodes, edges) {
  const root = nodes.find(n => n.type === "domain" && String(n.id || "").startsWith("domain:")) || nodes[0];
  const levels = new Map();
  const levelOf = (node) => {
    if (root && node.id === root.id) return 0;
    const type = node.type || "unknown";
    if (type === "profile") return 1;
    if (type === "domain" || type === "subdomain") return 1;
    if (type === "web" || type === "ip") return 2;
    if (type === "service") return 3;
    if (type === "cve" || type === "finding") return 4;
    return 5;
  };

  for (const node of nodes) {
    const level = levelOf(node);
    if (!levels.has(level)) levels.set(level, []);
    levels.get(level).push(node);
  }

  for (const [level, list] of levels.entries()) {
    list.sort((a, b) => String(a.label || a.id).localeCompare(String(b.label || b.id), "fr", { numeric: true }));
    if (level === 0 && root) {
      const idx = list.findIndex(n => n.id === root.id);
      if (idx > 0) list.unshift(list.splice(idx, 1)[0]);
    }
  }

  const maxColumn = Math.max(...[...levels.values()].map(v => v.length), 1);
  const width = 1540;
  const height = Math.max(900, Math.min(3600, 150 + maxColumn * 50));
  const columns = [95, 390, 700, 1000, 1285, 1460];
  const positions = new Map();

  for (const [level, list] of levels.entries()) {
    const xBase = columns[level] ?? (90 + level * 230);
    const span = height - 140;
    const gap = span / Math.max(1, list.length + 1);
    list.forEach((node, idx) => {
      let x = xBase;
      let y = 70 + gap * (idx + 1);
      if (level === 0) y = height / 2;
      const typeShift = { ip: 28, web: -28, finding: 18, cve: -18, profile: -44 }[node.type] || 0;
      const wave = ((idx % 3) - 1) * 10;
      positions.set(node.id, {
        x: Math.max(40, Math.min(width - 80, x + typeShift + wave)),
        y: Math.max(40, Math.min(height - 40, y)),
      });
    });
  }

  // Pull directly connected orphan nodes closer to their source column, without collapsing everything in one corner.
  for (const edge of edges) {
    const a = positions.get(edge.source);
    const b = positions.get(edge.target);
    if (!a || !b) continue;
    if (Math.abs(a.y - b.y) > 620) {
      b.y = Math.max(50, Math.min(height - 50, a.y + (b.y > a.y ? 260 : -260)));
    }
  }

  return { positions, width, height };
}

function centerGraphStage() {
  if (!graphStage || !graphSvg) return;
  const domainNode = graphSvg.querySelector(".graph-node.domain");
  if (!domainNode) {
    graphStage.scrollLeft = 0;
    graphStage.scrollTop = 0;
    return;
  }
  const match = /translate\(([-0-9.]+),\s*([-0-9.]+)\)/.exec(domainNode.getAttribute("transform") || "");
  if (!match) return;
  const x = Number(match[1]) || 0;
  const y = Number(match[2]) || 0;
  graphStage.scrollLeft = Math.max(0, x - graphStage.clientWidth * 0.25);
  graphStage.scrollTop = Math.max(0, y - graphStage.clientHeight * 0.5);
}

function showGraphNodeDetails(node, graph, edges) {
  if (!graphDetails) return;
  const related = edges.filter(e => e.source === node.id || e.target === node.id).slice(0, 18);
  const props = node.properties || {};
  const propHtml = Object.entries(props).slice(0, 12).map(([k, v]) => `<li><strong>${escapeHtml(k)}</strong> : ${escapeHtml(Array.isArray(v) ? v.join(", ") : v)}</li>`).join("");
  const relHtml = related.map(e => `<li>${escapeHtml(e.source === node.id ? "→" : "←")} ${escapeHtml(e.label || e.type)} ${escapeHtml(e.source === node.id ? e.target : e.source)}</li>`).join("");
  graphDetails.innerHTML = `
    <strong>${escapeHtml(node.label || node.id)}</strong>
    <p><span class="node-type ${escapeHtml(node.type || "unknown")}">${escapeHtml(node.type || "unknown")}</span></p>
    <h4>Propriétés</h4>
    <ul>${propHtml || "<li>Aucune propriété détaillée.</li>"}</ul>
    <h4>Relations</h4>
    <ul>${relHtml || "<li>Aucune relation affichée.</li>"}</ul>
  `;
}

function resetAudit() {
  domainInput.value = "";
  errorBox.classList.add("hidden");
  results.classList.add("hidden");
  loading.classList.add("hidden");
  comparisonCard.classList.add("hidden");
  domainInput.focus();
}

function shortenText(str, maxLength = 180) {
  const value = String(str || "");
  return value.length > maxLength ? value.slice(0, maxLength - 1) + "…" : value;
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (m) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;",
  }[m]));
}
