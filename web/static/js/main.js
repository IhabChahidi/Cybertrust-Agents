import { apiFetch, ApiError, goToAccessDenied } from "./api.js";
import { fetchMe, logout } from "./auth.js";
import { state, resetDashboardState, ENDPOINT_LABELS, LLM_MODE_LABELS } from "./state.js";
import { renderHeader, updatePipelineIndicator } from "./components/Header.js";
import { renderSummaryCards } from "./components/SummaryCards.js";
import { renderEvidenceFilters, applyEvidenceFilters } from "./components/EvidenceFilters.js";
import { renderEvidenceTable } from "./components/EvidenceTable.js";
import { renderCisoRequestForm, showValidationMessage, renderConfirmSummary } from "./components/CisoRequestForm.js";
import { renderPipelineConfig } from "./components/PipelineConfig.js";
import { renderRunning, renderIdle, renderStages, renderErrorBox, isTechnicalFailureCode } from "./components/PipelineProgress.js";
import { renderResults, wireCisoActions, setCisoActionFeedback, renderTimeline } from "./components/ResultsPanel.js";

const ALLOWED_ROLES = new Set(["CISO", "CISO_DELEGATE"]);

const el = {
  sessionGate: document.getElementById("session-gate"),
  appShell: document.getElementById("app-shell"),
  topnav: document.getElementById("topnav"),
  summaryCards: document.getElementById("summary-cards"),
  evidenceFilters: document.getElementById("evidence-filters"),
  evidenceTableContainer: document.getElementById("evidence-table-container"),
  cisoRequestForm: document.getElementById("ciso-request-form"),
  pipelineConfig: document.getElementById("pipeline-config"),
  launchBtn: document.getElementById("launch-btn"),
  pipelineProgress: document.getElementById("pipeline-progress"),
  resultsPanel: document.getElementById("results-panel"),
  resultsContent: document.getElementById("results-content"),
  journalPanel: document.getElementById("journal-panel"),
  journalTbody: document.getElementById("journal-tbody"),
};

// ---- targeted, cursor-preserving refresh helpers ----
// (Re-rendering a whole panel on every keystroke would reset focus/cursor in
// whatever input triggered it, so each interaction only re-renders the
// containers it actually needs to affect.)

function refreshSummary() {
  renderSummaryCards(el.summaryCards, state);
}

function refreshEvidenceTable() {
  renderEvidenceTable(el.evidenceTableContainer, state, {
    onToggleSelect: (id) => {
      if (state.selection.has(id)) state.selection.delete(id);
      else state.selection.add(id);
      refreshEvidenceTable();
      refreshSummary();
      updateSelectionCountText();
      updateLaunchButtonState();
    },
    onToggleExpand: (id) => {
      if (state.expandedRows.has(id)) state.expandedRows.delete(id);
      else state.expandedRows.add(id);
      refreshEvidenceTable();
    },
    onSort: (key) => {
      if (state.sort.key === key) state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
      else state.sort = { key, dir: "asc" };
      refreshEvidenceTable();
    },
    fetchDetail: async (id) => {
      if (state.evidenceDetailsCache[id]) return state.evidenceDetailsCache[id];
      try {
        const detail = await apiFetch(`/api/evidence/${id}`);
        state.evidenceDetailsCache[id] = detail;
        return detail;
      } catch {
        return null;
      }
    },
  });
}

function updateSelectionCountText() {
  const countEl = document.getElementById("ciso-selection-count");
  if (countEl) countEl.innerHTML = `<strong>${state.selection.size}</strong> Evidence selectionnee(s) pour cette requete.`;
}

function updateLaunchButtonState() {
  const hasSelection = state.selection.size > 0;
  const hasStatement = state.statement.trim() !== "";
  el.launchBtn.disabled = !(hasSelection && hasStatement) || state.pendingConfirm;

  if (!hasSelection || !hasStatement) {
    const msg = !hasSelection
      ? "Selectionnez au moins une Evidence avant de lancer l'analyse."
      : "Saisissez une requete avant de lancer l'analyse.";
    showValidationMessage(el.cisoRequestForm, msg);
  } else {
    showValidationMessage(el.cisoRequestForm, null);
  }
}

function initEvidenceFilters() {
  renderEvidenceFilters(el.evidenceFilters, state, {
    onChange: refreshEvidenceTable,
    onSelectAllVisible: () => {
      // "visible" = whatever the current filters show.
      applyEvidenceFilters(state).forEach((e) => state.selection.add(e.id));
      refreshEvidenceTable();
      refreshSummary();
      updateSelectionCountText();
      updateLaunchButtonState();
    },
    onClearSelection: () => {
      state.selection.clear();
      refreshEvidenceTable();
      refreshSummary();
      updateSelectionCountText();
      updateLaunchButtonState();
    },
  });
}

function initCisoRequestForm() {
  renderCisoRequestForm(el.cisoRequestForm, state, {
    onChange: () => {
      refreshSummary();
      updateLaunchButtonState();
    },
  });
}

function initPipelineConfig() {
  renderPipelineConfig(el.pipelineConfig, state, {
    onChange: refreshSummary,
  });
}

// ---- launch / confirm / submit flow ----

function renderLaunchIdle() {
  el.launchBtn.classList.remove("hidden");
  updateLaunchButtonState();
  renderIdle(el.pipelineProgress);
}

function renderLaunchConfirm() {
  el.launchBtn.classList.add("hidden");
  const endpointLabel = ENDPOINT_LABELS[state.endpoint] || state.endpoint;
  const modeLabel = LLM_MODE_LABELS[state.llmMode] || state.llmMode;
  el.pipelineProgress.innerHTML = `
    <p class="panel-helper">Verifiez les parametres avant de lancer l'analyse MCP.</p>
    ${renderConfirmSummary(state, endpointLabel, modeLabel)}
    <button type="button" class="btn btn-primary" id="confirm-launch-btn">Confirmer et lancer</button>
    <button type="button" class="btn btn-secondary" id="cancel-launch-btn">Modifier</button>
  `;
  document.getElementById("confirm-launch-btn").addEventListener("click", () => {
    state.pendingConfirm = false;
    doSubmit();
  });
  document.getElementById("cancel-launch-btn").addEventListener("click", () => {
    state.pendingConfirm = false;
    renderLaunchIdle();
  });
}

async function doSubmit() {
  el.launchBtn.classList.add("hidden");
  el.resultsPanel.classList.add("hidden");
  el.journalPanel.classList.add("hidden");
  renderRunning(el.pipelineProgress, state.llmMode);
  updatePipelineIndicator("running");

  try {
    const result = await apiFetch("/api/process", {
      method: "POST",
      body: {
        statement: state.statement,
        evidence_ids: Array.from(state.selection),
        llm_mode: state.llmMode,
        endpoint: state.endpoint,
      },
    });
    state.lastResult = result;
    handlePipelineResult(result);
  } catch (err) {
    if (err instanceof ApiError) {
      renderStages(el.pipelineProgress, []);
      renderErrorBox(el.pipelineProgress, {
        code: "REQUEST_ERROR", detail: err.detail, isTechnical: true, onRetry: doSubmit,
      });
    }
    updatePipelineIndicator("failure");
  } finally {
    el.launchBtn.classList.remove("hidden");
    updateLaunchButtonState();
  }
}

function handlePipelineResult(result) {
  const stagesEl = document.createElement("div");
  el.pipelineProgress.innerHTML = "";
  el.pipelineProgress.appendChild(stagesEl);
  renderStages(stagesEl, result.transitions);

  if (result.mcp_state === "COMPLETED") {
    updatePipelineIndicator("completed");
    renderResults(el.resultsContent, result);
    wireCisoActions(el.resultsContent, (decision) => submitCisoDecision(result, decision));
    el.resultsPanel.classList.remove("hidden");
    loadJournal(result.session_id);
  } else if (result.mcp_state === "BLOCKED") {
    updatePipelineIndicator("blocked");
    const errorBox = document.createElement("div");
    el.pipelineProgress.appendChild(errorBox);
    renderErrorBox(errorBox, {
      code: result.blocked_reason, detail: result.detail, isTechnical: false,
      lastStage: result.last_stage, partial: result.partial,
    });
    loadJournal(result.session_id);
  } else {
    updatePipelineIndicator("failure");
    const errorBox = document.createElement("div");
    el.pipelineProgress.appendChild(errorBox);
    renderErrorBox(errorBox, {
      code: result.failure_reason, detail: result.detail,
      isTechnical: isTechnicalFailureCode(result.failure_reason),
      lastStage: result.last_stage, partial: result.partial,
      onRetry: doSubmit,
    });
    loadJournal(result.session_id);
  }
}

async function submitCisoDecision(result, decision) {
  try {
    await apiFetch("/api/ciso-decision", {
      method: "POST",
      body: {
        session_id: result.session_id, correlation_id: result.correlation_id,
        llm_mode: state.llmMode, decision,
      },
    });
    setCisoActionFeedback(el.resultsContent, `Decision "${decision}" enregistree.`);
    loadJournal(result.session_id);
  } catch (err) {
    setCisoActionFeedback(el.resultsContent, err instanceof ApiError ? err.detail : "Erreur lors de l'enregistrement.");
  }
}

async function loadJournal(sessionId) {
  try {
    const events = await apiFetch(`/api/journal/${sessionId}`);
    state.journal = events;
    el.journalTbody.innerHTML = events
      .map(
        (e) => `
      <tr>
        <td>${e.state}</td><td>${e.event_type}</td><td>${e.role}</td><td>${e.result}</td>
        <td>${typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail)}</td>
        <td>${e.timestamp}</td>
      </tr>`
      )
      .join("");
    el.journalPanel.classList.toggle("hidden", events.length === 0);
  } catch {
    el.journalPanel.classList.add("hidden");
  }
}

el.launchBtn.addEventListener("click", () => {
  if (state.pendingConfirm) return;
  state.pendingConfirm = true;
  renderLaunchConfirm();
});

// ---- bootstrap ----

async function bootstrap() {
  let session;
  try {
    session = await fetchMe();
  } catch {
    return; // apiFetch already redirected to /login.html
  }

  if (!ALLOWED_ROLES.has(session.role)) {
    goToAccessDenied();
    return;
  }

  state.user = { username: session.username, role: session.role };

  el.sessionGate.classList.add("hidden");
  el.appShell.classList.remove("hidden");

  renderHeader(el.topnav, {
    user: state.user,
    pipelineStatus: state.pipeline.status,
    onLogout: async () => {
      await logout();
      resetDashboardState();
      location.href = "/login.html";
    },
  });

  try {
    const [config, evidence] = await Promise.all([apiFetch("/api/config"), apiFetch("/api/evidence")]);
    state.config = config;
    state.evidence = evidence;
    if (config.endpoints.length && !config.endpoints.includes(state.endpoint)) state.endpoint = config.endpoints[0];
  } catch {
    el.evidenceTableContainer.innerHTML = `<p class="panel-helper">Impossible de charger le catalogue Evidence.</p>`;
    return;
  }

  refreshSummary();
  initEvidenceFilters();
  refreshEvidenceTable();
  initCisoRequestForm();
  initPipelineConfig();
  renderLaunchIdle();
}

bootstrap();
