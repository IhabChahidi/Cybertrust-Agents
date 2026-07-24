import { PIPELINE_STAGES, stageLabel } from "../state.js";

// Friendly, non-technical explanations for the MCP error codes (mcp_server/errors.py).
// Falls back to the raw code if a new one appears server-side that isn't mapped yet.
const FRIENDLY_MESSAGES = {
  UNAUTHORIZED_ENDPOINT: "Le point de terminaison demande n'est pas autorise.",
  UNSUPPORTED_SCHEMA_VERSION: "La version du schema de donnees n'est pas prise en charge.",
  PROMPT_INJECTION: "Une tentative d'injection de prompt a ete detectee et bloquee.",
  EXFILTRATION_ATTEMPT: "Une tentative d'exfiltration de donnees a ete detectee et bloquee.",
  INVALID_EVIDENCE_ID: "Une ou plusieurs Evidence referencees sont introuvables dans le catalogue.",
  MISSING_EVIDENCE_IDS: "Aucune Evidence n'a ete fournie pour cette requete.",
  SCORE_OWNERSHIP_VIOLATION: "Une sortie LLM a tente de definir elle-meme un score, ce qui est interdit.",
  CISO_APPROVAL_REQUIRED: "Un dossier a risque eleve necessite une approbation CISO explicite non fournie.",
  LLM_TIMEOUT: "Le modele LLM n'a pas repondu dans le delai imparti.",
  LLM_EMPTY_RESPONSE: "Le modele LLM a renvoye une reponse vide.",
  LLM_PROVIDER_ERROR: "Le fournisseur LLM a renvoye une erreur technique.",
  SCHEMA_ERROR: "Une sortie ne respecte pas le schema de donnees attendu.",
};

const TECHNICAL_CODES = new Set(["LLM_TIMEOUT", "LLM_EMPTY_RESPONSE", "LLM_PROVIDER_ERROR", "SCORING_ENGINE_ERROR", "AUDIT_UNAVAILABLE", "EVIDENCE_CATALOG_UNAVAILABLE"]);

export function isTechnicalFailureCode(code) {
  return TECHNICAL_CODES.has(code);
}

export function renderRunning(container, llmMode) {
  container.innerHTML = `
    <div class="loading-row" role="status" aria-live="polite">
      <span class="spinner" aria-hidden="true"></span>
      <span>Analyse en cours...${llmMode !== "mock" ? " (mode live : jusqu'a 1 a 2 minutes)" : ""}</span>
    </div>
  `;
}

export function renderIdle(container) {
  container.innerHTML = "";
}

export function renderStages(container, transitions) {
  const reached = new Set(transitions || []);
  const lastReached = (transitions || [])[transitions.length - 1];

  const items = PIPELINE_STAGES.map((stage) => {
    const done = reached.has(stage.key);
    const isLast = stage.key === lastReached;
    const cls = done ? (isLast ? "active" : "done") : "";
    return `<li class="${cls}"><span class="stage-dot" aria-hidden="true">${done ? "✓" : ""}</span>${stage.label}</li>`;
  }).join("");

  container.innerHTML = `<ul class="stage-list">${items}</ul>`;
}

// Builds a plain-language, data-backed account of what happened before the
// block/failure — not just the raw code, but what was actually computed
// (Claim, VerificationResult, MCPScore, ValidationDecision) up to that point,
// and why that data specifically triggered this outcome.
function explainWhatHappened({ code, lastStage, partial }) {
  const p = partial || {};
  const lines = [];

  if (lastStage) {
    lines.push(`Le pipeline s'est arrete pendant l'etape <b>${stageLabel(lastStage)}</b>.`);
  }
  if (p.claim) {
    lines.push(`Un Claim a ete genere (<b>${p.claim.id}</b>) — voir l'encadre ci-dessus.`);
  }
  if (p.verification_result) {
    lines.push(
      `Le Verificateur a conclu a un statut <b>${p.verification_result.status}</b> : ${p.verification_result.reasoning_summary}`
    );
  }
  if (p.mcp_score) {
    lines.push(`Le serveur MCP a calcule un score de <b>${p.mcp_score.value}/100</b>, classe <b>${p.mcp_score.risk_level}</b>.`);
  }
  if (p.validation_decision) {
    lines.push(`Le Validateur avait produit une decision <b>${p.validation_decision.decision}</b> avant l'interruption.`);
  }

  // Code-specific causal explanation, when there is enough data to be precise
  // rather than generic.
  if (code === "CISO_APPROVAL_REQUIRED" && p.mcp_score) {
    lines.push(
      `Un score classe <b>${p.mcp_score.risk_level}</b> impose obligatoirement une approbation CISO explicite ` +
      `(<code>requires_ciso_approval = true</code>) avant de pouvoir avancer. La decision renvoyee par le ` +
      `Validateur ne positionnait pas cette approbation : le serveur MCP a donc bloque le dossier plutot que ` +
      `de le laisser progresser sans ce garde-fou, quel que soit le modele ou le raisonnement a l'origine de cette decision.`
    );
  }
  if (code === "INVALID_CLAIM_REFERENCE" || code === "INVALID_VERIFICATION_REFERENCE" || code === "INVALID_SCORE_REFERENCE") {
    lines.push(
      "Un des objets produits par un role LLM fait reference a un identifiant qui ne correspond a rien dans " +
      "cette session — un signe possible d'incoherence du modele ou de tentative de manipulation des references."
    );
  }
  if (code === "SCORE_OWNERSHIP_VIOLATION") {
    lines.push(
      "Le MCPScore ne doit jamais etre calcule ou modifie par un role LLM. Une sortie contenant elle-meme un " +
      "champ de score a ete rejetee avant meme d'etre validee contre son schema."
    );
  }

  return lines;
}

function claimCard(claim) {
  if (!claim) return "";
  return `
    <div class="result-card">
      <h3>Claim genere ${claim.id}</h3>
      <div class="field"><b>statement</b>${claim.statement}</div>
      <div class="field"><b>evidence_ids</b>${(claim.evidence_ids || []).join(", ")}</div>
      <div class="field"><b>confidence</b>${claim.confidence}</div>
    </div>
  `;
}

export function renderErrorBox(container, { code, detail, isTechnical, lastStage, partial, onRetry }) {
  const friendly = FRIENDLY_MESSAGES[code] || "Une erreur inattendue est survenue.";
  const narrative = explainWhatHappened({ code, lastStage, partial });

  container.innerHTML = `
    ${claimCard((partial || {}).claim)}
    <div class="error-detail-box" role="alert">
      <p><b>${friendly}</b></p>
      ${narrative.length ? `<ul class="field-hint" style="margin:0.4rem 0 0; padding-left:1.1rem;">${narrative.map((l) => `<li>${l}</li>`).join("")}</ul>` : ""}
      <details class="factor-details">
        <summary>Detail technique</summary>
        <p class="field"><b>Code</b><span class="error-code">${code}</span></p>
        ${detail ? `<p class="field-hint">${detail}</p>` : ""}
      </details>
      ${isTechnical ? `<button type="button" class="btn btn-secondary btn-sm" id="retry-btn">Reessayer</button>` : ""}
    </div>
  `;
  if (isTechnical) {
    container.querySelector("#retry-btn").addEventListener("click", onRetry);
  }
}
