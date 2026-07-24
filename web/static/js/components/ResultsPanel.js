import { severityBadge } from "./StatusBadge.js";

const CISO_ROUTING_LABELS = {
  READY_FOR_CISO_DECISION: "Decision CISO requise",
  READY_FOR_CISO_INFORMATION: "Information / synthese CISO",
  CLOSED_REJECTED: "Rejete",
  CLOSED_INSUFFICIENT_EVIDENCE: "Preuves insuffisantes",
};

const RISK_TREATMENT_TEXT = {
  LOW: "Informationnel : aucune decision CISO requise, simple remarque dans la synthese.",
  MEDIUM: "Point de vigilance : ajoute a la synthese, sans decision CISO immediate necessaire.",
  HIGH: "Decision CISO requise pour ce dossier.",
  CRITICAL: "Decision CISO urgente requise pour ce dossier.",
};

function treatmentClass(routing) {
  if (routing === "READY_FOR_CISO_DECISION") return "treatment-decision";
  if (routing === "CLOSED_REJECTED" || routing === "CLOSED_INSUFFICIENT_EVIDENCE") return "treatment-rejected";
  return "treatment-info";
}

// The routing outcome takes precedence over the raw risk-level guidance: a
// dossier that's REJECTED or INSUFFICIENT_EVIDENCE is closed regardless of
// its numeric score, so it must never be described as needing a CISO
// decision in the same breath as "preuves insuffisantes" / "rejete".
function treatmentNarrative(routing, riskLevel) {
  if (routing === "CLOSED_REJECTED") {
    return "Dossier rejete : le Claim n'est pas confirme par les Evidence disponibles. Aucune decision CISO n'est requise pour ce dossier.";
  }
  if (routing === "CLOSED_INSUFFICIENT_EVIDENCE") {
    return "Preuves insuffisantes pour conclure : le dossier est clos en l'etat, sans decision CISO requise tant que des elements complementaires ne sont pas fournis.";
  }
  return RISK_TREATMENT_TEXT[riskLevel] || "";
}

function factorBar(label, value, max) {
  const negative = value < 0;
  const pct = Math.min(100, (Math.abs(value) / max) * 100);
  return `
    <div class="factor-bar">
      <div class="label">${label}</div>
      <div class="track"><div class="fill ${negative ? "negative" : ""}" style="width:${pct}%"></div></div>
      <div class="value">${value}</div>
    </div>`;
}

const FACTOR_LABELS = {
  severity: "la gravite de l'Evidence principale",
  exposure: "le niveau d'exposition de l'actif concerne",
  impact: "l'impact metier potentiel",
  evidence_quality: "la qualite/completude des preuves",
  verification: "le resultat de la verification",
  contradiction_penalty: "une penalite de contradiction",
};

function dominantFactorExplanation(factors) {
  const entries = Object.entries(factors);
  const [key, value] = entries.reduce((max, entry) => (Math.abs(entry[1]) > Math.abs(max[1]) ? entry : max));
  if (value === 0) return "";
  const label = FACTOR_LABELS[key] || key;
  const sign = value < 0 ? "penalise" : "porte";
  return ` Le facteur le plus determinant est <b>${label}</b> (${value > 0 ? "+" : ""}${value} points), qui ${sign} le plus le score.`;
}

function executiveSummary(result) {
  const { validation_decision: decision, mcp_score: score, ciso_routing: routing } = result;
  return `Le dossier est classe <b>${score.risk_level}</b> (score ${score.value}/100), avec une decision
    <b>${decision.decision}</b>. Statut de routage : <b>${CISO_ROUTING_LABELS[routing] || routing}</b>.
    ${treatmentNarrative(routing, score.risk_level)}${dominantFactorExplanation(score.factors)}`;
}

export function renderResults(container, result) {
  const { claim, verification_result: vr, mcp_score: score, validation_decision: decision, ciso_routing: routing } = result;

  container.innerHTML = `
    <div class="result-card">
      <h3>Synthese executive</h3>
      <p>${executiveSummary(result)}</p>
    </div>

    <div class="result-card">
      <h3>Statut du Verificateur</h3>
      <div class="field"><b>Statut</b>${vr.status}</div>
      <div class="field"><b>Raisonnement</b>${vr.reasoning_summary}</div>
    </div>

    <div class="result-card">
      <h3>MCPScore</h3>
      <div class="score-display">
        <div class="score-number">${score.value}<span style="font-size:1rem; color:var(--muted)">/100</span></div>
        ${severityBadge(score.risk_level)}
        <div class="score-track">
          <div class="score-fill badge-${score.risk_level}-fill" style="width:${score.value}%"></div>
        </div>
      </div>
      <p class="field-hint mt-1">${treatmentNarrative(routing, score.risk_level)}</p>
      <details class="factor-details">
        <summary>Detail des facteurs de score</summary>
        ${factorBar("severity", score.factors.severity, 25)}
        ${factorBar("exposure", score.factors.exposure, 15)}
        ${factorBar("impact", score.factors.impact, 20)}
        ${factorBar("evidence_quality", score.factors.evidence_quality, 15)}
        ${factorBar("verification", score.factors.verification, 20)}
        ${factorBar("contradiction_penalty", score.factors.contradiction_penalty, 30)}
        <p class="field-hint">Version de calcul : ${score.calculation_version}</p>
      </details>
    </div>

    <div class="result-card">
      <h3>Traitement CISO</h3>
      <div class="ciso-treatment ${treatmentClass(routing)}">
        <b>${CISO_ROUTING_LABELS[routing] || routing}</b><br>
        ${treatmentNarrative(routing, score.risk_level)}
      </div>
    </div>

    <div class="result-card">
      <h3>Claim ${claim.id}</h3>
      <div class="field"><b>Affirmation</b>${claim.statement}</div>
      <div class="field"><b>Evidence referencees</b>${claim.evidence_ids.join(", ")}</div>
      <div class="field"><b>Confiance declaree</b>${claim.confidence} <span class="field-hint">(indicative, exclue du calcul du MCPScore)</span></div>
    </div>

    <div class="result-card">
      <h3>Preuves a l'appui / contradictions</h3>
      <div class="field"><b>Preuves a l'appui</b>${vr.supporting_evidence.join(", ") || "-"}</div>
      <div class="field"><b>Preuves contradictoires</b>${vr.contradicting_evidence.join(", ") || "-"}</div>
      <div class="field"><b>Preuves manquantes</b>${vr.missing_evidence.join("; ") || "-"}</div>
    </div>

    <div class="result-card">
      <h3>ValidationDecision ${decision.id}</h3>
      <div class="field"><b>Decision</b>${decision.decision}</div>
      <div class="field"><b>Justification</b>${decision.justification}</div>
      <div class="field"><b>Approbation CISO requise</b>${decision.requires_ciso_approval ? "Oui" : "Non"}</div>
    </div>

    <div class="result-card">
      <h3>Identifiants de session</h3>
      <div class="field"><b>session_id</b>${result.session_id}</div>
      <div class="field"><b>correlation_id</b>${result.correlation_id}</div>
    </div>

    <div class="result-card" id="ciso-actions-card">
      <h3>Decision du CISO</h3>
      <p class="field-hint">Action separee et explicite : le passage a l'etat COMPLETE du pipeline ne vaut pas approbation automatique.</p>
      <div class="ciso-actions">
        <button class="btn btn-secondary btn-sm" data-decision="APPROVE">APPROVE</button>
        <button class="btn btn-secondary btn-sm" data-decision="REJECT">REJECT</button>
        <button class="btn btn-secondary btn-sm" data-decision="REQUEST_MORE_EVIDENCE">REQUEST_MORE_EVIDENCE</button>
        <button class="btn btn-secondary btn-sm" data-decision="DEFER">DEFER</button>
        <span class="ciso-decision-feedback" id="ciso-decision-feedback" role="status" aria-live="polite"></span>
      </div>
    </div>
  `;
}

export function wireCisoActions(container, onDecision) {
  container.querySelectorAll("[data-decision]").forEach((btn) => {
    btn.addEventListener("click", () => onDecision(btn.dataset.decision));
  });
}

export function setCisoActionFeedback(container, message) {
  const el = container.querySelector("#ciso-decision-feedback");
  if (el) el.textContent = message;
}

export function renderTimeline(transitions) {
  return `<ul class="timeline">${(transitions || []).map((t) => `<li>${t}</li>`).join("")}</ul>`;
}
