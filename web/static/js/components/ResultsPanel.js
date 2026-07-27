import { severityBadge } from "./StatusBadge.js";

// Escapes untrusted text (Claim statements, Verifier reasoning, Evidence-derived
// content, CISO justification text) before it is interpolated into innerHTML.
// Evidence/Claim/VerificationResult content is untrusted by design throughout
// this pipeline (see mcp_server/orchestrator.py's injection scanning) -- the
// frontend must not be the one place that trusts it.
function escapeHtml(value) {
  const text = value === null || value === undefined ? "" : String(value);
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// The only four decision/routing values this pipeline can ever produce
// (mcp_server/policy.py). There is no HUMAN_REVIEW: the CISO is the sole human
// decision authority, and every case needing their attention is routed via
// READY_FOR_CISO_DECISION. Exact required CISO-facing wording -- do not use
// "approved", "validated", "human review", "accepted", "auto-approved", or
// "closure confirmed" anywhere in this module.
const CISO_ROUTING_LABELS = {
  READY_FOR_CISO_INFORMATION: "Information disponible — aucune décision demandée",
  READY_FOR_CISO_DECISION: "Décision du CISO requise",
  REJECTED: "Demande rejetée",
  INSUFFICIENT_EVIDENCE: "Preuves insuffisantes",
};

// Unknown/future diagnostic codes must render safely (fall back to the raw code
// string) rather than crash or show "undefined".
const DIAGNOSTIC_WARNING_LABELS = {
  EXPLICIT_ABSENCE_MARKER_DETECTED: "Champ explicitement marque absent detecte",
  POTENTIAL_INTER_EVIDENCE_CONFLICT: "Conflit potentiel entre Evidence detecte",
  VERIFIER_DIAGNOSTIC_DISAGREEMENT: "Desaccord entre le diagnostic deterministe et le Verificateur",
  CONTRADICTION_REQUIRES_CISO_DECISION: "Contradiction necessitant une decision CISO",
  LOW_EVIDENCE_COVERAGE: "Couverture de preuve limitee (Evidence unique)",
  STALE_EVIDENCE: "Evidence potentiellement perimee",
  MISSING_EXPECTED_FIELD: "Champ attendu manquant",
  AMBIGUOUS_EVIDENCE: "Evidence ambigue",
};

const RISK_TREATMENT_TEXT = {
  LOW: "Informationnel : aucune decision CISO requise, simple remarque dans la synthese.",
  MEDIUM: "Point de vigilance : ajoute a la synthese, sans decision CISO immediate necessaire.",
  HIGH: "Decision CISO requise pour ce dossier.",
  CRITICAL: "Decision CISO urgente requise pour ce dossier.",
};

function treatmentClass(routing) {
  if (routing === "READY_FOR_CISO_DECISION") return "treatment-decision";
  if (routing === "REJECTED" || routing === "INSUFFICIENT_EVIDENCE") return "treatment-rejected";
  return "treatment-info";
}

// The routing outcome takes precedence over the raw risk-level guidance: a
// dossier that's REJECTED or INSUFFICIENT_EVIDENCE is closed regardless of its
// numeric score, so it must never be described as needing a CISO decision in
// the same breath as "preuves insuffisantes" / "demande rejetee". Neither of
// these is a final CISO rejection -- both are pipeline recommendations; the
// CISO's own APPROVE/REJECT/REQUEST_MORE_EVIDENCE/DEFER action (below) is the
// only final decision, and READY_FOR_CISO_INFORMATION is never described as an
// approval anywhere in this text.
function treatmentNarrative(routing, riskLevel) {
  if (routing === "REJECTED") {
    return "Recommandation du pipeline : le Claim n'est pas confirme par les Evidence disponibles. Ceci n'est pas un rejet final du CISO ; aucune decision CISO immediate n'est requise pour ce dossier.";
  }
  if (routing === "INSUFFICIENT_EVIDENCE") {
    return "Preuves insuffisantes pour conclure : le dossier est clos en l'etat, sans decision CISO requise tant que des elements complementaires ne sont pas fournis. Le CISO peut demander des preuves supplementaires via REQUEST_MORE_EVIDENCE.";
  }
  if (routing === "READY_FOR_CISO_INFORMATION") {
    return `${RISK_TREATMENT_TEXT[riskLevel] || ""} Information disponible pour le CISO, en lecture seule : aucune decision n'est demandee et aucune action n'a ete prise automatiquement.`;
  }
  return RISK_TREATMENT_TEXT[riskLevel] || "";
}

function factorBar(label, value, max) {
  const negative = value < 0;
  const pct = Math.min(100, (Math.abs(value) / max) * 100);
  return `
    <div class="factor-bar">
      <div class="label">${escapeHtml(label)}</div>
      <div class="track"><div class="fill ${negative ? "negative" : ""}" style="width:${pct}%"></div></div>
      <div class="value">${escapeHtml(value)}</div>
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
  return ` Le facteur le plus determinant est <b>${escapeHtml(label)}</b> (${value > 0 ? "+" : ""}${value} points), qui ${sign} le plus le score.`;
}

function executiveSummary(result) {
  const { validation_decision: decision, mcp_score: score, ciso_routing: routing } = result;
  const routingLabel = CISO_ROUTING_LABELS[routing] || escapeHtml(routing);
  return `Le dossier est classe <b>${escapeHtml(score.risk_level)}</b> (score ${score.value}/100). Statut de routage :
    <b>${routingLabel}</b>.
    ${treatmentNarrative(routing, score.risk_level)}${dominantFactorExplanation(score.factors)}`;
}

// READY_FOR_CISO_DECISION is the ONLY routing where a CISO action is actually
// pending -- REJECTED/INSUFFICIENT_EVIDENCE/READY_FOR_CISO_INFORMATION must
// never offer an action button (spec 5.2): the first two are pipeline
// recommendations already closed pending more evidence or reconsideration, the
// third is explicitly read-only information, never an approval.
function cisoActionsCard(routing) {
  if (routing === "READY_FOR_CISO_DECISION") {
    return `
    <div class="result-card" id="ciso-actions-card">
      <h3>Decision du CISO requise</h3>
      <p class="field-hint">Action separee et explicite : le passage a l'etat COMPLETE du pipeline ne vaut pas approbation automatique. Aucune remediation ni action sensible n'est jamais effectuee automatiquement.</p>
      <div class="ciso-actions">
        <button class="btn btn-secondary btn-sm" data-decision="APPROVE">APPROVE</button>
        <button class="btn btn-secondary btn-sm" data-decision="REJECT">REJECT</button>
        <button class="btn btn-secondary btn-sm" data-decision="REQUEST_MORE_EVIDENCE">REQUEST_MORE_EVIDENCE</button>
        <button class="btn btn-secondary btn-sm" data-decision="DEFER">DEFER</button>
        <span class="ciso-decision-feedback" id="ciso-decision-feedback" role="status" aria-live="polite"></span>
      </div>
    </div>`;
  }
  if (routing === "READY_FOR_CISO_INFORMATION") {
    return `
    <div class="result-card" id="ciso-actions-card">
      <h3>Information — lecture seule</h3>
      <p class="field-hint">Ce dossier est inclus dans la synthese d'information du CISO. Aucune decision n'est demandee et aucun bouton d'action n'est propose pour ce dossier.</p>
    </div>`;
  }
  return `
    <div class="result-card" id="ciso-actions-card">
      <h3>Dossier clos par le pipeline</h3>
      <p class="field-hint">Recommandation du pipeline, pas une decision finale du CISO. Le CISO peut demander des preuves complementaires ou reconsiderer ce dossier via un nouveau traitement.</p>
    </div>`;
}

export function renderResults(container, result) {
  const { claim, verification_result: vr, mcp_score: score, validation_decision: decision, ciso_routing: routing } = result;
  const decisionLabel = CISO_ROUTING_LABELS[decision.decision] || escapeHtml(decision.decision);

  container.innerHTML = `
    <div class="result-card">
      <h3>Synthese executive</h3>
      <p>${executiveSummary(result)}</p>
    </div>

    <div class="result-card">
      <h3>Verdict du Verificateur</h3>
      <p class="field-hint">Seule autorite sur ce statut : jamais reecrit par les diagnostics ou la politique.</p>
      <div class="field"><b>Statut</b>${escapeHtml(vr.status)}</div>
      <div class="field"><b>Raisonnement</b>${escapeHtml(vr.reasoning_summary)}</div>
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
        <p class="field-hint">Version de calcul : ${escapeHtml(score.calculation_version)}</p>
      </details>
    </div>

    <div class="result-card">
      <h3>Traitement CISO</h3>
      <div class="ciso-treatment ${treatmentClass(routing)}">
        <b>${CISO_ROUTING_LABELS[routing] || escapeHtml(routing)}</b><br>
        ${treatmentNarrative(routing, score.risk_level)}
      </div>
    </div>

    <div class="result-card">
      <h3>Claim ${escapeHtml(claim.id)}</h3>
      <div class="field"><b>Affirmation</b>${escapeHtml(claim.statement)}</div>
      <div class="field"><b>Evidence referencees</b>${escapeHtml(claim.evidence_ids.join(", "))}</div>
      <div class="field"><b>Confiance declaree</b>${escapeHtml(claim.confidence)} <span class="field-hint">(indicative, exclue du calcul du MCPScore)</span></div>
    </div>

    <div class="result-card">
      <h3>Preuves a l'appui / contradictions</h3>
      <div class="field"><b>Preuves a l'appui</b>${escapeHtml(vr.supporting_evidence.join(", ")) || "-"}</div>
      <div class="field"><b>Preuves contradictoires</b>${escapeHtml(vr.contradicting_evidence.join(", ")) || "-"}</div>
      <div class="field"><b>Preuves manquantes</b>${escapeHtml(vr.missing_evidence.join("; ")) || "-"}</div>
    </div>

    <div class="result-card">
      <h3>Diagnostics deterministes</h3>
      <p class="field-hint">Signaux avertisseurs derives des Evidence, sans jamais reecrire le statut du Verificateur. Signaux consultatifs uniquement — ce ne sont pas un second verdict.</p>
      ${
        (decision.diagnostic_warnings || []).length
          ? `<ul>${decision.diagnostic_warnings.map((w) => `<li>${escapeHtml(DIAGNOSTIC_WARNING_LABELS[w] || w)}</li>`).join("")}</ul>`
          : `<p class="field-hint">Aucun avertissement diagnostique.</p>`
      }
    </div>

    <div class="result-card">
      <h3>ValidationDecision ${escapeHtml(decision.id)}</h3>
      <div class="field"><b>Decision</b>${decisionLabel}</div>
      <div class="field"><b>Justification</b>${escapeHtml(decision.justification)}</div>
      <div class="field"><b>Approbation CISO requise</b>${decision.requires_ciso_approval ? "Oui" : "Non"}</div>
      <div class="field"><b>Regle de politique</b>${escapeHtml(decision.policy_rule || "-")}</div>
      ${decision.policy_version ? `<div class="field"><b>Version de politique</b>${escapeHtml(decision.policy_version)}</div>` : ""}
    </div>

    <div class="result-card">
      <h3>Identifiants de session</h3>
      <div class="field"><b>session_id</b>${escapeHtml(result.session_id)}</div>
      <div class="field"><b>correlation_id</b>${escapeHtml(result.correlation_id)}</div>
    </div>

    ${cisoActionsCard(routing)}
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
  return `<ul class="timeline">${(transitions || []).map((t) => `<li>${escapeHtml(t)}</li>`).join("")}</ul>`;
}
