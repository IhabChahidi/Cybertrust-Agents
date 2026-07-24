// Single shared state object. Every component reads from this and main.js
// re-renders the affected components after a mutation — avoids each module
// keeping its own duplicate copy of the same data.

export const state = {
  user: null, // { username, role }

  evidence: [], // [{id, type, severity, summary}]
  evidenceDetailsCache: {}, // id -> full Evidence object (fetched lazily on row expand)
  selection: new Set(),
  expandedRows: new Set(),
  filters: { search: "", type: "ALL", severity: "ALL", selection: "ALL" },
  sort: { key: "id", dir: "asc" },

  statement: "",
  llmMode: "mock",
  endpoint: "GENERATOR_COPILOT_STUDIO",
  config: { llm_modes: [], endpoints: [] },

  pendingConfirm: false,

  pipeline: { status: "idle", stage: null }, // idle | running | completed | blocked | failure
  lastResult: null,
  journal: [],
};

export function resetDashboardState() {
  state.user = null;
  state.evidence = [];
  state.evidenceDetailsCache = {};
  state.selection = new Set();
  state.expandedRows = new Set();
  state.filters = { search: "", type: "ALL", severity: "ALL", selection: "ALL" };
  state.statement = "";
  state.pendingConfirm = false;
  state.pipeline = { status: "idle", stage: null };
  state.lastResult = null;
  state.journal = [];
}

// Human-readable labels for machine values. Data-driven (not hardcoded to a
// single provider) so swapping the Generator's backing model (e.g. to Llama 3)
// only requires updating this map, not the markup.
export const ENDPOINT_LABELS = {
  GENERATOR_COPILOT_STUDIO: "Generateur (LLM de generation des Claims)",
  VERIFIER_EXTERNAL_LLM: "Verificateur (LLM externe de verification)",
  VALIDATOR_EXTERNAL_LLM: "Validateur (LLM externe de decision)",
};

export const LLM_MODE_LABELS = {
  mock: "Mock — heuristiques deterministes",
  llama: "Live — modele local (Ollama)",
  real: "Live — fournisseur externe configure",
};

export const PIPELINE_STAGES = [
  { key: "VALIDATION_ENTREE", label: "Validation de l'entree" },
  { key: "SELECTION_EVIDENCE", label: "Selection des Evidence" },
  { key: "GENERATION_CLAIM", label: "Generation du Claim" },
  { key: "VERIFICATION", label: "Verification" },
  { key: "SCORING", label: "Calcul du MCPScore" },
  { key: "VALIDATION", label: "Validation" },
  { key: "DECISION_CISO", label: "Preparation de la synthese CISO" },
];

export function stageLabel(stageKey) {
  const stage = PIPELINE_STAGES.find((s) => s.key === stageKey);
  return stage ? stage.label : stageKey;
}
