// Severity/risk badges always carry a visible text label, never color alone
// (WCAG 1.4.1 — color is not used as the only visual means of conveying info).

export function severityBadge(severity) {
  return `<span class="badge badge-${severity}">${severity}</span>`;
}

export function statePill(mcpState) {
  const labels = {
    COMPLETED: "Termine",
    BLOCKED: "Bloque",
    TECHNICAL_FAILURE: "Echec technique",
  };
  const label = labels[mcpState] || mcpState;
  return `<span class="state-pill state-${mcpState}">${label}</span>`;
}

export function pipelineIndicatorState(status) {
  // idle | running | completed | blocked | failure -> nav dot state + label
  const map = {
    idle: "En attente",
    running: "Analyse en cours",
    completed: "Termine",
    blocked: "Bloque",
    failure: "Echec technique",
  };
  return map[status] || status;
}
