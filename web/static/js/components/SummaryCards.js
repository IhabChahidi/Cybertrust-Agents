export function renderSummaryCards(container, state) {
  const total = state.evidence.length;
  const selected = state.selection.size;
  const criticalHigh = state.evidence.filter(
    (e) => e.severity === "CRITICAL" || e.severity === "HIGH"
  ).length;
  const modeLabel = state.llmMode === "mock" ? "Mock" : "Live";

  let readiness = "Selection requise";
  if (selected > 0 && state.statement.trim() === "") readiness = "Requete requise";
  else if (selected > 0 && state.statement.trim() !== "") readiness = "Pret pour analyse";

  container.innerHTML = `
    <div class="summary-card">
      <div class="label">Total Evidence</div>
      <div class="value">${total}</div>
    </div>
    <div class="summary-card">
      <div class="label">Evidence selectionnees</div>
      <div class="value">${selected}</div>
    </div>
    <div class="summary-card">
      <div class="label">Critique / Haute</div>
      <div class="value">${criticalHigh}</div>
      <div class="sub">sur ${total} au catalogue</div>
    </div>
    <div class="summary-card">
      <div class="label">Mode courant</div>
      <div class="value">${modeLabel}</div>
    </div>
    <div class="summary-card">
      <div class="label">Etat de preparation</div>
      <div class="value" style="font-size:1.05rem">${readiness}</div>
    </div>
  `;
}
