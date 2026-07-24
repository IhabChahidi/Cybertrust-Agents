const TYPES = ["ticket", "report", "scan_result", "audit_record", "validation_record"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function renderEvidenceFilters(container, state, { onChange, onSelectAllVisible, onClearSelection }) {
  container.innerHTML = `
    <div class="evidence-toolbar">
      <div class="field-group">
        <label for="evd-search">Recherche</label>
        <input type="search" id="evd-search" placeholder="ID ou resume..." value="${state.filters.search}">
      </div>
      <div class="field-group">
        <label for="evd-type">Type</label>
        <select id="evd-type">
          <option value="ALL">Tous</option>
          ${TYPES.map((t) => `<option value="${t}" ${state.filters.type === t ? "selected" : ""}>${t}</option>`).join("")}
        </select>
      </div>
      <div class="field-group">
        <label for="evd-severity">Severite</label>
        <select id="evd-severity">
          <option value="ALL">Toutes</option>
          ${SEVERITIES.map((s) => `<option value="${s}" ${state.filters.severity === s ? "selected" : ""}>${s}</option>`).join("")}
        </select>
      </div>
      <div class="field-group">
        <label for="evd-selection">Selection</label>
        <select id="evd-selection">
          <option value="ALL" ${state.filters.selection === "ALL" ? "selected" : ""}>Toutes</option>
          <option value="SELECTED" ${state.filters.selection === "SELECTED" ? "selected" : ""}>Selectionnees</option>
          <option value="UNSELECTED" ${state.filters.selection === "UNSELECTED" ? "selected" : ""}>Non selectionnees</option>
        </select>
      </div>
      <div class="toolbar-actions">
        <button type="button" class="btn btn-secondary btn-sm" id="select-all-visible">Selectionner la vue</button>
        <button type="button" class="btn btn-secondary btn-sm" id="clear-selection">Effacer la selection</button>
      </div>
    </div>
  `;

  container.querySelector("#evd-search").addEventListener("input", (e) => {
    state.filters.search = e.target.value;
    onChange();
  });
  container.querySelector("#evd-type").addEventListener("change", (e) => {
    state.filters.type = e.target.value;
    onChange();
  });
  container.querySelector("#evd-severity").addEventListener("change", (e) => {
    state.filters.severity = e.target.value;
    onChange();
  });
  container.querySelector("#evd-selection").addEventListener("change", (e) => {
    state.filters.selection = e.target.value;
    onChange();
  });
  container.querySelector("#select-all-visible").addEventListener("click", onSelectAllVisible);
  container.querySelector("#clear-selection").addEventListener("click", onClearSelection);
}

export function applyEvidenceFilters(state) {
  const { search, type, severity, selection } = state.filters;
  const q = search.trim().toLowerCase();

  let items = state.evidence.filter((e) => {
    if (type !== "ALL" && e.type !== type) return false;
    if (severity !== "ALL" && e.severity !== severity) return false;
    const isSelected = state.selection.has(e.id);
    if (selection === "SELECTED" && !isSelected) return false;
    if (selection === "UNSELECTED" && isSelected) return false;
    if (q && !(e.id.toLowerCase().includes(q) || e.summary.toLowerCase().includes(q))) return false;
    return true;
  });

  const { key, dir } = state.sort;
  const severityRank = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
  items = items.slice().sort((a, b) => {
    let cmp = 0;
    if (key === "severity") cmp = severityRank[a.severity] - severityRank[b.severity];
    else if (key === "type") cmp = a.type.localeCompare(b.type);
    else cmp = a.id.localeCompare(b.id);
    return dir === "asc" ? cmp : -cmp;
  });

  return items;
}
