import { severityBadge } from "./StatusBadge.js";
import { applyEvidenceFilters } from "./EvidenceFilters.js";

function sortIndicator(state, key) {
  if (state.sort.key !== key) return "";
  return state.sort.dir === "asc" ? " ▲" : " ▼";
}

export function renderEvidenceTable(container, state, { onToggleSelect, onToggleExpand, onSort, fetchDetail }) {
  const rows = applyEvidenceFilters(state);

  if (rows.length === 0) {
    container.innerHTML = `<p class="panel-helper">Aucune Evidence ne correspond aux filtres actuels.</p>`;
    return;
  }

  const bodyRows = rows
    .map((e) => {
      const selected = state.selection.has(e.id);
      const expanded = state.expandedRows.has(e.id);
      const rowHtml = `
        <tr class="${selected ? "selected" : ""}" data-evd-row="${e.id}">
          <td data-label="Selection">
            <input type="checkbox" data-evd-checkbox="${e.id}" ${selected ? "checked" : ""}
                   aria-label="Selectionner ${e.id}">
          </td>
          <td data-label="ID">${e.id}</td>
          <td data-label="Type">${e.type}</td>
          <td data-label="Severite">${severityBadge(e.severity)}</td>
          <td data-label="Resume" class="col-summary">${e.summary}</td>
          <td data-label="Detail">
            <button type="button" class="row-detail-toggle" data-evd-toggle="${e.id}"
                    aria-expanded="${expanded}">
              ${expanded ? "Masquer" : "Details"}
            </button>
          </td>
        </tr>
      `;
      const detailHtml = expanded
        ? `<tr class="row-detail"><td colspan="6" data-evd-detail="${e.id}">Chargement des details...</td></tr>`
        : "";
      return rowHtml + detailHtml;
    })
    .join("");

  container.innerHTML = `
    <div class="table-scroll">
      <table class="evidence-table">
        <caption class="sr-only">Catalogue des Evidence disponibles pour le pipeline MCP</caption>
        <thead>
          <tr>
            <th scope="col"><span class="sr-only">Selection</span></th>
            <th scope="col" data-sort="id" tabindex="0" role="button" aria-sort="${state.sort.key === "id" ? state.sort.dir + "ending" : "none"}">ID${sortIndicator(state, "id")}</th>
            <th scope="col" data-sort="type" tabindex="0" role="button" aria-sort="${state.sort.key === "type" ? state.sort.dir + "ending" : "none"}">Type${sortIndicator(state, "type")}</th>
            <th scope="col" data-sort="severity" tabindex="0" role="button" aria-sort="${state.sort.key === "severity" ? state.sort.dir + "ending" : "none"}">Severite${sortIndicator(state, "severity")}</th>
            <th scope="col">Resume</th>
            <th scope="col"><span class="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody>${bodyRows}</tbody>
      </table>
    </div>
  `;

  container.querySelectorAll("[data-evd-checkbox]").forEach((cb) => {
    cb.addEventListener("change", () => onToggleSelect(cb.dataset.evdCheckbox));
  });
  container.querySelectorAll("[data-evd-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => onToggleExpand(btn.dataset.evdToggle));
  });
  container.querySelectorAll("[data-sort]").forEach((th) => {
    const activate = () => onSort(th.dataset.sort);
    th.addEventListener("click", activate);
    th.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activate(); }
    });
  });

  // Lazily fill in expanded-row details.
  rows.forEach((e) => {
    if (!state.expandedRows.has(e.id)) return;
    const cell = container.querySelector(`[data-evd-detail="${e.id}"]`);
    if (!cell) return;
    fetchDetail(e.id).then((detail) => {
      if (!detail) { cell.textContent = "Impossible de charger le detail."; return; }
      cell.innerHTML = `
        <dl>
          <dt>Source</dt><dd>${detail.source}</dd>
          <dt>Date</dt><dd>${detail.date}</dd>
          <dt>Actifs concernes</dt><dd>${(detail.content.affected_assets || []).join(", ") || "-"}</dd>
          <dt>Indicateurs</dt><dd>${(detail.content.indicators || []).join(", ") || "-"}</dd>
          <dt>Donnees brutes</dt><dd class="raw-data">${detail.content.raw_data}</dd>
        </dl>
      `;
    });
  });
}
