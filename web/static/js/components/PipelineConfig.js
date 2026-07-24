import { ENDPOINT_LABELS, LLM_MODE_LABELS } from "../state.js";

export function renderPipelineConfig(container, state, { onChange }) {
  const modes = state.config.llm_modes.length ? state.config.llm_modes : [state.llmMode];
  const endpoints = state.config.endpoints.length ? state.config.endpoints : [state.endpoint];

  container.innerHTML = `
    <p class="panel-helper">Choisissez comment le pipeline doit executer les roles Generateur / Verificateur / Validateur.</p>

    <div class="form-row">
      <div>
        <label for="llm-mode">Mode d'execution</label>
        <select id="llm-mode">
          ${modes.map((m) => `<option value="${m}" ${state.llmMode === m ? "selected" : ""}>${LLM_MODE_LABELS[m] || m}</option>`).join("")}
        </select>
        <p class="field-hint" id="llm-mode-hint"></p>
      </div>
      <div>
        <label for="endpoint">Role / point d'entree</label>
        <select id="endpoint">
          ${endpoints.map((e) => `<option value="${e}" ${state.endpoint === e ? "selected" : ""}>${ENDPOINT_LABELS[e] || e}</option>`).join("")}
        </select>
        <p class="field-hint">Le libelle est ajuste au modele configure ; la valeur transmise a l'API reste inchangee.</p>
      </div>
    </div>

    <div class="info-banner" role="note">
      <span class="icon" aria-hidden="true">ℹ️</span>
      <span>
        <strong>Mock</strong> utilise des heuristiques deterministes, sans appel a un modele — resultats instantanes, ideal pour les tests.
        <strong>Live</strong> invoque les points de terminaison LLM configures (modele local ou fournisseur externe) — les temps de reponse peuvent atteindre 1 a 2 minutes.
      </span>
    </div>
  `;

  const modeSelect = container.querySelector("#llm-mode");
  const modeHint = container.querySelector("#llm-mode-hint");

  function updateHint() {
    modeHint.textContent =
      modeSelect.value === "mock"
        ? "Aucun appel externe : reponses immediates, comportement reproductible."
        : "Appelle un modele reel : le delai depend du fournisseur/modele configure.";
  }
  updateHint();

  modeSelect.addEventListener("change", () => {
    state.llmMode = modeSelect.value;
    updateHint();
    onChange();
  });
  container.querySelector("#endpoint").addEventListener("change", (e) => {
    state.endpoint = e.target.value;
    onChange();
  });
}
