const MAX_CHARS = 1000; // mirrors the Claim.statement schema maxLength server-side
const EXAMPLE_PROMPTS = [
  "Les tickets critiques sont-ils tous clotures avec une preuve suffisante ?",
  "Quelles vulnerabilites prioritaires restent non remediees ?",
  "Quelles actions d'audit sont encore ouvertes ou partiellement traitees ?",
];

export function renderCisoRequestForm(container, state, { onChange }) {
  container.innerHTML = `
    <p class="panel-helper">
      Formulez la question ou l'affirmation a analyser par le pipeline MCP a partir des Evidence selectionnees.
    </p>

    <div class="example-prompts" role="group" aria-label="Exemples de requetes">
      ${EXAMPLE_PROMPTS.map((p, i) => `<button type="button" class="chip-btn" data-example="${i}">${p}</button>`).join("")}
    </div>

    <label for="ciso-statement">Question / affirmation</label>
    <textarea id="ciso-statement" rows="3" maxlength="${MAX_CHARS}"
      aria-describedby="ciso-char-counter ciso-selection-count"
      placeholder="Ex : le ticket SEC-1452 a-t-il ete correctement remedie ?">${state.statement}</textarea>
    <div id="ciso-char-counter" class="char-counter">${state.statement.length} / ${MAX_CHARS}</div>

    <p id="ciso-selection-count" class="selection-count">
      <strong>${state.selection.size}</strong> Evidence selectionnee(s) pour cette requete.
    </p>

    <div id="ciso-validation" class="validation-message hidden" role="alert" aria-live="polite"></div>
  `;

  const textarea = container.querySelector("#ciso-statement");
  const counter = container.querySelector("#ciso-char-counter");

  textarea.addEventListener("input", () => {
    state.statement = textarea.value;
    counter.textContent = `${textarea.value.length} / ${MAX_CHARS}`;
    counter.classList.toggle("warn", textarea.value.length > MAX_CHARS * 0.9);
    onChange();
  });

  container.querySelectorAll("[data-example]").forEach((btn) => {
    btn.addEventListener("click", () => {
      textarea.value = EXAMPLE_PROMPTS[Number(btn.dataset.example)];
      state.statement = textarea.value;
      counter.textContent = `${textarea.value.length} / ${MAX_CHARS}`;
      onChange();
    });
  });
}

export function showValidationMessage(container, message) {
  const box = container.querySelector("#ciso-validation");
  if (!box) return;
  if (!message) {
    box.classList.add("hidden");
    box.textContent = "";
    return;
  }
  box.textContent = message;
  box.classList.remove("hidden");
}

export function renderConfirmSummary(state, endpointLabel, modeLabel) {
  return `
    <div class="confirm-summary">
      <dl>
        <dt>Requete</dt><dd>${state.statement}</dd>
        <dt>Evidence</dt><dd>${state.selection.size} selectionnee(s) : ${Array.from(state.selection).join(", ")}</dd>
        <dt>Mode</dt><dd>${modeLabel}</dd>
        <dt>Endpoint</dt><dd>${endpointLabel}</dd>
      </dl>
    </div>
  `;
}
