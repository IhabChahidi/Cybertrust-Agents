import { pipelineIndicatorState } from "./StatusBadge.js";

export function renderHeader(container, { user, pipelineStatus, onLogout }) {
  container.innerHTML = `
    <div class="brand">
      <span>CyberTrust Agents</span>
      <span class="product-suffix">MCP Dashboard</span>
    </div>
    <span class="env-badge">Pilote SecOps</span>
    <div class="topnav-spacer"></div>
    <div class="pipeline-indicator" id="nav-pipeline-indicator" data-state="${pipelineStatus}">
      <span class="dot" aria-hidden="true"></span>
      <span id="nav-pipeline-label">${pipelineIndicatorState(pipelineStatus)}</span>
    </div>
    <div class="nav-user">
      <span>${user ? user.username : ""}</span>
      ${user ? `<span class="role-chip">${user.role}</span>` : ""}
      <button type="button" class="btn-logout" id="logout-btn">Se deconnecter</button>
    </div>
  `;
  container.querySelector("#logout-btn").addEventListener("click", onLogout);
}

export function updatePipelineIndicator(status) {
  const indicator = document.getElementById("nav-pipeline-indicator");
  const label = document.getElementById("nav-pipeline-label");
  if (!indicator || !label) return;
  indicator.dataset.state = status;
  label.textContent = pipelineIndicatorState(status);
}
