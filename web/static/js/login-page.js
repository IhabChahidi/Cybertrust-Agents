import { login } from "./auth.js";
import { ApiError } from "./api.js";

const form = document.getElementById("login-form");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const toggleBtn = document.getElementById("toggle-password");
const submitBtn = document.getElementById("login-submit");
const spinner = document.getElementById("login-spinner");
const btnLabel = document.getElementById("login-btn-label");
const errorBox = document.getElementById("form-error");
const flashBox = document.getElementById("flash-message");

function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
}
function hideError() {
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
}

function setLoading(isLoading) {
  submitBtn.disabled = isLoading;
  spinner.classList.toggle("hidden", !isLoading);
  btnLabel.textContent = isLoading ? "Connexion en cours..." : "Se connecter";
}

function init() {
  const flash = sessionStorage.getItem("mcp_flash_message");
  if (flash) {
    flashBox.textContent = flash;
    flashBox.classList.remove("hidden");
    sessionStorage.removeItem("mcp_flash_message");
  }
}

toggleBtn.addEventListener("click", () => {
  const isPassword = passwordInput.type === "password";
  passwordInput.type = isPassword ? "text" : "password";
  toggleBtn.textContent = isPassword ? "Masquer" : "Afficher";
  toggleBtn.setAttribute("aria-pressed", String(isPassword));
  toggleBtn.setAttribute("aria-label", isPassword ? "Masquer le mot de passe" : "Afficher le mot de passe");
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError();

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    showError("Merci de renseigner l'identifiant et le mot de passe.");
    return;
  }

  setLoading(true);
  try {
    await login(username, password);
    const params = new URLSearchParams(location.search);
    const returnTo = params.get("returnTo") || "/";
    location.href = returnTo.startsWith("/") ? returnTo : "/";
  } catch (err) {
    if (err instanceof ApiError) {
      showError(err.detail || "Identifiants invalides");
    } else {
      showError("Erreur de connexion au serveur. Reessayez.");
    }
    setLoading(false);
  }
});

init();
