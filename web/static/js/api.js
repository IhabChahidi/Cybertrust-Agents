// Thin fetch wrapper: attaches the in-memory CSRF token to state-changing
// requests, and centralizes 401/403 handling so every caller gets the same
// "session expired" / "access denied" behavior without repeating it.
//
// The session token itself lives only in an HttpOnly cookie the browser sends
// automatically — this module never reads or stores it. The CSRF token is not
// a secret on its own (it only prevents cross-site request forgery against the
// cookie), but it is still kept in memory only, never in localStorage.

let csrfToken = null;
// Tracks whether this tab ever held an authenticated session. A 401 before
// that has happened just means "not logged in yet" — not an expired session
// — so the two cases must not show the same "your session expired" message.
let hadSession = false;

export function setCsrfToken(token) {
  csrfToken = token;
  hadSession = true;
}

export function clearClientState() {
  csrfToken = null;
  hadSession = false;
  sessionStorage.removeItem("mcp_flash_message");
}

function redirectToLogin(message) {
  clearClientState();
  if (message) sessionStorage.setItem("mcp_flash_message", message);
  const returnTo = encodeURIComponent(location.pathname + location.search);
  if (!location.pathname.endsWith("/login.html")) {
    location.href = `/login.html?returnTo=${returnTo}`;
  }
}

function redirectToAccessDenied() {
  clearClientState();
  location.href = "/access-denied.html";
}

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `Erreur HTTP ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

export async function apiFetch(path, { method = "GET", body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    // Only claim the session "expired" if this tab actually held one — a
    // first-ever, never-authenticated visit is not an expiry and shouldn't
    // be described as one.
    redirectToLogin(hadSession ? "Votre session a expire. Merci de vous reconnecter." : null);
    throw new ApiError(401, "Session expiree");
  }
  if (res.status === 403) {
    let detail = "Action non autorisee.";
    try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
    // Two different things share this status code: a stale/missing CSRF token
    // (recoverable — the caller can just retry the action) and a genuine
    // role-based denial (not recoverable — the account itself lacks rights).
    // Only the latter sends the user to the dedicated Access Denied page.
    if (/r[oô]le/i.test(detail)) {
      redirectToAccessDenied();
    }
    throw new ApiError(403, detail);
  }
  if (!res.ok) {
    let detail = `Erreur HTTP ${res.status}`;
    try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

export function goToAccessDenied() {
  redirectToAccessDenied();
}
