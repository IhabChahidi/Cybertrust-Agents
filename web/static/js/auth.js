// Auth actions: login, logout, session check. Talks to the backend session
// endpoints in web/backend.py (POST /api/auth/login|logout, GET /api/auth/me).

import { apiFetch, ApiError, setCsrfToken, clearClientState } from "./api.js";

export async function login(username, password) {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    let detail = "Identifiants invalides";
    try { detail = (await res.json()).detail || detail; } catch { /* ignore */ }
    throw new ApiError(res.status, detail);
  }
  const session = await res.json();
  setCsrfToken(session.csrf_token);
  return session;
}

export async function fetchMe() {
  const session = await apiFetch("/api/auth/me");
  setCsrfToken(session.csrf_token);
  return session;
}

export async function logout() {
  try {
    await apiFetch("/api/auth/logout", { method: "POST", body: {} });
  } finally {
    clearClientState();
  }
}
