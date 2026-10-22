/**
 * Thin wrapper over the account HTTP API.
 *
 * The session cookie is HTTP-only and sent automatically for same-origin
 * requests, so nothing here handles tokens.
 */

async function call(path, { method = "GET", body } = {}) {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    // Some responses have no body.
  }

  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : null;
    const error = new Error(detail || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}

export const api = {
  register: (username, password, identityPublic) =>
    call("/api/register", { method: "POST", body: { username, password, identityPublic } }),
  login: (username, password) =>
    call("/api/login", { method: "POST", body: { username, password } }),
  logout: () => call("/api/logout", { method: "POST" }),
  me: () => call("/api/me"),
  users: () => call("/api/users"),
  setIdentity: (identityPublic) =>
    call("/api/identity", { method: "POST", body: { identityPublic } }),
};
