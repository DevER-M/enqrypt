/**
 * Verification pins.
 *
 * For each contact we remember the identity public key we saw first. If it ever
 * changes, the UI warns loudly. Marking a contact "verified" says the user
 * compared the verification code out of band. Pins live in localStorage; they
 * are a local trust decision, not something the server can alter.
 */

const STORAGE_KEY = "enc:pins";

function load() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function save(pins) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(pins));
  } catch {
    // Storage unavailable or full: verification still works for this visit.
  }
}

export function pinStatus(peer, publicKey) {
  const record = load()[peer.toLowerCase()];
  if (!record) return { state: "new", verified: false };
  if (record.key !== publicKey) return { state: "changed", verified: false };
  return { state: "same", verified: Boolean(record.verified) };
}

export function pin(peer, publicKey) {
  const pins = load();
  const key = peer.toLowerCase();
  const existing = pins[key];
  if (!existing || existing.key !== publicKey) {
    pins[key] = { key: publicKey, verified: false, at: new Date().toISOString() };
    save(pins);
  }
}

export function markVerified(peer, publicKey) {
  const pins = load();
  pins[peer.toLowerCase()] = {
    key: publicKey,
    verified: true,
    at: new Date().toISOString(),
  };
  save(pins);
}
