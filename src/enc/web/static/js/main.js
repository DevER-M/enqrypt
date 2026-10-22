/**
 * UI controller.
 *
 * Plaintext lives here and in the DOM; the Connection only moves public keys
 * and ciphertext. One Session per peer, created when a conversation is opened
 * and torn down when the peer leaves or the handshake fails.
 *
 * Accounts are managed over HTTP (api.js) and the session cookie authenticates
 * the websocket, so there is no join step: the server knows who is connecting.
 */

import { api } from "./api.js";
import { Connection } from "./connection.js";
import { History } from "./history.js";
import { HANDSHAKE_TIMEOUT_MS, Session, State } from "./session.js";
import { Identity, loadIdentity, saveIdentity } from "./identity.js";
import {
  MAX_TEXT_BYTES,
  b64decode,
  verifyCode,
} from "./crypto.js";
import { markVerified, pinStatus, pin } from "./verify.js";

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,32}$/;
const MAX_RENDERED = 500;
// Web-safe, maximum-saturation colours: white initials stay readable on all of
// them, and they read as 90s system accents rather than a modern palette.
const AVATAR_COLORS = [
  "bg-titlebar",
  "bg-teal",
  "bg-purple",
  "bg-green",
  "bg-blue",
  "bg-maroon",
  "bg-olive",
  "bg-dim",
];

const $ = (id) => document.getElementById(id);
const els = {
  authScreen: $("auth-screen"),
  tabLogin: $("tab-login"),
  tabRegister: $("tab-register"),
  authForm: $("auth-form"),
  authUsername: $("auth-username"),
  authPassword: $("auth-password"),
  authConfirm: $("auth-confirm"),
  confirmField: $("confirm-field"),
  authSubmit: $("auth-submit"),
  authError: $("auth-error"),
  app: $("app"),
  sidebar: $("sidebar"),
  chat: $("chat"),
  meAvatar: $("me-avatar"),
  meName: $("me-name"),
  connDot: $("conn-dot"),
  connLabel: $("conn-label"),
  identityButton: $("identity-button"),
  logoutButton: $("logout-button"),
  userSearch: $("user-search"),
  userList: $("user-list"),
  chatBack: $("chat-back"),
  chatAvatar: $("chat-avatar"),
  chatPeer: $("chat-peer"),
  verifyBadge: $("verify-badge"),
  chatStatus: $("chat-status"),
  verifyButton: $("verify-button"),
  retrySession: $("retry-session"),
  messages: $("messages"),
  typing: $("typing"),
  composer: $("composer"),
  input: $("input"),
  sendButton: $("send-button"),
  identityPanel: $("identity-panel"),
  identityTitle: $("identity-title"),
  identityCurrent: $("identity-current"),
  identityFingerprint: $("identity-fingerprint"),
  identityExport: $("identity-export"),
  identityCopy: $("identity-copy"),
  identityImport: $("identity-import"),
  identityImportButton: $("identity-import-button"),
  identityCreate: $("identity-create"),
  identityAdopt: $("identity-adopt"),
  identityMessage: $("identity-message"),
  identityClose: $("identity-close"),
  verifyPanel: $("verify-panel"),
  verifyPeer: $("verify-peer"),
  verifyState: $("verify-state"),
  verifyCode: $("verify-code"),
  verifyWarning: $("verify-warning"),
  verifyMark: $("verify-mark"),
  verifyClose: $("verify-close"),
  toast: $("toast"),
};

const app = {
  me: "",
  account: null,
  identity: null,
  authMode: "login",
  connection: null,
  history: null,
  directory: new Map(),
  online: new Set(),
  sessions: new Map(),
  messages: new Map(),
  historyLoaded: new Set(),
  historyLoads: new Map(),
  unread: new Map(),
  typingPeers: new Set(),
  typingTimers: new Map(),
  timers: new Map(),
  refreshTimer: null,
  current: null,
  search: "",
  starting: false,
};

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

function nowIso() {
  return new Date().toISOString();
}

function colorFor(name) {
  let hash = 0;
  for (const character of name) hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  return AVATAR_COLORS[hash % AVATAR_COLORS.length];
}

function initials(name) {
  const parts = String(name).split(/[^A-Za-z0-9]+/).filter(Boolean);
  if (parts.length === 0) return String(name).slice(0, 2).toUpperCase();
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[1][0]).toUpperCase();
}

function makeAvatar(name) {
  const node = document.createElement("span");
  node.className = `avatar ${colorFor(name)}`;
  node.textContent = initials(name);
  return node;
}

function setAvatar(node, name) {
  node.className = name ? `avatar ${colorFor(name)}` : "avatar";
  node.textContent = name ? initials(name) : "";
}

function makePresence(online) {
  const node = document.createElement("span");
  node.className = "user-presence";
  node.dataset.online = String(Boolean(online));
  return node;
}

function prefersInitiator(peer) {
  return app.me.toLowerCase() < peer.toLowerCase();
}

function messageEntry(direction, text) {
  return { kind: "message", direction, text, at: nowIso() };
}

function systemEntry(text, isError) {
  return { kind: "system", text, error: Boolean(isError), at: nowIso() };
}

function makeControl(kind, me, peer, payload) {
  return { version: 1, kind, from: me, to: peer, session: null, payload };
}

let toastTimer = null;
function toast(text) {
  els.toast.textContent = text;
  els.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.hidden = true;
  }, 2400);
}

function setMobileView(view) {
  els.sidebar.classList.toggle("max-md:hidden", view === "chat");
  els.chat.classList.toggle("max-md:hidden", view === "list");
}

/* ------------------------------------------------------------------ */
/* auth                                                               */
/* ------------------------------------------------------------------ */

function setAuthMode(mode) {
  app.authMode = mode;
  els.tabLogin.setAttribute("aria-selected", String(mode === "login"));
  els.tabRegister.setAttribute("aria-selected", String(mode === "register"));
  els.confirmField.hidden = mode !== "register";
  els.authConfirm.required = mode === "register";
  els.authPassword.autocomplete = mode === "register" ? "new-password" : "current-password";
  els.authSubmit.textContent = mode === "register" ? "Create account" : "Sign in";
  setAuthError("");
}

function setAuthError(message) {
  els.authError.textContent = message;
  els.authError.hidden = !message;
}

function showAuth(message = "") {
  els.app.hidden = true;
  els.authScreen.hidden = false;
  setAuthError(message);
  els.authSubmit.disabled = false;
  els.authUsername.focus();
}

async function submitAuth(event) {
  event.preventDefault();
  const username = els.authUsername.value.trim();
  const password = els.authPassword.value;
  const mode = app.authMode;

  if (!USERNAME_RE.test(username)) {
    setAuthError("Use 3-32 letters, digits, dots, underscores or hyphens.");
    return;
  }
  if (password.length < 8) {
    setAuthError("Password must be at least 8 characters.");
    return;
  }
  if (mode === "register" && password !== els.authConfirm.value) {
    setAuthError("Passwords do not match.");
    return;
  }

  setAuthError("");
  els.authSubmit.disabled = true;
  try {
    if (mode === "register") {
      const identity = Identity.create();
      const account = await api.register(username, password, identity.publicKeyBase64);
      await saveIdentity(identity);
      app.identity = identity;
      await enterApp(account);
    } else {
      const account = await api.login(username, password);
      app.identity = await loadIdentity().catch(() => null);
      await enterApp(account);
    }
  } catch (error) {
    setAuthError(error.message);
    els.authSubmit.disabled = false;
  }
}

async function enterApp(account) {
  app.account = account;
  app.me = account.username;
  els.meName.textContent = app.me;
  setAvatar(els.meAvatar, app.me);
  els.authScreen.hidden = true;
  els.app.hidden = false;

  if (!app.identity) {
    openIdentityPanel({
      required: true,
      message:
        "This browser has no identity key for this account. Import your backup, or create a new one (your contacts will be warned that it changed).",
    });
    return;
  }
  if (app.identity.publicKeyBase64 !== account.identityPublic) {
    openIdentityPanel({
      required: true,
      adopt: true,
      message:
        "This browser's identity key is not the one registered on your account. Use this browser's key, or import the registered backup.",
    });
    return;
  }
  startRealtime();
}

async function logout() {
  app.connection?.stop();
  try {
    await api.logout();
  } catch {
    // Signing out locally is enough.
  }
  location.reload();
}

/* ------------------------------------------------------------------ */
/* identity panel                                                      */
/* ------------------------------------------------------------------ */

let identityPanelMode = { required: false, adopt: false };

function openIdentityPanel({ required = false, adopt = false, message = "" } = {}) {
  identityPanelMode = { required, adopt };
  const hasIdentity = Boolean(app.identity);

  els.identityTitle.textContent = required ? "Identity needed" : "Your identity";
  els.identityCurrent.hidden = !hasIdentity;
  els.identityClose.hidden = required;
  els.identityCreate.hidden = !(required && !hasIdentity);
  els.identityAdopt.hidden = !(required && adopt && hasIdentity);
  els.identityMessage.textContent = message;
  els.identityMessage.hidden = !message;
  els.identityImport.value = "";

  if (hasIdentity) {
    els.identityFingerprint.textContent = app.identity.fingerprint;
    els.identityExport.value = app.identity.exportKey();
  }
  els.identityPanel.hidden = false;
}

function closeIdentityPanel() {
  if (identityPanelMode.required) return;
  els.identityPanel.hidden = true;
}

async function adoptIdentity(identity, { publish = true } = {}) {
  app.identity = identity;
  await saveIdentity(identity);
  if (publish) await api.setIdentity(identity.publicKeyBase64);
  if (app.account) app.account.identityPublic = identity.publicKeyBase64;
  identityPanelMode = { required: false, adopt: false };
  els.identityPanel.hidden = true;
  renderChatHeader();
  if (!app.connection) startRealtime();
  else refreshDirectory();
}

/* ------------------------------------------------------------------ */
/* realtime                                                            */
/* ------------------------------------------------------------------ */

function startRealtime() {
  if (app.connection || app.starting) return;
  app.starting = true;
  const connection = new Connection();
  bindConnection(connection);
  app.connection = connection;
  connection.start();
  els.connLabel.textContent = "connecting…";
  els.connDot.dataset.state = "connecting";
}

function bindConnection(connection) {
  connection.addEventListener("welcome", async (event) => {
    const { user, online } = event.detail;
    app.starting = false;
    app.me = user;
    els.meName.textContent = user;
    setAvatar(els.meAvatar, user);
    app.online = new Set(online.filter((name) => name.toLowerCase() !== user.toLowerCase()));
    els.connDot.dataset.state = "online";
    els.connLabel.textContent = "connected";
    renderUserList();
    renderChatHeader();
    renderMessages();
    updateTitle();
    await refreshDirectory();
    if (app.current) ensureSession(app.current);
  });

  connection.addEventListener("status", (event) => {
    const { state } = event.detail;
    els.connDot.dataset.state = state;
    if (state === "online") {
      els.connLabel.textContent = "connected";
    } else if (state === "connecting") {
      els.connLabel.textContent = "connecting…";
    } else {
      els.connLabel.textContent = "disconnected — retrying";
    }

    if (state === "offline") {
      for (const peer of [...app.sessions.keys()]) {
        dropSession(peer, "connection lost", { notify: app.current === peer });
      }
      app.online.clear();
      renderUserList();
      renderChatHeader();
    }
  });

  connection.addEventListener("presence", (event) => {
    const { user, online } = event.detail;
    if (user.toLowerCase() === app.me.toLowerCase()) return;
    if (online) {
      app.online.add(user);
      scheduleDirectoryRefresh();
    } else {
      app.online.delete(user);
      if (app.sessions.has(user)) {
        dropSession(user, `${user} went offline`, { notify: app.current === user });
      }
    }
    renderUserList();
    renderChatHeader();
    if (online && app.current === user) ensureSession(user);
  });

  connection.addEventListener("frame", (event) => onFrame(event.detail));

  connection.addEventListener("undelivered", (event) => {
    const { to } = event.detail;
    if (app.sessions.has(to)) dropSession(to, "not reachable", { notify: false });
    if (app.current === to) addEntry(to, systemEntry(`${to} is not reachable right now.`, true));
  });

  connection.addEventListener("server-error", (event) => toast(event.detail.message));

  connection.addEventListener("unauthorized", (event) => {
    app.connection?.stop();
    app.connection = null;
    showAuth(event.detail.message);
  });

  connection.addEventListener("taken-over", (event) => {
    app.connection?.stop();
    app.connection = null;
    showAuth(event.detail.message);
  });
}

function scheduleDirectoryRefresh() {
  clearTimeout(app.refreshTimer);
  app.refreshTimer = setTimeout(() => refreshDirectory(), 250);
}

async function refreshDirectory() {
  try {
    const data = await api.users();
    const next = new Map();
    for (const entry of data.users) {
      next.set(entry.username, entry);
      if (entry.online) app.online.add(entry.username);
    }
    app.directory = next;
  } catch (error) {
    if (error.status === 401) {
      app.connection?.stop();
      app.connection = null;
      showAuth("Your session expired. Sign in again.");
      return;
    }
    console.warn("could not load the directory", error);
  }
  renderUserList();
  renderChatHeader();
}

/* ------------------------------------------------------------------ */
/* sessions                                                            */
/* ------------------------------------------------------------------ */

function peerIdentity(peer) {
  return app.directory.get(peer)?.identityPublic || null;
}

function ensureSession(peer) {
  if (!app.me || !app.identity || app.sessions.has(peer)) return;
  const expected = peerIdentity(peer);
  if (!expected || !app.online.has(peer)) return;

  let session;
  try {
    session = Session.initiate(app.me, peer, {
      identity: app.identity,
      peerIdentity: expected,
    });
  } catch (error) {
    addEntry(peer, systemEntry(`Could not start a session: ${error.message}`, true));
    return;
  }
  app.sessions.set(peer, session);
  armTimeout(peer, session);
  if (!app.connection?.sendFrame(peer, session.start())) {
    dropSession(peer, "not connected", { notify: false });
    addEntry(peer, systemEntry("Not connected — could not start a session.", true));
  }
  renderUserList();
  renderChatHeader();
}

function armTimeout(peer, session) {
  clearTimeout(app.timers.get(peer));
  const timer = setTimeout(() => {
    if (app.sessions.get(peer) === session && !session.isActive) {
      app.sessions.delete(peer);
      session.close("timeout");
      addEntry(peer, systemEntry("Handshake timed out. Try restarting the session.", true));
      renderUserList();
      renderChatHeader();
    }
  }, HANDSHAKE_TIMEOUT_MS);
  app.timers.set(peer, timer);
}

function dropSession(peer, reason, { notify = true } = {}) {
  const session = app.sessions.get(peer);
  app.sessions.delete(peer);
  clearTimeout(app.timers.get(peer));
  app.timers.delete(peer);
  app.typingPeers.delete(peer);
  session?.close(reason);
  if (notify && session) addEntry(peer, systemEntry(`Session ended: ${reason}.`));
  renderUserList();
  renderTyping();
  if (app.current === peer) renderChatHeader();
}

/* ------------------------------------------------------------------ */
/* inbound frames                                                      */
/* ------------------------------------------------------------------ */

function onFrame({ from, frame }) {
  if (!frame || typeof frame !== "object") return;

  if (frame.kind === "hello") {
    handleHello(from, frame);
    return;
  }
  if (frame.kind === "typing") {
    onTyping(from, frame);
    return;
  }
  if (frame.kind === "receipt") {
    onReceipt(from, frame);
    return;
  }

  const session = app.sessions.get(from);
  if (!session) return;
  if (frame.kind === "message" && frame.session !== session.sessionId) return;

  const { out, events } = session.handle(frame);
  for (const envelope of out) app.connection?.sendFrame(from, envelope);
  applyEvents(from, session, events);
}

function handleHello(peer, frame) {
  const expected = peerIdentity(peer);
  if (!expected || !app.identity) return;

  const existing = app.sessions.get(peer);
  if (existing) {
    if (existing.state === State.ACTIVE || existing.state === State.CONFIRMING) return;
    if (existing.role === "responder") return;
    // Both sides opened the conversation at once. The lower name keeps its
    // handshake; the higher name answers the other offer.
    if (prefersInitiator(peer)) return;
    dropSession(peer, "peer started first", { notify: false });
  }

  let session;
  try {
    session = Session.respond(app.me, peer, { identity: app.identity, peerIdentity: expected });
  } catch (error) {
    addEntry(peer, systemEntry(`Could not answer the session: ${error.message}`, true));
    return;
  }
  app.sessions.set(peer, session);
  const { out, events } = session.handle(frame);
  if (out.length === 0) {
    applyEvents(peer, session, events);
    if (app.sessions.get(peer) === session) app.sessions.delete(peer);
    renderChatHeader();
    return;
  }
  for (const envelope of out) app.connection?.sendFrame(peer, envelope);
  applyEvents(peer, session, events);
  armTimeout(peer, session);
  renderUserList();
  renderChatHeader();
}

function applyEvents(peer, session, events) {
  if (app.sessions.get(peer) !== session) return;
  for (const event of events) {
    if (event.type === "established") {
      clearTimeout(app.timers.get(peer));
      app.timers.delete(peer);
      addEntry(peer, systemEntry("Secure session established."));
      renderChatHeader();
      renderUserList();
    } else if (event.type === "text") {
      addEntry(peer, messageEntry("in", event.text), { persist: true });
      const open = app.current === peer && document.visibilityState === "visible";
      app.connection?.sendFrame(
        peer,
        makeControl("receipt", app.me, peer, {
          seq: event.seq,
          state: open ? "read" : "delivered",
        }),
      );
      if (!open) {
        app.unread.set(peer, (app.unread.get(peer) || 0) + 1);
        renderUserList();
        updateTitle();
        toast(`${peer} sent a message`);
      }
    } else if (event.type === "ended") {
      app.sessions.delete(peer);
      clearTimeout(app.timers.get(peer));
      app.timers.delete(peer);
      addEntry(peer, systemEntry(`Session ended: ${event.reason}.`, true));
      renderUserList();
      renderChatHeader();
    }
  }
}

/* ------------------------------------------------------------------ */
/* typing and receipts                                                 */
/* ------------------------------------------------------------------ */

function sendTypingTo(peer, state) {
  const session = app.sessions.get(peer);
  if (!session?.isActive) return;
  app.connection?.sendFrame(peer, makeControl("typing", app.me, peer, { state }));
}

function noteTyping() {
  const peer = app.current;
  if (!peer || !app.sessions.get(peer)?.isActive) return;
  sendTypingTo(peer, true);
  clearTimeout(app.typingTimer);
  app.typingTimer = setTimeout(() => sendTypingTo(peer, false), 2500);
}

function stopTyping(peer) {
  clearTimeout(app.typingTimer);
  if (peer) sendTypingTo(peer, false);
}

function onTyping(from, frame) {
  const active = Boolean(frame.payload?.state);
  clearTimeout(app.typingTimers.get(from));
  if (active) {
    app.typingPeers.add(from);
    app.typingTimers.set(
      from,
      setTimeout(() => {
        app.typingPeers.delete(from);
        renderTyping();
      }, 6000),
    );
  } else {
    app.typingPeers.delete(from);
  }
  renderTyping();
}

function onReceipt(from, frame) {
  const seq = frame.payload?.seq;
  const state = frame.payload?.state;
  if (!Number.isInteger(seq)) return;
  const list = app.messages.get(from);
  if (!list) return;
  const entry = list.find(
    (item) => item.kind === "message" && item.direction === "out" && item.seq === seq,
  );
  if (!entry) return;
  if (state === "read" || (state === "delivered" && entry.status === "sent")) {
    entry.status = state;
    if (app.current === from) paintTicks(seq, state);
  }
}

function ticksFor(status) {
  if (status === "read") return { text: "✓✓", className: "ticks" };
  if (status === "delivered") return { text: "✓✓", className: "ticks-sent" };
  return { text: "✓", className: "ticks-sent" };
}

function paintTicks(seq, status) {
  const node = els.messages.querySelector(`.msg[data-seq="${seq}"] .ticks-cell`);
  if (!node) return;
  const { text, className } = ticksFor(status);
  node.textContent = text;
  node.className = `ticks-cell ${className}`;
}

/* ------------------------------------------------------------------ */
/* messages and history                                                */
/* ------------------------------------------------------------------ */

function getMessages(peer) {
  if (!app.messages.has(peer)) app.messages.set(peer, []);
  return app.messages.get(peer);
}

async function loadHistory(peer) {
  if (app.historyLoaded.has(peer)) return;
  if (app.historyLoads.has(peer)) return app.historyLoads.get(peer);

  const task = (async () => {
    let stored = [];
    try {
      stored = await app.history.list(peer);
    } catch (error) {
      console.warn("could not load history", error);
    }
    // Put old messages in front of anything that arrived while loading. The
    // array is mutated in place so later pushes are not lost.
    getMessages(peer).unshift(...stored.map((entry) => ({ kind: "message", ...entry })));
    app.historyLoaded.add(peer);
  })();

  app.historyLoads.set(peer, task);
  try {
    await task;
  } finally {
    app.historyLoads.delete(peer);
  }
}

function addEntry(peer, entry, { persist = false } = {}) {
  const list = getMessages(peer);
  list.push(entry);
  if (list.length > MAX_RENDERED) list.splice(0, list.length - MAX_RENDERED);
  if (persist) {
    app.history?.add(peer, entry).catch((error) => {
      console.warn("could not persist message", error);
    });
  }
  if (app.current === peer) {
    removeEmptyState();
    if (entry.kind === "system") appendSystemDom(entry);
    else appendMessageDom(entry);
    scrollToBottom();
  }
}

function removeEmptyState() {
  els.messages.querySelector(".empty")?.remove();
}

function appendMessageDom(entry) {
  const out = entry.direction === "out";
  const wrapper = document.createElement("div");
  wrapper.className = `msg ${out ? "msg-out" : "msg-in"}`;
  if (out && Number.isInteger(entry.seq)) wrapper.dataset.seq = String(entry.seq);

  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = entry.text;

  const meta = document.createElement("div");
  meta.className = "meta";
  const time = document.createElement("span");
  time.className = "time";
  time.textContent = formatTime(entry.at);
  meta.appendChild(time);
  if (out) {
    const { text, className } = ticksFor(entry.status);
    const ticks = document.createElement("span");
    ticks.className = `ticks-cell ${className}`;
    ticks.textContent = text;
    meta.appendChild(ticks);
  }

  wrapper.append(bubble, meta);
  els.messages.appendChild(wrapper);
}

function appendSystemDom(entry) {
  const node = document.createElement("div");
  node.className = `system${entry.error ? " system-error" : ""}`;
  node.textContent = entry.text;
  els.messages.appendChild(node);
}

function renderMessages() {
  els.messages.textContent = "";
  if (!app.current) {
    showEmptyState("Pick someone to start", "Messages are encrypted in this browser before they reach the server.");
    return;
  }
  const list = getMessages(app.current);
  if (list.length === 0) {
    showEmptyState(
      `Chat with ${app.current}`,
      app.online.has(app.current)
        ? "A secure session starts automatically."
        : `${app.current} is offline right now.`,
    );
    return;
  }
  for (const entry of list) {
    if (entry.kind === "system") appendSystemDom(entry);
    else appendMessageDom(entry);
  }
  scrollToBottom();
}

function showEmptyState(title, subtitle) {
  const wrap = document.createElement("div");
  wrap.className = "empty";
  const icon = document.createElement("span");
  icon.className = "empty-icon";
  icon.textContent = "🔒";
  const strong = document.createElement("strong");
  strong.textContent = title;
  const line = document.createElement("span");
  line.textContent = subtitle;
  wrap.append(icon, strong, line);
  els.messages.appendChild(wrap);
}

function formatTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function scrollToBottom() {
  els.messages.scrollTop = els.messages.scrollHeight;
}

async function openConversation(peer) {
  const previous = app.current;
  if (previous && previous !== peer) stopTyping(previous);

  app.current = peer;
  app.unread.delete(peer);
  setMobileView("chat");

  const entry = app.directory.get(peer);
  if (entry && pinStatus(peer, entry.identityPublic).state === "new") {
    pin(peer, entry.identityPublic);
  }

  renderUserList();
  renderChatHeader();
  renderTyping();

  await loadHistory(peer);
  if (app.current !== peer) return;

  renderMessages();
  if (app.online.has(peer)) ensureSession(peer);
  els.input.focus();
  updateTitle();
}

/* ------------------------------------------------------------------ */
/* outbound                                                            */
/* ------------------------------------------------------------------ */

function sendMessage() {
  const peer = app.current;
  if (!peer) return;
  const text = els.input.value.trim();
  if (!text) return;
  if (new TextEncoder().encode(text).length > MAX_TEXT_BYTES) {
    toast("Message is too long (32 KiB max)");
    return;
  }

  const session = app.sessions.get(peer);
  if (!session?.isActive) {
    addEntry(peer, systemEntry("No secure session yet — message not sent.", true));
    return;
  }

  let frame;
  try {
    frame = session.encrypt(text);
  } catch (error) {
    addEntry(peer, systemEntry(`Could not encrypt: ${error.message}`, true));
    return;
  }
  if (!app.connection?.sendFrame(peer, frame)) {
    addEntry(peer, systemEntry("Not connected — message not sent.", true));
    return;
  }

  stopTyping(peer);
  addEntry(peer, { ...messageEntry("out", text), seq: frame.payload.seq, status: "sent" }, { persist: true });
  els.input.value = "";
  resizeInput();
  els.input.focus();
}

function resizeInput() {
  els.input.style.height = "auto";
  els.input.style.height = `${Math.min(els.input.scrollHeight, 160)}px`;
}

/* ------------------------------------------------------------------ */
/* rendering                                                           */
/* ------------------------------------------------------------------ */

function renderUserList() {
  const query = app.search.trim().toLowerCase();
  const names = [...app.directory.keys()].filter(
    (name) => !query || name.toLowerCase().includes(query),
  );
  names.sort((a, b) => {
    const online = Number(app.online.has(b)) - Number(app.online.has(a));
    return online || a.localeCompare(b);
  });

  els.userList.textContent = "";
  if (names.length === 0) {
    const item = document.createElement("li");
    item.className = "px-2 py-6 text-center text-sm text-dim";
    item.textContent =
      app.directory.size === 0 ? "No other accounts yet." : "Nobody matches that search.";
    els.userList.appendChild(item);
    return;
  }

  for (const name of names) {
    const entry = app.directory.get(name);
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "user-row";
    button.setAttribute("aria-label", name);
    if (name === app.current) button.dataset.active = "true";

    button.appendChild(makeAvatar(name));

    const body = document.createElement("span");
    body.className = "flex min-w-0 flex-1 flex-col";
    const top = document.createElement("span");
    top.className = "flex items-center gap-1.5";
    const label = document.createElement("span");
    label.className = "user-name";
    label.textContent = name;
    top.appendChild(label);

    const status = pinStatus(name, entry.identityPublic);
    if (status.state === "changed") {
      const flag = document.createElement("span");
      flag.className = "badge badge-warn";
      flag.textContent = "key changed";
      top.appendChild(flag);
    } else if (status.verified) {
      const flag = document.createElement("span");
      flag.className = "badge badge-verified";
      flag.textContent = "✓";
      top.appendChild(flag);
    }
    body.appendChild(top);

    const subtitle = document.createElement("span");
    subtitle.className = "truncate user-sub";
    subtitle.textContent = app.typingPeers.has(name)
      ? "typing…"
      : app.online.has(name)
        ? "online"
        : "offline";
    body.appendChild(subtitle);
    button.appendChild(body);

    const right = document.createElement("span");
    right.className = "flex items-center gap-1.5";
    const unread = app.unread.get(name);
    if (unread) {
      const badge = document.createElement("span");
      badge.className = "unread";
      badge.textContent = String(unread);
      right.appendChild(badge);
    }
    right.appendChild(makePresence(app.online.has(name)));
    button.appendChild(right);

    button.addEventListener("click", () => openConversation(name));
    item.appendChild(button);
    els.userList.appendChild(item);
  }
}

function renderChatHeader() {
  const peer = app.current;
  if (!peer) {
    els.chatPeer.textContent = "No conversation";
    els.chatStatus.textContent = "";
    els.chatStatus.dataset.state = "idle";
    els.verifyBadge.hidden = true;
    els.verifyButton.hidden = true;
    els.retrySession.hidden = true;
    setAvatar(els.chatAvatar, null);
    updateComposer();
    return;
  }

  els.chatPeer.textContent = peer;
  setAvatar(els.chatAvatar, peer);

  const session = app.sessions.get(peer);
  let status;
  let state;
  if (!app.online.has(peer)) {
    status = "offline";
    state = "offline";
  } else if (session?.isActive) {
    status = "end-to-end encrypted";
    state = "secure";
  } else if (session) {
    status = "negotiating keys…";
    state = "negotiating";
  } else {
    status = "online";
    state = "idle";
  }
  els.chatStatus.textContent = status;
  els.chatStatus.dataset.state = state;

  const entry = app.directory.get(peer);
  if (!entry) {
    els.verifyBadge.hidden = true;
  } else {
    const pinState = pinStatus(peer, entry.identityPublic);
    els.verifyBadge.hidden = false;
    if (pinState.state === "changed") {
      els.verifyBadge.className = "badge badge-warn";
      els.verifyBadge.textContent = "key changed";
    } else if (pinState.verified) {
      els.verifyBadge.className = "badge badge-verified";
      els.verifyBadge.textContent = "✓ verified";
    } else {
      els.verifyBadge.className = "badge badge-muted";
      els.verifyBadge.textContent = "not verified";
    }
  }

  els.verifyButton.hidden = !entry;
  els.retrySession.hidden = !(app.online.has(peer) && !session?.isActive);
  updateComposer();
}

function updateComposer() {
  const peer = app.current;
  const session = peer ? app.sessions.get(peer) : null;
  const ready = Boolean(session?.isActive) && app.online.has(peer);
  els.input.disabled = !ready;
  els.sendButton.disabled = !ready;
  if (!peer) {
    els.input.placeholder = "Select someone to start";
  } else if (ready) {
    els.input.placeholder = `Write to ${peer}…`;
  } else if (!app.online.has(peer)) {
    els.input.placeholder = `${peer} is offline`;
  } else {
    els.input.placeholder = "Waiting for a secure session…";
  }
}

function renderTyping() {
  const peer = app.current;
  const typing = Boolean(peer && app.typingPeers.has(peer));
  els.typing.hidden = !typing;
  els.typing.textContent = typing ? `${peer} is typing…` : "";
  if (peer) renderUserList();
}

function updateTitle() {
  let total = 0;
  for (const count of app.unread.values()) total += count;
  document.title = total > 0 ? `(${total}) enc` : "enc";
}

/* ------------------------------------------------------------------ */
/* verify panel                                                        */
/* ------------------------------------------------------------------ */

function openVerifyPanel() {
  const peer = app.current;
  const entry = peer ? app.directory.get(peer) : null;
  if (!peer || !entry || !app.identity) return;

  const status = pinStatus(peer, entry.identityPublic);
  els.verifyPeer.textContent = peer;
  els.verifyCode.textContent = verifyCode(
    app.identity.publicKey,
    b64decode(entry.identityPublic),
  );
  els.verifyWarning.hidden = status.state !== "changed";
  if (status.state === "changed") {
    els.verifyWarning.textContent =
      "This contact's identity key has changed since you last saw it. Verify the new number before trusting it.";
  }

  if (status.verified) {
    els.verifyState.textContent = "Verified.";
  } else if (status.state === "changed") {
    els.verifyState.textContent = "Not verified — the key changed.";
  } else {
    els.verifyState.textContent = "Not verified yet.";
  }

  els.verifyMark.disabled = status.verified;
  els.verifyMark.textContent = status.verified ? "Verified" : "Mark as verified";
  els.verifyMark.dataset.peer = peer;
  els.verifyPanel.hidden = false;
}

/* ------------------------------------------------------------------ */
/* startup                                                             */
/* ------------------------------------------------------------------ */

function bindEvents() {
  els.tabLogin.addEventListener("click", () => setAuthMode("login"));
  els.tabRegister.addEventListener("click", () => setAuthMode("register"));
  els.authForm.addEventListener("submit", submitAuth);

  els.logoutButton.addEventListener("click", logout);
  els.identityButton.addEventListener("click", () => openIdentityPanel());

  els.userSearch.addEventListener("input", () => {
    app.search = els.userSearch.value;
    renderUserList();
  });

  els.identityCopy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(els.identityExport.value);
      toast("Backup key copied");
    } catch {
      toast("Could not copy — select the text manually");
    }
  });

  els.identityCreate.addEventListener("click", async () => {
    try {
      await adoptIdentity(Identity.create());
      toast("New identity created");
    } catch (error) {
      els.identityMessage.textContent = error.message;
      els.identityMessage.hidden = false;
    }
  });

  els.identityAdopt.addEventListener("click", async () => {
    if (!app.identity) return;
    try {
      await adoptIdentity(app.identity, { publish: true });
      toast("This browser's key is now registered");
    } catch (error) {
      els.identityMessage.textContent = error.message;
      els.identityMessage.hidden = false;
    }
  });

  els.identityImportButton.addEventListener("click", async () => {
    try {
      const identity = Identity.importKey(els.identityImport.value);
      await adoptIdentity(identity);
      toast("Identity key imported");
    } catch (error) {
      els.identityMessage.textContent = error.message;
      els.identityMessage.hidden = false;
    }
  });

  els.identityClose.addEventListener("click", closeIdentityPanel);

  els.verifyButton.addEventListener("click", openVerifyPanel);
  els.verifyClose.addEventListener("click", () => {
    els.verifyPanel.hidden = true;
  });
  els.verifyMark.addEventListener("click", () => {
    const peer = els.verifyMark.dataset.peer;
    const entry = peer ? app.directory.get(peer) : null;
    if (!peer || !entry) return;
    markVerified(peer, entry.identityPublic);
    els.verifyPanel.hidden = true;
    renderChatHeader();
    renderUserList();
    toast(`${peer} marked as verified`);
  });

  els.chatBack.addEventListener("click", () => {
    setMobileView("list");
  });

  els.retrySession.addEventListener("click", () => {
    if (!app.current) return;
    dropSession(app.current, "restarting", { notify: false });
    ensureSession(app.current);
  });

  els.composer.addEventListener("submit", (event) => {
    event.preventDefault();
    sendMessage();
  });

  els.input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });

  els.input.addEventListener("input", () => {
    resizeInput();
    noteTyping();
  });

  window.addEventListener("beforeunload", () => {
    app.connection?.stop();
  });
}

async function init() {
  bindEvents();
  setAuthMode("login");
  try {
    app.history = await History.open();
  } catch (error) {
    console.warn("history unavailable", error);
    app.history = null;
  }

  try {
    const account = await api.me();
    app.identity = await loadIdentity().catch(() => null);
    await enterApp(account);
  } catch (error) {
    showAuth(error.status === 401 ? "" : error.message);
  }
}

init();
