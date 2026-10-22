/**
 * Websocket link to the server.
 *
 * Authentication is the session cookie: the browser sends it with the
 * handshake, so no token ever appears in a URL or in client code.
 *
 * Emits:
 *   "status"      {state: "connecting" | "online" | "offline"}
 *   "welcome"     {user, identityPublic, online: string[]}
 *   "presence"    {user, online: boolean}
 *   "frame"       {from, frame}
 *   "undelivered" {to}
 *   "unauthorized"{message}
 *   "taken-over"  {message}
 *   "server-error"{message}
 *
 * The socket carries public keys and ciphertext. Everything the server sees is
 * routing metadata.
 */

const RETRY_MIN_MS = 500;
const RETRY_MAX_MS = 8000;

const CLOSE_UNAUTHORIZED = 4401;
const CLOSE_TAKEN_OVER = 4409;

export class Connection extends EventTarget {
  constructor() {
    super();
    this.socket = null;
    this.wanted = false;
    this.ready = false;
    this.retryMs = RETRY_MIN_MS;
    this.retryTimer = null;
  }

  start() {
    this.wanted = true;
    this.#open();
  }

  stop() {
    this.wanted = false;
    clearTimeout(this.retryTimer);
    if (this.socket) {
      this.socket.close(1000, "leaving");
      this.socket = null;
    }
    this.ready = false;
  }

  sendFrame(peer, frame) {
    if (!this.socket || this.socket.readyState !== WebSocket.OPEN || !this.ready) {
      return false;
    }
    this.socket.send(JSON.stringify({ type: "relay", to: peer, frame }));
    return true;
  }

  #emit(type, detail = {}) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  #open() {
    const secure = location.protocol === "https:";
    const url = `${secure ? "wss" : "ws"}://${location.host}/ws`;
    this.#emit("status", { state: "connecting" });

    let socket;
    try {
      socket = new WebSocket(url);
    } catch {
      this.#scheduleRetry();
      return;
    }
    this.socket = socket;

    socket.onopen = () => {
      this.retryMs = RETRY_MIN_MS;
    };

    socket.onmessage = (event) => {
      let data;
      try {
        data = JSON.parse(event.data);
      } catch {
        return;
      }
      this.#handle(data);
    };

    socket.onclose = (event) => {
      this.ready = false;
      this.socket = null;
      if (event.code === CLOSE_UNAUTHORIZED) {
        this.wanted = false;
        this.#emit("unauthorized", { message: "Your session expired. Sign in again." });
        return;
      }
      if (event.code === CLOSE_TAKEN_OVER) {
        this.wanted = false;
        this.#emit("taken-over", { message: "This account signed in somewhere else." });
        return;
      }
      this.#emit("status", { state: "offline" });
      if (this.wanted) this.#scheduleRetry();
    };

    socket.onerror = () => {
      // onclose always follows; retry logic lives there.
    };
  }

  #scheduleRetry() {
    clearTimeout(this.retryTimer);
    this.retryTimer = setTimeout(() => {
      if (this.wanted) this.#open();
    }, this.retryMs);
    this.retryMs = Math.min(this.retryMs * 2, RETRY_MAX_MS);
  }

  #handle(data) {
    switch (data.type) {
      case "welcome":
        this.ready = true;
        this.#emit("welcome", {
          user: data.user,
          identityPublic: data.identityPublic,
          online: Array.isArray(data.online) ? data.online : [],
        });
        this.#emit("status", { state: "online" });
        break;
      case "presence":
        this.#emit("presence", {
          user: data.user,
          online: Boolean(data.online),
        });
        break;
      case "relay":
        if (typeof data.from !== "string" || !data.frame) return;
        this.#emit("frame", { from: data.from, frame: data.frame });
        break;
      case "undelivered":
        this.#emit("undelivered", { to: data.to });
        break;
      case "error":
        this.#emit("server-error", { message: String(data.message || "server error") });
        break;
      default:
        break;
    }
  }
}
