/**
 * Browser smoke test: two real Chrome contexts, end-to-end through the UI.
 *
 * Covers registering accounts, the identity key, the signed handshake, the
 * verification code, typing indicators, read receipts and history after a
 * reload. Uses the locally installed Chrome (`channel: "chrome"`) so no browser
 * download is required. Run with: npm run test:browser
 */

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SHOTS = process.env.ENC_SHOTS_DIR || "/Users/mith/tmp/opencode";
const PASSWORD = "correct horse battery";
const SECRET = "hello from the browser test 🔐";

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function pythonPath() {
  const candidate =
    process.platform === "win32"
      ? path.join(ROOT, ".venv", "Scripts", "python.exe")
      : path.join(ROOT, ".venv", "bin", "python");
  return fs.existsSync(candidate) ? candidate : "python3";
}

async function waitForHealth(url, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Not up yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new Error(`server did not become healthy at ${url}`);
}

async function register(page, username, password = PASSWORD) {
  await page.click("#tab-register");
  await page.fill("#auth-username", username);
  await page.fill("#auth-password", password);
  await page.fill("#auth-confirm", password);
  await page.click("#auth-submit");
  await page.waitForSelector("#app:not([hidden])", { timeout: 20_000 });
  await page.waitForFunction(
    (name) => document.getElementById("me-name")?.textContent === name,
    username,
    { timeout: 20_000 },
  );
}

async function openChat(page, peer) {
  await page.click(`button.user-row[aria-label="${peer}"]`);
  await page.waitForFunction(
    (name) => document.getElementById("chat-peer")?.textContent === name,
    peer,
  );
}

async function waitSecure(page) {
  await page.waitForFunction(
    () => document.getElementById("chat-status")?.textContent === "end-to-end encrypted",
    null,
    { timeout: 30_000 },
  );
}

async function waitForBubble(page, direction, text) {
  await page.waitForFunction(
    ([kind, wanted]) =>
      [...document.querySelectorAll(`#messages .msg.${kind} .bubble`)].some(
        (node) => node.textContent === wanted,
      ),
    [direction, text],
    { timeout: 15_000 },
  );
}

async function waitForReadTicks(page) {
  // "✓✓" means the recipient acknowledged the message (delivered, or read if
  // their chat was open and visible).
  await page.waitForFunction(
    () => {
      const node = document.querySelector("#messages .msg.msg-out .ticks-cell");
      return Boolean(node && node.textContent === "✓✓");
    },
    null,
    { timeout: 15_000 },
  );
}

async function readVerifyCode(page) {
  await page.click("#verify-button");
  await page.waitForSelector("#verify-panel:not([hidden])");
  const code = (await page.textContent("#verify-code"))?.trim();
  await page.click("#verify-close");
  return code;
}

function collectErrors(page, label, sink) {
  page.on("pageerror", (error) => sink.push(`${label} pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    // Probing /api/me or signing in with a bad password is expected to 401.
    const url = message.location()?.url || "";
    if (url.endsWith("/api/me") || url.endsWith("/api/login")) return;
    sink.push(`${label} console: ${message.text()}`);
  });
}

async function main() {
  const port = await freePort();
  const url = `http://127.0.0.1:${port}/`;
  const database = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "enc-browser-")), "enc.db");
  let logs = "";
  const server = spawn(
    pythonPath(),
    [
      "-m",
      "enc",
      "serve",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--db",
      database,
      "--log-level",
      "warning",
    ],
    { cwd: ROOT, env: { ...process.env, PYTHONUNBUFFERED: "1" } },
  );
  server.stdout.on("data", (chunk) => (logs += chunk));
  server.stderr.on("data", (chunk) => (logs += chunk));

  let browser;
  try {
    await waitForHealth(`${url}health`);
    browser = await chromium.launch({ channel: "chrome", headless: true });

    const errors = [];
    const aliceContext = await browser.newContext({ viewport: { width: 1100, height: 760 } });
    const bobContext = await browser.newContext({ viewport: { width: 1100, height: 760 } });
    const alice = await aliceContext.newPage();
    const bob = await bobContext.newPage();
    collectErrors(alice, "alice", errors);
    collectErrors(bob, "bob", errors);

    await alice.goto(url);
    await bob.goto(url);
    await register(alice, "alice");
    await register(bob, "bob");
    console.log("registered alice and bob through the UI");

    await alice.waitForSelector('button.user-row[aria-label="bob"]', { timeout: 15_000 });
    await bob.waitForSelector('button.user-row[aria-label="alice"]', { timeout: 15_000 });

    await openChat(alice, "bob");
    await waitSecure(alice);
    await openChat(bob, "alice");
    await waitSecure(bob);
    console.log("signed handshake completed in both browsers");

    const aliceCode = await readVerifyCode(alice);
    const bobCode = await readVerifyCode(bob);
    assert.equal(aliceCode, bobCode);
    assert.match(aliceCode, /^(\d{5} ){11}\d{5}$/);
    console.log(`verification codes match: ${aliceCode}`);

    await alice.click("#verify-button");
    await alice.click("#verify-mark");
    await alice.waitForSelector('#verify-badge:has-text("verified")', { timeout: 5_000 });
    console.log("alice marked bob as verified");

    // Typing indicator travels between the two clients.
    await bob.fill("#input", "half a thought");
    await alice.waitForSelector("#typing:not([hidden])", { timeout: 10_000 });
    console.log("typing indicator works");

    await bob.fill("#input", SECRET);
    await bob.press("#input", "Enter");
    await waitForBubble(alice, "msg-in", SECRET);
    await waitForReadTicks(bob);
    console.log("message delivered and read receipt received");

    await alice.fill("#input", "got it");
    await alice.press("#input", "Enter");
    await waitForBubble(bob, "msg-in", "got it");

    if (fs.existsSync(SHOTS)) {
      await alice.screenshot({ path: path.join(SHOTS, "enc-alice.png") });
      await bob.screenshot({ path: path.join(SHOTS, "enc-bob.png") });
    }

    // A wrong password is refused.
    const thirdContext = await browser.newContext();
    const intruder = await thirdContext.newPage();
    collectErrors(intruder, "intruder", errors);
    await intruder.goto(url);
    await intruder.fill("#auth-username", "alice");
    await intruder.fill("#auth-password", "definitely wrong");
    await intruder.click("#auth-submit");
    await intruder.waitForSelector("#auth-error:not([hidden])", { timeout: 10_000 });
    const message = (await intruder.textContent("#auth-error"))?.trim();
    assert.match(message, /wrong username or password/i);
    console.log(`wrong password rejected: ${message}`);

    // Reloading stays signed in and keeps encrypted local history.
    await bob.reload();
    await bob.waitForSelector("#app:not([hidden])", { timeout: 20_000 });
    await bob.waitForSelector('button.user-row[aria-label="alice"]', { timeout: 15_000 });
    await openChat(bob, "alice");
    await waitForBubble(bob, "msg-out", SECRET);
    console.log("history survived a reload");

    // The verification pin survives a reload too.
    await alice.reload();
    await alice.waitForSelector("#app:not([hidden])", { timeout: 20_000 });
    await alice.waitForSelector('button.user-row[aria-label="bob"]', { timeout: 15_000 });
    await openChat(alice, "bob");
    await alice.waitForSelector('#verify-badge:has-text("verified")', { timeout: 10_000 });
    console.log("verification pin survived a reload");

    if (errors.length > 0) {
      throw new Error("browser errors:\n" + errors.join("\n"));
    }
    console.log("no console or page errors");
    return 0;
  } catch (error) {
    if (logs.trim()) {
      console.error("\n--- server output ---\n" + logs.trim() + "\n");
    }
    throw error;
  } finally {
    await browser?.close();
    if (server.exitCode === null) {
      server.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => server.once("exit", resolve)),
        new Promise((resolve) => setTimeout(resolve, 4000)),
      ]);
      if (server.exitCode === null) server.kill("SIGKILL");
    }
  }
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
