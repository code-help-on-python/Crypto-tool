/* CryptoShield Web (client-side)
   IMPORTANT REALITY CHECK:
   - Any JavaScript/HTML/CSS shipped to a browser can be viewed or copied by a determined user.
   - The measures below are deterrents + UI hardening, NOT a true way to hide source code.
*/

"use strict";

/* =========================
   BACKEND-COMPAT CONSTANTS
========================= */
const MAGIC = new TextEncoder().encode("CSP1");
const SALT_LEN = 16;

// ✅ MUST match your Python backend (per your uploaded backend)
const KDF_ITERS = 200;

/* =========================
   DOMAIN LOCK CONFIG
========================= */
const ALLOWED_HOST = "code-help-on-python.github.io";
const ALLOWED_PATH_PREFIX = "/Crypto-tool"; // no trailing slash

/* =========================
   LOCAL STORAGE
========================= */
const LS_THEME = "cryptoshield-theme";
const LS_ACCEPTED = "cryptoshield-accepted-v1";

/* =========================
   ELEMENTS
========================= */
const passphraseDecrypt = document.getElementById("passphrase-decrypt");
const tokenInput = document.getElementById("token");
const outputBox = document.getElementById("output");
const statusEl = document.getElementById("status");
const decryptBtn = document.getElementById("decrypt");
const copyBtn = document.getElementById("copy");
const clearBtn = document.getElementById("clear");

const passphraseEncrypt = document.getElementById("passphrase-encrypt");
const plaintextInput = document.getElementById("plaintext");
const tokenOut = document.getElementById("token-out");
const statusEncEl = document.getElementById("status-encrypt");
const encryptBtn = document.getElementById("encrypt");
const copyEncBtn = document.getElementById("copy-encrypt");
const clearEncBtn = document.getElementById("clear-encrypt");

const tabButtons = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");
const themeButtons = document.querySelectorAll(".theme-btn");
const togglePassButtons = document.querySelectorAll(".toggle-pass");

// Modals
const aboutOpen = document.getElementById("about-open");
const aboutClose = document.getElementById("about-close");
const aboutModal = document.getElementById("modal-about");

const firstModal = document.getElementById("modal-first");
const firstAccept = document.getElementById("first-accept");

const devtoolsModal = document.getElementById("devtools-warning");
const originModal = document.getElementById("origin-lock");

/* =========================
   UI HELPERS
========================= */
function show(el) { if (el) el.hidden = false; }
function hide(el) { if (el) el.hidden = true; }

function safeLSGet(key) {
  try { return localStorage.getItem(key); } catch (_) { return null; }
}
function safeLSSet(key, val) {
  try { localStorage.setItem(key, val); } catch (_) {}
}

function setStatus(text, type) {
  statusEl.textContent = text;
  statusEl.classList.remove("ok", "err");
  if (type) statusEl.classList.add(type);
}
function setStatusEnc(text, type) {
  statusEncEl.textContent = text;
  statusEncEl.classList.remove("ok", "err");
  if (type) statusEncEl.classList.add(type);
}

function setTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = normalized;
  themeButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.theme === normalized));
  safeLSSet(LS_THEME, normalized);
}

/* =========================
   BASE64 URL HELPERS
   ✅ Python-compatible (keeps '=')
========================= */
function base64urlToBytes(str) {
  const cleaned = (str || "").replace(/\s+/g, "");
  const b64 = cleaned.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const raw = atob(b64 + pad);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

// ✅ Keep '=' padding (Python urlsafe_b64encode keeps padding)
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
}

/* =========================
   CRYPTO PRIMITIVES
========================= */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function pkcs7Unpad(data) {
  if (data.length === 0) throw new Error("Invalid padding.");
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16) throw new Error("Invalid padding.");
  for (let i = data.length - pad; i < data.length; i += 1) {
    if (data[i] !== pad) throw new Error("Invalid padding.");
  }
  return data.slice(0, data.length - pad);
}

function pkcs7Pad(data) {
  const pad = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

async function deriveKeys(passphrase, salt) {
  const pwBytes = new TextEncoder().encode(passphrase);
  const material = await crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: KDF_ITERS },
    material,
    256
  );
  const keyBytes = new Uint8Array(bits);
  // Fernet wants signing (16) + encryption (16) in this implementation
  return { signingKey: keyBytes.slice(0, 16), encryptionKey: keyBytes.slice(16, 32) };
}

async function verifyHmac(signingKey, data, expected) {
  const key = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  return constantTimeEqual(sig, expected);
}

async function decryptAesCbc(encryptionKey, iv, ciphertext) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, { name: "AES-CBC" }, false, ["decrypt"]);
  const padded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext));
  return pkcs7Unpad(padded);
}

function parseFernetToken(tokenRaw) {
  // version(1) + ts(8) + iv(16) + hmac(32) minimal, ciphertext can be empty but realistically not
  if (tokenRaw.length < 1 + 8 + 16 + 32) throw new Error("Invalid token format.");
  const version = tokenRaw[0];
  if (version !== 0x80) throw new Error("Invalid token version.");

  const ivStart = 1 + 8;
  const hmacStart = tokenRaw.length - 32;

  const iv = tokenRaw.slice(ivStart, ivStart + 16);
  const ciphertext = tokenRaw.slice(ivStart + 16, hmacStart);
  const dataToSign = tokenRaw.slice(0, hmacStart);
  const hmac = tokenRaw.slice(hmacStart);

  return { iv, ciphertext, dataToSign, hmac };
}

async function encryptFernet(encryptionKey, signingKey, plaintextBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const padded = pkcs7Pad(plaintextBytes);

  const aesKey = await crypto.subtle.importKey("raw", encryptionKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aesKey, padded));

  const timestamp = Math.floor(Date.now() / 1000);
  let ts = BigInt(timestamp);
  const tsBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) { tsBytes[i] = Number(ts & 0xffn); ts >>= 8n; }

  const dataToSign = new Uint8Array(1 + 8 + 16 + ciphertext.length);
  dataToSign[0] = 0x80;
  dataToSign.set(tsBytes, 1);
  dataToSign.set(iv, 1 + 8);
  dataToSign.set(ciphertext, 1 + 8 + 16);

  const hmacKey = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, dataToSign));

  const tokenRaw = new Uint8Array(dataToSign.length + hmac.length);
  tokenRaw.set(dataToSign);
  tokenRaw.set(hmac, dataToSign.length);

  // NOTE: This returns the RAW Fernet token bytes (not base64 text).
  return tokenRaw;
}

/* =========================
   PAYLOAD FORMAT (BACKEND)
   ✅ base64url( MAGIC + salt(16) + fernet_raw_bytes )
========================= */
async function encryptPayload(passphrase, plaintext) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!plaintext) throw new Error("Plaintext is required.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const { signingKey, encryptionKey } = await deriveKeys(passphrase, salt);

  const fernetRaw = await encryptFernet(encryptionKey, signingKey, new TextEncoder().encode(plaintext));

  const payload = new Uint8Array(MAGIC.length + SALT_LEN + fernetRaw.length);
  payload.set(MAGIC, 0);
  payload.set(salt, MAGIC.length);
  payload.set(fernetRaw, MAGIC.length + SALT_LEN);

  return bytesToBase64Url(payload);
}

async function decryptPayload(passphrase, payload) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!payload) throw new Error("Token is required.");

  const payloadBytes = base64urlToBytes(payload);
  if (payloadBytes.length < MAGIC.length + SALT_LEN + (1 + 8 + 16 + 32)) throw new Error("Invalid token format.");

  // Verify MAGIC
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (payloadBytes[i] !== MAGIC[i]) throw new Error("Invalid token format.");
  }

  const salt = payloadBytes.slice(MAGIC.length, MAGIC.length + SALT_LEN);
  const tokenRaw = payloadBytes.slice(MAGIC.length + SALT_LEN);

  const { signingKey, encryptionKey } = await deriveKeys(passphrase, salt);

  const { iv, ciphertext, dataToSign, hmac } = parseFernetToken(tokenRaw);
  const ok = await verifyHmac(signingKey, dataToSign, hmac);
  if (!ok) throw new Error("Wrong passphrase or corrupted token.");

  const plaintextBytes = await decryptAesCbc(encryptionKey, iv, ciphertext);
  return new TextDecoder().decode(plaintextBytes);
}

/* =========================
   UI: TABS
========================= */
tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabButtons.forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    tabPanels.forEach((panel) => panel.classList.remove("active"));

    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");

    tabPanels.forEach((panel) => { panel.hidden = true; });

    const target = document.getElementById(`tab-${btn.dataset.tab}`);
    if (target) {
      target.hidden = false;
      target.classList.add("active");
    }
  });
});

/* =========================
   UI: THEME
========================= */
themeButtons.forEach((btn) => btn.addEventListener("click", () => setTheme(btn.dataset.theme)));

/* =========================
   UI: SHOW/HIDE PASS
========================= */
togglePassButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    const isHidden = input.type === "password";
    input.type = isHidden ? "text" : "password";
    btn.textContent = isHidden ? "Hide" : "Show";
  });
});

/* =========================
   UI: ACTIONS
========================= */
decryptBtn.addEventListener("click", async () => {
  setStatus("Decrypting...", "");
  outputBox.value = "";
  decryptBtn.disabled = true;

  try {
    const result = await decryptPayload(passphraseDecrypt.value.trim(), tokenInput.value.trim());
    outputBox.value = result;
    setStatus("Decrypted.", "ok");
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Decryption failed.";
    const safeMsg = String(msg).toLowerCase().includes("padding")
      ? "Wrong passphrase or corrupted token."
      : msg;
    setStatus(safeMsg, "err");
  } finally {
    decryptBtn.disabled = false;
  }
});

copyBtn.addEventListener("click", async () => {
  if (!outputBox.value.trim()) return setStatus("Nothing to copy.", "err");
  try {
    await navigator.clipboard.writeText(outputBox.value);
    setStatus("Copied to clipboard.", "ok");
  } catch (_) {
    setStatus("Copy failed. Please copy manually.", "err");
  }
});

clearBtn.addEventListener("click", () => {
  passphraseDecrypt.value = "";
  tokenInput.value = "";
  outputBox.value = "";
  setStatus("Cleared.", "");
});

encryptBtn.addEventListener("click", async () => {
  setStatusEnc("Encrypting...", "");
  tokenOut.value = "";
  encryptBtn.disabled = true;

  try {
    const token = await encryptPayload(passphraseEncrypt.value.trim(), plaintextInput.value.trim());
    tokenOut.value = token;
    setStatusEnc("Encrypted.", "ok");
  } catch (err) {
    setStatusEnc(err instanceof Error ? err.message : "Encryption failed.", "err");
  } finally {
    encryptBtn.disabled = false;
  }
});

copyEncBtn.addEventListener("click", async () => {
  if (!tokenOut.value.trim()) return setStatusEnc("Nothing to copy.", "err");
  try {
    await navigator.clipboard.writeText(tokenOut.value);
    setStatusEnc("Copied to clipboard.", "ok");
  } catch (_) {
    setStatusEnc("Copy failed. Please copy manually.", "err");
  }
});

clearEncBtn.addEventListener("click", () => {
  passphraseEncrypt.value = "";
  plaintextInput.value = "";
  tokenOut.value = "";
  setStatusEnc("Cleared.", "");
});

/* =========================
   UI: MODALS
========================= */
if (aboutOpen && aboutModal) aboutOpen.addEventListener("click", () => show(aboutModal));
if (aboutClose && aboutModal) aboutClose.addEventListener("click", () => hide(aboutModal));
if (aboutModal) {
  aboutModal.addEventListener("click", (e) => {
    if (e.target === aboutModal) hide(aboutModal);
  });
}

if (firstAccept && firstModal) {
  firstAccept.addEventListener("click", () => {
    safeLSSet(LS_ACCEPTED, "yes");
    hide(firstModal);
  });
}

// Show first-run notice once
if (firstModal) {
  const accepted = safeLSGet(LS_ACCEPTED);
  if (accepted !== "yes") show(firstModal);
}

/* =========================
   ✅ DOMAIN LOCK (RUNS AFTER EVERYTHING EXISTS)
========================= */
function isLicensed() {
  // allow only your GH Pages + correct repo path
  if (location.hostname !== ALLOWED_HOST) return false;

  return (
    location.pathname === ALLOWED_PATH_PREFIX ||
    location.pathname.startsWith(ALLOWED_PATH_PREFIX + "/")
  );
}

if (originModal && !isLicensed()) {
  show(originModal);
  [decryptBtn, encryptBtn, copyBtn, copyEncBtn, clearBtn, clearEncBtn].forEach((b) => {
    if (b) b.disabled = true;
  });
  setStatus("Unlicensed domain or path. This tool runs only on the official site.", "err");
  setStatusEnc("Unlicensed domain or path. This tool runs only on the official site.", "err");
}

/* =========================
   DETERRENTS (NOT REAL SECURITY)
========================= */
document.addEventListener("contextmenu", (e) => e.preventDefault());

document.addEventListener("keydown", (e) => {
  const key = String(e.key || "").toLowerCase();
  const ctrl = e.ctrlKey || e.metaKey; // Ctrl (Win/Linux) / Cmd (macOS)

  const blocked =
    key === "f12" ||
    (ctrl && key === "u") ||
    (ctrl && e.shiftKey && ["i", "j", "c"].includes(key));

  if (blocked) {
    e.preventDefault();
    e.stopPropagation();
    if (devtoolsModal) show(devtoolsModal);
  }
}, true);

// Light devtools heuristic (false positives possible)
let devtoolsShown = false;
setInterval(() => {
  const threshold = 220;
  const dw = Math.abs(window.outerWidth - window.innerWidth);
  const dh = Math.abs(window.outerHeight - window.innerHeight);
  const maybeOpen = dw > threshold || dh > threshold;

  if (maybeOpen && !devtoolsShown) {
    devtoolsShown = true;
    if (devtoolsModal) show(devtoolsModal);
  }
  if (!maybeOpen && devtoolsShown) {
    devtoolsShown = false;
    if (devtoolsModal) hide(devtoolsModal);
  }
}, 800);

/* =========================
   BOOT
========================= */
setTheme(safeLSGet(LS_THEME) === "dark" ? "dark" : "light");

const activeTab = document.querySelector(".tab.active");
if (activeTab) activeTab.click();
