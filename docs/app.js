/* CryptoShield Web (client-side)
   IMPORTANT REALITY CHECK:
   - Any JavaScript/HTML/CSS shipped to a browser can be viewed or copied by a determined user.
   - The measures below are deterrents + UI hardening, NOT a true way to hide source code.
*/

"use strict";

const MAGIC = new TextEncoder().encode("CSP1");
const SALT_LEN = 16; // If you changed this between versions, old tokens may fail unless decrypt tries multiple salt sizes.
const ITERATIONS = 210000; // PBKDF2 iterations
const KEY_LEN = 32;
const HMAC_LEN = 32;
const IV_LEN = 16;

// Domain/license gating (deterrent, not security)
const ALLOWED_HOSTS = [
  "code-help-on-python.github.io",
  "localhost",
  "127.0.0.1",
];
const ALLOWED_PATH_PREFIX = "/Crypto-tool"; // no trailing slash

function isLicensedOrigin() {
  const normalizeHost = (value) => String(value || "").replace(/\.$/, "").toLowerCase();
  const normalizePath = (value) => {
    let path = String(value || "/");
    try { path = decodeURIComponent(path); } catch (_) {}
    path = path
      .replace(/\/index\.html$/i, "")
      .replace(/\/+$/g, "")
      .toLowerCase();
    return path === "" ? "/" : path;
  };

  if (window.location.protocol === "file:") return true;

  const host = normalizeHost(window.location.hostname);
  const allowedHosts = ALLOWED_HOSTS.map(normalizeHost);
  if (!allowedHosts.includes(host)) return false;
  if (host === "localhost" || host === "127.0.0.1") return true;

  let prefix = normalizePath(ALLOWED_PATH_PREFIX);
  if (!prefix.startsWith("/")) prefix = `/${prefix}`;
  if (prefix === "/") return true;

  const path = normalizePath(window.location.pathname);
  return path === prefix || path.startsWith(`${prefix}/`);
}

function bytesToBase64Url(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.slice(i, i + chunk));
  }
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlToBytes(s) {
  const clean = String(s).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = clean.length % 4 === 0 ? "" : "=".repeat(4 - (clean.length % 4));
  const b64 = clean + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function getTokenCandidates(tokenBytes) {
  const candidates = [];

  // Most common case: tokenBytes is ASCII base64url string (e.g., "gAAAAA...")
  try {
    const s = new TextDecoder().decode(tokenBytes);
    if (s && s.length > 10) {
      // If it looks like base64url, accept it
      candidates.push(base64urlToBytes(s));
    }
  } catch {
    // ignore
  }

  // Sometimes the token bytes already ARE the decoded token
  // If first byte is 0x80, that matches Fernet version.
  if (tokenBytes.length > 1 && tokenBytes[0] === 0x80) {
    candidates.push(tokenBytes);
  }

  // Deduplicate
  const seen = new Set();
  const unique = [];
  for (const c of candidates) {
    const k = bytesToBase64Url(c);
    if (!seen.has(k)) {
      seen.add(k);
      unique.push(c);
    }
  }
  return unique;
}

async function pbkdf2(passphraseBytes, saltBytes, keyLen) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    passphraseBytes,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: ITERATIONS,
    },
    baseKey,
    keyLen * 8
  );
  return new Uint8Array(bits);
}

async function deriveKeys(passphrase, saltBytes) {
  const passBytes = new TextEncoder().encode(passphrase);
  const dk = await pbkdf2(passBytes, saltBytes, 64);
  const signingKeyBytes = dk.slice(0, 32);
  const encryptionKeyBytes = dk.slice(32, 64);

  const signingKey = await crypto.subtle.importKey(
    "raw",
    signingKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  const encryptionKey = await crypto.subtle.importKey(
    "raw",
    encryptionKeyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );

  return { signingKey, encryptionKey };
}

// Fernet parsing: [0x80][timestamp(8)][IV(16)][ciphertext(...)] [HMAC(32)]
function parseFernetToken(tokenRaw) {
  if (!(tokenRaw instanceof Uint8Array)) throw new Error("Invalid token bytes.");

  if (tokenRaw.length < 1 + 8 + IV_LEN + HMAC_LEN + 1) throw new Error("Token too short.");
  const version = tokenRaw[0];
  if (version !== 0x80) throw new Error("Invalid token version.");

  const ts = tokenRaw.slice(1, 9); // 8 bytes
  const iv = tokenRaw.slice(9, 9 + IV_LEN);
  const hmac = tokenRaw.slice(tokenRaw.length - HMAC_LEN);
  const ciphertext = tokenRaw.slice(9 + IV_LEN, tokenRaw.length - HMAC_LEN);

  const dataToSign = tokenRaw.slice(0, tokenRaw.length - HMAC_LEN);
  return { ts, iv, ciphertext, dataToSign, hmac };
}

async function verifyHmac(signingKey, data, expectedHmacBytes) {
  const ok = await crypto.subtle.verify(
    "HMAC",
    signingKey,
    expectedHmacBytes,
    data
  );
  return ok;
}

async function decryptFernet(encryptionKey, ivBytes, ciphertextBytes) {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: ivBytes },
    encryptionKey,
    ciphertextBytes
  );
  return new Uint8Array(plaintext);
}

async function encryptFernet(encryptionKey, ivBytes, plaintextBytes) {
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: ivBytes },
    encryptionKey,
    plaintextBytes
  );
  return new Uint8Array(ciphertext);
}

async function hmacSha256(signingKey, data) {
  const mac = await crypto.subtle.sign("HMAC", signingKey, data);
  return new Uint8Array(mac);
}

// Create CryptoShield wrapper: base64url( MAGIC + salt + fernetTokenStringBytes )
async function encryptPayload(passphrase, plaintext) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!plaintext) throw new Error("Plaintext is required.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const { signingKey, encryptionKey } = await deriveKeys(passphrase, salt);

  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ptBytes = new TextEncoder().encode(plaintext);

  // Fernet format: version + timestamp + iv + ciphertext + hmac
  const version = new Uint8Array([0x80]);
  const ts = new Uint8Array(8);
  // big-endian timestamp (seconds since epoch)
  let now = Math.floor(Date.now() / 1000);
  for (let i = 7; i >= 0; i -= 1) {
    ts[i] = now & 0xff;
    // eslint-disable-next-line no-bitwise
    now >>>= 8;
  }

  const ct = await encryptFernet(encryptionKey, iv, ptBytes);
  const dataToSign = concatBytes(version, ts, iv, ct);
  const mac = await hmacSha256(signingKey, dataToSign);
  const tokenRaw = concatBytes(dataToSign, mac);

  // We store ASCII base64url token bytes inside our wrapper
  const tokenB64u = bytesToBase64Url(tokenRaw);
  const tokenStrBytes = new TextEncoder().encode(tokenB64u);

  const payloadBytes = concatBytes(MAGIC, salt, tokenStrBytes);
  return bytesToBase64Url(payloadBytes);
}

/* ===========================
   ✅ FIXED + COMPATIBLE DECRYPT
   =========================== */
async function decryptPayload(passphrase, payload) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!payload) throw new Error("Token is required.");

  const cleaned = String(payload).replace(/\s+/g, "");
  if (!cleaned.startsWith("Q1NQ")) {
    throw new Error("Not a CryptoShield token (expected it to start with Q1NQ).");
  }

  const payloadBytes = base64urlToBytes(cleaned);
  if (payloadBytes.length < MAGIC.length + 1) throw new Error("Invalid token format.");

  // Check MAGIC header
  const magic = payloadBytes.slice(0, MAGIC.length);
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (magic[i] !== MAGIC[i]) throw new Error("Invalid token format.");
  }

  // Backward/forward compatibility: try multiple salt lengths.
  // If SALT_LEN changed between builds, older tokens would otherwise fail with “Invalid token version”.
  const saltLensToTry = [SALT_LEN, 12, 16, 24, 32].filter((v, i, a) => a.indexOf(v) === i);

  let lastErr = null;
  let authErr = null;

  for (const saltLen of saltLensToTry) {
    if (payloadBytes.length < MAGIC.length + saltLen + 1) continue;

    const salt = payloadBytes.slice(MAGIC.length, MAGIC.length + saltLen);
    const tokenBytes = payloadBytes.slice(MAGIC.length + saltLen);

    // tokenBytes are ASCII of the fernet base64url token string
    const candidates = getTokenCandidates(tokenBytes);

    try {
      const { signingKey, encryptionKey } = await deriveKeys(passphrase, salt);

      for (const tokenRaw of candidates) {
        try {
          const { iv, ciphertext, dataToSign, hmac } = parseFernetToken(tokenRaw);
          const ok = await verifyHmac(signingKey, dataToSign, hmac);
          if (!ok) throw new Error("Wrong passphrase or corrupted token.");

          const plaintextBytes = await decryptFernet(encryptionKey, iv, ciphertext);
          return new TextDecoder().decode(plaintextBytes);
        } catch (err) {
          lastErr = err;
          const msg = err instanceof Error ? err.message.toLowerCase() : "";
          if (msg.includes("passphrase") || msg.includes("password") || msg.includes("corrupted") || msg.includes("hmac")) {
            authErr = err;
          }
        }
      }
    } catch (err) {
      lastErr = err;
    }
  }

  if (authErr) throw authErr;
  if (lastErr) throw lastErr;
  throw new Error("Wrong passphrase or corrupted token.");
}

/* ===========================
   UI wiring
   =========================== */

const LS_THEME = "cryptoshield-theme";
const LS_ACCEPTED = "cryptoshield-accepted-v1";

// ---- UI: Elements ----
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

const aboutOpen = document.getElementById("about-open");
const aboutClose = document.getElementById("about-close");
const aboutModal = document.getElementById("modal-about");

const firstModal = document.getElementById("modal-first");
const firstAccept = document.getElementById("first-accept");

const devtoolsModal = document.getElementById("devtools-warning");
const originModal = document.getElementById("origin-lock");

function show(el) { if (el) el.hidden = false; }
function hide(el) { if (el) el.hidden = true; }

function safeLSGet(key) {
  try { return localStorage.getItem(key); } catch (_) { return null; }
}
function safeLSSet(key, val) {
  try { localStorage.setItem(key, val); } catch (_) {}
}

function setStatus(text, type) {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.classList.remove("ok", "err");
  if (type) statusEl.classList.add(type);
}
function setStatusEnc(text, type) {
  if (!statusEncEl) return;
  statusEncEl.textContent = text;
  statusEncEl.classList.remove("ok", "err");
  if (type) statusEncEl.classList.add(type);
}

function setTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  if (document.body) document.body.dataset.theme = normalized;
  themeButtons.forEach((btn) =>
    btn.classList.toggle("active", btn.dataset.theme === normalized)
  );
  safeLSSet(LS_THEME, normalized);
}

// ---- Apply domain lock AFTER elements exist ----
if (!isLicensedOrigin()) {
  [decryptBtn, encryptBtn, copyBtn, copyEncBtn, clearBtn, clearEncBtn].forEach((b) => {
    if (b) b.disabled = true;
  });
  show(originModal);
  setStatus("Unlicensed domain/path.", "err");
  setStatusEnc("Unlicensed domain/path.", "err");
}

// ---- Tabs ----
tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    tabButtons.forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    tabPanels.forEach((p) => { p.hidden = true; p.classList.remove("active"); });

    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");

    const target = document.getElementById(`tab-${btn.dataset.tab}`);
    if (target) { target.hidden = false; target.classList.add("active"); }
  });
});

// ---- Theme ----
themeButtons.forEach((btn) => btn.addEventListener("click", () => setTheme(btn.dataset.theme)));

// ---- Show/Hide pass ----
togglePassButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    btn.textContent = hidden ? "Hide" : "Show";
  });
});

// ---- Actions: Decrypt ----
if (decryptBtn) {
  decryptBtn.addEventListener("click", async () => {
    setStatus("Decrypting...", "");
    if (outputBox) outputBox.value = "";
    decryptBtn.disabled = true;

    try {
      const result = await decryptPayload(
        passphraseDecrypt ? passphraseDecrypt.value.trim() : "",
        tokenInput ? tokenInput.value : ""
      );
      if (outputBox) outputBox.value = result;
      setStatus("Decrypted.", "ok");
    } catch (err) {
      setStatus(err instanceof Error ? err.message : "Decryption failed.", "err");
    } finally {
      decryptBtn.disabled = false;
    }
  });
}

if (copyBtn) {
  copyBtn.addEventListener("click", async () => {
    if (!outputBox || !outputBox.value.trim()) return setStatus("Nothing to copy.", "err");
    try {
      await navigator.clipboard.writeText(outputBox.value);
      setStatus("Copied.", "ok");
    } catch (_) {
      setStatus("Copy failed. Please copy manually.", "err");
    }
  });
}

if (clearBtn) {
  clearBtn.addEventListener("click", () => {
    if (passphraseDecrypt) passphraseDecrypt.value = "";
    if (tokenInput) tokenInput.value = "";
    if (outputBox) outputBox.value = "";
    setStatus("Cleared.", "");
  });
}

// ---- Actions: Encrypt ----
if (encryptBtn) {
  encryptBtn.addEventListener("click", async () => {
    setStatusEnc("Encrypting...", "");
    if (tokenOut) tokenOut.value = "";
    encryptBtn.disabled = true;

    try {
      const token = await encryptPayload(
        passphraseEncrypt ? passphraseEncrypt.value.trim() : "",
        plaintextInput ? plaintextInput.value.trim() : ""
      );
      if (tokenOut) tokenOut.value = token;
      setStatusEnc("Encrypted.", "ok");
    } catch (err) {
      setStatusEnc(err instanceof Error ? err.message : "Encryption failed.", "err");
    } finally {
      encryptBtn.disabled = false;
    }
  });
}

if (copyEncBtn) {
  copyEncBtn.addEventListener("click", async () => {
    if (!tokenOut || !tokenOut.value.trim()) return setStatusEnc("Nothing to copy.", "err");
    try {
      await navigator.clipboard.writeText(tokenOut.value);
      setStatusEnc("Copied.", "ok");
    } catch (_) {
      setStatusEnc("Copy failed. Please copy manually.", "err");
    }
  });
}

if (clearEncBtn) {
  clearEncBtn.addEventListener("click", () => {
    if (passphraseEncrypt) passphraseEncrypt.value = "";
    if (plaintextInput) plaintextInput.value = "";
    if (tokenOut) tokenOut.value = "";
    setStatusEnc("Cleared.", "");
  });
}

// ---- Modals ----
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

// ---- Boot ----
setTheme(safeLSGet(LS_THEME) === "dark" ? "dark" : "light");
const activeTab = document.querySelector(".tab.active");
if (activeTab) activeTab.click();
