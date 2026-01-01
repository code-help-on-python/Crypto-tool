"use strict";

/* =========================
   CryptoShield Web (client-side)
   Matches Python backend:
   - MAGIC = "CSP1"
   - SALT_LEN = 16
   - PBKDF2-HMAC-SHA256, 200,000 iterations
   - Fernet token is stored as BYTES (which are ASCII base64url chars)
   - Outer token is base64.urlsafe_b64encode(MAGIC + salt + fernet_token_bytes)
   ========================= */

const MAGIC = new TextEncoder().encode("CSP1");
const SALT_LEN = 16;
const KDF_ITERS = 200000; // ✅ MUST match backend (Python uses 200_000) :contentReference[oaicite:1]{index=1}

// Domain lock (deterrent only)
const ALLOWED_HOSTS = ["code-help-on-python.github.io"];
const ALLOWED_PATH_PREFIX = "/Crypto-tool"; // no trailing slash

// --- Elements ---
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
const originModal = document.getElementById("origin-lock");

function show(el) { if (el) el.hidden = false; }
function hide(el) { if (el) el.hidden = true; }

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

// --- Theme ---
const LS_THEME = "cryptoshield-theme";
function safeLSGet(key) { try { return localStorage.getItem(key); } catch (_) { return null; } }
function safeLSSet(key, val) { try { localStorage.setItem(key, val); } catch (_) {} }

function setTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.body.dataset.theme = normalized;
  themeButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.theme === normalized));
  safeLSSet(LS_THEME, normalized);
}
setTheme(safeLSGet(LS_THEME) === "dark" ? "dark" : "light");

// --- Domain lock (deterrent only) ---
function isLicensed() {
  if (!ALLOWED_HOSTS.includes(location.hostname)) return false;

  // allow local dev anywhere
  if (location.hostname === "localhost" || location.hostname === "127.0.0.1") return true;

  // enforce path on github pages
  return (
    location.pathname === ALLOWED_PATH_PREFIX ||
    location.pathname.startsWith(ALLOWED_PATH_PREFIX + "/")
  );
}

if (!isLicensed()) {
  [decryptBtn, encryptBtn, copyBtn, copyEncBtn, clearBtn, clearEncBtn].forEach((b) => { if (b) b.disabled = true; });
  show(originModal);
  setStatus("Unlicensed domain/path.", "err");
  setStatusEnc("Unlicensed domain/path.", "err");
}

// --- Base64 helpers (urlsafe) ---
function base64urlToBytes(str) {
  const cleaned = (str || "").replace(/\s+/g, "");
  const b64 = cleaned.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const raw = atob(b64 + pad);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToBase64Url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// Fernet token bytes in Python are ASCII characters; decode to a JS string safely:
function bytesToAscii(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += String.fromCharCode(bytes[i]);
  return out;
}

// --- Crypto primitives ---
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

async function deriveKeyBytes(passphrase, salt) {
  const pwBytes = new TextEncoder().encode(passphrase);
  const material = await crypto.subtle.importKey("raw", pwBytes, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: KDF_ITERS },
    material,
    256
  );
  return new Uint8Array(bits); // 32 bytes
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

async function encryptAesCbc(encryptionKey, iv, plaintextBytes) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const padded = pkcs7Pad(plaintextBytes);
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, padded));
}

function parseFernetToken(raw) {
  // Fernet: version(1)=0x80 + timestamp(8) + iv(16) + ciphertext + hmac(32)
  if (raw.length < 1 + 8 + 16 + 32) throw new Error("Invalid Fernet token.");
  if (raw[0] !== 0x80) throw new Error("Invalid token version.");
  const ivStart = 1 + 8;
  const hmacStart = raw.length - 32;
  const iv = raw.slice(ivStart, ivStart + 16);
  const ciphertext = raw.slice(ivStart + 16, hmacStart);
  const dataToSign = raw.slice(0, hmacStart);
  const hmac = raw.slice(hmacStart);
  return { iv, ciphertext, dataToSign, hmac };
}

async function decryptPayload(passphrase, payload) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!payload) throw new Error("Token is required.");

  const payloadBytes = base64urlToBytes(payload);
  if (payloadBytes.length < MAGIC.length + SALT_LEN + 10) throw new Error("Invalid token format.");

  // MAGIC check
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (payloadBytes[i] !== MAGIC[i]) throw new Error("Invalid token format.");
  }

  const salt = payloadBytes.slice(MAGIC.length, MAGIC.length + SALT_LEN);
  const fernetTokenBytesAscii = payloadBytes.slice(MAGIC.length + SALT_LEN);

  // Python stores Fernet token as BYTES of an ASCII base64url string. :contentReference[oaicite:2]{index=2}
  const fernetStr = bytesToAscii(fernetTokenBytesAscii).trim();
  const fernetRaw = base64urlToBytes(fernetStr);

  const keyBytes = await deriveKeyBytes(passphrase, salt);
  const signingKey = keyBytes.slice(0, 16);
  const encryptionKey = keyBytes.slice(16, 32);

  const { iv, ciphertext, dataToSign, hmac } = parseFernetToken(fernetRaw);
  const ok = await verifyHmac(signingKey, dataToSign, hmac);
  if (!ok) throw new Error("Wrong password or corrupted token.");

  const plaintextBytes = await decryptAesCbc(encryptionKey, iv, ciphertext);
  return new TextDecoder().decode(plaintextBytes);
}

async function encryptPayload(passphrase, plaintext) {
  if (!passphrase) throw new Error("Passphrase is required.");
  if (!plaintext) throw new Error("Plaintext is required.");

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const keyBytes = await deriveKeyBytes(passphrase, salt);
  const signingKey = keyBytes.slice(0, 16);
  const encryptionKey = keyBytes.slice(16, 32);

  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ciphertext = await encryptAesCbc(encryptionKey, iv, new TextEncoder().encode(plaintext));

  // timestamp 8 bytes big-endian
  const timestamp = Math.floor(Date.now() / 1000);
  let ts = BigInt(timestamp);
  const tsBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) { tsBytes[i] = Number(ts & 0xffn); ts >>= 8n; }

  // dataToSign = ver + ts + iv + ciphertext
  const dataToSign = new Uint8Array(1 + 8 + 16 + ciphertext.length);
  dataToSign[0] = 0x80;
  dataToSign.set(tsBytes, 1);
  dataToSign.set(iv, 1 + 8);
  dataToSign.set(ciphertext, 1 + 8 + 16);

  const hmacKey = await crypto.subtle.importKey("raw", signingKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, dataToSign));

  const fernetRaw = new Uint8Array(dataToSign.length + hmac.length);
  fernetRaw.set(dataToSign);
  fernetRaw.set(hmac, dataToSign.length);

  // Python's f.encrypt returns ASCII base64url BYTES
  const fernetStr = bytesToBase64Url(fernetRaw);
  const fernetAsciiBytes = new TextEncoder().encode(fernetStr);

  // Outer payload matches Python: base64url(MAGIC + salt + tokenBytes) :contentReference[oaicite:3]{index=3}
  const payloadBytes = new Uint8Array(MAGIC.length + SALT_LEN + fernetAsciiBytes.length);
  payloadBytes.set(MAGIC, 0);
  payloadBytes.set(salt, MAGIC.length);
  payloadBytes.set(fernetAsciiBytes, MAGIC.length + SALT_LEN);

  return bytesToBase64Url(payloadBytes);
}

// --- UI wiring ---
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

themeButtons.forEach((btn) => btn.addEventListener("click", () => setTheme(btn.dataset.theme)));

togglePassButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    btn.textContent = hidden ? "Hide" : "Show";
  });
});

// Decrypt
decryptBtn.addEventListener("click", async () => {
  setStatus("Decrypting...", "");
  outputBox.value = "";
  decryptBtn.disabled = true;

  try {
    const result = await decryptPayload(passphraseDecrypt.value.trim(), tokenInput.value.trim());
    outputBox.value = result;
    setStatus("Decrypted.", "ok");
  } catch (err) {
    setStatus(err instanceof Error ? err.message : "Decryption failed.", "err");
  } finally {
    decryptBtn.disabled = false;
  }
});

copyBtn.addEventListener("click", async () => {
  if (!outputBox.value.trim()) return setStatus("Nothing to copy.", "err");
  try {
    await navigator.clipboard.writeText(outputBox.value);
    setStatus("Copied.", "ok");
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

// Encrypt
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
    setStatusEnc("Copied.", "ok");
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

// About modal
if (aboutOpen && aboutModal) aboutOpen.addEventListener("click", () => show(aboutModal));
if (aboutClose && aboutModal) aboutClose.addEventListener("click", () => hide(aboutModal));
if (aboutModal) aboutModal.addEventListener("click", (e) => { if (e.target === aboutModal) hide(aboutModal); });
