/* CryptoShield Web (client-side)
   IMPORTANT REALITY CHECK:
   - Any JavaScript/HTML/CSS shipped to a browser can be viewed or copied by a determined user.
   - The measures below are deterrents + UI hardening, NOT a true way to hide source code.
*/

"use strict";

const MAGIC = new TextEncoder().encode("CSP1");
const SALT_LEN = 16; // If you changed this between versions, old tokens may fail unless decrypt tries multiple salt sizes.
const ITERATIONS = 200000; // PBKDF2 iterations
const KEY_LEN = 32;
const IV_LEN = 16;

// Domain/license gating (deterrent, not security)
// Allowlist: hostname -> required path prefix (or "/" for any path)
const LICENSE_ALLOWLIST = {
  // GitHub Pages serves the site under /Crypto-tool
  "code-help-on-python.github.io": "/Crypto-tool",

  // Netlify serves the site at the root
  "cryptoshield-tool.netlify.app": "/",

  // Optional: add your custom domain(s) here, typically "/"
  // "cryptoshield.lk": "/",
};

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

  // Allow local file use (opened directly from disk)
  if (window.location.protocol === "file:") return true;

  const host = normalizeHost(window.location.hostname);

  // Allow local dev
  if (host === "localhost" || host === "127.0.0.1") return true;

  // Optional: allow Netlify deploy previews for this site
  // e.g. deploy-preview-12--cryptoshield-tool.netlify.app
  const isNetlifyPreview =
    host.endsWith(".netlify.app") && host.includes("cryptoshield-tool");
  if (isNetlifyPreview) return true;

  const expectedPrefixRaw = LICENSE_ALLOWLIST[host];
  if (!expectedPrefixRaw) return false;

  let prefix = normalizePath(expectedPrefixRaw);
  if (!prefix.startsWith("/")) prefix = `/${prefix}`;

  if (prefix === "/") return true;

  const path = normalizePath(window.location.pathname);
  return path === prefix || path.startsWith(`${prefix}/`);
}

function bytesToBase64Url(bytes) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(b64url) {
  const b64 = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
  return diff === 0;
}

async function deriveKey(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(String(passphrase || "")),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: ITERATIONS,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: KEY_LEN * 8 },
    false,
    ["encrypt", "decrypt"]
  );
}

function randomBytes(len) {
  const u = new Uint8Array(len);
  crypto.getRandomValues(u);
  return u;
}

async function encryptToken(plaintext, passphrase) {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = await deriveKey(passphrase, salt);

  const pt = new TextEncoder().encode(String(plaintext || ""));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    pt
  ));

  const tokenBytes = concatBytes(MAGIC, salt, iv, ct);
  return bytesToBase64Url(tokenBytes);
}

async function decryptToken(token, passphrase) {
  const bytes = base64UrlToBytes(token);

  // Basic length sanity
  if (bytes.length < MAGIC.length + SALT_LEN + IV_LEN + 1) {
    throw new Error("Token too short / invalid.");
  }

  const magic = bytes.subarray(0, MAGIC.length);
  if (!equalBytes(magic, MAGIC)) {
    throw new Error("Invalid token header.");
  }

  const saltStart = MAGIC.length;
  const saltEnd = saltStart + SALT_LEN;
  const ivStart = saltEnd;
  const ivEnd = ivStart + IV_LEN;

  const salt = bytes.subarray(saltStart, saltEnd);
  const iv = bytes.subarray(ivStart, ivEnd);
  const ct = bytes.subarray(ivEnd);

  const key = await deriveKey(passphrase, salt);

  let ptBuf;
  try {
    ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  } catch (e) {
    throw new Error("Wrong passphrase or corrupted token.");
  }

  return new TextDecoder().decode(new Uint8Array(ptBuf));
}

// -------- UI helpers --------

function $(sel) {
  return document.querySelector(sel);
}
function setText(sel, text) {
  const el = $(sel);
  if (el) el.textContent = text;
}
function setValue(sel, val) {
  const el = $(sel);
  if (el) el.value = val;
}

function showModal(id) {
  const modal = $(id);
  if (!modal) return;
  modal.classList.add("open");
  modal.setAttribute("aria-hidden", "false");
}
function hideModal(id) {
  const modal = $(id);
  if (!modal) return;
  modal.classList.remove("open");
  modal.setAttribute("aria-hidden", "true");
}

function toast(msg) {
  const el = $("#toast");
  if (!el) return alert(msg);
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 1800);
}

function setBusy(btn, busy) {
  if (!btn) return;
  btn.disabled = !!busy;
  btn.classList.toggle("busy", !!busy);
}

function setTheme(theme) {
  const t = (theme === "dark") ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("cs_theme", t); } catch (_) {}
}

function loadTheme() {
  let t = "light";
  try { t = localStorage.getItem("cs_theme") || "light"; } catch (_) {}
  setTheme(t);
}

function copyToClipboard(text) {
  const s = String(text || "");
  if (!s) return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(s).then(() => toast("Copied ✅")).catch(() => toast("Copy failed"));
  } else {
    const ta = document.createElement("textarea");
    ta.value = s;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast("Copied ✅"); }
    catch (_) { toast("Copy failed"); }
    finally { document.body.removeChild(ta); }
  }
}

// -------- License gate UI --------

function showUnlicensedDomainModal() {
  const host = window.location.hostname;
  const path = window.location.pathname;
  setText("#licenseHost", host || "");
  setText("#licensePath", path || "");
  showModal("#licenseModal");
}

function applyLicenseGate() {
  if (isLicensedOrigin()) return;

  // Disable whole app UI
  document.documentElement.classList.add("license-blocked");

  // Show notice modal
  showUnlicensedDomainModal();
}

// -------- App logic --------

function bind() {
  const btnEncrypt = $("#btnEncrypt");
  const btnDecrypt = $("#btnDecrypt");
  const btnCopy = $("#btnCopy");
  const btnCopyPlain = $("#btnCopyPlain");
  const btnShow = $("#btnShow");
  const pass = $("#passphrase");
  const plain = $("#plaintext");
  const token = $("#token");

  const tabEncrypt = $("#tabEncrypt");
  const tabDecrypt = $("#tabDecrypt");

  function setMode(mode) {
    const isEnc = mode === "encrypt";
    tabEncrypt?.classList.toggle("active", isEnc);
    tabDecrypt?.classList.toggle("active", !isEnc);
    document.documentElement.setAttribute("data-mode", isEnc ? "encrypt" : "decrypt");
  }

  tabEncrypt?.addEventListener("click", () => setMode("encrypt"));
  tabDecrypt?.addEventListener("click", () => setMode("decrypt"));

  btnShow?.addEventListener("click", () => {
    if (!pass) return;
    const type = pass.getAttribute("type");
    pass.setAttribute("type", type === "password" ? "text" : "password");
    btnShow.textContent = type === "password" ? "Hide" : "Show";
  });

  btnEncrypt?.addEventListener("click", async () => {
    try {
      setBusy(btnEncrypt, true);
      const p = pass?.value || "";
      const pt = plain?.value || "";
      if (!p) return toast("Enter a passphrase");
      if (!pt) return toast("Enter plaintext");
      const t = await encryptToken(pt, p);
      setValue("#token", t);
      toast("Encrypted ✅");
    } catch (e) {
      toast(e?.message || "Encrypt failed");
    } finally {
      setBusy(btnEncrypt, false);
    }
  });

  btnDecrypt?.addEventListener("click", async () => {
    try {
      setBusy(btnDecrypt, true);
      const p = pass?.value || "";
      const t = token?.value || "";
      if (!p) return toast("Enter a passphrase");
      if (!t) return toast("Enter token");
      const pt = await decryptToken(t, p);
      setValue("#plaintext", pt);
      toast("Decrypted ✅");
    } catch (e) {
      toast(e?.message || "Decrypt failed");
    } finally {
      setBusy(btnDecrypt, false);
    }
  });

  btnCopy?.addEventListener("click", () => copyToClipboard(token?.value || ""));
  btnCopyPlain?.addEventListener("click", () => copyToClipboard(plain?.value || ""));

  // Theme toggle
  $("#themeLight")?.addEventListener("click", () => setTheme("light"));
  $("#themeDark")?.addEventListener("click", () => setTheme("dark"));

  // About modal
  $("#btnAbout")?.addEventListener("click", () => showModal("#aboutModal"));
  $("#aboutClose")?.addEventListener("click", () => hideModal("#aboutModal"));

  // License modal close
  $("#licenseClose")?.addEventListener("click", () => hideModal("#licenseModal"));
}

function init() {
  loadTheme();
  bind();
  applyLicenseGate();
}

document.addEventListener("DOMContentLoaded", init);
