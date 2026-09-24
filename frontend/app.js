/*
 * DCTA overlay — transaction confirmation. (brief 4.2 / 4.5)
 *
 * SECURITY MODEL (read before editing):
 *  - The overlay renders the ResolvedPlan via a FIXED template (known fields
 *    -> fixed labels). It never displays LLM-generated text as the summary.
 *    Values are set via textContent (never innerHTML for data) so an
 *    attacker-controllable field cannot inject markup -- the client-integrity
 *    assumption made as strong as possible.
 *  - The browser RECOMPUTES payload_hash itself, from the SAME object it
 *    rendered, using frontend/canonical.js (byte-identical to Python's
 *    canonical_json). It then builds the WebAuthn challenge from its own hash
 *    + the server nonce. The server verifies the assertion against its own
 *    independently-derived hash. A divergence between displayed and signed is
 *    therefore impossible rather than unlikely.
 *  - userVerification: "required" -> the real device biometric is used.
 */
"use strict";

const API = "";
const DEMO_USER = "u_alice";

/* ---------- base64url + SHA-256 helpers (no build step) ---------- */
function b64uToBuf(b64u) {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64 + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64u(buf) {
  const arr = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function strToBuf(s) {
  return new TextEncoder().encode(s).buffer;
}
async function sha256Hex(s) {
  const h = await crypto.subtle.digest("SHA-256", strToBuf(s));
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256Buf(s) {
  return crypto.subtle.digest("SHA-256", strToBuf(s)); // 32-byte ArrayBuffer
}
function centsToDisplay(cents) {
  // Matches Python backend/display.py: cents -> "$1,234.56"
  const dollars = cents / 100;
  return "$" + dollars.toLocaleString("en-US", {
    minimumFractionDigits: 2, maximumFractionDigits: 2,
  });
}

/* ---------- tiny fetch helper ---------- */
async function jget(url) {
  const r = await fetch(url);
  return r.json();
}
async function jpost(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

/* ---------- fixed-template render (no innerHTML for data) ---------- */
function el(tag, cls) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  return n;
}
function row(dt, dd) {
  const dl = el("dl");
  const k = el("dt"); k.textContent = dt;
  const v = el("dd"); v.textContent = dd;
  dl.append(k, v);
  return dl;
}
function renderPlan(plan) {
  const legsEl = document.getElementById("legs");
  legsEl.replaceChildren();
  for (const leg of plan.plan) {
    const card = el("div", "leg");
    const badge = el("span", "type"); badge.textContent = leg.type;
    card.append(badge);
    const dl = el("dl");
    const addRow = (k, v) => {
      const dt = el("dt"); dt.textContent = k;
      const dd = el("dd"); dd.textContent = v;
      dl.append(dt, dd);
    };
    addRow("From", leg.source_account);
    if (leg.payee_display) addRow("To", leg.payee_display + " (" + leg.payee_id + ")");
    if (leg.amount_cents != null) {
      const dt = el("dt"); dt.textContent = "Amount";
      const dd = el("dd"); dd.className = "amt"; dd.textContent = centsToDisplay(leg.amount_cents);
      dl.append(dt, dd);
    }
    if (leg.ticker) addRow("Ticker", leg.ticker);
    if (leg.estimated_shares != null) addRow("Est. shares", String(leg.estimated_shares));
    card.append(dl);
    legsEl.append(card);
  }
  document.getElementById("window").textContent =
    plan.created_at + " \u2192 " + plan.expires_at + " (Unix sec UTC)";
  document.getElementById("txhash").textContent = plan.transcript_hash.slice(0, 16) + "\u2026";
}

function showErr(msg) {
  const e = document.getElementById("err");
  e.textContent = msg;
  e.hidden = false;
}

/* ---------- registration ---------- */
function prepareCreateOptions(opts) {
  // options_to_json gives base64url STRINGS; navigator.credentials.create
  // wants BufferSources for challenge / user.id / excludeCredentials[].id.
  const o = JSON.parse(JSON.stringify(opts));
  o.challenge = b64uToBuf(o.challenge);
  if (o.user && o.user.id) o.user.id = b64uToBuf(o.user.id);
  if (Array.isArray(o.excludeCredentials))
    o.excludeCredentials = o.excludeCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  return o;
}
function credentialToJson(c) {
  const r = c.response;
  return {
    id: c.id, rawId: c.id, type: c.type,
    response: {
      attestationObject: bufToB64u(r.attestationObject),
      clientDataJSON: bufToB64u(r.clientDataJSON),
    },
    authenticatorAttachment: c.authenticatorAttachment || null,
  };
}
async function registerPasskey() {
  const begin = await jpost(API + "/api/auth/register/begin", { user_id: DEMO_USER });
  const opts = prepareCreateOptions(JSON.parse(begin.json.options).publicKey || JSON.parse(begin.json.options));
  const cred = await navigator.credentials.create({ publicKey: opts });
  const payload = { user_id: DEMO_USER, credential: credentialToJson(cred) };
  const res = await jpost(API + "/api/auth/register/complete", payload);
  if (res.status !== 200) throw new Error("registration failed: " + (res.json.detail || res.status));
  return res.json.credential_id;
}

/* ---------- signing ---------- */
function assertionToJson(a) {
  const r = a.response;
  return {
    id: a.id, rawId: a.id, type: a.type,
    response: {
      authenticatorData: bufToB64u(r.authenticatorData),
      clientDataJSON: bufToB64u(r.clientDataJSON),
      signature: bufToB64u(r.signature),
      userHandle: r.userHandle ? bufToB64u(r.userHandle) : null,
    },
    authenticatorAttachment: a.authenticatorAttachment || null,
  };
}
async function signAndExecute(plan, credentialIds, rpId) {
  // rpId comes from the server (/api/auth/config) so registration and signing
  // cannot disagree (M1: location.hostname would differ from settings.rp_id
  // when the app is reached at 127.0.0.1 instead of localhost).
  // 1. recompute payload_hash from the SAME object we rendered (canonical.js
  //    is byte-identical to Python's canonical_json -> the hashes match).
  const canonical = canonicalJson(plan);
  const payloadHash = await sha256Hex(canonical);
  document.getElementById("phash").textContent = payloadHash.slice(0, 16) + "\u2026";

  // 2. draft-bound server nonce (single-use, 120s TTL).
  const nonceResp = await jget(API + "/api/auth/nonce?draft_id=" + encodeURIComponent(plan.draft_id));
  const nonce = nonceResp.nonce;

  // 3. build the challenge OURSELF: sha256(payload_hash + nonce). The server
  //    re-derives the same bytes from its own payload_hash + the nonce and
  //    verifies the authenticator signed exactly that.
  const challenge = await sha256Buf(payloadHash + nonce);

  // 4. biometric sign.
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: challenge,
      rpId: rpId,
      userVerification: "required",
      timeout: 60000,
      allowCredentials: credentialIds.map((id) => ({ type: "public-key", id: b64uToBuf(id) })),
    },
  });

  // 5. submit to the gateway.
  return jpost(API + "/api/gateway/execute-webauthn", {
    resolved_plan: plan,
    assertion: assertionToJson(assertion),
    nonce: nonce,
    credential_id: assertion.id,
  });
}

function showResult(res) {
  const box = document.getElementById("result");
  const status = res.json.accepted ? "EXECUTED" : res.json.rejection || "REJECTED";
  // status + body are TEXT, never parsed as HTML. A rejection reason carries
  // executor/LLM-influenced text (e.g. a failed account "<img src=x ...>");
  // this is the trusted overlay -- the surface the "what you see is what you
  // sign" argument presumes renders faithfully -- so markup must appear as
  // literal characters, not as a parsed element. Same textContent-only rule
  // renderPlan() follows for every field. (H1: this was an innerHTML sink;
  // JSON.stringify escapes quotes but not </>, so the tag parsed.)
  const h3 = el("h3"); h3.textContent = status;
  const pre = el("pre");
  pre.textContent = JSON.stringify(
    res.json.accepted ? res.json.execution : res.json, null, 2);
  box.replaceChildren(h3, pre);           // clears any prior content, appends
  box.className = "result " + (res.json.accepted ? "ok" : "bad");
  box.hidden = false;
}

/* ---------- bootstrap ---------- */
async function init() {
  const creds = await jget(API + "/api/auth/credentials?user_id=" + DEMO_USER);
  const hasPasskey = creds.credential_ids && creds.credential_ids.length > 0;

  if (!hasPasskey) {
    const reg = document.getElementById("register");
    reg.hidden = false;
    document.getElementById("register-btn").onclick = async () => {
      try {
        await registerPasskey();
        reg.hidden = true;
        location.reload();
      } catch (e) { showErr(String(e)); }
    };
    return;
  }

  // passkey exists -> show the overlay + sign button
  const plan = await jget(API + "/api/drafts/demo");
  const cfg = await jget(API + "/api/auth/config");   // server RP id (M1)
  renderPlan(plan);
  document.getElementById("plan").hidden = false;
  const btn = document.getElementById("sign");
  btn.disabled = false;
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      const res = await signAndExecute(plan, creds.credential_ids, cfg.rp_id);
      showResult(res);
    } catch (e) {
      showErr(String(e));
    } finally {
      btn.disabled = false;
    }
  };
}
window.addEventListener("DOMContentLoaded", init);
