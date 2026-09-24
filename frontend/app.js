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
/* The overlay is the one surface we tell the user to trust, so it must not
   show database internals. These are pure, deterministic transforms of the
   SIGNED payload — no extra inputs, no new trust surface, and the template
   stays fixed (brief 4.2). */
function acctLabel(id) {
  // "acct_savings" -> "Savings". Deterministic and local; falls back to the
  // raw id rather than inventing a name it cannot derive.
  const m = /^acct_(.+)$/.exec(id || "");
  if (!m) return id || "";
  return m[1].charAt(0).toUpperCase() + m[1].slice(1);
}
function windowLabel(created, expires) {
  // Unix seconds are correct in the payload and meaningless on screen.
  const mins = Math.max(0, Math.round((expires - created) / 60));
  const until = new Date(expires * 1000).toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  return `${mins} min — expires ${until}`;
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
    addRow("From", acctLabel(leg.source_account));
    // payee_display is already the safe DB-sourced label (nickname + last 4).
    // The raw payee_id is an internal identifier and does not belong on the
    // confirmation screen.
    if (leg.payee_display) addRow("To", leg.payee_display);
    if (leg.biller_display) addRow("To", leg.biller_display);
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
    windowLabel(plan.created_at, plan.expires_at);
  document.getElementById("txhash").textContent = plan.transcript_hash.slice(0, 16) + "\u2026";
  // Computed at sign time; show a placeholder rather than an empty row, which
  // reads as broken.
  document.getElementById("phash").textContent = "computed when you confirm";
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

/* ---------- M7: transcript -> draft, with the clarify loop ---------- */
/* The draft lives SERVER-SIDE (backend/drafts.py). We send a transcript and get
   a draft_id back; answering a question sends only {field, choice_id} for that
   id. The client never holds or returns the plan — so it cannot substitute one,
   and a clarify round-trip re-RESOLVES against the stored IntentPlan rather
   than re-parsing the transcript, which with a real model could otherwise
   produce a different plan on every turn. */
let CURRENT = { draftId: null, plan: null, credentialIds: [], transcript: "" };

function setStatus(msg) {
  const el = document.getElementById("status");
  if (el) { el.textContent = msg; el.hidden = !msg; }
}

function handleDraft(res) {
  if (res.status !== 200) {
    const d = res.json.detail || {};
    showErr(d.error || `request failed (${res.status})`);
    setStatus("");
    return;
  }
  const body = res.json;
  CURRENT.draftId = body.draft_id;
  setStatus("");

  // Four outcomes, and the user must be able to tell them apart. All are HTTP
  // 200: needing to ask is a normal conversational result, and a refusal is a
  // successful request whose answer is "no".
  if (body.status === "clarify") {
    renderClarify(body);
    Voice.speak(body.question);
    return;
  }
  if (body.status === "blocked") {                 // M5 policy refusal
    showRefusal("BLOCKED BY POLICY", body.reasons || [],
      "A policy rule refused this before it could be drafted.");
    return;
  }
  if (body.status === "frozen") {                  // M6 validator freeze
    showRefusal("FROZEN BY VALIDATOR",
      (body.validation && body.validation.checks) || body.validation || [],
      "The independent validator found a mismatch between what you said and "
      + "what was drafted. This draft cannot be signed.");
    return;
  }

  CURRENT.plan = body.resolved_plan;
  renderPlan(body.resolved_plan);
  document.getElementById("plan").hidden = false;
  if (body.requires_extra_confirmation) {
    setStatus("This amount needs an extra out-of-band confirmation.");
  }
  const btn = document.getElementById("sign");
  btn.disabled = false;
  btn.onclick = onSign;
}

async function submitTranscript(transcript) {
  setStatus("Working…");
  CURRENT.transcript = transcript;
  handleDraft(await jpost(API + "/api/drafts", {
    transcript, user_id: DEMO_USER,
  }));
}

async function answerClarification(field, choiceId) {
  setStatus("Working…");
  handleDraft(await jpost(
    API + "/api/drafts/" + encodeURIComponent(CURRENT.draftId) + "/clarify",
    { field, choice_id: choiceId },
  ));
}

function showRefusal(title, detail, explanation) {
  const box = document.getElementById("result");
  box.replaceChildren();
  const h = el("h3"); h.textContent = title;
  const p = el("p"); p.textContent = explanation;
  const pre = el("pre");
  pre.textContent = JSON.stringify(detail, null, 2);   // textContent, never innerHTML (H1)
  box.append(h, p, pre);
  box.className = "result bad";
  box.hidden = false;
}

function renderClarify(body) {
  const box = document.getElementById("clarify");
  box.replaceChildren();
  const q = el("p", "question"); q.textContent = body.question;
  box.append(q);

  if (body.choices && body.choices.length) {
    // 2+ disambiguation: the user picks, and we resume with `answers`. The
    // resolver re-validates the chosen id against a fresh deterministic match,
    // so a tampered choice cannot inject a payee the mention never justified.
    const row = el("div", "choices");
    for (const c of body.choices) {
      const b = el("button", "choice");
      b.textContent = c.display;                 // textContent: DB-sourced, still never innerHTML
      b.onclick = () => {
        box.hidden = true;
        answerClarification(body.field, c.id);
      };
      row.append(b);
    }
    box.append(row);
  } else {
    // 0-match / empty / insufficient: no candidate list to choose from, so the
    // user re-states the request and it re-enters the pipeline from the top.
    const hint = el("p", "hint");
    hint.textContent = "Say or type it again with more detail.";
    box.append(hint);
  }
  box.hidden = false;
}

function showFrozen(body) {
  const box = document.getElementById("result");
  box.replaceChildren();
  const h = el("h3"); h.textContent = "FROZEN";
  const p = el("p");
  p.textContent = "The independent validator found a mismatch between what you "
    + "said and what was drafted. This draft cannot be signed.";
  const pre = el("pre");
  pre.textContent = JSON.stringify(body.reasons, null, 2);   // never innerHTML (H1)
  box.append(h, p, pre);
  box.className = "result bad";
  box.hidden = false;
}

async function onSign() {
  const btn = document.getElementById("sign");
  btn.disabled = true;
  try {
    const res = await signAndExecute(CURRENT.plan, CURRENT.credentialIds);
    showResult(res);
  } catch (e) {
    showErr(String(e));
  } finally {
    btn.disabled = false;
  }
}

/* ---------- M7: voice input, three tiers ---------- */
function wireVoice() {
  const mic = document.getElementById("mic");
  const textForm = document.getElementById("say-form");
  const textIn = document.getElementById("say");
  if (!mic) return;

  const onText = (t, provider) => {
    textIn.value = t;
    setStatus(`Heard (${provider}): "${t}"`);
    submitTranscript(t);
  };
  const onError = (e) => { setStatus(""); mic.classList.remove("live"); showErr(String(e.message || e)); };
  const onState = (st) => {
    mic.classList.toggle("live", st === "listening");
    setStatus(st === "listening" ? "Listening…" : st === "thinking" ? "Transcribing…" : "");
  };

  let active = null;
  mic.onclick = async () => {
    if (active) { Voice.stop(); active = null; return; }
    document.getElementById("err").hidden = true;
    // Tier 1 first (server-side Tencent ASR). On 503 we drop to tier 2 without
    // telling the user anything went wrong — nothing did.
    active = await Voice.recordAndUpload({
      onText: (t, p) => { active = null; onText(t, p); },
      onError: (e) => { active = null; onError(e); },
      onState,
      onFallback: () => {
        active = null;
        if (!Voice.speechRecognitionAvailable()) {
          setStatus("Speech unavailable — type it instead.");
          textIn.focus();
          return;
        }
        Voice.listenWebSpeech({ onText, onError, onState });
      },
    });
  };

  // Tier 3, always present: typing the same sentence must always work.
  textForm.onsubmit = (e) => {
    e.preventDefault();
    const t = textIn.value.trim();
    if (!t) return;
    document.getElementById("err").hidden = true;
    document.getElementById("clarify").hidden = true;
    submitTranscript(t);
  };
}

/* ---------- bootstrap ---------- */
async function init() {
  const creds = await jget(API + "/api/auth/credentials?user_id=" + DEMO_USER);
  const hasPasskey = creds.credential_ids && creds.credential_ids.length > 0;
  CURRENT.credentialIds = creds.credential_ids || [];

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
  wireVoice();
  document.getElementById("say-box").hidden = false;
}
window.addEventListener("DOMContentLoaded", init);
