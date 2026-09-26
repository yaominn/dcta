/*
 * DCTA assistant — a chat that drafts payments; the user signs them. (brief 4.2 / 4.5)
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
async function signAndExecute(plan, credentialIds, rpId,
                              endpoint = "/api/gateway/execute-webauthn",
                              field = "resolved_plan") {
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
  // Already executed (a retry after a lost response, a double tap): the server
  // issues no nonce, so don't ask for a fingerprint — report what happened.
  const done = nonceResp.detail;
  if (done && done.already_executed) {
    return { status: 409, json: { accepted: false, rejection: "DUPLICATE",
                                  execution: done.execution, executed_at: done.executed_at } };
  }
  // Any other refusal (cancelled, expired, not ready): the server will not
  // count a signature, so don't ask for one — say why instead.
  if (!nonceResp.nonce) {
    return { status: 409, json: { accepted: false, rejection: "STATE",
                                  reason: "This can't be approved: " + ((done && done.error) || "no signing challenge")
                                          + ". Nothing was sent." } };
  }
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
  return jpost(API + endpoint, {
    [field]: plan,
    assertion: assertionToJson(assertion),
    nonce: nonce,
    credential_id: assertion.id,
  });
}

/* ---------- chat rendering (no innerHTML for data, ever) ---------- */
/* The page is a conversation. Messages are built with createElement +
   textContent only. A payment is rendered as a FIXED-TEMPLATE card from the
   ResolvedPlan JSON (known fields -> fixed labels); the assistant never shows
   LLM-generated text as a transaction summary. */
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
const thread = () => document.getElementById("thread");

function scrollDown() {
  const t = thread();
  requestAnimationFrame(() => { t.scrollTop = t.scrollHeight; });
}
function addMsg(who, ...children) {
  const m = el("section", "msg " + who);
  m.append(...children);
  thread().append(m);
  scrollDown();
  return m;
}
function botSay(text, cls) {
  return addMsg("bot", el("div", "bubble" + (cls ? " " + cls : ""), text));
}
function userSay(text) {
  return addMsg("user", el("div", "bubble", text));
}

let typingEl = null;
function typing(on) {
  if (typingEl) { typingEl.remove(); typingEl = null; }
  if (!on) return;
  const b = el("div", "bubble typing");
  b.append(el("i"), el("i"), el("i"));
  typingEl = addMsg("bot", b);
}

/* The latest payment card owns the element ids (#plan, #sign, #stepup, …) so
   the live controls are unambiguous. A newer card retires the older one:
   its ids are dropped and its controls disabled — an old draft can't be
   signed from further up the conversation. */
const LIVE_IDS = ["plan", "legs", "window", "txhash", "phash", "sign", "decline",
                  "stepup", "stepup-reason", "stepup-form", "stepup-code"];
function retireLiveCard() {
  // Every control on the spent card, not only the ones with ids — the
  // step-up Verify button stayed live after a Cancel.
  const live = document.getElementById("plan");
  if (live) live.querySelectorAll("button, input").forEach((n) => { n.disabled = true; });
  for (const id of LIVE_IDS) {
    const n = document.getElementById(id);
    if (!n) continue;
    n.removeAttribute("id");
    if (n.tagName === "BUTTON" || n.tagName === "INPUT") n.disabled = true;
  }
  document.querySelectorAll(".chips.live").forEach((c) => {
    c.classList.remove("live");
    c.querySelectorAll("button").forEach((b) => { b.disabled = true; });
  });
}

/* The payment card is the one surface we tell the user to trust, so it must
   not show database internals. These are pure, deterministic transforms of
   the SIGNED payload — no extra inputs, no new trust surface (brief 4.2). */
// Display names for the account id suffixes. The joint account is presented
// as the everyday "Spending" account. Mirrors ACCOUNT_NAMES in
// backend/display.py (the phone message and the resolver's questions); the
// resolver understands "spending" as it (ACCOUNT_TYPE_SYNONYMS).
const ACCOUNT_LABELS = { savings: "Savings", joint: "Spending", invest: "Investments" };
function acctLabel(id) {
  // "acct_savings" -> "Savings". Deterministic and local; falls back to the
  // raw id rather than inventing a name it cannot derive.
  const m = /^acct_(.+)$/.exec(id || "");
  if (!m) return id || "";
  return ACCOUNT_LABELS[m[1]] || m[1].charAt(0).toUpperCase() + m[1].slice(1);
}
function windowLabel(created, expires) {
  // Unix seconds are correct in the payload and meaningless on screen.
  const mins = Math.max(0, Math.round((expires - created) / 60));
  const until = new Date(expires * 1000).toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  return `${mins} min — expires ${until}`;
}
const LEG_ICON = { TRANSFER: "→", PAY_BILL: "≡", BUY_EQUITY: "↗" };
const LEG_NAME = { TRANSFER: "Transfer", PAY_BILL: "Bill payment", BUY_EQUITY: "Buy shares" };

function legRow(leg) {
  const row = el("div", "leg");
  row.append(el("div", "icon", LEG_ICON[leg.type] || "•"));
  // payee_display / biller_display are already the safe DB-sourced labels
  // (nickname + last 4). Raw ids are internal and never shown.
  let title = LEG_NAME[leg.type] || leg.type;
  if (leg.payee_display) title = "To " + leg.payee_display;
  if (leg.biller_display) title = "To " + leg.biller_display;
  if (leg.type === "BUY_EQUITY" && leg.ticker) {
    title = (leg.estimated_shares != null ? leg.estimated_shares + " × " : "") + leg.ticker;
  }
  row.append(el("div", "title", title));
  row.append(el("div", "amt", leg.amount_cents != null ? centsToDisplay(leg.amount_cents) : ""));
  const sub = el("div", "sub");
  sub.textContent = (LEG_NAME[leg.type] || leg.type) + " · from " + acctLabel(leg.source_account);
  row.append(sub);
  row.append(el("div", "sub right",
    leg.type === "BUY_EQUITY" && leg.estimated_fill_price_cents
      ? "@ " + centsToDisplay(leg.estimated_fill_price_cents) : ""));
  return row;
}

function buildPlanCard(plan, confirmation) {
  retireLiveCard();
  const card = el("div", "bubble card plan-card plan");
  card.id = "plan";
  card.append(el("p", "card-title", "Review payment"));

  const legs = el("div", "legs"); legs.id = "legs";
  for (const leg of plan.plan) legs.append(legRow(leg));
  card.append(legs);

  const sec = el("details", "sec");
  sec.append(el("summary", null, "Security details"));
  const dl = el("dl", "meta");
  const add = (k, v, id, cls) => {
    const dd = el("dd", cls, v); if (id) dd.id = id;
    dl.append(el("dt", null, k), dd);
  };
  add("Authorization window", windowLabel(plan.created_at, plan.expires_at), "window");
  add("Transcript hash", plan.transcript_hash.slice(0, 16) + "…", "txhash", "mono");
  // Computed at sign time; a placeholder reads better than an empty row.
  add("Payload hash (your browser)", "computed when you confirm", "phash", "mono");
  sec.append(dl);
  card.append(sec);

  if (confirmation) card.append(buildStepUp(confirmation));

  const btn = el("button", "btn primary", "Confirm with biometric");
  btn.id = "sign";
  // Escalated: signing stays disabled until the out-of-band code is verified.
  // That is UX only — the gateway refuses an unconfirmed escalated plan
  // whatever this page does (gateway/stepup.py).
  btn.disabled = !!confirmation;
  btn.onclick = onSign;
  card.append(btn, declineButton());
  card.append(el("p", "hint",
    "Your device signs a hash of exactly this payment, recomputed in your browser."));
  return card;
}

/* A contact change, through the same fixed template rules as a payment:
   DB-sourced labels, textContent only, old value shown next to the new one so
   the user sees exactly what they are overwriting. */
function buildChangeCard(change, confirmation) {
  retireLiveCard();
  const card = el("div", "bubble card plan-card plan");
  card.id = "plan";
  card.append(el("p", "card-title", "Review change"));
  const legs = el("div", "legs"); legs.id = "legs";
  for (const e of change.edits) {
    const row = el("div", "leg change");
    row.append(el("div", "icon", e.field === "phone" ? "☎" : "✎"));
    row.append(el("div", "title", e.payee_display));
    row.append(el("div", "amt", ""));
    const sub = el("div", "sub diff");
    sub.append(el("span", null, (e.field === "phone" ? "Phone" : "Name") + ": "),
               el("s", "old", e.old_value || "none"),
               el("span", "arrow", " → "),
               el("b", "new", e.new_value));
    row.append(sub);
    legs.append(row);
  }
  card.append(legs);

  const sec = el("details", "sec");
  sec.append(el("summary", null, "Security details"));
  const dl = el("dl", "meta");
  const add = (k, v, id, cls) => {
    const dd = el("dd", cls, v); if (id) dd.id = id;
    dl.append(el("dt", null, k), dd);
  };
  add("Authorization window", windowLabel(change.created_at, change.expires_at), "window");
  add("Transcript hash", change.transcript_hash.slice(0, 16) + "\u2026", "txhash", "mono");
  add("Payload hash (your browser)", "computed when you confirm", "phash", "mono");
  sec.append(dl);
  card.append(sec);

  if (confirmation) card.append(buildStepUp(confirmation));
  const btn = el("button", "btn primary", "Confirm with biometric");
  btn.id = "sign";
  btn.disabled = !!confirmation;
  btn.onclick = onSign;
  card.append(btn, declineButton());
  card.append(el("p", "hint",
    "Nothing changes until you confirm. Your device signs exactly this change."));
  return card;
}

function buildContactsCard(contacts) {
  const card = el("div", "bubble card contacts");
  card.append(el("p", "card-title", "Contacts"));
  const ul = el("ul", "contact-list");
  for (const c of contacts) {
    const li = el("li");
    const av = el("div", "cavatar", (c.nickname || "?").charAt(0).toUpperCase());
    const who = el("div", "cwho");
    who.append(el("div", "cname", c.display), el("div", "cphone",
      (c.phone || "No phone number") + (c.hold_until ? " \u00b7 payments open " + atTime(c.hold_until) : "")));
    li.append(av, who);
    ul.append(li);
  }
  card.append(ul);
  card.append(el("p", "hint", "Say \"add Bob as a contact, 9123 4567\", \"rename John to Johnny\" "
    + "or \"change Mom's number to 9123 4567\"."));
  return card;
}

/* A NEW contact. Same template rules as the other cards: the name and number
   come from the signed payload; the warnings are the server's FIXED sentences
   (backend/policy/new_contact.py), never model text; the safeguards shown are
   the ones inside the payload the biometric signs. */
function holdLabel(minutes) {
  const h = Math.floor(minutes / 60), m = minutes % 60;
  return [h ? h + (h === 1 ? " hour" : " hours") : "", m ? m + " min" : ""].filter(Boolean).join(" ");
}
function atTime(unix) {
  return new Date(unix * 1000).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });
}
function riskBox(risk, heading) {
  const box = el("div", "risk " + (risk.rung === "CODE" || risk.rung === "STANDARD" ? "mid" : "high"));
  box.append(el("p", "risk-title", heading));
  const ul = el("ul", "risk-list");
  const warnings = (risk.warnings || []).slice()
    .sort((a, b) => (a.weight === "ai") - (b.weight === "ai"));    // the rules first
  for (const w of warnings) ul.append(el("li", w.weight === "ai" ? "ai" : null, w.text));
  box.append(ul);
  return box;
}

function buildAddCard(add, risk, confirmation) {
  retireLiveCard();
  const card = el("div", "bubble card plan-card plan");
  card.id = "plan";
  card.append(el("p", "card-title", "Add new contact"));
  const legs = el("div", "legs"); legs.id = "legs";
  const row = el("div", "leg change");
  row.append(el("div", "icon", "+"), el("div", "title", add.nickname), el("div", "amt", ""));
  const sub = el("div", "sub diff");
  sub.append(el("span", null, "Mobile: "), el("b", "new", add.phone));
  row.append(sub);
  legs.append(row);
  card.append(legs);

  if (risk && (risk.warnings || []).length) {
    card.append(riskBox(risk, risk.rung === "HOLD" ? "Some of this looks like a scam"
                                                   : "Worth a second look"));
  }
  const sg = el("ul", "safeguards");
  const item = (icon, text) => {
    const li = el("li");
    li.append(el("span", "sg-icon", icon), el("span", null, text));
    sg.append(li);
  };
  item("\u2713", "Your biometric, over exactly this contact");
  if (add.safeguards.includes("PHONE_CODE")) item("\u2713", "A code sent to your phone");
  if (add.safeguards.includes("HOLD")) {
    item("\u23F8", "No payments to " + add.nickname + " for " + holdLabel(add.hold_minutes)
      + " after saving \u2014 time to call them and check");
  }
  card.append(el("p", "sg-title", "Safeguards"), sg);

  const sec = el("details", "sec");
  sec.append(el("summary", null, "Security details"));
  const dl = el("dl", "meta");
  const addRow = (k, v, id, cls) => {
    const dd = el("dd", cls, v); if (id) dd.id = id;
    dl.append(el("dt", null, k), dd);
  };
  addRow("Scam check (AI)", risk ? risk.ai_risk : "\u2014");
  addRow("Authorization window", windowLabel(add.created_at, add.expires_at), "window");
  addRow("Transcript hash", add.transcript_hash.slice(0, 16) + "\u2026", "txhash", "mono");
  addRow("Payload hash (your browser)", "computed when you confirm", "phash", "mono");
  sec.append(dl);
  card.append(sec);

  if (confirmation) card.append(buildStepUp(confirmation));
  const btn = el("button", "btn primary", "Save contact with biometric");
  btn.id = "sign";
  btn.disabled = !!confirmation;
  btn.onclick = onSign;
  card.append(btn, declineButton());
  card.append(el("p", "hint", "Nothing is saved until you confirm. Your device signs exactly "
    + "this contact and these safeguards."));
  return card;
}

function showContactRefused(body) {
  retireLiveCard();
  CURRENT.afterAdd = null;
  const card = newResultCard(false);
  card.append(el("h3", null, "NOT ADDED"));
  card.append(el("p", "lead", "I won't save " + ((body.contact && body.contact.display) || "this contact")
    + ". Nothing was saved and nothing was sent."));
  card.append(riskBox(body.risk || {}, "Why"));
  card.append(el("p", "scam-help", "If someone asked you to do this, stop. Call the ScamShield "
    + "Helpline on 1799, or your bank on the number on your card."));
  Voice.speak("I won't save this contact. It looks like a scam. Nothing was sent.");
}

/* "What's their number?" — the next thing the user says answers it. The server
   gets only the id of the draft that asked; it reads the name and any waiting
   payment from its own copy. */
let NEW_CONTACT = null;          // { forDraft, name } while waiting for a number
function awaitNumber(forDraft, name) {
  NEW_CONTACT = { forDraft, name };
  const input = document.getElementById("say");
  if (input) { input.placeholder = name + "'s mobile number\u2026"; input.focus(); }
}
function stopAwaitingNumber() {
  NEW_CONTACT = null;
  const input = document.getElementById("say");
  if (input) input.placeholder = "Pay, invest, or edit a contact\u2026";
}

/* Out-of-band step-up. The code is NOT in any response this page receives: it
   goes to the user's phone, in a message describing the payment from the
   server's copy of the plan. */
function buildStepUp(conf) {
  const box = el("div", "stepup"); box.id = "stepup";
  box.append(el("p", "stepup-title", "Extra confirmation needed"));
  const reason = el("p", "stepup-reason", (conf.reasons || []).join(" "));
  reason.id = "stepup-reason";
  box.append(reason);
  const hint = el("p", "hint", "We texted a 6-digit code to your phone. Check the details in the "
    + "message at the top of the screen, then enter it. ");
  const a = el("a", null, "Open the demo phone");
  a.href = "/phone"; a.target = "dcta-phone";
  hint.append(a);
  box.append(hint);

  const form = el("form", "stepup-form"); form.id = "stepup-form";
  const input = el("input"); input.id = "stepup-code";
  input.inputMode = "numeric"; input.autocomplete = "one-time-code";
  input.maxLength = 6; input.placeholder = "••••••";
  const go = el("button", "btn primary", "Verify"); go.type = "submit";
  form.append(input, go);
  box.append(form);

  form.onsubmit = async (e) => {
    e.preventDefault();
    const code = input.value.trim();
    if (!code) return;
    go.disabled = true;
    const res = await jpost(
      API + "/api/drafts/" + encodeURIComponent(CURRENT.draftId) + "/confirm", { code });
    if (res.status === 200) {
      input.disabled = true;
      box.classList.add("done");
      box.querySelector(".stepup-title").textContent = "Confirmed on your phone";
      form.remove();
      const sign = document.getElementById("sign");
      if (sign) sign.disabled = false;
      botSay("Code accepted. Confirm with your biometric to "
        + (CURRENT.kind === "contact_add" ? "save the contact."
           : CURRENT.kind === "contact_edit" ? "make the change." : "send it."));
      return;
    }
    go.disabled = false;
    const d = res.json.detail || {};
    showErr(d.error || `confirmation failed (${res.status})`);
    if (d.attempts_left === 0) { input.disabled = true; go.disabled = true; }
    else { input.select(); }
  };
  return box;
}

function showErr(msg) {
  typing(false);
  botSay(msg, "error");
}

/* ---------- results ---------- */
/* #result is always the LATEST outcome card. showResult / showRefusal move the
   id to a new card; an empty placeholder (the static one) is removed. */
function newResultCard(ok) {
  typing(false);
  const prev = document.getElementById("result");
  if (prev) {
    prev.removeAttribute("id");
    if (!prev.childElementCount) prev.remove();
  }
  const box = el("section", "msg bot result " + (ok ? "ok" : "bad"));
  box.id = "result";
  const card = el("div", "bubble card");
  box.append(card);
  thread().append(box);
  scrollDown();
  return card;
}

// A repeat of a draft that already ran. Not a failure: the one real execution
// is shown, stated as such, so a retry after a lost response ends in the truth.
function showAlreadySent(res) {
  refreshBalances();          // money did move — possibly just now, in a race
  const exec = res.json.execution || {};
  const card = newResultCard(exec.status !== "FAILED");
  card.append(el("h3", null, "ALREADY SENT"));
  const at = res.json.executed_at
    ? new Date(res.json.executed_at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "earlier";
  card.append(el("p", "lead", "This was already sent at " + at + ". Nothing was sent twice."));
  const ul = el("ul");
  for (const leg of exec.legs || []) {
    const li = el("li");
    li.append(el("span", null, LEG_NAME[leg.type] || leg.type),
              el("span", null, (leg.amount_cents != null ? centsToDisplay(leg.amount_cents) + " · " : "") + leg.status));
    ul.append(li);
  }
  for (const c of exec.changes || []) {
    const li = el("li");
    li.append(el("span", null, c.payee_display + " · " + (c.field === "phone" ? "phone" : "name")),
              el("span", null, c.new_value));
    ul.append(li);
  }
  card.append(ul);
}

/* ---------- balances + the drop-down notification ---------- */
// Read from the ledger, never computed here: the panel shows what the bank
// holds, so a payment that failed can't make it look like money moved.
// Several refreshes can be in flight (focus fires as the biometric sheet
// closes, just before the post-payment refresh): only the NEWEST request may
// write, or a pre-payment read landing last would show the old balance.
let balanceSeq = 0;
async function refreshBalances() {
  const mine = ++balanceSeq;
  let rows;
  try {
    rows = (await jget(API + "/api/seed/accounts?user_id=" + DEMO_USER)).accounts || [];
  } catch (_) {
    return;                           // a missing panel value is not worth an error
  }
  if (mine !== balanceSeq) return;    // a newer refresh was started; it wins
  for (const a of rows) {
    const n = document.getElementById("bal-" + String(a.id).replace(/^acct_/, ""));
    if (!n) continue;
    const text = centsToDisplay(a.balance);
    if (n.textContent !== text && n.textContent !== "—") {
      n.classList.add("changed");
      setTimeout(() => n.classList.remove("changed"), 1500);
    }
    n.textContent = text;
  }
}

// One line per leg that actually ran, from the executor's result joined to the
// signed plan by leg id — the same trusted surface as the payment card.
function executedLines(exec, plan) {
  const byId = Object.fromEntries(((plan && plan.plan) || []).map((l) => [l.id, l]));
  const lines = [];
  for (const leg of exec.legs || []) {
    if (leg.status !== "EXECUTED") continue;
    const p = byId[leg.id] || {};
    const amount = centsToDisplay(leg.amount_cents);
    const from = p.source_account ? " · from " + acctLabel(p.source_account) : "";
    if (leg.type === "TRANSFER") lines.push(amount + " to " + (p.payee_display || "payee") + from);
    else if (leg.type === "PAY_BILL") lines.push(amount + " to " + (p.biller_display || "biller") + from);
    else if (leg.type === "BUY_EQUITY") lines.push(amount + " of " + (p.ticker || "shares") + from);
  }
  return lines;
}

let toastTimer = null;     // auto-hide after 5s
let toastHideTimer = null; // display:none once the slide-up has finished
function showToast(title, lines) {
  const t = document.getElementById("toast");
  if (!t || !lines.length) return;
  // A new notification cancels BOTH pending timers — otherwise the previous
  // one's delayed hidden=true could blank this one moments after it appears.
  clearTimeout(toastTimer);
  clearTimeout(toastHideTimer);
  t.replaceChildren();
  const body = el("div");
  body.append(el("p", "toast-title", title));
  for (const line of lines) body.append(el("p", "toast-line", line));
  t.append(el("span", "toast-icon", "✓"), body);
  t.classList.remove("show");
  t.hidden = false;
  void t.offsetHeight;       // commit the hidden-state styles, so the slide plays
  t.classList.add("show");
  const hide = () => {
    clearTimeout(toastTimer);
    t.classList.remove("show");
    toastHideTimer = setTimeout(() => { t.hidden = true; }, 350);
  };
  toastTimer = setTimeout(hide, 5000);
  t.onclick = hide;
}

// The notification for an execution result, as data: { title, lines }. Pure,
// so tests run exactly what the page shows. Announces whatever ACTUALLY ran —
// including when a later leg failed (status FAILED, earlier legs EXECUTED):
// money moved, so say so, and say it was partial. A leg that did not run is
// never listed; nothing ran means no notification.
function successToast(exec, plan) {
  if (exec.legs) {
    const lines = executedLines(exec, plan);
    if (!lines.length) return { title: "", lines: [] };   // nothing moved: say nothing
    const total = exec.legs.length;
    const only = total === 1 ? exec.legs[0].type : null;
    const title = lines.length < total ? lines.length + " of " + total + " payments sent"
      : lines.length > 1 ? lines.length + " payments sent"
      : only === "PAY_BILL" ? "Bill paid"
      : only === "BUY_EQUITY" ? "Order placed"
      : "Transfer successful";
    return { title, lines };
  }
  if (exec.status === "ADDED" && exec.contact) {
    return { title: "Contact added", lines: [exec.contact.payee_display + " \u00b7 " + exec.contact.phone] };
  }
  if (exec.status === "UPDATED") {
    return { title: "Contact updated", lines: (exec.changes || []).map((c) =>
      c.payee_display + " · " + (c.field === "phone" ? "phone" : "name") + " → " + c.new_value) };
  }
  return { title: "", lines: [] };
}

function announceSuccess(res) {
  const { title, lines } = successToast(res.json.execution || {}, CURRENT.plan);
  showToast(title, lines);             // no-op when nothing ran
}

function showResult(res) {
  if (res.json.rejection === "DUPLICATE") return showAlreadySent(res);
  const ok = !!res.json.accepted;
  if (ok) {
    announceSuccess(res);
    refreshBalances();
  }
  const exec = res.json.execution || {};
  const status = ok ? (exec.status || "EXECUTED") : res.json.rejection || "REJECTED";
  const card = newResultCard(ok);
  // status + body are TEXT, never parsed as HTML. A rejection reason carries
  // executor/LLM-influenced text (e.g. a failed account "<img src=x ...>");
  // this is the trusted surface the "what you see is what you sign" argument
  // presumes renders faithfully, so markup must appear as literal characters.
  // (H1: this was an innerHTML sink; JSON.stringify escapes quotes but not </>.)
  card.append(el("h3", null, status));
  if (ok) {
    card.append(el("p", "lead", "Done. Here's what went through:"));
    const ul = el("ul");
    if (exec.contact) {
      const c = exec.contact;
      const li = el("li");
      li.append(el("span", null, c.payee_display), el("span", null, c.phone));
      ul.append(li);
      if (c.hold_until) {
        const hold = el("li");
        hold.append(el("span", null, "Payments open"), el("span", null, atTime(c.hold_until)));
        ul.append(hold);
      }
    }
    for (const c of exec.changes || []) {
      const li = el("li");
      li.append(el("span", null, c.payee_display + " · " + (c.field === "phone" ? "phone" : "name")),
                el("span", null, c.new_value));
      ul.append(li);
    }
    for (const leg of exec.legs || []) {
      const li = el("li");
      li.append(el("span", null, LEG_NAME[leg.type] || leg.type),
                el("span", null, (leg.amount_cents != null ? centsToDisplay(leg.amount_cents) + " · " : "") + leg.status));
      ul.append(li);
    }
    card.append(ul);
    if (exec.contact) afterContactAdded(exec.contact);
  } else {
    card.append(el("p", "lead", res.json.reason || "The gateway refused this payment."));
    const pre = el("pre");
    pre.textContent = JSON.stringify(res.json, null, 2);
    card.append(pre);
  }
}

// The contact exists now. If it was added to pay them, offer to carry on —
// unless it is on hold, in which case say when payments open instead.
function afterContactAdded(c) {
  const pending = CURRENT.afterAdd;
  CURRENT.afterAdd = null;
  if (c.hold_until) {
    botSay(c.nickname + " is saved. Payments to them open " + atTime(c.hold_until)
      + ". Use the time to call them on a number you already know.");
    return;
  }
  if (!pending) return;
  const m = botSay(c.nickname + " is saved. Shall I carry on with your payment?");
  const chips = el("div", "chips live");
  const b = el("button", "chip choice", "Continue: " + pending);
  b.type = "button";
  b.onclick = () => {
    chips.classList.remove("live");
    b.disabled = true;
    submitTranscript(pending);
  };
  chips.append(b);
  m.append(chips);
}

function showRefusal(title, detail, explanation) {
  const card = newResultCard(false);
  card.append(el("h3", null, title));
  card.append(el("p", "lead", explanation));
  const pre = el("pre");
  pre.textContent = JSON.stringify(detail, null, 2);   // textContent, never innerHTML (H1)
  card.append(pre);
}

/* ---------- the conversation: transcript -> draft, with the clarify loop ---------- */
/* The draft lives SERVER-SIDE (backend/drafts.py). We send a transcript and get
   a draft_id back; answering a question sends only {field, choice_id} for that
   id. The client never holds or returns the plan — so it cannot substitute one,
   and a clarify round-trip re-RESOLVES against the stored IntentPlan rather
   than re-parsing the transcript. */
let CURRENT = { draftId: null, plan: null, kind: "payment", credentialIds: [], rpId: undefined, transcript: "",
                afterAdd: null };   // afterAdd: the payment to carry on with once a new contact is saved

function setStatus(msg) {
  const s = document.getElementById("status");
  if (s) { s.textContent = msg; s.hidden = !msg; }
}

function handleDraft(res) {
  typing(false);
  if (res.status !== 200) {
    const d = res.json.detail || {};
    showErr(d.error || `Something went wrong (${res.status}).`);
    return;
  }
  const body = res.json;
  CURRENT.draftId = body.draft_id;
  if (body.kind === "contact_add" && body.status === "blocked") {   // refused: a scam
    showContactRefused(body);
    return;
  }

  // Four outcomes, and the user must be able to tell them apart. All are HTTP
  // 200: needing to ask is a normal conversational result, and a refusal is a
  // successful request whose answer is "no".
  if (body.status === "clarify") {
    renderClarify(body);
    Voice.speak(body.question);
    return;
  }
  if (body.status === "blocked") {                 // M5 policy refusal
    showRefusal("Blocked by policy", body.reasons || [],
      "A policy rule refused this before it could be drafted. Nothing was sent.");
    return;
  }
  if (body.status === "frozen") {                  // M6 validator freeze
    showRefusal("Frozen by validator",
      (body.validation && body.validation.checks) || body.validation || [],
      "The independent validator found a mismatch between what you said and "
      + "what was drafted. This draft cannot be signed.");
    return;
  }

  if (body.kind === "contacts") {                  // read-only list
    addMsg("bot", el("div", "bubble", "Here are your saved contacts."),
           buildContactsCard(body.contacts || []));
    return;
  }
  const conf = body.requires_extra_confirmation ? (body.confirmation || {}) : null;
  if (body.kind === "contact_add") {
    CURRENT.plan = body.contact_add;
    CURRENT.kind = "contact_add";
    const rung = (body.risk && body.risk.rung) || "STANDARD";
    const intro = el("div", "bubble",
      rung === "HOLD" ? "I can save them, but with extra protection \u2014 parts of this look like "
                        + "common scams. Please read the warnings first."
      : conf ? "Here's the new contact. Before I save them, I've texted a code to your phone."
      : "Here's the new contact. Check the number, then confirm with your biometric.");
    addMsg("bot", intro, buildAddCard(body.contact_add, body.risk, conf));
    if (conf) { const code = document.getElementById("stepup-code"); if (code) code.focus(); }
    return;
  }
  if (body.kind === "contact_edit") {
    CURRENT.plan = body.contact_change;
    CURRENT.kind = "contact_edit";
    const intro = el("div", "bubble",
      conf ? "Here's the change. A new phone number changes where payments go, so I need one more check first."
           : "Here's the change. Check it, then confirm with your biometric.");
    addMsg("bot", intro, buildChangeCard(body.contact_change, conf));
    if (conf) { const code = document.getElementById("stepup-code"); if (code) code.focus(); }
    return;
  }

  CURRENT.plan = body.resolved_plan;
  CURRENT.kind = "payment";
  const intro = el("div", "bubble",
    conf ? "Here's the draft. It's unusual for you, so I need one more check first."
         : "Here's the draft. Check it, then confirm with your biometric.");
  addMsg("bot", intro, buildPlanCard(body.resolved_plan, conf));
  if (conf) {
    const code = document.getElementById("stepup-code");
    if (code) code.focus();
  }
}

async function submitTranscript(transcript, via) {
  Voice.silence();                  // don't talk over the user's next request
  CURRENT.transcript = transcript;
  userSay(transcript);
  if (via) {
    const last = thread().lastElementChild;
    last.append(el("p", "meta-note", "via " + via));
  }
  typing(true);
  const nc = NEW_CONTACT;
  stopAwaitingNumber();
  if (!nc) CURRENT.afterAdd = null;       // a fresh request, not the number we asked for
  handleDraft(await jpost(API + "/api/drafts", {
    transcript, user_id: DEMO_USER, ...(nc ? { new_contact_for: nc.forDraft } : {}),
  }));
}

async function answerClarification(field, choiceId) {
  typing(true);
  handleDraft(await jpost(
    API + "/api/drafts/" + encodeURIComponent(CURRENT.draftId) + "/clarify",
    { field, choice_id: choiceId },
  ));
}

function renderClarify(body) {
  retireLiveCard();
  stopAwaitingNumber();
  const m = addMsg("bot", el("div", "bubble", body.question));
  const nc = body.new_contact;
  if (nc && body.kind !== "payee") {
    // A new contact still missing (or with a bad) number: the reply is the number.
    awaitNumber(body.draft_id, nc.name);
    m.append(el("p", "meta-note", "Say or type their number."));
    return;
  }
  if (body.choices && body.choices.length || nc) {
    // 2+ disambiguation: the user picks, and we resume with `answers`. The
    // resolver re-validates the chosen id against a fresh deterministic match,
    // so a tampered choice cannot inject a payee the mention never justified.
    const chips = el("div", "chips live");
    for (const c of body.choices) {
      const b = el("button", "chip choice", c.display);  // textContent: DB-sourced
      b.type = "button";
      b.onclick = () => {
        chips.classList.remove("live");
        chips.querySelectorAll("button").forEach((x) => { x.disabled = true; });
        b.classList.add("chosen");
        stopAwaitingNumber();
        userSay(c.display);
        answerClarification(body.field, c.id);
      };
      chips.append(b);
    }
    if (nc) {
      // Someone who isn't a contact yet. Adding them is its own signed draft,
      // with safeguards chosen by how risky it looks.
      const b = el("button", "chip choice add", "+ Add " + nc.name + " as a new contact");
      b.type = "button";
      b.onclick = () => {
        chips.classList.remove("live");
        chips.querySelectorAll("button").forEach((x) => { x.disabled = true; });
        b.classList.add("chosen");
        userSay("Add " + nc.name + " as a new contact");
        CURRENT.afterAdd = CURRENT.transcript;        // the payment to carry on with
        const ask = "What's " + nc.name + "'s mobile number? It's where payments to them will go.";
        botSay(ask);
        Voice.speak(ask);
        awaitNumber(body.draft_id, nc.name);
      };
      chips.append(b);
    }
    m.append(chips);
  } else {
    // 0-match / empty / insufficient: no candidate list to choose from, so the
    // user re-states the request and it re-enters the pipeline from the top.
    m.append(el("p", "meta-note", "Say or type it again with more detail."));
  }
}

// Cancel, before confirming. The server records the decline durably and the
// draft can never be signed afterwards — not a button that merely hides a card.
function declineButton() {
  const b = el("button", "btn danger", "Cancel");
  b.id = "decline";
  b.onclick = onDecline;
  return b;
}

async function onDecline() {
  const btn = document.getElementById("decline");
  if (!btn) return;
  const sign = document.getElementById("sign");
  btn.disabled = true;
  if (sign) sign.disabled = true;
  const res = await jpost(API + "/api/drafts/" + encodeURIComponent(CURRENT.draftId) + "/decline", {});
  const d = res.json.detail || {};
  if (res.status === 200) {
    showCancelled();
  } else if (d.already_executed) {
    // It was signed first: tell the truth rather than "cancelled".
    showAlreadySent({ json: { rejection: "DUPLICATE", execution: d.execution,
                              executed_at: d.executed_at } });
  } else {
    showErr("Couldn't cancel: " + (d.error || res.status) + ". Nothing has been sent.");
    btn.disabled = false;
    if (sign) sign.disabled = false;
    return;
  }
  retireLiveCard();
}

function showCancelled() {
  const card = newResultCard(true);
  card.append(el("h3", null, "CANCELLED"));
  card.append(el("p", "lead", "Nothing was sent. This can't be approved now — "
    + "say it again if you still want to send it."));
}

async function onSign() {
  const btn = document.getElementById("sign");
  if (!btn) return;
  btn.disabled = true;
  try {
    const res = CURRENT.kind === "contact_edit"
      ? await signAndExecute(CURRENT.plan, CURRENT.credentialIds, CURRENT.rpId,
                             "/api/contacts/apply-webauthn", "contact_change")
      : CURRENT.kind === "contact_add"
      ? await signAndExecute(CURRENT.plan, CURRENT.credentialIds, CURRENT.rpId,
                             "/api/contacts/add-webauthn", "contact_add")
      : await signAndExecute(CURRENT.plan, CURRENT.credentialIds, CURRENT.rpId);
    // One draft, one signature: the card is spent whatever the outcome.
    // Retired BEFORE the result renders, so chips the result offers (carry on
    // with the payment) are not retired along with it.
    retireLiveCard();
    showResult(res);
  } catch (e) {
    showErr(e && e.name === "NotAllowedError"
      ? "Biometric cancelled — nothing was sent. Tap confirm to try again."
      : String(e));
    btn.disabled = false;
  }
}

/* ---------- voice input, three tiers ---------- */
/* Readable messages for the Web Speech API's error codes. */
const SPEECH_ERRORS = {
  "not-allowed": "Microphone access is blocked. Allow it in the address bar, or type instead.",
  "service-not-allowed": "This browser won't run speech recognition here (in Safari, turn on "
    + "Dictation in System Settings → Keyboard). Type it instead.",
  "no-speech": "I didn't hear anything. Tap the mic and try again.",
  "audio-capture": "No microphone was found. Type it instead.",
  "network": "The browser's speech service couldn't be reached. Type it instead.",
  "aborted": "",
};

function wireVoice() {
  const mic = document.getElementById("mic");
  const textForm = document.getElementById("say-form");
  const textIn = document.getElementById("say");

  // Once server-side ASR CANNOT serve this browser — no provider configured,
  // or a container it will keep refusing — skip it for the rest of the
  // session: otherwise every press records, uploads, gets refused, and asks
  // the user to say it all a second time. A transient failure is different:
  // it drops a tier for that one utterance only, and only two in a row give
  // up on tier 1. Previously ANY refusal was permanent, so one quiet clip left
  // the mic on the browser tier — dead in Safari without Dictation — until
  // the page was reloaded.
  let serverAsrDown = false;
  let serverAsrFailures = 0;       // consecutive transient tier-1 failures
  let active = null;               // { stop() } for whichever tier is listening

  const onText = (t, provider) => {
    active = null;
    setStatus("");
    if (!t || !t.trim()) { showErr("I didn't catch that. Tap the mic and try again."); return; }
    submitTranscript(t.trim(), provider === "webspeech" ? "browser speech" : provider);
  };
  const onError = (e) => {
    active = null;
    setStatus("");
    mic.classList.remove("live");
    const m = /^speech recognition: (.+)$/.exec(String(e && e.message || e));
    const msg = m ? SPEECH_ERRORS[m[1]] ?? ("Speech recognition failed (" + m[1] + "). Type it instead.")
                  : String(e && e.message || e);
    if (msg) showErr(msg);
  };
  const onState = (st) => {
    // "idle" = the browser recognizer ended on its own (pause, result, error).
    if (st === "idle") active = null;
    mic.classList.toggle("live", st === "listening");
    setStatus(st === "listening" ? "Listening… tap the mic when you're done"
      : st === "thinking" ? "Transcribing…" : "");
  };

  function startWebSpeech() {
    if (!Voice.speechRecognitionAvailable()) {
      setStatus("");
      showErr("Speech isn't available in this browser — type it instead.");
      textIn.focus();
      return;
    }
    const rec = Voice.listenWebSpeech({ onText, onError, onState });
    active = rec ? { stop: () => rec.stop() } : null;
  }

  mic.onclick = async () => {
    Voice.silence();                // the mic must not hear the assistant
    // A second press stops whichever tier is listening.
    if (active) { active.stop(); active = null; return; }
    if (serverAsrDown) { startWebSpeech(); return; }
    // Tier 1 first (server-side ASR: OpenAI or Tencent, the backend decides).
    const rec = await Voice.recordAndUpload({
      onText: (t, provider) => { serverAsrFailures = 0; onText(t, provider); },
      onError, onState,
      onFallback: (_reason, { sticky } = {}) => {
        // The recording can't be reused by the browser tier, so say so rather
        // than silently listening again.
        if (sticky || ++serverAsrFailures >= 2) serverAsrDown = true;
        active = null;
        botSay("Server speech recognition isn't available right now, so I'll "
          + "use your browser's instead. Please say it again.");
        startWebSpeech();
      },
    });
    active = rec ? { stop: () => Voice.stop() } : null;
  };

  // Tier 3, always present: typing the same sentence must always work.
  textForm.onsubmit = (e) => {
    e.preventDefault();
    const t = textIn.value.trim();
    if (!t) return;
    textIn.value = "";
    submitTranscript(t);
  };
}

const SUGGESTIONS = [
  "Pay mom five hundred then buy Apple with the rest",
  "Send fifty to John",
  "Send five thousand to John",
  "Send 200 to Uncle Bob",
  "Show my contacts",
  "Change Mom's number to 9123 4567",
];

function greet() {
  const m = botSay("Hi Alice. Tell me what you'd like to do — pay someone, "
    + "pay a bill, buy shares, or update a contact. I'll draft it, and nothing moves until you "
    + "approve it with your biometric.");
  const chips = el("div", "chips");
  for (const s of SUGGESTIONS) {
    const b = el("button", "chip", s);
    b.type = "button";
    b.onclick = () => submitTranscript(s);
    chips.append(b);
  }
  m.append(chips);
}

function tickClock() {
  const c = document.getElementById("clock");
  if (c) c.textContent = new Date().toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }).replace(/\s?[AP]M$/i, "");
}

/* ---------- bootstrap ---------- */
/* The voice button, top right. What a tap does depends on the moment:
   talking -> stop now and mute; on -> mute; muted -> unmute. */
const SOUND_LABELS = {
  speaking: "Stop talking and mute the assistant",
  on: "Mute the assistant's voice",
  muted: "Unmute the assistant's voice",
};
function wireSound() {
  const btn = document.getElementById("sound");
  if (!btn || !Voice.ttsAvailable()) return;   // no speech engine: nothing to mute
  btn.hidden = false;
  Voice.onStateChange((st) => {
    btn.dataset.state = st;
    btn.setAttribute("aria-pressed", String(st === "muted"));
    btn.setAttribute("aria-label", SOUND_LABELS[st]);
    btn.title = SOUND_LABELS[st];
  });
  btn.onclick = () => Voice.setMuted(!Voice.isMuted());
}

async function init() {
  wireSound();
  tickClock();
  setInterval(tickClock, 15000);
  refreshBalances();
  // A payment made elsewhere (another tab, the red-team runner) shows up when
  // the demo window is focused again.
  window.addEventListener("focus", refreshBalances);
  const [creds, cfg] = await Promise.all([
    jget(API + "/api/auth/credentials?user_id=" + DEMO_USER),
    jget(API + "/api/auth/config").catch(() => ({})),
  ]);
  CURRENT.credentialIds = creds.credential_ids || [];
  CURRENT.rpId = cfg.rp_id || undefined;

  if (!CURRENT.credentialIds.length) {
    const reg = document.getElementById("register");
    reg.hidden = false;
    const btn = document.getElementById("register-btn");
    btn.onclick = async () => {
      btn.disabled = true;
      try {
        await registerPasskey();
        location.reload();
      } catch (e) {
        btn.disabled = false;
        showErr(e && e.name === "NotAllowedError"
          ? "Passkey setup was cancelled. Tap Register passkey to try again."
          : String(e));
      }
    };
    return;
  }
  wireVoice();
  document.getElementById("say-box").hidden = false;
  greet();
}
window.addEventListener("DOMContentLoaded", init);

