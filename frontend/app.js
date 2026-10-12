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
                              field = "resolved_plan", extra = {}) {
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
    ...extra,
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
const LIVE_IDS = ["plan", "legs", "window", "txhash", "phash", "sign", "decline", "name-check",
                  "stepup", "stepup-reason", "stepup-form", "stepup-code"];
function retireLiveCard() {
  clearInterval(CURRENT.holdTimer);
  CURRENT.gate = {};                  // a new card starts with no gates of its own
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

// Where each field of a payment came from, as one short line. Quotes are the
// user's OWN words, cut from the transcript by the server (backend/narrate.py);
// "by default" / "calculated" say what the assistant filled in. Pure — the
// review card's evidence is tested under Node (tests/js/app_runner.js).
/* ---------- scam protection: the sign gate, the hold, the name check ---------- */
const SIGN_LABEL = "Confirm with biometric";

// Help lines the user can call themselves. Check against the live pages
// before a demo: dbs.com.sg/personal/scam-defence and scamshield.gov.sg.
const HELP_LINES = [
  { label: "Call DBS Fraud Hotline", number: "1800 339 6963", tel: "tel:18003396963",
    overseas: { number: "+65 6339 6963", tel: "tel:+6563396963" } },
  { label: "Call ScamShield", number: "1799", tel: "tel:1799" },
];

// One tap to a call the user places themselves, to a number a scammer on the
// line didn't give them. Plain tel: links: they cancel, send and change
// nothing here, and no Confirm gate ever disables them.
function buildHelpCalls() {
  const row = el("div", "help-calls");
  for (const line of HELP_LINES) {
    const cell = el("div", "help-call-cell");
    const a = el("a", "btn secondary help-call", line.label + " \u00b7 " + line.number);
    a.href = line.tel;
    a.setAttribute("aria-label", line.label + ", " + line.number);
    cell.append(a);
    if (line.overseas) {                  // a 1800 number can't be dialled from abroad
      const note = el("p", "help-note", "Overseas: ");
      const o = el("a", null, line.overseas.number);
      o.href = line.overseas.tel;
      o.setAttribute("aria-label", line.label + " from overseas, " + line.overseas.number);
      note.append(o);
      cell.append(note);
    }
    row.append(cell);
  }
  return row;
}

// A card calls this with its own button while it is being built: the card
// isn't on the page yet, so looking "#sign" up would find nothing and leave
// Confirm enabled through a hold or before the phone code.
function updateSignGate(btn = document.getElementById("sign")) {
  if (!btn) return;
  const g = CURRENT.gate || {};
  btn.disabled = !!(g.code || g.name || g.hold);
}

// A server-enforced hold, shown as a countdown. When it ends NOTHING is sent:
// Confirm simply becomes available, and the user still decides.
function startHoldCountdown(seconds, cardBtn) {
  clearInterval(CURRENT.holdTimer);
  let left = Math.max(0, Math.ceil(seconds));
  const paint = () => {
    const btn = cardBtn || document.getElementById("sign");
    if (!btn) { clearInterval(CURRENT.holdTimer); return; }
    if (left > 0) {
      btn.textContent = "\u23f3 Confirm available in " + Math.floor(left / 60) + ":"
        + String(left % 60).padStart(2, "0");
    } else {
      clearInterval(CURRENT.holdTimer);
      btn.textContent = SIGN_LABEL;
      CURRENT.gate.hold = false;
      updateSignGate(btn);
    }
    left -= 1;
  };
  paint();
  CURRENT.holdTimer = setInterval(paint, 1000);
}

function buildNameCheck(name) {
  const box = el("div", "name-check");
  box.append(el("label", null, "To continue, type " + name + "\u2019s name:"));
  const input = el("input");
  input.type = "text";
  input.autocomplete = "off";
  input.id = "name-check";
  input.oninput = () => {
    CURRENT.gate.name = input.value.trim().toLowerCase() !== name.toLowerCase();
    updateSignGate();
  };
  box.append(input);
  return box;
}

function evidenceText(ev, leg) {
  if (!ev) return "";
  const q = (x) => "\u201c" + x + "\u201d";
  const parts = [];
  const a = ev.amount || {};
  if (a.kind === "said") parts.push(q(a.quote));
  else if (a.kind === "chosen") parts.push("you chose " + (a.quote ? q(a.quote) : centsToDisplay(leg.amount_cents)));
  else if (a.kind === "calculated") parts.push("calculated: " + a.text);
  else parts.push("\u26a0 amount not in your words");
  const t = ev.to || {};
  parts.push(t.kind === "said" ? q(t.quote) : "\u26a0 recipient not in your words");
  const f = ev.from || {};
  if (f.kind === "said") parts.push(q(f.quote));
  else if (f.kind === "default") parts.push(acctLabel(leg.source_account) + " by default");
  else if (f.kind === "derived") parts.push("same account");
  else if (f.kind === "not_found") parts.push("\u26a0 account not in your words");
  return parts.join(" · ");
}

function legRow(leg, ev) {
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
  // WHERE the money goes — signed as part of the payment (data/destinations.py).
  if (leg.destination_masked) row.append(el("div", "dest", "PayNow " + leg.destination_masked));
  const evidence = evidenceText(ev, leg);
  if (evidence) row.append(el("div", "ev", evidence));
  return row;
}

function buildPlanCard(plan, confirmation, narration, transcript, risk) {
  retireLiveCard();
  const card = el("div", "bubble card plan-card plan");
  card.id = "plan";
  card.append(el("p", "card-title", "Review payment"));
  // Scam warnings: FIXED sentences from the server's rules (policy/scam.py),
  // never model text — the card only renders trusted text.
  // Shown whenever the outcome isn't ALLOW, with the help lines to call.
  if (risk && ((risk.warnings && risk.warnings.length) || (risk.outcome && risk.outcome !== "ALLOW"))) {
    const box = el("div", "scam-warn " + (risk.outcome === "WARN" ? "warn" : "stop"));
    for (const w of risk.warnings || []) box.append(el("p", null, "\u26a0\ufe0f " + w));
    box.append(buildHelpCalls());
    card.append(box);
  }
  // A large payment waits after Confirm (scam.RELEASE_DELAY_SECONDS) and can
  // still be cancelled: say so before the user signs.
  if (risk && risk.release_delay_seconds) {
    card.append(el("p", "hint", "\u23f1 Large payment: after you confirm, it waits "
      + risk.release_delay_seconds + " seconds before it's sent, and you can still cancel it."));
  }
  // The server's copy of what was said — what the draft was actually built from.
  if (transcript) card.append(el("p", "said", "You said: \u201c" + transcript + "\u201d"));

  const legs = el("div", "legs"); legs.id = "legs";
  const ev = (narration && narration.evidence) || {};
  for (const leg of plan.plan) legs.append(legRow(leg, ev[leg.id]));
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

  // HOLD_STEP_UP: type the payee's name. Someone rushing through a coached
  // call is more likely to stop at typing than at a button. (UX friction; the
  // server enforces the hold and the code whatever this page does.)
  if (risk && risk.confirm_name) card.append(buildNameCheck(risk.confirm_name));

  const btn = el("button", "btn primary", SIGN_LABEL);
  btn.id = "sign";
  btn.onclick = onSign;
  // Gates that must ALL clear before Confirm enables — each is UX only; the
  // gateway refuses an unconfirmed, unheld or unbound payment regardless.
  CURRENT.gate = { code: !!confirmation, name: !!(risk && risk.confirm_name),
                   hold: !!(risk && risk.hold && risk.hold.seconds_left > 0) };
  card.append(btn, declineButton());
  if (CURRENT.gate.hold) startHoldCountdown(risk.hold.seconds_left, btn);
  updateSignGate(btn);
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
  // The same gate as a payment's, so a failed Cancel can't unlock Confirm
  // before the phone code (updateSignGate reads CURRENT.gate).
  CURRENT.gate = { code: !!confirmation };
  updateSignGate(btn);
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
    const acts = el("div", "cacts");
    li.append(av, who, acts);
    contactRemoveButton(acts, c);
    CONTACT_ROWS.push({ display: c.display, li });
    ul.append(li);
  }
  card.append(ul, buildAddContactForm());
  card.append(el("p", "hint", "To rename someone or change a number, just say it."));
  return card;
}

/* Every contact row on screen, in every contacts card: a removal takes the
   contact off all of them, so no older card keeps a Remove for it. */
const CONTACT_ROWS = [];

/* Remove: a confirm tap, not a passkey — removing someone only narrows who
   can be paid, and the server refuses any payment drafted to them before.
   The contact is named as the card shows it (name + last 4). */
function contactRemoveButton(acts, c) {
  acts.replaceChildren();
  acts.classList.remove("asking");
  const b = el("button", "chip cremove", "Remove");
  b.type = "button";
  b.onclick = () => {
    acts.replaceChildren();
    acts.classList.add("asking");           // its own line, under the contact
    const yes = el("button", "chip danger", "Yes, remove");
    const no = el("button", "chip", "Cancel");
    yes.type = no.type = "button";
    no.onclick = () => contactRemoveButton(acts, c);
    yes.onclick = async () => {
      yes.disabled = no.disabled = true;
      let r;
      try {
        r = await jpost(API + "/api/contacts/remove",
                        { nickname: c.nickname, last4: c.last4, user_id: DEMO_USER });
      } catch (e) {
        r = { status: 0, json: {} };
      }
      if (r.status === 200) {
        CONTACT_ROWS.filter((x) => x.display === c.display).forEach((x) => x.li.remove());
        botSay(r.json.removed + " is no longer in your contacts.");
        return;
      }
      contactRemoveButton(acts, c);
      showErr(r.status === 0 ? "Couldn't remove " + c.display + " (no connection). Nothing changed."
        : (typeof r.json.detail === "string" ? r.json.detail : "Couldn't remove " + c.display + "."));
    };
    acts.append(el("span", "cask", "Remove " + c.display + "?"), yes, no);
  };
  acts.append(b);
}

/* Add: the same request as saying "add Bob as a contact, 9123 4567", so a new
   contact gets every check a spoken one does — the scam list, the hold, the
   phone code and the passkey. Always a fresh request: not the answer to a
   question still waiting further up. */
function buildAddContactForm() {
  const wrap = el("div", "cadd");
  const open = el("button", "chip add", "+ Add contact");
  open.type = "button";
  const form = el("form", "cadd-form");
  form.hidden = true;
  const name = el("input");
  name.placeholder = "Name";
  name.autocomplete = "off";
  name.maxLength = 40;
  const phone = el("input");
  phone.placeholder = "Mobile number";
  phone.inputMode = "tel";
  phone.autocomplete = "off";
  phone.maxLength = 20;
  const add = el("button", "btn primary", "Add");
  add.type = "submit";
  const cancel = el("button", "btn secondary", "Cancel");
  cancel.type = "button";
  form.append(name, phone, add, cancel);
  open.onclick = () => { form.hidden = false; open.hidden = true; name.focus(); };
  cancel.onclick = () => { form.hidden = true; open.hidden = false; };
  form.onsubmit = (e) => {
    e.preventDefault();
    const n = name.value.trim(), p = phone.value.trim();
    if (!n || !p) { (n ? phone : name).focus(); return; }
    name.value = phone.value = "";
    form.hidden = true;
    open.hidden = false;
    stopAwaitingNumber();
    submitTranscript("add " + n + " as a contact, " + p);
  };
  wrap.append(open, form);
  return wrap;
}

function showContactsCard(contacts) {
  addMsg("bot", el("div", "bubble", "Here are your saved contacts."), buildContactsCard(contacts));
}

/* The greeting's one button: the list, straight from the server (no model). */
async function showContacts() {
  userSay("Show my contacts");
  let body = null;
  try {
    body = await jget(API + "/api/contacts?user_id=" + DEMO_USER);
  } catch (e) { /* below */ }
  // Never an empty card for a list that couldn't be read.
  if (!body || !Array.isArray(body.contacts)) {
    showErr("Couldn't load your contacts. Try again.");
    return;
  }
  showContactsCard(body.contacts);
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
  CURRENT.gate = { code: !!confirmation };        // as in buildChangeCard
  updateSignGate(btn);
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
  card.append(el("p", "scam-help", "If someone asked you to do this, stop and call one of "
    + "these yourself:"));
  card.append(buildHelpCalls());
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
/* "What is this payment for?" — asked by the server when the scam score is
   high. The next thing the user says is the answer, scored by the rules. */
let PURPOSE_FOR = null;          // the draft waiting for its purpose
function awaitPurpose(forDraft) {
  PURPOSE_FOR = forDraft;
  const input = document.getElementById("say");
  if (input) { input.placeholder = "What is this payment for?\u2026"; input.focus(); }
}
function stopAwaitingNumber() {
  NEW_CONTACT = null;
  PURPOSE_FOR = null;
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
      CURRENT.gate = CURRENT.gate || {};
      CURRENT.gate.code = false;          // one gate of several (hold, name, code)
      updateSignGate();
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
  if (res.json.accepted && res.json.mandate_id) return showMandateCreated(res);
  refreshBillsBadge();               // a recurring payment approved (or refused) here
  if (res.json.rejection === "DUPLICATE") return showAlreadySent(res);
  if (res.json.accepted && res.json.scheduled) return showScheduled(res);
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
  const pendingVia = CURRENT.afterAddVia || null;
  CURRENT.afterAdd = null;
  CURRENT.afterAddVia = null;
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
    submitTranscript(pending, pendingVia);   // a spoken payment keeps its spoken reply
  };
  chips.append(b);
  m.append(chips);
}

/* The scam score is too high to go ahead in the app at all (scam.BLOCK). The
   sentences are FIXED server text; the way forward is a channel the user
   opens themselves, which a scammer on the line can't be part of. */
function showScamBlocked(body) {
  const card = newResultCard(false);
  card.append(el("h3", null, "Payment stopped"));
  card.append(el("p", "lead", "This payment shows several signs of a scam, so it can't be made "
    + "in the app. Nothing was sent."));
  const box = el("div", "scam-warn stop");
  for (const w of body.reasons || []) box.append(el("p", null, "\u26a0\ufe0f " + w));
  card.append(box);
  card.append(el("p", "scam-help", "If you still need to make it, call DBS. If someone is "
    + "telling you to make this payment, hang up first, then call ScamShield."));
  card.append(buildHelpCalls());
  Voice.speak("I've stopped this payment. It shows several signs of a scam. Nothing was sent.");
}

/* A large payment, signed: it waits before the money moves, and Cancel still
   works until then. The server sends it (its release loop); this page only
   watches, and asks the server again rather than trusting its own clock. */
function showScheduled(res) {
  const draftId = res.json.draft_id;
  const card = newResultCard(true);
  card.append(el("h3", null, "Scheduled"));
  const lead = el("p", "lead", "");
  card.append(lead);
  const cancel = el("button", "btn danger", "Cancel this payment");
  card.append(cancel, buildHelpCalls());
  let left = Math.max(0, res.json.seconds_left || 0);
  const paint = () => {
    lead.textContent = "This is a large payment, so it waits before it's sent. It goes in "
      + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0")
      + ". You can still cancel it until then.";
  };
  const finish = (title, text) => {
    clearInterval(tick); clearInterval(poll);
    cancel.remove();
    card.querySelector("h3").textContent = title;
    lead.textContent = text;
  };
  paint();
  const tick = setInterval(() => { left = Math.max(0, left - 1); paint(); }, 1000);
  const poll = setInterval(async () => {
    let st;
    try { st = await jget(API + "/api/drafts/" + encodeURIComponent(draftId) + "/release"); }
    catch (_) { return; }                        // try again on the next tick
    if (st.status === "SENT") {
      finish("Sent", "The wait is over and the payment has been sent.");
      const { title, lines } = successToast(st.execution || {}, CURRENT.plan);
      showToast(title, lines);
      refreshBalances();
    } else if (st.status === "CANCELLED") {
      finish("Cancelled", "This payment was cancelled. Nothing was sent.");
    } else if (typeof st.seconds_left === "number") {
      left = st.seconds_left;
    }
  }, 2000);
  cancel.onclick = async () => {
    cancel.disabled = true;
    const r = await jpost(API + "/api/drafts/" + encodeURIComponent(draftId) + "/cancel", {});
    if (r.status === 200) {
      finish("Cancelled", "You cancelled this payment. Nothing was sent.");
    } else {
      cancel.disabled = false;
      const d = r.json.detail || {};
      if (d.already_executed) finish("Sent", "Too late to cancel: the payment had already been sent.");
    }
  };
}

// `reasons`: plain sentences for the person. `detail`, if any: the raw checks,
// folded away under "Technical details".
function showRefusal(title, reasons, explanation, detail) {
  const card = newResultCard(false);
  card.append(el("h3", null, title));
  card.append(el("p", "lead", explanation));
  if (reasons.length) {
    const ul = el("ul");
    reasons.forEach(r => ul.append(el("li", null, r)));   // textContent, never innerHTML (H1)
    card.append(ul);
  }
  if (detail) {
    const more = el("details", "sec");
    more.append(el("summary", null, "Technical details"));
    const pre = el("pre");
    pre.textContent = JSON.stringify(detail, null, 2);
    more.append(pre);
    card.append(more);
  }
}

// What a validator freeze says: each failed check's plain sentence. A failure
// with none (an older server) still says which check it was.
function freezeReasons(checks) {
  return checks.filter(c => c && c.outcome === "fail")
    .map(c => c.say || ("The " + String(c.check).replace(/_/g, " ") + " check didn't match."));
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

// [[7, "HOLD_STEP_UP"], [4, "HOLD"], [2, "WARN"], [0, "ALLOW"]]
//   -> "0–1 ALLOW · 2–3 WARN · 4–6 HOLD · 7+ HOLD_STEP_UP"
// The two thresholds (policy/scam.py), as the console prints them.
function thresholdsText(t) {
  if (!t) return "";
  const lines = t.facts_ask_lines;   // this payment's ask line, of the three it can be
  const which = lines ? " (doubt " + lines.doubt + " / usual " + lines.usual
    + " / small " + lines.small + ")" : "";
  return "facts <" + t.facts_ask + " pass · " + t.facts_ask + "+ ask" + which + " · " + t.facts_fail
    + "+ delay · " + t.facts_call_bank + "+ call bank  |  words <" + t.words_fail + " pass · "
    + t.words_fail + "+ delay · " + t.words_serious + "+ code · " + t.words_call_bank + "+ call bank";
}

// CONSOLE_DEBUG (server setting): the scam score and every prompt sent to the
// model, printed to the browser console for each request.
function logDebug(body) {
  const d = body && body.debug;
  if (!d || typeof console === "undefined") return;
  const s = d.scam;
  // Open, not collapsed: the score and which rule gave which points, at a glance.
  console.group("%cDCTA scam check: " + (s ? "facts " + s.facts + ", words "
                                             + (s.words_weighed ? s.words : "not weighed")
                                             + " → " + s.decision + " → " + s.outcome
                                           : "no payment to score"), "font-weight:bold");
  if (s) {
    const rules = s.breakdown || [];
    console.table(rules.map((r) => ({ rule: r.rule, points: r.points ? "+" + r.points : "0",
                                      worth: r.worth, "looks for": r.looks_for,
                                      why: r.why.join("; ") })));
    const given = rules.filter((r) => r.points).map((r) => r.points);
    console.log("total: " + (given.length ? given.join(" + ") + " = " : "") + s.score
                + " → " + s.scored + "   (" + thresholdsText(s.thresholds) + ")");
    if (s.outcome !== s.scored) {
      console.log("outcome kept at " + s.outcome + ": an earlier score on this draft was "
                  + "higher, and a draft's safeguards never go down");
    }
    console.log("warnings shown:", s.warnings);
    console.log("full assessment (rules, not the model):", s);
  }
  if (d.scam_language && Object.keys(d.scam_language).length) {
    console.log("scam phrases found in your words:", d.scam_language);
  }
  const w = d.words;
  if (w) {
    const parts = w.categories.map((c) => c.category + " " + c.points
                                     + (c.counts < 1 ? " × " + c.counts : ""));
    console.log("word score: " + (parts.length ? parts.join(" + ") + " = " + w.raw : "no scam or urgency words")
                + (w.raw > w.points ? "  →  capped at " + w.points : "")
                + "  (adds " + w.points + " of at most " + w.max + ")"
                + (w.never_rules.length ? "  ·  NEVER RULE: " + w.never_rules.join(", ")
                                          + " → at least HOLD_STEP_UP" : ""));
    if (w.urgent_words.length) {
      console.log("  urgency words: " + w.urgent_words.map((x) => x[0] + " " + x[1]).join(", ")
                  + (w.capitals ? ", capitals +" + w.capitals : "")
                  + (w.exclamations ? ", !! +" + w.exclamations : ""));
    }
  }
  console.groupEnd();
  (d.llm_calls || []).forEach((c, i) => {
    console.groupCollapsed("DCTA \u2192 model call " + (i + 1) + " (" + (c.ms != null ? c.ms : "?") + " ms)");
    console.log("SYSTEM PROMPT:\n" + c.system);
    console.log("USER PROMPT:\n" + c.user);
    console.log(c.error ? "ERROR: " + c.error : "REPLY:\n" + c.output);
    console.groupEnd();
  });
}

function handleDraft(res) {
  typing(false);
  if (res.status !== 200) {
    const d = res.json.detail || {};
    showErr(d.error || `Something went wrong (${res.status}).`);
    return;
  }
  const body = res.json;
  logDebug(body);
  // CURRENT.draftId is the draft on screen: the live card's Cancel and Verify
  // post to it. Only a reply that shows its own card or question takes it
  // over; a contacts list or a refusal leaves the live card's draft in place
  // (it used to re-point a held payment's Cancel at another draft, or none).

  // Scam phrases in the user's own words, even with no draft to review yet.
  if (body.scam_language && body.scam_language.warning) {
    botSay("\u26a0\ufe0f " + body.scam_language.warning);
  }
  if (body.kind === "contact_add" && body.status === "blocked") {   // refused: a scam
    showContactRefused(body);
    return;
  }
  if (body.kind === "recurring_setup") {           // the setup form, with what's missing
    renderSetupForm(body);
    if (body.questions && body.questions.length) Voice.speak(body.questions.join(" "));
    return;
  }
  if (body.kind === "mandate" && body.status === "ready") {   // recurring terms to sign
    CURRENT.draftId = body.draft_id;
    CURRENT.plan = body.mandate;
    CURRENT.kind = "mandate";
    addMsg("bot", el("div", "bubble", "Here's the recurring payment. Check every detail — you're "
      + "agreeing to these exact terms — then confirm with your biometric."),
      buildMandateCard(body.mandate, body.preview));
    return;
  }
  if (body.status === "info") {                    // nothing to draft (e.g. unsupported)
    botSay(body.message);
    return;
  }
  if (body.status === "blocked" && body.kind === "recurring_review") {
    showRefusal("Not paid", body.reasons || [], body.message || "Nothing was sent.");
    refreshBillsBadge();
    return;
  }

  // Four outcomes, and the user must be able to tell them apart. All are HTTP
  // 200: needing to ask is a normal conversational result, and a refusal is a
  // successful request whose answer is "no".
  if (body.status === "clarify") {
    if (body.draft_id) CURRENT.draftId = body.draft_id;   // the question's answer goes to it
    renderClarify(body);
    Voice.speak(body.question);
    return;
  }
  if (body.status === "blocked" && body.kind === "scam") {   // too many scam signs
    showScamBlocked(body);
    return;
  }
  if (body.status === "blocked") {                 // M5 policy refusal
    showRefusal("Blocked by policy", body.reasons || [],
      "A policy rule refused this before it could be drafted. "
      + (body.kind === "contact_edit" ? "Nothing was saved." : "Nothing was sent."));
    return;
  }
  if (body.status === "frozen") {                  // M6 validator freeze
    const checks = (body.validation && body.validation.checks) || [];
    showRefusal("Stopped: this doesn't match what you said",
      freezeReasons(checks),
      "Before you approve anything, an independent check compares the draft with "
      + "your words. It didn't match, so this draft can't be signed and nothing was sent.",
      body.validation);
    return;
  }

  if (body.kind === "contacts") {
    showContactsCard(body.contacts || []);
    return;
  }
  const conf = body.requires_extra_confirmation ? (body.confirmation || {}) : null;
  if (body.kind === "contact_add") {
    CURRENT.draftId = body.draft_id;
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
    CURRENT.draftId = body.draft_id;
    CURRENT.plan = body.contact_change;
    CURRENT.kind = "contact_edit";
    const intro = el("div", "bubble",
      conf ? "Here's the change. A new phone number changes where payments go, so I need one more check first."
           : "Here's the change. Check it, then confirm with your biometric.");
    addMsg("bot", intro, buildChangeCard(body.contact_change, conf));
    if (conf) { const code = document.getElementById("stepup-code"); if (code) code.focus(); }
    return;
  }

  CURRENT.draftId = body.draft_id;
  CURRENT.plan = body.resolved_plan;
  CURRENT.kind = "payment";
  // The assistant's reply: what it worked out, built by the server from the
  // same checked data as the card (backend/narrate.py) — never model text.
  const reply = body.narration && body.narration.reply;
  const rec = body.recurring;
  const intro = el("div", "bubble", rec
    ? "Payment " + rec.seq + " of " + rec.count + " for your " + rec.biller + " arrangement is due. "
      + "Check it, then approve it with your biometric — nothing is paid until you do."
    : reply
    ? reply
    : conf ? "Here's the draft. It's unusual for you, so I need one more check first."
           : "Here's the draft. Check it, then confirm with your biometric.");
  // A recurring payment wasn't said by anyone just now: don't label the
  // server's description of it "You said".
  const card = buildPlanCard(body.resolved_plan, conf, body.narration, rec ? null : body.transcript,
                             body.scam);
  if (rec) {
    card.insertBefore(el("p", "said", "Payment " + rec.seq + " of " + rec.count + " under the recurring "
      + "arrangement you set up. Its biller, account and amount are fixed by what you signed then."),
      card.querySelector(".legs"));
  }
  addMsg("bot", intro, card);
  if (reply && CURRENT.via) Voice.speak(reply);     // spoken request -> spoken reply
  if (conf) {
    const code = document.getElementById("stepup-code");
    if (code) code.focus();
  }
}

async function submitTranscript(transcript, via) {
  Voice.silence();                  // don't talk over the user's next request
  CURRENT.transcript = transcript;
  CURRENT.via = via || null;        // spoken requests get a spoken reply
  userSay(transcript);
  if (via) {
    const last = thread().lastElementChild;
    last.append(el("p", "meta-note", "via " + via));
  }
  typing(true);
  const nc = NEW_CONTACT;
  const purposeFor = PURPOSE_FOR;
  stopAwaitingNumber();
  if (purposeFor) {                        // the answer to "what is this payment for?"
    handleDraft(await jpost(API + "/api/drafts/" + encodeURIComponent(purposeFor) + "/purpose",
                            { answer: transcript }));
    return;
  }
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
  const bubble = el("div", "bubble", body.kind === "purpose" && body.questions ? "" : body.question);
  if (body.kind === "purpose" && body.questions) {
    if (body.note) bubble.append(el("p", null, body.note));            // asked again
    for (const q of body.questions) bubble.append(el("p", null, q));   // fixed server text
  }
  const m = addMsg("bot", bubble);
  if (body.kind === "purpose") {
    awaitPurpose(body.draft_id);
    m.append(el("p", "meta-note", "Type or say your answer. Nothing has been sent."));
    return;
  }
  if (body.kind === "recurrence") {                // "pay my bill": once, or recurring?
    const chips = el("div", "chips live");
    for (const c of body.choices || []) {
      const b = el("button", "chip choice", c.display);
      b.type = "button";
      b.onclick = () => {
        chips.classList.remove("live");
        chips.querySelectorAll("button").forEach((x) => { x.disabled = true; });
        b.classList.add("chosen");
        userSay(c.display);
        resubmitWithRecurrence(body.transcript, c.id);
      };
      chips.append(b);
    }
    m.append(chips);
    return;
  }
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
    const choices = [];
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
      choices.push(b);
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
        CURRENT.afterAddVia = CURRENT.via;            // ...and whether it was spoken
        const ask = "What's " + nc.name + "'s mobile number? It's where payments to them will go.";
        botSay(ask);
        Voice.speak(ask);
        awaitNumber(body.draft_id, nc.name);
      };
      chips.append(b);            // first: the question asks about adding them
    }
    chips.append(...choices);
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
  let res;
  try {
    res = await jpost(API + "/api/drafts/" + encodeURIComponent(CURRENT.draftId) + "/decline", {});
  } catch (_) {
    res = { status: 0, json: {} };      // no connection: say so, and let them retry
  }
  const d = res.json.detail || {};
  if (res.status === 200) {
    showCancelled();
  } else if (d.already_executed) {
    // It was signed first: tell the truth rather than "cancelled".
    showAlreadySent({ json: { rejection: "DUPLICATE", execution: d.execution,
                              executed_at: d.executed_at } });
  } else {
    showErr("Couldn't cancel: " + (d.error || res.status || "no connection")
      + ". Nothing has been sent.");
    btn.disabled = false;
    updateSignGate();                     // back to what the hold, name and code allow
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

// HOLD_STEP_UP: the payee's name as typed on the live card. The gateway checks
// it too — the disabled button is only the page's half of the check.
function typedName() {
  const input = document.getElementById("name-check");
  return input ? { confirm_name: input.value } : {};
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
      : CURRENT.kind === "mandate"
      ? await signAndExecute(CURRENT.plan, CURRENT.credentialIds, CURRENT.rpId,
                             "/api/recurring/mandates/enroll-webauthn", "mandate")
      : await signAndExecute(CURRENT.plan, CURRENT.credentialIds, CURRENT.rpId,
                             undefined, undefined, typedName());
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

/* ---------- recurring bills ---------- */
/* Setup is a FORM, not a guess: the server reads what it can by rules (never
   the model) and every field is confirmed here before any terms exist. The
   terms are signed once with the passkey. Each of the first payments is its
   own card, signed like any payment; later ones are paid by the server only
   if the user chose that, explicitly, on this form. Every value shown comes
   from the server's JSON and is set with textContent. */
const OCC_LABELS = {
  SCHEDULED: "Scheduled", PENDING_APPROVAL: "Waiting for your approval",
  NEEDS_REVIEW: "Needs your review", HELD: "On hold — not paid", EXECUTED: "Paid",
  FAILED: "Failed — not paid", DECLINED: "Declined — not paid", EXPIRED: "Expired — not paid",
  MISSED: "Missed — not paid", SKIPPED: "Skipped (paused) — not paid", CANCELLED: "Cancelled",
};
const MANDATE_LABELS = { ACTIVE: "Active", PAUSED: "Paused", SUSPENDED: "Stopped — needs new setup",
                         CANCELLED: "Cancelled", COMPLETED: "Finished" };

function centsToInput(cents) {
  // Integer arithmetic only: the amount box shows "85.00" for 8500.
  return cents == null ? "" : Math.floor(cents / 100) + "." + String(cents % 100).padStart(2, "0");
}

function setupRow(labelText, control, error) {
  const row = el("label", "setup-row");
  row.append(el("span", "setup-label", labelText), control);
  if (error) row.append(el("span", "setup-error", error));
  return row;
}

function selectBox(name, options, value) {
  const s = el("select");
  s.name = name;
  for (const o of options) {
    const opt = el("option", null, o.label);
    opt.value = o.value;
    if (o.value === value) opt.selected = true;
    s.append(opt);
  }
  return s;
}

function radioGroup(name, options, value) {
  const box = el("div", "setup-radios");
  for (const o of options) {
    const lab = el("label", "setup-radio");
    const r = el("input");
    r.type = "radio"; r.name = name; r.value = o.value;
    r.checked = o.value === value;      // only what the user said or chose
    lab.append(r, el("span", null, o.label));
    if (o.extra) lab.append(o.extra);
    box.append(lab);
  }
  return box;
}

function renderSetupForm(body) {
  retireLiveCard();
  CURRENT.draftId = body.draft_id;
  CURRENT.kind = "recurring_setup";
  const f = body.fields || {}, err = body.errors || {}, opt = body.options || {};
  const card = el("div", "bubble card plan-card setup-card");
  card.append(el("p", "card-title", "Set up a recurring bill payment"));
  if (body.transcript) card.append(el("p", "said", "You said: “" + body.transcript + "”"));
  if ((body.questions || []).length) {
    const q = el("div", "setup-questions");
    q.append(el("p", null, "I need a few more details:"));
    for (const t of body.questions) q.append(el("p", null, "• " + t));
    card.append(q);
  }
  for (const n of body.notes || []) card.append(el("p", "hint", n));

  const form = el("form", "setup-form");
  form.append(setupRow("Bill", selectBox("biller_id",
    [{ value: "", label: "Choose a bill" }].concat((opt.billers || []).map(
      (b) => ({ value: b.id, label: b.name + " · " + b.reference }))), f.biller_id || ""),
    err.biller_id));
  form.append(setupRow("From", selectBox("source_account",
    [{ value: "", label: "Choose an account" }].concat((opt.accounts || []).map(
      (a) => ({ value: a.id, label: a.label }))), f.source_account || ""), err.source_account));
  const amount = el("input");
  amount.name = "amount"; amount.inputMode = "decimal"; amount.placeholder = "e.g. 85.00";
  amount.value = f.amount != null ? String(f.amount) : centsToInput(f.amount_cents);
  const amountBox = el("div", "setup-amount");
  amountBox.append(el("span", null, "S$"), amount);
  form.append(setupRow("Amount, the same every time", amountBox, err.amount));
  form.append(setupRow("How often", radioGroup("frequency",
    (opt.frequencies || []).map((x) => ({ value: x.id, label: x.label })), f.frequency),
    err.frequency));
  const start = el("input");
  start.type = "date"; start.name = "start_date"; start.min = body.today || "";
  start.value = f.start_date || "";
  form.append(setupRow("First payment (" + (body.due_time || "09:00") + ", "
    + (body.timezone || "") + ")", start, err.start_date));
  const count = el("input");
  count.type = "number"; count.name = "occurrence_count"; count.min = "1";
  count.max = String(opt.max_occurrences || 60); count.className = "setup-count";
  count.value = f.occurrence_count != null ? String(f.occurrence_count) : "";
  const until = el("input");
  until.type = "date"; until.name = "end_date"; until.value = f.end_date || "";
  const endBy = f.end_date ? "date" : f.occurrence_count != null ? "count" : null;
  const ends = radioGroup("end_by", [
    { value: "count", label: "After this many payments:", extra: count },
    { value: "date", label: "On this date:", extra: until }], endBy);
  form.append(setupRow("Ends", ends, err.end));

  // The automation choice: two options, NEITHER selected until the user picks
  // one (the server refuses terms without it). Never a pre-ticked box.
  const n = opt.approvals || 3;
  const auto = f.auto_after_supervised === true ? "auto" : f.auto_after_supervised === false ? "each" : null;
  form.append(setupRow("Approvals", radioGroup("approvals", [
    { value: "each", label: "Ask me to approve every payment" },
    { value: "auto", label: "Ask me to approve the first " + n + " payments, then pay the rest "
                              + "automatically on their due dates" }], auto),
    err.auto_after_supervised));

  const submit = el("button", "btn primary", "Review");
  submit.type = "submit";
  form.append(submit);
  form.onsubmit = async (e) => {
    e.preventDefault();
    const pick = (name) => { const r = form.querySelector("input[name=" + name + "]:checked"); return r ? r.value : null; };
    const by = pick("end_by"), choice = pick("approvals");
    const payload = {
      biller_id: form.querySelector("select[name=biller_id]").value || null,
      source_account: form.querySelector("select[name=source_account]").value || null,
      amount: amount.value.trim() || null,
      frequency: pick("frequency"),
      start_date: start.value || null,
      occurrence_count: by === "count" && count.value ? parseInt(count.value, 10) : null,
      end_date: by === "date" && until.value ? until.value : null,
      auto_after_supervised: choice === "auto" ? true : choice === "each" ? false : null,
    };
    submit.disabled = true;
    typing(true);
    let res;
    try {
      res = await jpost(API + "/api/recurring/setup/" + encodeURIComponent(body.draft_id), payload);
    } catch (_) {
      res = { status: 0, json: { detail: { error: "No connection — nothing was set up." } } };
    }
    form.querySelectorAll("input, select, button").forEach((x) => { x.disabled = true; });
    handleDraft(res);
  };
  card.append(form);
  const cancel = el("button", "btn danger", "Cancel");
  cancel.type = "button";
  cancel.onclick = () => {
    form.querySelectorAll("input, select, button").forEach((x) => { x.disabled = true; });
    cancel.disabled = true;
    botSay("OK — nothing was set up.");
  };
  card.append(cancel);
  addMsg("bot", card);
}

function buildMandateCard(m, preview) {
  retireLiveCard();
  const p = preview || {};
  const card = el("div", "bubble card plan-card plan mandate-card");
  card.id = "plan";
  card.append(el("p", "card-title", "Review recurring payment"));
  const dl = el("dl", "meta terms");
  const row = (k, v, cls) => dl.append(el("dt", null, k), el("dd", cls || null, v));
  row("Pay", m.biller_display + " · " + m.biller_reference_masked);
  row("From", m.source_display);
  row("Amount", p.amount_display + " each time", "strong");
  row("How often", p.frequency_label);
  row("First payment", (p.first_dates || [])[0] + " at " + p.due_time);
  if ((p.first_dates || []).length > 1) row("Then", p.first_dates.slice(1).join(", ") + (p.count > 3 ? ", …" : ""));
  row("Last payment", p.final_date);
  row("Payments", "at most " + p.count);
  row("Total", "at most " + p.total_display, "strong");
  card.append(dl);
  if (p.short_months) card.append(el("p", "hint", p.short_months));
  const box = el("div", "approvals-box" + (m.auto_after_supervised ? " auto" : ""));
  box.append(el("p", null, p.approvals));
  if (m.auto_after_supervised) {
    box.append(el("p", null, "Automatic payments only ever pay these exact terms. They stop "
      + "for anything unusual — a changed bill reference, a frozen account, a safety check — "
      + "and you're told after every payment."));
  }
  card.append(box);
  card.append(el("p", "hint", "You can pause or cancel it at any time under Bills. Pausing "
    + "skips payments; nothing is ever paid late."));

  const sec = el("details", "sec");
  sec.append(el("summary", null, "Security details"));
  const meta = el("dl", "meta");
  const add = (k, v, id, cls) => { const dd = el("dd", cls, v); if (id) dd.id = id; meta.append(el("dt", null, k), dd); };
  add("Arrangement", m.mandate_id + " v" + m.version, null, "mono");
  add("Signing window", windowLabel(m.created_at, m.expires_at), "window");
  add("Transcript hash", m.transcript_hash.slice(0, 16) + "…", "txhash", "mono");
  add("Payload hash (your browser)", "computed when you confirm", "phash", "mono");
  sec.append(meta);
  card.append(sec);

  const btn = el("button", "btn primary", SIGN_LABEL);
  btn.id = "sign";
  btn.onclick = onSign;
  CURRENT.gate = {};
  card.append(btn, declineButton());
  updateSignGate(btn);
  card.append(el("p", "hint", "Your device signs a hash of exactly these terms. Nothing is paid now."));
  return card;
}

function showMandateCreated(res) {
  const card = newResultCard(true);
  card.append(el("h3", null, "SET UP"));
  card.append(el("p", "lead", "Your recurring payment is set up. Nothing has been paid yet — "
    + "when a payment falls due, you'll get a message and it will wait under Bills for you to approve."));
  const b = el("button", "btn secondary", "Open Bills");
  b.type = "button";
  b.onclick = showBills;
  card.append(b);
  refreshBillsBadge();
}

async function resubmitWithRecurrence(transcript, choice) {
  typing(true);
  handleDraft(await jpost(API + "/api/drafts", { transcript, user_id: DEMO_USER, recurrence: choice }));
}

async function reviewOccurrence(mandateId, seq) {
  typing(true);
  let res;
  try {
    res = await jpost(API + "/api/recurring/occurrences/" + encodeURIComponent(mandateId) + "/"
      + encodeURIComponent(seq) + "/review", { user_id: DEMO_USER });
  } catch (_) {
    res = { status: 0, json: { detail: { error: "No connection" } } };
  }
  handleDraft(res);
}

async function mandateAction(mandateId, action) {
  const r = await jpost(API + "/api/recurring/mandates/" + encodeURIComponent(mandateId) + "/" + action,
                        { user_id: DEMO_USER });
  if (r.status !== 200) { showErr(((r.json.detail || {}).error || "That didn't work") + "."); return; }
  botSay(action === "pause"
    ? "Paused. Nothing will be paid while it's paused, and payments that fall due are skipped, not paid later."
    : action === "cancel" ? "Cancelled. Nothing more will be paid under it."
    : "Resumed. Payments due from now on go ahead as agreed.");
  showBills();
}

function resumeControls(mandateId, holder) {
  const b = el("button", "btn secondary", "Resume (code by text)");
  b.type = "button";
  b.onclick = async () => {
    const r = await jpost(API + "/api/recurring/mandates/" + encodeURIComponent(mandateId) + "/resume/begin",
                          { user_id: DEMO_USER });
    if (r.status !== 200) { showErr(((r.json.detail || {}).error || "Couldn't send a code") + "."); return; }
    b.disabled = true;
    const form = el("form", "stepup-form");
    const code = el("input");
    code.inputMode = "numeric"; code.maxLength = 6; code.placeholder = "6-digit code";
    const go = el("button", "btn primary", "Resume");
    go.type = "submit";
    form.append(code, go);
    form.onsubmit = async (e) => {
      e.preventDefault();
      const rr = await jpost(API + "/api/recurring/mandates/" + encodeURIComponent(mandateId) + "/resume",
                             { user_id: DEMO_USER, code: code.value.trim() });
      if (rr.status !== 200) { showErr(((rr.json.detail || {}).error || "That code didn't work") + "."); return; }
      form.querySelectorAll("input, button").forEach((x) => { x.disabled = true; });
      botSay("Resumed. Payments due from now on go ahead as agreed; anything skipped while paused stays unpaid.");
      showBills();
    };
    holder.append(form);
    code.focus();
    botSay("I've texted a code to your phone. Enter it to resume the payments.");
  };
  return b;
}

function mandateBlock(m) {
  const box = el("div", "mandate");
  const head = el("div", "mandate-head");
  head.append(el("span", "mandate-name", m.biller || "Recurring payment"),
              el("span", "pill " + String(m.status || "").toLowerCase(), MANDATE_LABELS[m.status] || m.status));
  box.append(head);
  if (m.broken) { box.append(el("p", "hint", m.status_reason)); return box; }
  box.append(el("p", "mandate-line", m.amount_display + " " + (m.frequency === "WEEKLY" ? "weekly" : "monthly")
    + " from " + m.account + " · " + m.reference));
  box.append(el("p", "mandate-line", "Paid " + m.paid_count + " of " + m.count + " (" + m.paid_total_display
    + " of at most " + m.total_cap_display + ")"));
  if (m.next_due && (m.status === "ACTIVE" || m.status === "PAUSED")) {
    box.append(el("p", "mandate-line", "Next due: " + m.next_due + " at " + m.due_time + " (" + m.timezone + ")"));
  }
  box.append(el("p", "mandate-line strong", "Automatic payment: " + m.automatic));
  if (m.status_reason && m.status !== "ACTIVE") box.append(el("p", "hint", m.status_reason));
  const det = el("details", "sec");
  det.append(el("summary", null, "Payments"));
  const ul = el("ul", "occ-list");
  for (const o of m.occurrences || []) {
    const li = el("li", "occ " + String(o.status).toLowerCase());
    li.append(el("span", null, "#" + o.seq + " · " + o.due), el("span", null, OCC_LABELS[o.status] || o.status));
    if (o.reason && o.status !== "EXECUTED") li.append(el("span", "occ-reason", o.reason));
    if (o.approvable) {
      const b = el("button", "chip choice", "Review & approve");
      b.type = "button";
      b.onclick = () => reviewOccurrence(m.mandate_id, o.seq);
      li.append(b);
    }
    ul.append(li);
  }
  det.append(ul);
  box.append(det);
  const actions = el("div", "mandate-actions");
  if (m.status === "ACTIVE") {
    const b = el("button", "btn secondary", "Pause");
    b.type = "button";
    b.onclick = () => mandateAction(m.mandate_id, "pause");
    actions.append(b);
  }
  if (m.status === "PAUSED") actions.append(resumeControls(m.mandate_id, actions));
  if (m.status === "ACTIVE" || m.status === "PAUSED" || m.status === "SUSPENDED") {
    const b = el("button", "btn danger", "Cancel arrangement");
    b.type = "button";
    b.onclick = () => {
      if (!confirm("Cancel this recurring payment? Nothing more will be paid under it.")) return;
      mandateAction(m.mandate_id, "cancel");
    };
    actions.append(b);
  }
  box.append(actions);
  return box;
}

async function showBills() {
  let mandates = [], pending = [], notes = [], clock = {};
  try {
    [mandates, pending, notes, clock] = await Promise.all([
      jget(API + "/api/recurring/mandates?user_id=" + DEMO_USER).then((r) => r.mandates || []),
      jget(API + "/api/recurring/pending?user_id=" + DEMO_USER).then((r) => r.pending || []),
      jget(API + "/api/recurring/notifications?user_id=" + DEMO_USER).then((r) => r.notifications || []),
      jget(API + "/api/recurring/clock").catch(() => ({})),
    ]);
  } catch (_) {
    showErr("Couldn't load your recurring payments.");
    return;
  }
  paintBillsBadge(pending.length);
  const card = el("div", "bubble card plan-card bills-card");
  card.append(el("p", "card-title", "Recurring payments"));
  if (pending.length) {
    card.append(el("p", "sg-title", "WAITING FOR YOUR APPROVAL"));
    const ul = el("ul", "occ-list pending");
    for (const p of pending) {
      const li = el("li", "occ pending_approval");
      li.append(el("span", null, p.biller + " · " + p.amount_display + " · payment " + p.seq + " of " + p.count),
                el("span", null, "Due " + p.due + "; approve by " + p.review_until));
      if (p.reason) li.append(el("span", "occ-reason", p.reason));
      const b = el("button", "chip choice", "Review & approve");
      b.type = "button";
      b.onclick = () => reviewOccurrence(p.mandate_id, p.seq);
      li.append(b);
      ul.append(li);
    }
    card.append(ul);
  }
  if (!mandates.length) {
    card.append(el("p", "hint", "No recurring payments yet. Try: “Pay SP Group S$85 from savings every "
      + "month, starting 1 November, for six months.”"));
  }
  for (const m of mandates) card.append(mandateBlock(m));
  if (notes.length) {
    const act = el("details", "sec");
    act.append(el("summary", null, "Recent messages"));
    const ul = el("ul", "occ-list");
    for (const n of notes.slice(0, 8)) {
      const li = el("li", "occ");
      li.append(el("span", "strong", n.title), el("span", "occ-reason", n.body));
      ul.append(li);
    }
    act.append(ul);
    card.append(act);
  }
  if (clock.demo) {
    // DEMO ONLY: the server's RECURRING_DEMO_CLOCK lets a demo reach next
    // month's due date now. Off (and this button absent) on a normal server.
    card.append(el("p", "hint", "Demo clock: today is " + clock.today + "."));
    const b = el("button", "btn secondary", "⏭ Demo: jump to the next due date");
    b.type = "button";
    b.onclick = async () => {
      b.disabled = true;
      const r = await jpost(API + "/api/recurring/clock/advance", { user_id: DEMO_USER });
      if (r.status !== 200) { showErr(((r.json.detail || {}).error || "Couldn't move the clock") + "."); return; }
      botSay("Demo clock moved to " + r.json.today + ".");
      refreshBalances();
      showBills();
    };
    card.append(b);
  }
  addMsg("bot", card);
}

function paintBillsBadge(n) {
  const badge = document.getElementById("bills-badge");
  if (!badge) return;
  badge.hidden = !n;
  badge.textContent = n ? String(n) : "";
}

async function refreshBillsBadge() {
  try {
    const pending = (await jget(API + "/api/recurring/pending?user_id=" + DEMO_USER)).pending || [];
    paintBillsBadge(pending.length);
    return pending;
  } catch (_) {
    return null;                       // the badge is a convenience; the list is the record
  }
}

function wireBills() {
  const btn = document.getElementById("bills");
  if (btn) btn.onclick = showBills;
  setInterval(refreshBillsBadge, 15000);
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

function greet() {
  const m = botSay("Hi Alice. Tell me what you'd like to do — pay someone, "
    + "pay a bill, buy shares, or update a contact. I'll draft it, and nothing moves until you "
    + "approve it with your biometric.");
  const chips = el("div", "chips");
  const b = el("button", "chip", "Show my contacts");
  b.type = "button";
  b.onclick = showContacts;
  chips.append(b);
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

/* ---------- kill switch ---------- */
function paintFreeze(engaged) {
  const banner = document.getElementById("frozen");
  const btn = document.getElementById("freeze");
  if (banner) banner.hidden = !engaged;
  if (btn) { btn.classList.toggle("on", engaged); btn.textContent = engaged ? "Frozen" : "Freeze"; }
}

// Paints the server's freeze state and returns it (null if it can't be read).
async function refreshKillSwitch() {
  try {
    const engaged = !!(await jget(API + "/api/killswitch?user_id=" + DEMO_USER)).engaged;
    paintFreeze(engaged);
    return engaged;
  } catch (_) {       /* the banner is a convenience; the server enforces the freeze */
    return null;
  }
}

function wireKillSwitch() {
  const btn = document.getElementById("freeze");
  const unfreeze = document.getElementById("unfreeze");
  const form = document.getElementById("unfreeze-form");
  const code = document.getElementById("unfreeze-code");
  if (!btn) return;
  // One tap (plus "are you sure") — making things safer should be easy.
  btn.onclick = async () => {
    if (btn.classList.contains("on")) return;
    if (!confirm("Freeze all outgoing payments? Unfreezing needs a code sent to your phone.")) return;
    let r;
    try {
      r = await jpost(API + "/api/killswitch", { user_id: DEMO_USER });
    } catch (_) {
      r = { status: 0, json: {} };
    }
    if (r.status !== 200) {
      // Never "frozen" unless the server says so: false assurance on a safety
      // control is worse than an error. And never "couldn't freeze" when it
      // did (the freeze is recorded first, then the cleanup can fail): ask.
      if (await refreshKillSwitch()) {
        retireLiveCard();
        botSay("Your payments are frozen. Something went wrong while cancelling requests "
          + "waiting for approval, but none of them can be sent while you're frozen.");
        return;
      }
      showErr("Couldn't freeze your payments (" + (((r.json.detail || {}).error) || r.status
        || "no connection") + "). Try again.");
      return;
    }
    paintFreeze(true);
    retireLiveCard();
    botSay("Done — all outgoing payments are frozen. " + (r.json.drafts_cancelled
      ? r.json.drafts_cancelled + " request(s) waiting for approval were cancelled. " : "")
      + (r.json.already_sent
      ? r.json.already_sent + " payment(s) had already gone through before the freeze — check your balance. " : "")
      + "Nothing can be sent until you unfreeze with a code from your phone.");
  };
  unfreeze.onclick = async () => {
    const r = await jpost(API + "/api/killswitch/release/begin", { user_id: DEMO_USER });
    if (r.status !== 200) {                    // too many codes this hour
      showErr(((r.json.detail || {}).error || "Couldn't send a code") + ".");
      return;
    }
    if (r.json.engaged === false) { paintFreeze(false); return; }
    form.hidden = false;
    code.focus();
    botSay("I've texted a code to your phone. Enter it to unfreeze your payments.");
  };
  form.onsubmit = async (e) => {
    e.preventDefault();
    const r = await jpost(API + "/api/killswitch/release", { user_id: DEMO_USER, code: code.value.trim() });
    if (r.status === 200 && r.json.engaged === false) {
      form.hidden = true;
      code.value = "";
      paintFreeze(false);
      if (r.json.drafts_cancelled) retireLiveCard();
      botSay("Payments are unfrozen." + (r.json.drafts_cancelled
        ? " " + r.json.drafts_cancelled + " request(s) made while frozen were cancelled — ask again if you still want them."
        : ""));
    } else {
      showErr(((r.json.detail || {}).error || "That code didn't work") + ".");
    }
  };
}

async function init() {
  wireSound();
  wireKillSwitch();
  refreshKillSwitch();
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
  wireBills();
  document.getElementById("say-box").hidden = false;
  greet();
  // Bills that fell due while the app was closed are still waiting: say so.
  const pending = await refreshBillsBadge();
  if (pending && pending.length) {
    const m = botSay("You have " + pending.length + " bill payment" + (pending.length > 1 ? "s" : "")
      + " waiting for your approval. Nothing is paid until you approve.");
    const chips = el("div", "chips live");
    const b = el("button", "chip choice", "Review now");
    b.type = "button";
    b.onclick = () => { chips.classList.remove("live"); b.disabled = true; showBills(); };
    chips.append(b);
    m.append(chips);
  }
}
window.addEventListener("DOMContentLoaded", init);

