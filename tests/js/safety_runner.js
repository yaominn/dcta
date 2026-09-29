// Loads frontend/app.js under Node (as app_runner.js does) with a small fake
// DOM, and drives the safety controls: the Confirm gate a card is shown with,
// which draft Cancel acts on, and Freeze/Cancel when the server can't be
// reached or refuses. tests/test_scam_protection.py asserts on the output.
"use strict";
const fs = require("fs");
const path = require("path");
const SRC = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "app.js"), "utf8");

// Elements are plain objects. Like a browser, getElementById only finds
// elements attached to the page: a card that is still being built isn't.
function descendants(node) {
  const out = [];
  for (const k of node.children) out.push(k, ...descendants(k));
  return out;
}
function makeEl(tag) {
  const classes = new Set();
  return {
    tagName: String(tag).toUpperCase(), id: "", children: [], parent: null,
    disabled: false, hidden: false, textContent: "", value: "", style: {}, dataset: {},
    classList: {
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      contains: (c) => classes.has(c),
      toggle: (c, on) => {
        if (on === undefined ? !classes.has(c) : on) classes.add(c); else classes.delete(c);
      },
    },
    set className(v) { String(v).split(/\s+/).filter(Boolean).forEach((x) => classes.add(x)); },
    get childElementCount() { return this.children.length; },
    append(...kids) {
      for (const k of kids) if (k && typeof k === "object") { k.parent = this; this.children.push(k); }
    },
    remove() {
      if (!this.parent) return;
      this.parent.children = this.parent.children.filter((k) => k !== this);
      this.parent = null;
    },
    removeAttribute(k) { if (k === "id") this.id = ""; },
    setAttribute(k, v) { this[k] = v; },
    querySelectorAll(sel) {            // tag lists only ("button, input")
      const tags = sel.split(",").map((s) => s.trim().toUpperCase());
      return descendants(this).filter((d) => tags.includes(d.tagName));
    },
    querySelector(sel) {               // a single ".class"
      return descendants(this).find((d) => d.classList.contains(sel.replace(/^\./, ""))) || null;
    },
    focus() {}, select() {},
  };
}
const body = makeEl("body");
const document = {
  body,
  createElement: makeEl,
  getElementById: (id) => descendants(body).find((d) => d.id === id) || null,
  querySelectorAll: () => [],
};
for (const id of ["thread", "freeze", "frozen", "unfreeze", "unfreeze-form", "unfreeze-code", "say"]) {
  const n = makeEl(id === "thread" ? "main" : "div");
  n.id = id;
  body.append(n);
}

const offline = async () => { throw new TypeError("Failed to fetch"); };
let respond = offline;
const reply = (status, json) => ({ status, json: async () => json });
const errors = [];
const said = [];
const env = {
  window: { addEventListener() {} },
  document,
  navigator: {},
  fetch: (...args) => respond(...args),
  confirm: () => true,
  requestAnimationFrame: () => 0,
  errors,
  said,
};
const app = new Function(...Object.keys(env), SRC + `
  showErr = (msg) => errors.push(msg);
  botSay = (text) => { said.push(text); };
  return { wireKillSwitch, onDecline, handleDraft, typedName, CURRENT };`)(...Object.values(env));
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
const sign = () => document.getElementById("sign");
const now = Math.floor(Date.now() / 1000);
const heldPayment = { status: 200, json: {
  status: "ready", draft_id: "d-held", transcript: "pay mom 500", narration: null,
  requires_extra_confirmation: false,
  resolved_plan: { draft_id: "d-held", created_at: now, expires_at: now + 300,
                   transcript_hash: "a".repeat(64),
                   plan: [{ id: "t1", type: "TRANSFER", source_account: "acct_savings",
                            payee_display: "Mom ··4567", amount_cents: 50000,
                            destination_masked: "+65 8123 ••67" }] },
  scam: { outcome: "HOLD", score: 5, warnings: ["Mom's PayNow number was changed just now."],
          confirm_name: null, hold: { release_at: now + 30, seconds_left: 30 } } } };

(async () => {
  const out = {};

  // A held payment: Confirm is locked from the moment the card is shown.
  app.handleDraft(heldPayment);
  out.heldCard = { signDisabled: sign().disabled };

  // Cancel with no connection during the hold: Cancel can be tried again,
  // and Confirm stays locked by the hold.
  respond = offline;
  await app.onDecline();
  out.cancelOffline = { cancelDisabled: document.getElementById("decline").disabled,
                        signDisabled: sign().disabled, error: errors.pop() || null };

  // A contacts list and a refusal in between: Cancel still acts on the held
  // payment's draft.
  app.handleDraft({ status: 200, json: { status: "info", kind: "contacts", contacts: [] } });
  app.handleDraft({ status: 200, json: { status: "blocked", draft_id: "d-blocked",
                                         reasons: ["over your daily limit"] } });
  let declined = null;
  respond = async (url) => { declined = url; return reply(200, { status: "cancelled" }); };
  await app.onDecline();
  out.cancelTarget = { draftId: app.CURRENT.draftId, url: declined };

  // A contact change waiting for its phone code: Confirm is locked, a failed
  // Cancel keeps it locked, and the right code unlocks it.
  app.handleDraft({ status: 200, json: {
    status: "ready", kind: "contact_edit", draft_id: "d-edit", requires_extra_confirmation: true,
    confirmation: { reasons: ["A new number changes where payments go."] },
    contact_change: { draft_id: "d-edit", created_at: now, expires_at: now + 300,
                      transcript_hash: "b".repeat(64),
                      edits: [{ payee_display: "Mom ··3310", field: "phone",
                                old_value: "+65 9123 4510", new_value: "+65 8123 4567" }] } } });
  const atRender = sign().disabled;
  respond = async () => reply(500, { detail: { error: "boom" } });
  await app.onDecline();
  const afterFailedCancel = sign().disabled;
  respond = async () => reply(200, { confirmed: true });
  document.getElementById("stepup-code").value = "123456";
  await document.getElementById("stepup-form").onsubmit({ preventDefault() {} });
  out.contactCard = { atRender, afterFailedCancel, afterCode: sign().disabled };
  errors.length = 0;
  said.length = 0;

  // HOLD_STEP_UP: the name typed on the live card goes with the signature; a
  // newer card retires the box, and its old value is never sent.
  const stepUp = JSON.parse(JSON.stringify(heldPayment));
  Object.assign(stepUp.json, { draft_id: "d-step", requires_extra_confirmation: true,
                               confirmation: { reasons: [] } });
  Object.assign(stepUp.json.scam, { outcome: "HOLD_STEP_UP", score: 8, confirm_name: "Mom" });
  app.handleDraft(stepUp);
  document.getElementById("name-check").value = " mom";
  const live = app.typedName();
  app.handleDraft(heldPayment);
  out.typedName = { live, afterNewCard: app.typedName() };

  // Freeze with no connection: never shown as frozen.
  app.wireKillSwitch();
  const freeze = document.getElementById("freeze");
  respond = offline;
  await freeze.onclick();
  await settle();
  out.freezeOffline = { on: freeze.classList.contains("on"), error: errors.pop() || null };

  // Freeze refused, and the server says payments aren't frozen.
  const freezeFails = (engaged) => async (url, opts) => (opts && opts.method === "POST"
    ? reply(500, { detail: { error: "boom" } }) : reply(200, { engaged }));
  respond = freezeFails(false);
  await freeze.onclick();
  await settle();
  out.freezeRefused = { on: freeze.classList.contains("on"), error: errors.pop() || null };

  // The freeze was recorded but its cleanup failed: shown as frozen, and
  // never "couldn't freeze".
  respond = freezeFails(true);
  await freeze.onclick();
  await settle();
  out.freezeHalfDone = { on: freeze.classList.contains("on"), error: errors.pop() || null,
                         said: said.pop() || null };

  clearInterval(app.CURRENT.holdTimer);
  process.stdout.write(JSON.stringify(out));
})();
