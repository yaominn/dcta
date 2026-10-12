// Loads frontend/app.js under Node (as safety_runner.js does) with a small
// fake DOM, and drives the greeting's one button and the contacts card:
// Remove -> confirm, and the Add contact form.
// tests/test_contact_remove.py asserts on the output.
"use strict";
const fs = require("fs");
const path = require("path");
const SRC = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "app.js"), "utf8");

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
    },
    set className(v) { String(v).split(/\s+/).filter(Boolean).forEach((x) => classes.add(x)); },
    get lastElementChild() { return this.children[this.children.length - 1] || null; },
    append(...kids) {
      for (const k of kids) if (k && typeof k === "object") { k.parent = this; this.children.push(k); }
    },
    replaceChildren(...kids) {
      for (const k of this.children) k.parent = null;
      this.children = [];
      this.append(...kids);
    },
    remove() {
      if (!this.parent) return;
      this.parent.children = this.parent.children.filter((k) => k !== this);
      this.parent = null;
    },
    setAttribute(k, v) { this[k] = v; },
    querySelectorAll(sel) {
      const tags = sel.split(",").map((s) => s.trim().toUpperCase());
      return descendants(this).filter((d) => tags.includes(d.tagName));
    },
    focus() { focused = this; },
  };
}
let focused = null;
const body = makeEl("body");
const document = {
  body,
  createElement: makeEl,
  getElementById: (id) => descendants(body).find((d) => d.id === id) || null,
  querySelectorAll: () => [],
};
for (const id of ["thread", "say"]) {
  const n = makeEl(id === "thread" ? "main" : "input");
  n.id = id;
  body.append(n);
}

const calls = [];
let removeReply = null;               // what POST /api/contacts/remove answers
let listReply = null;                 // what GET /api/contacts answers
const reply = (status, json) => ({ status, json: async () => json });
const CONTACTS = [
  { display: "Landlord ··7001", nickname: "Landlord", last4: "7001", phone: "+65 6123 7001", hold_until: null },
  { display: "Mom ··3310", nickname: "Mom", last4: "3310", phone: "+65 9123 3310", hold_until: null },
];
const env = {
  window: { addEventListener() {} },
  document,
  navigator: {},
  Voice: { speak() {}, silence() {} },
  requestAnimationFrame: () => 0,
  fetch: async (url, opts) => {
    const body = opts && opts.body ? JSON.parse(opts.body) : null;
    calls.push({ url, method: (opts && opts.method) || "GET", body });
    if (url.split("?")[0].endsWith("/api/contacts")) return listReply();
    if (url.endsWith("/api/contacts/remove")) return removeReply();
    return new Promise(() => {});     // a draft: never answered here
  },
};
listReply = async () => reply(200, { status: "info", kind: "contacts", contacts: CONTACTS });
const app = new Function(...Object.keys(env), SRC + `
  return { greet, PENDING: () => ({ purpose: PURPOSE_FOR, number: NEW_CONTACT }),
           awaitPurpose };`)(...Object.values(env));
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
const thread = () => document.getElementById("thread");
const all = () => descendants(thread());
const buttons = (node) => descendants(node).filter((d) => d.tagName === "BUTTON");
const texts = (node) => descendants(node).map((d) => d.textContent).filter(Boolean);
const lastCard = () => all().filter((d) => d.classList.contains("contacts")).pop();
const cards = () => all().filter((d) => d.classList.contains("contacts"));
const rowIn = (card, name) => descendants(card).find(
  (d) => d.tagName === "LI" && texts(d).some((t) => t.startsWith(name)));
const rowOf = (name) => rowIn(lastCard(), name);
const byText = (node, t) => buttons(node).find((b) => b.textContent === t);

(async () => {
  const out = {};

  // The greeting: one button, and it reads the list without the model.
  app.greet();
  out.greetingButtons = buttons(thread()).map((b) => b.textContent);
  byText(thread(), "Show my contacts").onclick();
  await settle();
  out.showCalls = calls.map((c) => c.method + " " + c.url);
  byText(thread(), "Show my contacts").onclick();         // a second card, further down
  await settle();
  const card = lastCard();
  out.cardRows = descendants(card).filter((d) => d.tagName === "LI").length;
  out.rowButtons = buttons(rowOf("Landlord")).map((b) => b.textContent);

  // Remove -> a confirm on that row; Cancel puts it back; nothing is sent.
  byText(rowOf("Landlord"), "Remove").onclick();
  out.confirmButtons = buttons(rowOf("Landlord")).map((b) => b.textContent);
  out.confirmAsk = texts(rowOf("Landlord")).find((t) => t.startsWith("Remove ")) || null;
  byText(rowOf("Landlord"), "Cancel").onclick();
  out.afterCancel = buttons(rowOf("Landlord")).map((b) => b.textContent);
  out.removeCallsAfterCancel = calls.filter((c) => c.url.endsWith("/remove")).length;

  // The server refuses: the contact stays, the reason is shown.
  removeReply = async () => reply(409, { detail: "Two contacts have that name and number ending. Rename one first." });
  byText(rowOf("Landlord"), "Remove").onclick();
  byText(rowOf("Landlord"), "Yes, remove").onclick();
  await settle();
  out.refused = { stillListed: !!rowOf("Landlord"),
                  error: texts(thread()).filter((t) => t.startsWith("Two contacts")).pop() || null,
                  buttons: buttons(rowOf("Landlord")).map((b) => b.textContent) };

  // No connection: the same, with a plain reason.
  removeReply = async () => { throw new TypeError("Failed to fetch"); };
  byText(rowOf("Landlord"), "Remove").onclick();
  byText(rowOf("Landlord"), "Yes, remove").onclick();
  await settle();
  out.offline = { stillListed: !!rowOf("Landlord"),
                  error: texts(thread()).filter((t) => t.startsWith("Couldn't remove")).pop() || null };

  // Removed: the row goes, and the assistant says so.
  removeReply = async () => reply(200, { removed: "Landlord ··7001" });
  byText(rowOf("Landlord"), "Remove").onclick();
  byText(rowOf("Landlord"), "Yes, remove").onclick();
  await settle();
  const sent = calls.filter((c) => c.url.endsWith("/remove")).pop();
  out.removed = { body: sent.body, stillListed: !!rowOf("Landlord"), momListed: !!rowOf("Mom"),
                  olderCardStillListed: !!rowIn(cards()[0], "Landlord"),
                  said: texts(thread()).filter((t) => t.includes("Landlord ··7001")).pop() || null };

  // Add contact: a form; empty fields send nothing; a filled one is a fresh
  // request even while a payment waits for its purpose.
  const c = lastCard();
  byText(c, "+ Add contact").onclick();
  const form = descendants(c).find((d) => d.tagName === "FORM");
  const inputs = descendants(form).filter((d) => d.tagName === "INPUT");
  out.formShown = !form.hidden && inputs.length === 2;
  const before = calls.length;
  form.onsubmit({ preventDefault() {} });
  out.emptySent = calls.length - before;
  out.emptyFocus = focused === inputs[0];
  app.awaitPurpose("d-waiting");
  inputs[0].value = "  Uncle Bob ";
  inputs[1].value = "9123 4567";
  form.onsubmit({ preventDefault() {} });
  await settle();
  const draft = calls.filter((c) => c.method === "POST").pop();
  out.added = { url: draft.url, transcript: draft.body.transcript, formHidden: form.hidden,
                pending: app.PENDING() };

  // The list can't be read: say so, never an empty list.
  for (const [name, fail] of [["serverError", async () => reply(500, { detail: "boom" })],
                              ["offline", async () => { throw new TypeError("Failed to fetch"); }]]) {
    listReply = fail;
    const before = cards().length;
    byText(thread(), "Show my contacts").onclick();
    await settle();
    out["load_" + name] = { newCard: cards().length !== before,
      error: texts(thread()).filter((t) => t.startsWith("Couldn't load")).pop() || null };
  }

  process.stdout.write(JSON.stringify(out));
})();
