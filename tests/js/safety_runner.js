// Loads frontend/app.js under Node (as app_runner.js does) and drives the
// safety controls' failure paths: Freeze and Cancel when the server can't be
// reached or refuses. tests/test_scam_protection.py asserts on the output.
"use strict";
const fs = require("fs");
const path = require("path");
const SRC = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "app.js"), "utf8");

const els = {};
function fakeEl(id) {
  if (!els[id]) {
    const classes = new Set();
    els[id] = { id, disabled: false, hidden: false, textContent: "", onclick: null,
                classList: { contains: (c) => classes.has(c),
                             toggle: (c, on) => { if (on) classes.add(c); else classes.delete(c); } } };
  }
  return els[id];
}
const offline = async () => { throw new TypeError("Failed to fetch"); };
let respond = offline;
const errors = [];
const env = {
  window: { addEventListener() {} },
  document: { getElementById: fakeEl, querySelectorAll() { return []; } },
  navigator: {},
  fetch: (...args) => respond(...args),
  confirm: () => true,
  errors,
};
// The page's own showErr/botSay/retireLiveCard draw into a DOM this stub
// doesn't have: record the errors, skip the drawing.
const app = new Function(...Object.keys(env), SRC + `
  showErr = (msg) => errors.push(msg);
  botSay = () => {};
  retireLiveCard = () => {};
  return { wireKillSwitch, onDecline, CURRENT };`)(...Object.values(env));
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

(async () => {
  const out = {};

  // Freeze with no connection: never shown as frozen.
  app.wireKillSwitch();
  await settle();
  await els.freeze.onclick();
  await settle();
  out.freezeOffline = { on: els.freeze.classList.contains("on"), error: errors.pop() || null };

  // Freeze refused by the server, which says payments aren't frozen.
  respond = async (url, opts) => {
    const post = !!(opts && opts.method === "POST");
    return { status: post ? 500 : 200,
             json: async () => (post ? { detail: { error: "boom" } } : { engaged: false }) };
  };
  await els.freeze.onclick();
  await settle();
  out.freezeRefused = { on: els.freeze.classList.contains("on"), error: errors.pop() || null };

  // Cancel with no connection during a hold: Cancel can be tried again, and
  // Confirm stays locked by the hold.
  respond = offline;
  app.CURRENT.draftId = "d-held";
  app.CURRENT.gate = { hold: true };
  await app.onDecline();
  out.cancelOffline = { cancelDisabled: fakeEl("decline").disabled,
                        signDisabled: fakeEl("sign").disabled, error: errors.pop() || null };

  process.stdout.write(JSON.stringify(out));
})();
