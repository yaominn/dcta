// Loads frontend/app.js under Node with a minimal window/document stub and
// exercises its pure helpers (no DOM work happens at load time: init waits for
// DOMContentLoaded). tests/test_balances_and_spending.py asserts on the output.
"use strict";
const fs = require("fs");
const path = require("path");
const SRC = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "app.js"), "utf8");
const env = {
  window: { addEventListener() {} },
  document: { getElementById() { return null; }, querySelectorAll() { return []; } },
  navigator: {},
};
const app = new Function(...Object.keys(env),
  SRC + "\nreturn { acctLabel, executedLines, successToast, evidenceText };")(...Object.values(env));

const plan = { plan: [
  { id: "t1", type: "TRANSFER", source_account: "acct_joint", payee_display: "Mom ··3310" },
  { id: "t2", type: "PAY_BILL", source_account: "acct_savings", biller_display: "SP Group" },
  { id: "t3", type: "BUY_EQUITY", source_account: "acct_savings", ticker: "AAPL" },
] };
const exec = { status: "FAILED", legs: [
  { id: "t1", type: "TRANSFER", status: "EXECUTED", amount_cents: 5000 },
  { id: "t2", type: "PAY_BILL", status: "EXECUTED", amount_cents: 12345 },
  { id: "t3", type: "BUY_EQUITY", status: "FAILED", error: "insufficient funds" },
] };
const single = { status: "EXECUTED", legs: [
  { id: "t1", type: "TRANSFER", status: "EXECUTED", amount_cents: 5000 }] };
const noneRan = { status: "FAILED", legs: [
  { id: "t1", type: "TRANSFER", status: "FAILED", error: "insufficient funds" }] };
process.stdout.write(JSON.stringify({
  labels: ["acct_savings", "acct_joint", "acct_invest", "acct_other", "weird"].map(app.acctLabel),
  lines: app.executedLines(exec, plan),
  partial: app.successToast(exec, plan),          // FAILED overall, 2 of 3 legs ran
  single: app.successToast(single, plan),
  noneRan: app.successToast(noneRan, plan),
  evidence: [
    app.evidenceText({ amount: { kind: "said", quote: "50 dollars" }, to: { kind: "said", quote: "mom" },
                       from: { kind: "default" } }, { source_account: "acct_savings", amount_cents: 5000 }),
    app.evidenceText({ amount: { kind: "chosen", quote: "500" }, to: { kind: "said", quote: "mom" },
                       from: { kind: "said", quote: "spending" } }, { source_account: "acct_joint", amount_cents: 50000 }),
    app.evidenceText({ amount: { kind: "calculated", text: "the rest of what's left in Savings" },
                       to: { kind: "said", quote: "apple" }, from: { kind: "derived" } },
                     { source_account: "acct_savings", amount_cents: 772800 }),
    app.evidenceText({ amount: { kind: "not_found" }, to: { kind: "not_found" }, from: { kind: "default" } },
                     { source_account: "acct_savings", amount_cents: 100 }),
    app.evidenceText({ amount: { kind: "said", quote: "50" }, to: { kind: "said", quote: "mom" },
                       from: { kind: "not_found" } }, { source_account: "acct_joint", amount_cents: 5000 }),
    app.evidenceText(null, {}),
  ],
  contact: app.successToast({ status: "UPDATED", changes: [
    { payee_display: "John ··8892", field: "nickname", new_value: "Johnny" }] }, null),
}));
