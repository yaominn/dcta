/*
 * Cross-language acceptance runner for the M2 canonicalizer.
 *
 * Reads a ResolvedPlan (as JSON) on stdin, canonicalizes it with the SAME
 * frontend/canonical.js the browser overlay uses, SHA-256 hashes the UTF-8
 * bytes, and prints {"canonical":"...","hash":"..."} on stdout.
 *
 * The pytest (tests/test_js_canonicalizer.py) builds the SAME plan in Python,
 * computes Python's canonical_json + payload_hash, and asserts byte-identical
 * equality — including for a non-ASCII (accented + CJK) payee_display, which is
 * exactly where two independent canonicalizers would otherwise drift.
 */
const crypto = require("node:crypto");
const path = require("node:path");
const canonicalJson = require(path.join(__dirname, "..", "..", "frontend", "canonical.js"));

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const plan = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
  const canonical = canonicalJson(plan);
  const hash = crypto
    .createHash("sha256")
    .update(Buffer.from(canonical, "utf-8"))
    .digest("hex");
  process.stdout.write(JSON.stringify({ canonical: canonical, hash: hash }));
});
