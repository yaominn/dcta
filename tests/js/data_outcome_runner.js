// Runs the /data page's badge rule (outcomeOf in frontend/data.html) under
// Node: reads {"traces": [...]} from stdin — the /api/data body — and prints
// each trace's [class, label]. tests/test_data_outcome.py asserts on it.
"use strict";
const fs = require("fs");
const path = require("path");
const HTML = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "data.html"), "utf8");
const src = HTML.match(/function outcomeOf\(tr\) \{[\s\S]*?\n  \}\n/);
if (!src) throw new Error("outcomeOf not found in frontend/data.html");
const outcomeOf = new Function(src[0] + "\nreturn outcomeOf;")();
const body = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(body.traces.map(outcomeOf)));
