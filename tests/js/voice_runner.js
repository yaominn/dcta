// Drives frontend/voice.js's tier-1 path (record -> upload -> react to the
// status) under Node with a fake MediaRecorder and fetch, and prints which
// callback each server answer produced. tests/test_voice_js_fallback.py
// asserts on the result.
"use strict";
const fs = require("fs");
const path = require("path");

const SRC = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "voice.js"), "utf8");

function load(fetchImpl) {
  class FakeRecorder {
    constructor(_stream, opts) {
      this.mimeType = (opts && opts.mimeType) || "audio/mp4";
      this.state = "inactive";
    }
    static isTypeSupported(t) { return t === "audio/mp4"; }   // Safari's answer
    start() { this.state = "recording"; }
    stop() {
      this.state = "inactive";
      this.ondataavailable({ data: new Blob(["audio"]) });
      return this.onstop();              // voice.js's onstop is async: hand back its promise
    }
  }
  const env = {
    navigator: { mediaDevices: { getUserMedia: async () => ({ getTracks: () => [{ stop() {} }] }) } },
    MediaRecorder: FakeRecorder,
    fetch: fetchImpl,
    Blob,
    FormData,
    window: {},
  };
  return new Function(...Object.keys(env), SRC + "\nreturn Voice;")(...Object.values(env));
}

async function scenario(status, body) {
  const calls = [];
  const Voice = load(async () => ({
    status, ok: status >= 200 && status < 300, json: async () => body,
  }));
  const rec = await Voice.recordAndUpload({
    onText: (t, p) => calls.push(["text", t, p]),
    onError: (e) => calls.push(["error", String(e && e.message)]),
    onState: () => {},
    onFallback: (_reason, opts) => calls.push(["fallback", Boolean(opts && opts.sticky)]),
  });
  await rec.stop();
  return calls;
}

const CASES = {
  ok:               [200, { transcript: "pay mom fifty dollars", provider: "openai" }],
  no_speech:        [422, { detail: { error: "no text", provider: "openai", no_speech: true } }],
  malformed_422:    [422, { detail: [{ type: "missing", loc: ["body", "audio"] }] }],
  upstream_503:     [503, { detail: { error: "HTTP 429", provider: "openai", fallback: "webspeech" } }],
  unconfigured_503: [503, { detail: { error: "none", provider: "unavailable", fallback: "webspeech" } }],
  container_415:    [415, { detail: { error: "webm", provider: "tencent", fallback: "webspeech" } }],
  too_long_413:     [413, { detail: { error: "too large", fallback: "webspeech" } }],
};

(async () => {
  const out = {};
  for (const [name, [status, body]] of Object.entries(CASES)) out[name] = await scenario(status, body);
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error(e); process.exit(1); });
