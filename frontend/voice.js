/*
 * DCTA voice input — three tiers, degrading gracefully. (M7)
 *
 *   1. Tencent Cloud ASR   POST /api/transcribe (credentials live server-side;
 *                          they must never reach this file)
 *   2. Web Speech API      in-browser, free, no keys, lower latency
 *   3. Text input          always works — the demo floor
 *
 * A tier failing is NOT a product failure. /api/transcribe answering 503 with
 * {"fallback":"webspeech"} is the designed degradation path: we drop a tier and
 * the user sees a different engine, not an error. Brief §5: "Text input must
 * always work as a demo fallback" — if the room's acoustics beat the mic on
 * stage, you type the same sentence and the demo continues.
 *
 * SPEAKING (TTS) uses the browser's speechSynthesis: free, offline, no keys,
 * and it makes clarifying questions audible for a voice-first demo.
 */
"use strict";

const Voice = (() => {
  let mediaRecorder = null;
  let chunks = [];

  function speechRecognitionAvailable() {
    return !!(window.SpeechRecognition || window.webkitSpeechRecognition);
  }

  /* ---------- audio container negotiation ---------- */
  /* Browser MIME type -> the VoiceFormat name the backend allows. Anything not
     listed here is sent without a hint, and the server answers 415 and names
     the tier to fall back to. Keep in step with SUPPORTED_VOICE_FORMATS in
     backend/asr/provider.py. */
  const MIME_TO_VOICE_FORMAT = [
    ["audio/ogg", "ogg-opus"],
    ["audio/mpeg", "mp3"],
    ["audio/mp4", "m4a"],
    ["audio/aac", "aac"],
    ["audio/wav", "wav"],
    ["audio/wave", "wav"],
    ["audio/x-wav", "wav"],
  ];

  function voiceFormatOf(mimeType) {
    const m = (mimeType || "").toLowerCase();
    for (const [prefix, fmt] of MIME_TO_VOICE_FORMAT) {
      if (m.startsWith(prefix)) return fmt;
    }
    // Unknown container (audio/webm is the common case): report the subtype
    // VERBATIM rather than nothing. Sending no hint would let the server apply
    // its configured default and forward webm audio labelled "mp3" — the exact
    // mislabelling this negotiation exists to prevent. Naming it truthfully
    // gets an honest 415 and a clean drop to the Web Speech tier.
    const subtype = m.split(";")[0].split("/")[1];
    return subtype || null;
  }

  function pickRecorderOptions() {
    if (typeof MediaRecorder === "undefined" ||
        typeof MediaRecorder.isTypeSupported !== "function") return undefined;
    // Ordered by upstream preference, not by browser popularity.
    for (const t of ["audio/ogg;codecs=opus", "audio/ogg", "audio/mp4", "audio/mpeg"]) {
      if (MediaRecorder.isTypeSupported(t)) return { mimeType: t };
    }
    return undefined;     // browser default (usually webm) -> 415 -> tier 2
  }

  /* ---------- tier 2: Web Speech API ---------- */
  function listenWebSpeech({ onText, onError, onState }) {
    const Rec = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!Rec) return onError(new Error("Web Speech API not supported in this browser"));
    const rec = new Rec();
    rec.lang = "en-SG";
    rec.interimResults = false;
    rec.maxAlternatives = 1;
    rec.onresult = (e) => onText(e.results[0][0].transcript, "webspeech");
    rec.onerror = (e) => onError(new Error("speech recognition: " + e.error));
    rec.onend = () => onState("idle");
    onState("listening");
    rec.start();
    return rec;
  }

  /* ---------- tier 1: record, then POST to our backend ---------- */
  async function recordAndUpload({ onText, onError, onState, onFallback }) {
    let stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch (e) {
      return onError(new Error("microphone permission denied"));
    }
    chunks = [];
    // Ask for a container the upstream ASR actually documents, best first.
    // Chrome's default is audio/webm;codecs=opus, which shares a codec but NOT
    // a container with the documented ogg-opus and is rejected upstream. This
    // is the single likeliest first-live-call failure, so we express a
    // preference instead of taking whatever the browser picks.
    mediaRecorder = new MediaRecorder(stream, pickRecorderOptions());
    mediaRecorder.ondataavailable = (e) => e.data.size && chunks.push(e.data);
    mediaRecorder.onstop = async () => {
      stream.getTracks().forEach((t) => t.stop());
      onState("thinking");
      const blob = new Blob(chunks, { type: mediaRecorder.mimeType });
      const fd = new FormData();
      fd.append("audio", blob, "utterance");
      // Tell the server what we ACTUALLY recorded rather than letting it assume
      // its configured default. Previously nothing sent this, so webm audio was
      // forwarded labelled "mp3" — the mislabelling the whole three-tier
      // fallback exists to avoid guessing about.
      const fmt = voiceFormatOf(mediaRecorder.mimeType);
      const url = "/api/transcribe" + (fmt ? "?fmt=" + encodeURIComponent(fmt) : "");
      try {
        const r = await fetch(url, { method: "POST", body: fd });
        if (r.status === 503 || r.status === 415 || r.status === 413) {
          // Designed degradation: no server-side ASR configured (503), a
          // container it cannot forward (415), or too much audio (413). All
          // three mean "this tier cannot serve this request" -> drop a tier.
          const body = await r.json().catch(() => ({}));
          return onFallback(body?.detail?.error || "server ASR unavailable");
        }
        if (!r.ok) return onError(new Error("transcription failed: " + r.status));
        const { transcript, provider } = await r.json();
        onText(transcript, provider);
      } catch (e) {
        onError(e);
      }
    };
    onState("listening");
    mediaRecorder.start();
    return mediaRecorder;
  }

  function stop() {
    if (mediaRecorder && mediaRecorder.state === "recording") mediaRecorder.stop();
  }

  /* ---------- speak (clarifying questions) ---------- */
  function speak(text) {
    try {
      if (!window.speechSynthesis) return;
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.lang = "en-SG";
      window.speechSynthesis.speak(u);
    } catch (_) {
      /* speaking is an enhancement; never let it break the flow */
    }
  }

  return { listenWebSpeech, recordAndUpload, stop, speak, speechRecognitionAvailable,
           voiceFormatOf, pickRecorderOptions };
})();
