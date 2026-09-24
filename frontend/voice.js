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
    mediaRecorder = new MediaRecorder(stream);
    mediaRecorder.ondataavailable = (e) => e.data.size && chunks.push(e.data);
    mediaRecorder.onstop = async () => {
      stream.getTracks().forEach((t) => t.stop());
      onState("thinking");
      const blob = new Blob(chunks, { type: mediaRecorder.mimeType });
      const fd = new FormData();
      fd.append("audio", blob, "utterance");
      try {
        const r = await fetch("/api/transcribe", { method: "POST", body: fd });
        if (r.status === 503) {
          // Designed degradation: no server-side ASR configured. Drop a tier.
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

  return { listenWebSpeech, recordAndUpload, stop, speak, speechRecognitionAvailable };
})();
