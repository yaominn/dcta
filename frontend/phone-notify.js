/* MOCK: the demo phone's notifications, shown on the assistant page so the
   demo needs one window, not two.

   This is the SIMULATED PHONE drawing over the assistant, not the assistant
   reading its own code: it polls the phone's inbox (/api/phone/messages), the
   same mock endpoint /phone renders. app.js never calls it, and no draft or
   confirm response carries the code. A deployment sends a real SMS or push
   notification and this file goes away; nothing else changes. */
(function () {
  "use strict";
  const INBOX = "/api/phone/messages?user_id=u_alice";
  const SHOW_MS = 6000;      // like an iPhone banner; tap it to open the full text
  const LINGER_MS = 2500;    // after the pointer leaves it
  let seen = null;           // message keys already delivered; null = first poll
  let hideTimer = null;

  const key = (m) => m.sent_at + "|" + m.text;

  // Text only: split around the code so it can be bold without ever parsing
  // server text as HTML (same approach as phone.html).
  function body(text) {
    const p = document.createElement("p");
    p.className = "sms-banner-text";
    const m = /^(.*?code )(\d{6})(.*)$/s.exec(text);
    if (m) {
      const b = document.createElement("b");
      b.className = "sms-banner-code";
      b.textContent = m[2];
      p.append(document.createTextNode(m[1]), b, document.createTextNode(m[3]));
    } else {
      p.textContent = text;
    }
    return p;
  }

  function hide(n) {
    clearTimeout(hideTimer);
    n.classList.remove("show");
    hideTimer = setTimeout(() => { n.hidden = true; }, 320);
  }

  function show(msg) {
    const n = document.getElementById("sms-banner");
    if (!n) return;
    clearTimeout(hideTimer);
    const icon = document.createElement("span");
    icon.className = "sms-banner-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = "💬";
    const head = document.createElement("p");
    head.className = "sms-banner-head";
    const app = document.createElement("span");
    app.textContent = "MESSAGES";
    const when = document.createElement("span");
    when.textContent = "now";
    head.append(app, when);
    const from = document.createElement("p");
    from.className = "sms-banner-from";
    from.textContent = "DCTA Bank";
    const main = document.createElement("div");
    main.className = "sms-banner-main";
    main.append(head, from, body(msg.text));
    n.replaceChildren(icon, main);
    n.hidden = false;
    requestAnimationFrame(() => n.classList.add("show"));
    // Tapping a notification opens the app it came from: the demo phone, in
    // its own tab (the same one the "Open the demo phone" link uses), so the
    // draft waiting on this page is not navigated away from.
    n.onclick = () => { hide(n); window.open("/phone", "dcta-phone"); };
    n.title = "Open in Messages";
    // Holding the pointer over it keeps it up, so a presenter can read it out.
    n.onmouseenter = () => clearTimeout(hideTimer);
    n.onmouseleave = () => { clearTimeout(hideTimer); hideTimer = setTimeout(() => hide(n), LINGER_MS); };
    hideTimer = setTimeout(() => hide(n), SHOW_MS);
  }

  async function poll() {
    try {
      const r = await fetch(INBOX);
      if (!r.ok) return;
      const msgs = (await r.json()).messages || [];      // newest first
      if (seen === null) {                                // don't replay old texts on load
        seen = new Set(msgs.map(key));
        return;
      }
      const fresh = msgs.filter((m) => !seen.has(key(m)));
      fresh.forEach((m) => seen.add(key(m)));
      if (fresh.length) show(fresh[0]);
    } catch (e) { /* server restarting; try again next tick */ }
  }

  poll();
  setInterval(poll, 1500);
})();
