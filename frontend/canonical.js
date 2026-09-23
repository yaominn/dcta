/*
 * DCTA — JS canonical JSON serializer.
 *
 * MUST produce a byte-for-byte identical string to Python's
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 *
 * That is: recursive key sort (by Unicode code point), no whitespace, and raw
 * UTF-8 for non-ASCII characters (NO \uXXXX escaping). Unicode-escaping is
 * exactly where two independent canonicalizers drift, so non-ASCII test data
 * (accented + CJK) is the acceptance test — ASCII-only data would never
 * surface a divergence.
 *
 * Why this file exists (brief 4.5 + the M2 binding constraint): the browser
 * recomputes payload_hash ITSELF, from the SAME ResolvedPlan object it
 * rendered into the confirmation overlay. The server independently recomputes
 * the same hash and verifies the WebAuthn signature was over that hash. A
 * divergence between what was displayed and what was signed then becomes
 * impossible rather than unlikely — "what you see is what you sign" is a
 * property of the system, not a convention between two pieces of our own code
 * that a bug or XSS in the overlay could silently break.
 *
 * This is only achievable because money is int cents (L2): integers serialize
 * identically in Python and JS, where the old 2-decimal floats would not have.
 *
 * Works in the browser (no dependencies) and in Node (for the cross-language
 * acceptance test) via a UMD-ish guard.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.canonicalJson = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function canonicalString(s) {
    // Match Python json.dumps(ensure_ascii=False): escape ", \ and the JSON
    // control chars; emit everything else RAW (including non-ASCII / CJK /
    // astral, as their UTF-8 bytes at hash time — never \uXXXX).
    var out = '"';
    // for..of iterates by code point, so astral chars (emoji) are one unit —
    // matching Python's iteration over str code points.
    for (var ch of s) {
      var cp = ch.codePointAt(0);
      if (ch === '"') out += '\\"';
      else if (ch === "\\") out += "\\\\";
      else if (cp === 0x08) out += "\\b";
      else if (cp === 0x09) out += "\\t";
      else if (cp === 0x0a) out += "\\n";
      else if (cp === 0x0c) out += "\\f";
      else if (cp === 0x0d) out += "\\r";
      else if (cp < 0x20) out += "\\u" + cp.toString(16).padStart(4, "0");
      else out += ch;
    }
    return out + '"';
  }

  function canonicalJson(value) {
    if (value === null || value === undefined) return "null";
    var t = typeof value;
    if (t === "number") {
      // Mirrors Python's canonical_json, which RAISES on any float: money is
      // int cents, and a float in a signed payload would reintroduce the L2
      // hash-collision class of bug. Reject here so the divergence is caught
      // client-side, at canonicalization, not silently.
      if (!Number.isFinite(value))
        throw new Error("non-finite number in canonical payload");
      if (!Number.isInteger(value))
        throw new Error("float in canonical payload: money must be int cents");
      return String(value); // integer -> base-10, matches Python str(int)
    }
    if (t === "boolean") return value ? "true" : "false";
    if (t === "string") return canonicalString(value);
    if (Array.isArray(value))
      return "[" + value.map(canonicalJson).join(",") + "]";
    if (t === "object") {
      // sort_keys=True. Our schema keys are ASCII, where JS default sort
      // (UTF-16 code unit) agrees with Python (code point) sort. A
      // locale-independent comparator keeps it correct if non-ASCII keys are
      // ever added.
      var keys = Object.keys(value).sort(function (a, b) {
        return a < b ? -1 : a > b ? 1 : 0;
      });
      return (
        "{" +
        keys
          .map(function (k) {
            return canonicalString(k) + ":" + canonicalJson(value[k]);
          })
          .join(",") +
        "}"
      );
    }
    throw new Error("unsupported type in canonical payload: " + t);
  }

  return canonicalJson;
});
