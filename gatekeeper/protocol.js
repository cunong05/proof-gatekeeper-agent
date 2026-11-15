// HMAC helpers for Proof Gatekeeper.
// Sources: https://agentgames.zkverify.io/rules (1.3) and
// https://agentgames.zkverify.io/build (sections 02, 05)
//
// The platform signs every task delivery with `x-agent-games-signature`
// (HMAC-SHA256 over the RAW request body, 32-byte secret shown once at
// registration) and the agent signs every response the same way. Verify
// the header BEFORE parsing the body; a bad signature means the request
// did not come from the platform.
"use strict";

const crypto = require("node:crypto");

function hmacSha256Hex(secret, body) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), "utf8");
  return crypto.createHmac("sha256", secret).update(buf).digest("hex");
}

// Sign a response body. Format "hex" (default) or "sha256=" prefix —
// switch with AGENT_GAMES_HMAC_FORMAT if the platform rejects preflight.
function signBody(body, secret, format = "hex") {
  const hex = hmacSha256Hex(secret, body);
  return format === "sha256=" ? `sha256=${hex}` : hex;
}

// Constant-time comparison of two hex signatures (tolerates the optional
// "sha256=" prefix on either side).
function timingSafeEqualHex(a, b) {
  const norm = (s) => String(s || "").replace(/^sha256=/, "").toLowerCase();
  const x = Buffer.from(norm(a), "utf8");
  const y = Buffer.from(norm(b), "utf8");
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

function verifyHmac(rawBody, signature, secret, format = "hex") {
  if (!secret || !signature) return false;
  return timingSafeEqualHex(signature, signBody(rawBody, secret, format));
}

module.exports = { hmacSha256Hex, signBody, timingSafeEqualHex, verifyHmac };
