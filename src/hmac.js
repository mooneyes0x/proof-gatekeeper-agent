'use strict';
/**
 * HMAC-SHA256 helpers for the Agent Games platform.
 *
 * The platform signs every incoming request with:
 *   x-agent-games-signature: <hmac-sha256-hex of the RAW request body>
 * using the secret issued at agent registration (Rotate Secret in the
 * dashboard), which the operator stores in AGENT_GAMES_HMAC_SECRET.
 *
 * Every response we send must be signed the same way over the RAW
 * response body, in the x-agent-games-signature header.
 *
 * The secret is NEVER hardcoded, logged, or committed. It comes only
 * from the environment.
 */
const crypto = require('node:crypto');

function getSecret() {
  return process.env.AGENT_GAMES_HMAC_SECRET || '';
}

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

/** Sign a raw response body. Returns the hex signature. */
function signResponse(rawBody) {
  const secret = getSecret();
  if (!secret) return null;
  return hmacHex(secret, rawBody);
}

/**
 * Verify an incoming signature against the raw body.
 * Returns { ok: boolean, reason: string }.
 * Uses timingSafeEqual so the comparison is not timing-oracleable.
 */
function verifySignature(rawBody, signatureHeader) {
  const secret = getSecret();
  if (!secret) {
    return { ok: false, reason: 'server has no AGENT_GAMES_HMAC_SECRET configured' };
  }
  if (!signatureHeader || typeof signatureHeader !== 'string') {
    return { ok: false, reason: 'missing x-agent-games-signature header' };
  }
  const provided = signatureHeader.trim().toLowerCase();
  // Accept both bare hex and "sha256=<hex>" forms.
  const hex = provided.startsWith('sha256=') ? provided.slice(7) : provided;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    return { ok: false, reason: 'malformed x-agent-games-signature header' };
  }
  const expected = hmacHex(secret, rawBody);
  let ok = false;
  try {
    ok = crypto.timingSafeEqual(Buffer.from(hex, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    ok = false;
  }
  return ok ? { ok: true, reason: '' } : { ok: false, reason: 'signature mismatch' };
}

module.exports = { getSecret, hmacHex, signResponse, verifySignature };
