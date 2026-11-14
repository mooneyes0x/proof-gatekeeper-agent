'use strict';
/**
 * Proof Gatekeeper live agent — HTTP server (Node.js built-ins only).
 *
 * Endpoints:
 *   POST /agent     — signed task envelope, returns decision + reason_code
 *   POST /preflight — signed preflight, returns { ok: true, protocolVersion: "v1" }
 *   GET  /health    — unsigned liveness check (for the operator / deploy probe)
 *   GET  /          — unsigned info page
 *
 * Security order on every signed endpoint:
 *   1. Read the RAW body (no parsing first).
 *   2. Verify x-agent-games-signature (HMAC-SHA256 over the raw body).
 *   3. Only then JSON-parse. Reject malformed/unsigned/expired requests.
 *   4. Decide (see src/decide.js) and fail closed (REJECT) on any doubt.
 *   5. Sign the RAW response body with x-agent-games-signature.
 *   6. Answer well inside the 60s window (watchdog at 50s -> fail-closed REJECT).
 *
 * Env:
 *   PORT (default 3000), HOST (default 0.0.0.0)
 *   AGENT_GAMES_HMAC_SECRET (required in production; server refuses signed
 *     traffic without it — fail closed, never accept unsigned in production)
 *   ALLOW_UNSIGNED=1 (local dev only: accept requests without a valid
 *     signature, clearly logged; NEVER set in production)
 *   SEEN_FILE (default ./data/seen.json) — persisted proof_reference seen-set
 *   KURIER_API_KEY (optional) — submit own proof via Kurier, see src/proof.js
 *   CIRCUIT_INPUTS_JSON (optional) — circuit signal mapping, see src/proof.js
 *   CURRENT_BLOCK (optional) — fallback current block number for expiry checks
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { verifySignature, signResponse, getSecret } = require('./hmac');
const { decide, SeenSet } = require('./decide');
const { generateProof, submitViaKurier } = require('./proof');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const ALLOW_UNSIGNED = process.env.ALLOW_UNSIGNED === '1';
const DECISION_TIMEOUT_MS = 50000; // hard watchdog inside the 60s window

const seenFile = process.env.SEEN_FILE || path.join(__dirname, '..', 'data', 'seen.json');
try { fs.mkdirSync(path.dirname(seenFile), { recursive: true }); } catch { /* best-effort */ }
const seenSet = new SeenSet(seenFile);

function log(...args) {
  // Never log request/response bodies or secrets — only ids and outcomes.
  console.log(new Date().toISOString(), ...args);
}

/** Send a JSON response, HMAC-signed over the raw body. */
function sendJson(res, statusCode, obj) {
  const raw = JSON.stringify(obj);
  const sig = signResponse(raw);
  res.writeHead(statusCode, {
    'content-type': 'application/json',
    ...(sig ? { 'x-agent-games-signature': sig } : {}),
  });
  res.end(raw);
}

function readRawBody(req, limitBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limitBytes) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Check an envelope timestamp if one is present (reject stale/future). */
function timestampCheck(task) {
  const ts = task.timestamp ?? task.signed_at ?? task.signedAt ?? task.issued_at;
  if (ts === undefined || ts === null) return null; // no timestamp supplied: nothing to check
  const ms = typeof ts === 'number' ? (ts > 1e12 ? ts : ts * 1000) : Date.parse(String(ts));
  if (!Number.isFinite(ms)) return 'unparseable task timestamp';
  const now = Date.now();
  if (ms < now - 5 * 60 * 1000) return 'task timestamp too old (>5 min)';
  if (ms > now + 60 * 1000) return 'task timestamp in the future';
  return null;
}

async function handlePreflight(rawBody, req, res) {
  if (!getSecret() && !ALLOW_UNSIGNED) {
    return sendJson(res, 500, { ok: false, error: 'server misconfigured: AGENT_GAMES_HMAC_SECRET not set' });
  }
  const sig = req.headers['x-agent-games-signature'];
  const check = verifySignature(rawBody, sig);
  if (!check.ok && !ALLOW_UNSIGNED) {
    log('[preflight] rejected:', check.reason);
    return sendJson(res, 401, { ok: false, error: `unauthorized: ${check.reason}` });
  }
  if (!check.ok) log('[preflight] WARNING: accepted unsigned request (ALLOW_UNSIGNED=1, dev only)');
  let body = {};
  try { body = rawBody.length ? JSON.parse(rawBody.toString('utf8')) : {}; } catch {
    return sendJson(res, 400, { ok: false, error: 'malformed JSON' });
  }
  if (body.type && body.type !== 'agent-games.preflight.v1') {
    log('[preflight] unexpected type:', body.type);
  }
  log('[preflight] ok');
  return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
}

async function handleAgent(rawBody, req, res) {
  const started = Date.now();
  if (!getSecret() && !ALLOW_UNSIGNED) {
    return sendJson(res, 500, { ok: false, error: 'server misconfigured: AGENT_GAMES_HMAC_SECRET not set' });
  }
  const sig = req.headers['x-agent-games-signature'];
  const check = verifySignature(rawBody, sig);
  if (!check.ok && !ALLOW_UNSIGNED) {
    log('[agent] rejected:', check.reason);
    return sendJson(res, 401, { ok: false, error: `unauthorized: ${check.reason}` });
  }
  if (!check.ok) log('[agent] WARNING: accepted unsigned request (ALLOW_UNSIGNED=1, dev only)');

  let task;
  try {
    task = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return sendJson(res, 400, { ok: false, error: 'malformed JSON' });
  }
  const taskId = task.task_id || task.taskId || task.id || 'unknown';
  const mode = task.mode || 'competition';

  // Timestamp freshness, when the envelope carries one.
  const tsProblem = timestampCheck(task);
  if (tsProblem) {
    log(`[agent] ${taskId} rejected: ${tsProblem}`);
    return sendJson(res, 200, { task_id: taskId, decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', detail: tsProblem });
  }

  // Decide with a hard watchdog so we always answer inside 60s, fail closed.
  const decisionPromise = (async () => {
    const decision = decide(task, seenSet, {
      currentBlock: process.env.CURRENT_BLOCK ? Number(process.env.CURRENT_BLOCK) : undefined,
    });
    let proofInfo = { status: 'SKIPPED', proof: null, reason: 'proof only required for APPROVE decisions' };
    let proofTx = null;
    if (decision.decision === 'APPROVE') {
      proofInfo = await generateProof(task, decision);
      if (proofInfo.status === 'PROVEN' && process.env.KURIER_API_KEY) {
        const sub = await submitViaKurier(proofInfo.proof, proofInfo.publicSignals, { idempotencyKey: `gk-${taskId}` });
        if (sub.status === 'FINALIZED') proofTx = sub.proof_tx;
        else log(`[agent] ${taskId} Kurier ${sub.status}: ${sub.reason || ''}`);
      }
    }
    return { decision, proofInfo, proofTx };
  })();

  const timeoutPromise = new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), DECISION_TIMEOUT_MS));
  const result = await Promise.race([decisionPromise, timeoutPromise]);

  const ms = Date.now() - started;
  if (result.timedOut) {
    log(`[agent] ${taskId} TIMEOUT after ${ms}ms -> fail closed REJECT`);
    return sendJson(res, 200, { task_id: taskId, decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', detail: 'decision timed out, fail closed' });
  }

  const { decision, proofInfo, proofTx } = result;
  log(`[agent] ${taskId} mode=${mode} ${decision.decision}/${decision.reason_code} proof=${proofInfo.status} ${ms}ms`);

  const response = {
    task_id: taskId,
    decision: decision.decision,
    reason_code: decision.reason_code,
    detail: decision.detail,
    ...(proofInfo.proof ? { proof: proofInfo.proof, public_signals: proofInfo.publicSignals } : {}),
    ...(proofTx ? { proof_tx: proofTx } : {}),
    ...(proofInfo.status === 'NOT_IMPLEMENTED' ? { proof_status: 'NOT_IMPLEMENTED', proof_note: proofInfo.reason } : {}),
  };
  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, { ok: true, uptime_s: Math.floor(process.uptime()), seen_proof_references: seenSet.size(), hmac_configured: Boolean(getSecret()) });
    }
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('Proof Gatekeeper agent (zkVerify Agent Games) — POST /agent and POST /preflight. See README.md.\n');
    }
    if (req.method === 'POST' && url.pathname === '/preflight') {
      const raw = await readRawBody(req);
      return handlePreflight(raw, req, res);
    }
    if (req.method === 'POST' && url.pathname === '/agent') {
      const raw = await readRawBody(req);
      return handleAgent(raw, req, res);
    }
    return sendJson(res, 404, { ok: false, error: 'not found' });
  } catch (err) {
    log('[server] error:', err.message);
    if (!res.headersSent) return sendJson(res, 500, { ok: false, error: 'internal error' });
    return res.end();
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    log(`Proof Gatekeeper agent listening on http://${HOST}:${PORT}`);
    log(`HMAC secret configured: ${Boolean(getSecret())} (ALLOW_UNSIGNED=${ALLOW_UNSIGNED})`);
    log(`Seen-set: ${seenSet.size()} proof references loaded`);
  });
}

module.exports = { server, handleAgent, handlePreflight };
