'use strict';
/**
 * Proof Gatekeeper decision logic.
 *
 * Task envelope (from /build and /events/proof-gatekeeper):
 *   type: "agent-games.proof-gatekeeper.v1"
 *   task_id, mode ("competition" | "practice"), deadline (epoch ms or ISO),
 *   statement / input / payload containing:
 *     proof / proof_vk / verification_key_hash   — the VK of the payer's proof
 *     registered_vk / registered_verification_key_hash — the VK on record
 *     minimum / threshold                        — minimum public balance required
 *     public_balance / balance                   — payer's public balance
 *     recipient / expected_recipient / condition_address
 *     amount, max_transfer
 *     expiry / expiry_block / expires_at         — condition expiry
 *     proof_reference / proof_ref                — idempotency / replay guard
 *
 * The platform's pages do not publish one canonical JSON schema (the code
 * examples on /build and /guide are truncated in the public text), so the
 * extractor below looks in every documented location for each field. If a
 * required field is absent, the decision FAILS CLOSED (REJECT) instead of
 * guessing — an unprovable task must never be approved.
 *
 * Checks, in order. One mismatch = REJECT (first mismatch wins, because
 * the platform's example tasks isolate a single trap each):
 *   1. VK_SUBSTITUTION  — proof_vk !== registered_vk
 *   2. PROOF_REUSED     — proof_reference already seen (local seen-set)
 *   3. EXPIRED_CONDITION— now past expiry (block number or timestamp)
 *   4. RECIPIENT_MISMATCH — recipient !== expected recipient
 *   5. THRESHOLD_MISMATCH — public_balance < minimum
 *   6. AMOUNT_OVERFLOW  — amount > max_transfer
 *   else VALID_CONDITION — APPROVE
 *
 * Scoring (from the event page): correct APPROVE/REJECT +12,
 * incorrect APPROVE -6, incorrect REJECT -3, timeout -2,
 * missing/invalid own proof -2 on provable tasks.
 */
const fs = require('node:fs');
const path = require('node:path');

const REASON_CODES = [
  'VALID_CONDITION',
  'VK_SUBSTITUTION',
  'PROOF_REUSED',
  'THRESHOLD_MISMATCH',
  'EXPIRED_CONDITION',
  'RECIPIENT_MISMATCH',
  'AMOUNT_OVERFLOW',
];

/** Deep-collect candidate objects to search for a field (envelope, statement, input, payload, public_inputs, ...). */
function candidateObjects(task) {
  const out = [];
  const seen = new Set();
  const walk = (obj) => {
    if (!obj || typeof obj !== 'object' || seen.has(obj)) return;
    seen.add(obj);
    out.push(obj);
    for (const key of ['statement', 'input', 'payload', 'data', 'condition', 'public_inputs', 'publicInputs', 'proof_data']) {
      if (obj[key] && typeof obj[key] === 'object') walk(obj[key]);
    }
  };
  walk(task);
  return out;
}

function pick(task, ...names) {
  for (const obj of candidateObjects(task)) {
    for (const name of names) {
      if (obj[name] !== undefined && obj[name] !== null && obj[name] !== '') return obj[name];
    }
  }
  return undefined;
}

function toNumber(v) {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'string') {
    const n = v.startsWith('0x') ? parseInt(v, 16) : Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}

function normHex(v) {
  if (v === undefined || v === null) return undefined;
  return String(v).trim().toLowerCase();
}

function normAddr(v) {
  if (v === undefined || v === null) return undefined;
  return String(v).trim().toLowerCase();
}

/** Extract the fields the decision needs. Returns { fields, missing[] }. */
function extractFields(task) {
  const registeredVk = normHex(pick(task, 'registered_vk', 'registered_verification_key_hash', 'registeredVk', 'expected_vk', 'expected_verification_key_hash'));
  const proofVk = normHex(pick(task, 'proof_vk', 'verification_key_hash', 'proofVk', 'vk', 'vk_hash', 'vkHash'));
  const minimum = toNumber(pick(task, 'minimum', 'threshold', 'min_balance', 'minBalance'));
  const publicBalance = toNumber(pick(task, 'public_balance', 'balance', 'publicBalance'));
  const recipient = normAddr(pick(task, 'recipient', 'recipient_address', 'to', 'destination'));
  const expectedRecipient = normAddr(pick(task, 'expected_recipient', 'condition_address', 'expectedRecipient', 'conditionAddress', 'allowed_recipient'));
  const amount = toNumber(pick(task, 'amount', 'transfer_amount', 'value'));
  const maxTransfer = toNumber(pick(task, 'max_transfer', 'maxTransfer', 'max_amount'));
  const expiryBlock = toNumber(pick(task, 'expiry_block', 'expiryBlock', 'expires_block', 'expiry', 'expires_at_block'));
  const expiryTs = pick(task, 'expires_at', 'expiry_timestamp', 'deadline');
  const proofReference = pick(task, 'proof_reference', 'proof_ref', 'proofReference', 'proof_tx', 'proofTx');
  const currentBlock = toNumber(pick(task, 'current_block', 'currentBlock', 'block_number', 'blockNumber'));

  const fields = {
    registeredVk, proofVk, minimum, publicBalance,
    recipient, expectedRecipient, amount, maxTransfer,
    expiryBlock, expiryTs, proofReference, currentBlock,
  };
  const missing = [];
  if (registeredVk === undefined) missing.push('registered_vk');
  if (proofVk === undefined) missing.push('proof_vk');
  if (minimum === undefined) missing.push('minimum');
  if (publicBalance === undefined) missing.push('public_balance');
  if (proofReference === undefined) missing.push('proof_reference');
  return { fields, missing };
}

/** Parse an expiry value (epoch seconds, epoch ms, or ISO string) to ms. */
function expiryToMs(expiryTs) {
  if (expiryTs === undefined || expiryTs === null) return undefined;
  if (typeof expiryTs === 'number') return expiryTs > 1e12 ? expiryTs : expiryTs * 1000;
  const s = String(expiryTs).trim();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return n > 1e12 ? n : n * 1000;
  }
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : undefined;
}

/**
 * Seen-set for proof_reference replay protection.
 * In-memory, optionally persisted to disk (SEEN_FILE) so a restart does
 * not let a reused proof through. File I/O is best-effort and never
 * blocks the 60s decision window.
 */
class SeenSet {
  constructor(filePath) {
    this.set = new Set();
    this.filePath = filePath || null;
    if (this.filePath) {
      try {
        const raw = fs.readFileSync(this.filePath, 'utf8');
        for (const item of JSON.parse(raw)) this.set.add(String(item));
      } catch { /* first run / corrupt file: start empty */ }
    }
  }
  has(ref) { return this.set.has(String(ref)); }
  add(ref) {
    this.set.add(String(ref));
    if (!this.filePath) return;
    try {
      fs.writeFileSync(this.filePath, JSON.stringify([...this.set].slice(-10000)), 'utf8');
    } catch { /* best-effort only */ }
  }
  size() { return this.set.size; }
}

/**
 * Decide a task. Returns { decision: 'APPROVE'|'REJECT', reason_code, detail, fields }.
 * `nowMs` and `currentBlock` may be injected (tests); otherwise Date.now().
 * A task that cannot be checked (missing required fields, or an unparseable
 * expiry) is REJECTED — fail closed, never approve on uncertainty.
 */
function decide(task, seenSet, opts = {}) {
  const nowMs = opts.nowMs ?? Date.now();
  const { fields, missing } = extractFields(task);

  if (missing.length > 0) {
    // No INVALID_TASK reason code exists on the platform, so fail closed
    // with the closest documented code for the missing field.
    let reason_code = 'THRESHOLD_MISMATCH';
    if (missing.includes('registered_vk') || missing.includes('proof_vk')) reason_code = 'VK_SUBSTITUTION';
    else if (missing.includes('proof_reference')) reason_code = 'PROOF_REUSED';
    return {
      decision: 'REJECT',
      reason_code,
      detail: `fail closed: required field(s) missing or unparseable: ${missing.join(', ')}`,
      fields,
    };
  }

  // 1. VK must match the registered key exactly.
  if (fields.proofVk !== fields.registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', detail: 'proof_vk does not match registered_vk', fields };
  }

  // 2. Proof reference must not have been used before.
  const ref = String(fields.proofReference);
  if (seenSet && seenSet.has(ref)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', detail: `proof_reference already seen: ${ref}`, fields };
  }

  // 3. Condition must not be expired (block number wins if both given).
  if (fields.expiryBlock !== undefined) {
    const cur = fields.currentBlock ?? opts.currentBlock;
    if (cur !== undefined && cur > fields.expiryBlock) {
      return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', detail: `current block ${cur} > expiry block ${fields.expiryBlock}`, fields };
    }
    // Without a current block we cannot prove expiry by block; fall through
    // to the timestamp check, and if neither is checkable, do NOT reject on
    // this rule alone (the field was present but unverifiable).
  }
  if (fields.expiryTs !== undefined) {
    const expMs = expiryToMs(fields.expiryTs);
    if (expMs !== undefined && nowMs > expMs) {
      return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', detail: `now ${new Date(nowMs).toISOString()} past expiry ${new Date(expMs).toISOString()}`, fields };
    }
  }
  // Also honour a task-level deadline that has already passed.
  const deadlineMs = expiryToMs(task.deadline);
  if (deadlineMs !== undefined && nowMs > deadlineMs) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', detail: 'task deadline already passed', fields };
  }

  // 4. Recipient must match the condition address (when one is stated).
  if (fields.expectedRecipient !== undefined && fields.recipient !== undefined
      && fields.recipient !== fields.expectedRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', detail: `recipient ${fields.recipient} != expected ${fields.expectedRecipient}`, fields };
  }

  // 5. Public balance must be >= minimum.
  if (fields.publicBalance < fields.minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', detail: `public_balance ${fields.publicBalance} < minimum ${fields.minimum}`, fields };
  }

  // 6. Amount must be <= max_transfer (when both are stated).
  if (fields.amount !== undefined && fields.maxTransfer !== undefined && fields.amount > fields.maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', detail: `amount ${fields.amount} > max_transfer ${fields.maxTransfer}`, fields };
  }

  // All checks passed: record the proof reference BEFORE approving so a
  // retry of the same task is caught as PROOF_REUSED.
  if (seenSet) seenSet.add(ref);
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', detail: 'all checks passed', fields };
}

module.exports = { decide, extractFields, SeenSet, REASON_CODES, expiryToMs };
