'use strict';
/**
 * Own-proof generation (Groth16/BN128, Circom 2.x, snarkjs) and optional
 * zkVerify submission via Kurier.
 *
 * HONEST STATUS (verified 15 Nov 2026):
 * - Circuit artifacts are downloaded and present in ./circuits/:
 *   gatekeeper.wasm (1.7 MB), gatekeeper_final.zkey (303 KB),
 *   vfy-policy.wasm, vfy-policy_final.zkey.
 * - `snarkjs zkey export verificationkey` works: gatekeeper is Groth16/BN128
 *   with nPublic = 13. The exported key is saved as circuits/gatekeeper_vk.json
 *   and its vkHash matches the platform value 0x6b79c6...bad77b0 (see README).
 * - What is BLOCKING a valid proof: the platform publishes only the .wasm and
 *   .zkey files. It does NOT publish the .circom source, the .sym file, or the
 *   witness-calculator JS, so the input signal NAMES and their ORDER (the 13
 *   public inputs) are not publicly known. snarkjs fullProve() needs those
 *   names — without them no valid proof can be generated, and a guessed proof
 *   would be rejected by the platform's re-verification.
 *   The /build and /guide pages show truncated code examples; neither page
 *   lists the circuit's input signals.
 * - Therefore generateProof() works like this:
 *   1. If the operator supplies the signal mapping (env CIRCUIT_INPUTS_JSON
 *      or a file circuits/gatekeeper_inputs.json mapping task fields to the
 *      circuit's input signals, e.g. from the platform or the circuit author),
 *      it calls snarkjs groth16.fullProve() with real inputs and returns the
 *      proof + public signals.
 *   2. Otherwise it returns { proof: null, status: 'NOT_IMPLEMENTED', ... }
 *      with the exact reason, and the server answers the task WITHOUT a proof
 *      rather than with a fake one. The decision itself is still correct; on
 *      provable tasks that costs -2 (missing/invalid proof), which is cheaper
 *      than an incorrect APPROVE (-6) and honest.
 * - Kurier submission only runs when a real proof exists AND a KURIER_API_KEY
 *   is set. It polls until Finalized and never returns IncludedInBlock /
 *   Submitted as confirmed.
 */
const fs = require('node:fs');
const path = require('node:path');

const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');
const GATEKEEPER_WASM = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const GATEKEEPER_ZKEY = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const GATEKEEPER_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function artifactsPresent() {
  return fs.existsSync(GATEKEEPER_WASM) && fs.existsSync(GATEKEEPER_ZKEY);
}

/** Load the operator-supplied signal mapping, if any. */
function loadInputMapping() {
  const fromEnv = process.env.CIRCUIT_INPUTS_JSON;
  if (fromEnv) {
    try { return JSON.parse(fromEnv); } catch { return null; }
  }
  const file = path.join(CIRCUITS_DIR, 'gatekeeper_inputs.json');
  if (fs.existsSync(file)) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
  }
  return null;
}

/**
 * Attempt to generate the agent's own Groth16 proof for an APPROVED task.
 * `inputs` is the object of circuit input signals (only used when a mapping
 * is supplied). Returns a promise resolving to:
 *   { status: 'PROVEN', proof, publicSignals }
 *   { status: 'NOT_IMPLEMENTED', proof: null, reason }
 *   { status: 'FAILED', proof: null, reason }
 */
async function generateProof(task, decision) {
  if (decision.decision !== 'APPROVE') {
    // The platform only requires a proof on provable (approved) tasks.
    return { status: 'SKIPPED', proof: null, reason: 'proof only required for APPROVE decisions' };
  }
  if (!artifactsPresent()) {
    return { status: 'NOT_IMPLEMENTED', proof: null, reason: 'circuit artifacts missing from ./circuits/ — run npm run download-circuits' };
  }
  const mapping = loadInputMapping();
  if (!mapping) {
    return {
      status: 'NOT_IMPLEMENTED',
      proof: null,
      reason: 'circuit input signal mapping not published: the platform ships only gatekeeper.wasm + gatekeeper_final.zkey (Groth16/BN128, nPublic=13) and does not publish the .circom source, .sym file, or witness-calculator JS, so the 13 public-input signal names/order are unknown. Supply them via CIRCUIT_INPUTS_JSON or circuits/gatekeeper_inputs.json to enable proving. No fake proof is returned.',
    };
  }
  try {
    const snarkjs = require('snarkjs');
    const input = typeof mapping === 'function' ? mapping(task, decision) : mapping;
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, GATEKEEPER_WASM, GATEKEEPER_ZKEY);
    return { status: 'PROVEN', proof, publicSignals };
  } catch (err) {
    return { status: 'FAILED', proof: null, reason: `snarkjs fullProve failed: ${err.message}` };
  }
}

/**
 * Submit a Groth16 proof to zkVerify via Kurier and poll until Finalized.
 * Only call with a real proof and a KURIER_API_KEY. Returns
 * { status: 'FINALIZED', proof_tx } or { status, reason }.
 * Never returns Submitted/IncludedInBlock as confirmed.
 */
async function submitViaKurier(proof, publicSignals, opts = {}) {
  const apiKey = process.env.KURIER_API_KEY;
  if (!apiKey) return { status: 'SKIPPED', reason: 'KURIER_API_KEY not set' };
  if (!proof) return { status: 'SKIPPED', reason: 'no proof to submit' };
  const timeoutMs = opts.timeoutMs ?? 55000; // must fit inside the 60s window
  const started = Date.now();
  try {
    const submitRes = await fetch(`https://api.kurier.xyz/api/v1/submit-proof/${apiKey}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        proofType: 'groth16',
        vkHash: GATEKEEPER_VK_HASH,
        proof,
        publicSignals,
        idempotencyKey: opts.idempotencyKey || `gk-${Date.now()}`,
      }),
      signal: AbortSignal.timeout(Math.min(timeoutMs, 20000)),
    });
    if (!submitRes.ok) {
      return { status: 'FAILED', reason: `Kurier submit HTTP ${submitRes.status}` };
    }
    const submit = await submitRes.json();
    const jobId = submit.jobId || submit.id;
    if (!jobId) return { status: 'FAILED', reason: 'Kurier gave no job id' };
    // Poll for Finalized.
    for (;;) {
      if (Date.now() - started > timeoutMs) {
        return { status: 'TIMEOUT', reason: 'Kurier did not reach Finalized within the decision window' };
      }
      await new Promise((r) => setTimeout(r, 3000));
      const stRes = await fetch(`https://api.kurier.xyz/api/v1/job/${jobId}`, {
        headers: { 'x-api-key': apiKey },
        signal: AbortSignal.timeout(10000),
      });
      if (!stRes.ok) continue;
      const st = await stRes.json();
      const status = String(st.status || st.state || '').toLowerCase();
      if (status === 'finalized') {
        return { status: 'FINALIZED', proof_tx: st.proofTx || st.txHash || st.proof_tx || jobId };
      }
      if (status === 'failed' || status === 'error') {
        return { status: 'FAILED', reason: `Kurier job ${status}` };
      }
      // Submitted / IncludedInBlock: keep polling, never return as confirmed.
    }
  } catch (err) {
    return { status: 'FAILED', reason: `Kurier error: ${err.message}` };
  }
}

module.exports = { generateProof, submitViaKurier, artifactsPresent, GATEKEEPER_VK_HASH };
