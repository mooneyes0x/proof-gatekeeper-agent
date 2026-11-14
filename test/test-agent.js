'use strict';
/**
 * Local tests for the Proof Gatekeeper agent. No test framework needed.
 * Starts the server on a scratch port with a TEST HMAC secret, then:
 *   1. Preflight (valid signature)            -> { ok: true, protocolVersion: "v1" }
 *   2. Preflight (bad signature)              -> 401
 *   3. Preflight (no signature)               -> 401
 *   4. Task VALID_CONDITION                   -> APPROVE / VALID_CONDITION
 *   5. Task VK_SUBSTITUTION                   -> REJECT / VK_SUBSTITUTION
 *   6. Task THRESHOLD_MISMATCH                -> REJECT / THRESHOLD_MISMATCH
 *   7. Task PROOF_REUSED (same ref as #4)     -> REJECT / PROOF_REUSED
 *   8. Task RECIPIENT_MISMATCH                -> REJECT / RECIPIENT_MISMATCH
 *   9. Task AMOUNT_OVERFLOW                   -> REJECT / AMOUNT_OVERFLOW
 *  10. Task EXPIRED_CONDITION (past deadline) -> REJECT / EXPIRED_CONDITION
 *  11. Unsigned task                          -> 401
 *  12. Health endpoint                        -> ok
 *
 * Run:  npm test
 * The test uses its own SEEN_FILE in a temp dir so it never touches the
 * real seen-set.
 */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.AGENT_GAMES_HMAC_SECRET = 'test-secret-do-not-use-in-production';
process.env.PORT = '0'; // ephemeral port
process.env.SEEN_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'gk-test-')), 'seen.json');

const { server } = require('../src/server');

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
let failures = 0;

function sign(raw) {
  return crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
}

function post(port, pathName, obj, { signature = 'valid' } = {}) {
  const raw = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) };
  if (signature === 'valid') headers['x-agent-games-signature'] = sign(raw);
  else if (signature === 'bad') headers['x-agent-games-signature'] = '0'.repeat(64);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: pathName, method: 'POST', headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data ? JSON.parse(data) : null }));
    });
    req.on('error', reject);
    req.end(raw);
  });
}

function get(port, pathName) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: pathName }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }));
    }).on('error', reject);
  });
}

function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ` — ${extra}` : ''}`);
  if (!cond) failures += 1;
}

function checkResponseSignature(res, rawCheck) {
  const sig = res.headers['x-agent-games-signature'];
  if (!sig) return false;
  return sig.length === 64;
}

const BASE = {
  type: 'agent-games.proof-gatekeeper.v1',
  mode: 'competition',
  statement: {
    registered_vk: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    proof_vk: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    minimum: 1000,
    public_balance: 1460,
    recipient: '0x1111111111111111111111111111111111111111',
    expected_recipient: '0x1111111111111111111111111111111111111111',
    amount: 500,
    max_transfer: 1000,
    proof_reference: 'ref-valid-001',
  },
};

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  console.log(`test server on 127.0.0.1:${port}`);

  // 1. Preflight, valid signature
  let r = await post(port, '/preflight', { type: 'agent-games.preflight.v1' });
  check('1. preflight valid -> 200 {ok:true, protocolVersion:v1}', r.status === 200 && r.body.ok === true && r.body.protocolVersion === 'v1', JSON.stringify(r.body));
  check('   preflight response is HMAC-signed', checkResponseSignature(r));

  // 2-3. Preflight, bad / missing signature
  r = await post(port, '/preflight', { type: 'agent-games.preflight.v1' }, { signature: 'bad' });
  check('2. preflight bad signature -> 401', r.status === 401, `status=${r.status}`);
  r = await post(port, '/preflight', { type: 'agent-games.preflight.v1' }, { signature: 'none' });
  check('3. preflight missing signature -> 401', r.status === 401, `status=${r.status}`);

  // 4. VALID_CONDITION
  r = await post(port, '/agent', { ...BASE, task_id: 'gk_test_valid' });
  check('4. VALID_CONDITION -> APPROVE', r.status === 200 && r.body.decision === 'APPROVE' && r.body.reason_code === 'VALID_CONDITION', JSON.stringify(r.body));
  check('   agent response is HMAC-signed', checkResponseSignature(r));
  check('   proof honestly reported as NOT_IMPLEMENTED (no signal mapping yet)', r.body.proof_status === 'NOT_IMPLEMENTED', `proof_status=${r.body.proof_status}`);

  // 5. VK_SUBSTITUTION (mirrors the platform example: registered_vk vs proof_vk differ)
  const vkTask = JSON.parse(JSON.stringify(BASE));
  vkTask.task_id = 'gk_test_vk';
  vkTask.statement.proof_vk = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  vkTask.statement.proof_reference = 'ref-vk-001';
  r = await post(port, '/agent', vkTask);
  check('5. VK_SUBSTITUTION -> REJECT', r.body.decision === 'REJECT' && r.body.reason_code === 'VK_SUBSTITUTION', JSON.stringify(r.body));

  // 6. THRESHOLD_MISMATCH
  const thTask = JSON.parse(JSON.stringify(BASE));
  thTask.task_id = 'gk_test_threshold';
  thTask.statement.public_balance = 500;
  thTask.statement.proof_reference = 'ref-th-001';
  r = await post(port, '/agent', thTask);
  check('6. THRESHOLD_MISMATCH -> REJECT', r.body.decision === 'REJECT' && r.body.reason_code === 'THRESHOLD_MISMATCH', JSON.stringify(r.body));

  // 7. PROOF_REUSED — same proof_reference as test 4
  r = await post(port, '/agent', { ...BASE, task_id: 'gk_test_reused' });
  check('7. PROOF_REUSED -> REJECT', r.body.decision === 'REJECT' && r.body.reason_code === 'PROOF_REUSED', JSON.stringify(r.body));

  // 8. RECIPIENT_MISMATCH
  const rcTask = JSON.parse(JSON.stringify(BASE));
  rcTask.task_id = 'gk_test_recipient';
  rcTask.statement.recipient = '0x2222222222222222222222222222222222222222';
  rcTask.statement.proof_reference = 'ref-rc-001';
  r = await post(port, '/agent', rcTask);
  check('8. RECIPIENT_MISMATCH -> REJECT', r.body.decision === 'REJECT' && r.body.reason_code === 'RECIPIENT_MISMATCH', JSON.stringify(r.body));

  // 9. AMOUNT_OVERFLOW
  const amTask = JSON.parse(JSON.stringify(BASE));
  amTask.task_id = 'gk_test_amount';
  amTask.statement.amount = 5000;
  amTask.statement.proof_reference = 'ref-am-001';
  r = await post(port, '/agent', amTask);
  check('9. AMOUNT_OVERFLOW -> REJECT', r.body.decision === 'REJECT' && r.body.reason_code === 'AMOUNT_OVERFLOW', JSON.stringify(r.body));

  // 10. EXPIRED_CONDITION — deadline 1 hour ago
  const exTask = JSON.parse(JSON.stringify(BASE));
  exTask.task_id = 'gk_test_expired';
  exTask.deadline = Date.now() - 60 * 60 * 1000;
  exTask.statement.proof_reference = 'ref-ex-001';
  r = await post(port, '/agent', exTask);
  check('10. EXPIRED_CONDITION -> REJECT', r.body.decision === 'REJECT' && r.body.reason_code === 'EXPIRED_CONDITION', JSON.stringify(r.body));

  // 11. Unsigned task -> 401
  r = await post(port, '/agent', { ...BASE, task_id: 'gk_test_unsigned' }, { signature: 'none' });
  check('11. unsigned task -> 401', r.status === 401, `status=${r.status}`);

  // 12. Health
  r = await get(port, '/health');
  check('12. GET /health -> ok', r.status === 200 && r.body.ok === true, JSON.stringify(r.body));

  server.close();
  console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => { console.error('test harness error:', err); process.exit(1); });
