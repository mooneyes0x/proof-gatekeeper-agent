# Proof Gatekeeper Agent — zkVerify Agent Games

Live agent for the **Proof Gatekeeper** track of zkVerify Agent Games, account
**@cryptopunkfdn**. It answers payment-gatekeeper tasks: verify the payer's
proof against the registered verification key, check every condition field,
and return `APPROVE` / `REJECT` with a reason code — all inside the 60-second
decision window, with every response HMAC-signed.

This agent exists to earn **one scored task** so the account's eligibility
checklist reaches 5/5 ("At least one scored agent"). The Wildcard submission
(Wallet Security Sentinel, PENDING) does **not** count as a scored task, and
practice tasks do not create score-ledger entries.

## How it decides

One mismatch = `REJECT`. Checks, in order:

| # | Check | Reason code |
|---|-------|-------------|
| 1 | `proof_vk` must equal `registered_vk` | `VK_SUBSTITUTION` |
| 2 | `proof_reference` must not have been seen before (local seen-set, persisted to disk) | `PROOF_REUSED` |
| 3 | Condition must not be expired (expiry block / timestamp / task deadline) | `EXPIRED_CONDITION` |
| 4 | `recipient` must match the condition address (when one is stated) | `RECIPIENT_MISMATCH` |
| 5 | `public_balance >= minimum` | `THRESHOLD_MISMATCH` |
| 6 | `amount <= max_transfer` (when both are stated) | `AMOUNT_OVERFLOW` |
| — | All checks pass | `VALID_CONDITION` → `APPROVE` |

Fail closed, always: a task with missing/unparseable required fields, an
unsigned or stale request, or a decision that overruns the watchdog is
`REJECT` — never approve on uncertainty. Correct APPROVE/REJECT scores +12;
incorrect APPROVE −6, incorrect REJECT −3, timeout −2 (per the event page).

The extractor (`src/decide.js`) looks for each field in every documented
location of the envelope (`statement`, `input`, `payload`, `public_inputs`,
…). The platform's public pages do not publish one canonical JSON schema
(the code examples on `/build` and `/guide` are truncated), so this
flexibility is deliberate and documented in the code.

## Endpoints

| Method & path | Purpose |
|---|---|
| `POST /agent` | Signed task envelope → `{ task_id, decision, reason_code, ... }` |
| `POST /preflight` | Signed preflight → `{ ok: true, protocolVersion: "v1" }` |
| `GET /health` | Unsigned liveness check |
| `GET /` | Info text |

Security order on signed endpoints: read the **raw body** → verify
`x-agent-games-signature` (HMAC-SHA256 over the raw body, `timingSafeEqual`)
→ only then JSON-parse → decide → sign the **raw response body** with the
same header. Requests with a missing/malformed/mismatched signature get
`401`. If `AGENT_GAMES_HMAC_SECRET` is not configured, signed endpoints
return `500` (fail closed). `ALLOW_UNSIGNED=1` exists for local dev only —
never set it in production. Bodies and secrets are never logged.

## Own proof — honest status (verified 15 Nov 2026)

- Circuit artifacts are in `circuits/` (downloaded from the platform):
  `gatekeeper.wasm` (1.7 MB), `gatekeeper_final.zkey` (303 KB),
  `vfy-policy.wasm`, `vfy-policy_final.zkey`.
- `snarkjs zkey export verificationkey` works: gatekeeper is **Groth16/BN128
  with nPublic = 13**; the exported key is `circuits/gatekeeper_vk.json`.
  Platform-published gatekeeper vkHash:
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
  (also served at `GET /api/circuit-info`).
- **Blocking issue — no fake proof is returned:** the platform publishes
  only the `.wasm` and `.zkey` files. It does **not** publish the `.circom`
  source, the `.sym` file, or the witness-calculator JS, so the input signal
  names and order for the 13 public inputs are not publicly known.
  `snarkjs groth16.fullProve()` needs those names. The `/build` and `/guide`
  pages show truncated code examples; neither lists the circuit's inputs.
- `src/proof.js` therefore: (1) generates a real proof **only if** the
  operator supplies the signal mapping via `CIRCUIT_INPUTS_JSON` or
  `circuits/gatekeeper_inputs.json` (e.g. obtained from the platform or the
  circuit author); (2) otherwise returns `proof_status: "NOT_IMPLEMENTED"`
  with the exact reason, and the agent answers the task **without** a proof
  rather than with a fake one. On provable tasks that costs −2
  (missing/invalid proof) — cheaper than an incorrect APPROVE (−6), and
  honest. The decision itself is still scored on its correctness.
- Kurier submission (`KURIER_API_KEY`) only runs when a real proof exists,
  polls until **Finalized**, and never returns Submitted/IncludedInBlock as
  confirmed.

## Quick start (local)

```bash
npm install
npm run download-circuits   # re-downloads the artifacts into circuits/
cp .env.example .env        # put the platform HMAC secret in .env (never commit it)
npm test                    # 12 tests, all local, no network
npm start                   # listens on $PORT (default 3000)
```

Test secret note: `npm test` uses its own throwaway secret
(`test-secret-do-not-use-in-production`) and a temp seen-set file.

## Deploy (public HTTPS, path `/agent`)

The agent must be at a public HTTPS URL with the full handler path, e.g.
`https://<app>.onrender.com/agent` — not root, no localhost/private IP/
custom port. The server already listens on `$PORT` (Render/Railway inject
it) and needs one env var: `AGENT_GAMES_HMAC_SECRET` (from the dashboard,
Rotate Secret — shown exactly once).

**Recommended: Railway** — always-on (no sleep), which matters because a
round task must be answered within 60 s. Free trial: $5 credit for 30 days,
no card required; after that the Free plan gives $1/month credit, and the
Hobby plan ($5/month, includes $5 usage) covers a small always-on Node
service. Steps (needs the user's login in their browser — this repo cannot
deploy itself): sign in at railway.com with GitHub → New Project → Deploy
from GitHub repo → pick this repo → set env `AGENT_GAMES_HMAC_SECRET` →
deploy → copy the public URL (`*.up.railway.app`) → register
`<url>/agent` on the Agent Games dashboard.

**Alternative: Render (free, no card)** — New → Web Service → connect this
repo → Build `npm install`, Start `npm start`, Free instance → public URL
`*.onrender.com`. **Warning:** free Render services sleep after 15 minutes
idle and cold-start in ~30–60 s, which can eat the whole 60 s decision
window and fail preflight/tasks that arrive while asleep. Only use free
Render with a keep-alive ping (e.g. an external uptime monitor hitting
`/health` every 10 minutes), or pay $7/month for the always-on Starter plan.
A `render.yaml` is included for one-click deploy.

**Not recommended: Vercel serverless** — a persistent Node server with an
in-memory seen-set does not map to serverless functions (short timeouts,
no shared memory); it would need a rewrite plus an external store.

Free-tier terms change often; verify the live pricing on each provider's
site before committing.

## Register & enter a scored round (parent agent / user, browser)

1. Dashboard → My Agents (`/dashboard/agents`) → Register agent → name,
   tick **Proof Gatekeeper**, Repository URL = this repo → Register.
   Quota seen on the account: 0/3 agents.
2. Rotate Secret in the dashboard, copy the plaintext once, set it as
   `AGENT_GAMES_HMAC_SECRET` on the host (env var, never in code/logs).
3. Run the signed preflight from the dashboard until the agent shows
   **active** (must return `{ ok: true, protocolVersion: "v1" }` signed).
4. Complete at least one practice task (`/dashboard/practice`) — required
   before entering an event, but practice does **not** count as scored.
5. Enter the event (`/events/proof-gatekeeper`) and answer live tasks.
   Rounds run daily 17:30–03:30 WIB, 13–20 Nov 2026, 8 tasks/agent/round.
   One scored task in the ledger flips "At least one scored agent" to met.

## Repo layout

```
src/server.js    HTTP server, /agent + /preflight + /health, HMAC, 50s watchdog
src/hmac.js      HMAC-SHA256 sign/verify (timingSafeEqual, raw body)
src/decide.js    field extraction, 6 checks, reason codes, persisted seen-set
src/proof.js     snarkjs proof attempt + Kurier submit (see honest status above)
test/test-agent.js  12 local tests (preflight, all 7 reason codes, 401s, health)
circuits/        official artifacts + exported gatekeeper_vk.json
scripts/download-circuits.sh
render.yaml      Render one-click deploy
.env.example     env template (no real secrets)
```

## Security notes

- No secret, API key, or private key is hardcoded, committed, or logged
  anywhere in this repo (`.env` and `data/` are gitignored).
- The seen-set is the replay guard: a `proof_reference` is recorded
  **before** an APPROVE is returned, so a retried task is caught.
- `npm audit` was not run as part of this build; run it before deploying.
