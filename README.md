# Proof Gatekeeper — Agent CUNONG-1

Agent for the **Proof Gatekeeper** track of zkVerify Agent Games Season 01
(21 Oct – 21 Nov 2026). One Node.js server, no framework, plain `http`.

- Track: each task is a structured payment decision — verify a zero-knowledge
  proof against a registered condition and return `APPROVE` or `REJECT` with
  a reason code. 8 tasks per agent per daily round, 8 rounds (13–20 Nov),
  scores cumulative.
- Every task must carry a Groth16 **decision proof** (circuit `gatekeeper`,
  Groth16/BN128, Circom 2.x) proving the decision follows the rules. The
  platform re-verifies the proof against its own registered key.
- Score: correct APPROVE +12, correct REJECT +12, wrong APPROVE −6, wrong
  REJECT −3, timeout −2, missing/invalid proof −2, reliability bonus +0..+5
  per round (pro-rated by the share of provable tasks whose proof verified).
  Wrong approvals penalize more than wrong rejections — the cost of
  approving a trap is higher than caution.

Sources (official): https://agentgames.zkverify.io/events/proof-gatekeeper ·
https://agentgames.zkverify.io/build · https://agentgames.zkverify.io/rules ·
circuit info: https://agentgames.zkverify.io/api/circuit-info ·
Kurier docs: https://docs.zkverify.io/overview/getting-started/kurier

## Quick start

```bash
npm install
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET from the dashboard
node server.js         # listens on $PORT (default 8080)
# health:  GET /health
# tasks:   POST /gatekeeper
```

Deploy the server to a public HTTPS host (the platform requires a public
HTTPS endpoint — no localhost, no private IPs, no custom ports). Railway is
the proven path for this tournament (deploy from this repo; the dashboard
registers the `https://<app>.up.railway.app/gatekeeper` URL). Free-tier hosts that
sleep after inactivity will cost you tasks — use a host that stays awake.

## Registration checklist (dashboard)

1. Register the agent: name `CUNONG-1`, check **only** `Proof Gatekeeper`,
   repository URL = this repo, endpoint = `https://<your-host>/gatekeeper`
   (endpoint is optional at registration and can be added later).
2. Copy the HMAC secret from the dashboard ("Rotate Secret") into `.env`
   as `AGENT_GAMES_HMAC_SECRET`. It is shown exactly once — never commit it.
3. Complete the **signed preflight** and at least **1 practice task** from
   the dashboard. The practice task is the first real task envelope you
   will see: confirm the exact field names against `gatekeeper/policy.js`
   and fill in `gatekeeper/proof.js` `INPUT_MAPPING` (see "Open items").
4. The agent must respond within **60 seconds** per task; the platform
   retries after network failures (task IDs are idempotency keys).

## How a task works

1. The platform POSTs a signed task envelope to `/gatekeeper`:
   `task_id`, `mode` (`competition` / `practice`), `issued_at`,
   `deadline_at`, and `input` with `registered_vk`, `proof_vk`, `minimum`,
   `public_balance`, `expiry_block`, `current_block`, `recipient`,
   `condition_recipient`, `amount`, `max_transfer`, `proof_tx`.
2. The server verifies the `x-agent-games-signature` HMAC-SHA256 header over
   the raw body **before parsing**. Bad signature → 401, nothing else.
3. `gatekeeper/policy.js` runs the 7 checks (see Policy below) and returns
   `APPROVE` / `VALID_CONDITION` or `REJECT` + the trap's reason code.
4. An APPROVED competition task's `proof_tx` is recorded in the persistent
   seen-set (`data/seen-proof-refs.json`) so a re-submission is caught as
   `PROOF_REUSED`. Practice approvals are never recorded.
5. `gatekeeper/proof.js` generates the Groth16 decision proof locally with
   snarkjs and the official `gatekeeper` circuit, and returns it with the
   response. If proof generation fails (or the deadline already passed),
   the server answers with the decision but no proof instead of timing out
   (a missing proof costs −2; a timeout costs −2 AND loses the decision).
6. The response echoes `proof_tx`, declares `decision` + `reason_code`,
   attaches the proof (`circuitVersion`, Groth16 `proof`, `publicSignals`),
   and is signed with the same HMAC over the raw response body.
7. Retries of the same `task_id` return the cached response — the
   idempotency key is never reused for a different task.

## Policy — the 7 checks

In priority order (the build checklist's order, with the amount-cap check
grouped with the numeric field checks). Published trap frequencies in
parentheses; ~50% of tasks are valid.

| # | Check | Fail → reason code | Rule |
|---|---|---|---|
| 1 | VK match | `VK_SUBSTITUTION` (~13%) | `proof_vk` must equal `registered_vk` (case-insensitive). A proof that verifies is not the same as a proof that matches the condition. |
| 2 | Threshold | `THRESHOLD_MISMATCH` (~8%) | `public_balance >= minimum`, exact BigInt comparison. |
| 3 | Amount cap | `AMOUNT_OVERFLOW` (~6%) | `amount <= max_transfer`. Approve only up to the cap. |
| 4 | Recipient | `RECIPIENT_MISMATCH` (~6%) | `recipient` must equal `condition_recipient` (case-insensitive). |
| 5 | Reuse | `PROOF_REUSED` (~11%) | `proof_tx` must not be in the seen-set of previously APPROVED competition tasks. |
| 6 | Expiry | `EXPIRED_CONDITION` (~6%) | `current_block < expiry_block`. Expired at the expiry block itself; a later confirmation does not revive it. |
| — | All pass | `VALID_CONDITION` (~50%) | `APPROVE`. |

Fail-closed: a required field that is missing or unparseable fails its
check (never approved on uncertainty). The optional Kurier on-chain
confirmation (`gatekeeper/verify.js`, needs `ZKVERIFY_KURIER_API_KEY`)
adds a definitive-"failed" override to REJECT; anything inconclusive
leaves the payload checks in charge, and a flaky lookup never rejects a
valid task.

## Files

| File | What it is |
|---|---|
| `server.js` | HTTP server: `GET /health`, `POST /gatekeeper`, HMAC, idempotency, signed responses, 45s proof budget inside the 60s deadline |
| `gatekeeper/protocol.js` | HMAC helpers (sign/verify, constant-time compare) |
| `gatekeeper/policy.js` | The 7 checks + reason codes + persistent seen-set |
| `gatekeeper/verify.js` | Optional Kurier on-chain proof confirmation (API key required) |
| `gatekeeper/proof.js` | Groth16 decision-proof generation (snarkjs + official circuit) |
| `circuits/` | Official `gatekeeper` artifacts from agentgames.zkverify.io |
| `test/policy.test.js` | Policy checks + seen-set persistence + server end-to-end (no network, no secrets) |

## Open items (fill in from the dashboard practice task)

1. **Exact task-envelope field names** — the public sample uses snake_case
   (`task_id`, `registered_vk`, …); `gatekeeper/policy.js` also accepts
   camelCase variants. Confirm against the first practice envelope.
2. **Decision-proof input mapping** — the `gatekeeper` circuit takes 13
   inputs, all public (verified locally). The signal names and their field
   encoding are not published; they come from the practice flow.
   `gatekeeper/proof.js` has a single `INPUT_MAPPING` table for exactly
   this, plus an unconfirmed hypothesis (11 task fields + decision +
   reason code = 13) that must NOT be used until practice confirms it.
3. **Response proof field** — the official sample response shows only
   `decision` + `reason_code` + `proof_tx`, while the score model penalizes
   a provable task answered without a valid Groth16 proof. This agent
   attaches the proof as a `proof` object (same shape as Steal the VFY);
   confirm the accepted shape from the first practice response.
4. **On-chain proof lookup** — Kurier tracks jobs by jobId, not by
   transaction hash; whether a task's `proof_tx` is usable as a jobId is
   unconfirmed. Until then `gatekeeper/verify.js` treats a non-matching
   lookup as "unknown" and the payload checks decide.

## Security

No wallet keys, seeds, or private keys live on this server and it never
signs a transaction or spends anything. The only secrets are the HMAC
secret from the dashboard (`.env`, never committed) and, optionally, a
Kurier API key (`.env`, never committed). Never paste a private key,
wallet seed, or API key into any tool or repo.
