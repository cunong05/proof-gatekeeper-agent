// Checks for the Proof Gatekeeper policy + server. No network, no secrets.
// Run: npm test
"use strict";

const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { normalizeTask, decide, SeenSet } = require("../gatekeeper/policy");
const { signBody, verifyHmac } = require("../gatekeeper/protocol");

// The official sample task from
// https://agentgames.zkverify.io/events/proof-gatekeeper (valid condition).
function sampleTask(overrides = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    issued_at: "2026-11-15T10:00:00Z",
    deadline_at: "2026-11-15T10:01:00Z",
    input: {
      registered_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
      proof_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0xDe4200000000000000000000000000000000009f01",
      condition_recipient: "0xDe4200000000000000000000000000000000009f01",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
      ...overrides,
    },
  };
}

function decideRaw(raw, seen = new SeenSet(path.join(os.tmpdir(), "gk-test-seen.json"))) {
  return decide(normalizeTask(raw), seen);
}

// 1. Valid condition -> APPROVE.
{
  const d = decideRaw(sampleTask());
  assert.strictEqual(d.decision, "APPROVE");
  assert.strictEqual(d.reason_code, "VALID_CONDITION");
  assert.strictEqual(d.checks.length, 6, "all six checks pass");
  assert.ok(d.checks.every((c) => c.pass), "every check passes");
}

// 2. VK substitution -> REJECT.
{
  const d = decideRaw(sampleTask({ proof_vk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff" }));
  assert.strictEqual(d.decision, "REJECT");
  assert.strictEqual(d.reason_code, "VK_SUBSTITUTION");
}

// 2b. VK comparison is case-insensitive (checksummed vs lowercase).
{
  const d = decideRaw(sampleTask({
    proof_vk: "0X7D3A00000000000000000000000000000000000000000000000000000000F291",
  }));
  assert.strictEqual(d.decision, "APPROVE", "VK match must ignore case");
}

// 3. Threshold mismatch -> REJECT (balance below minimum).
{
  const d = decideRaw(sampleTask({ public_balance: "999" }));
  assert.strictEqual(d.reason_code, "THRESHOLD_MISMATCH");
}

// 3b. Balance exactly at the minimum passes.
{
  const d = decideRaw(sampleTask({ public_balance: "1000" }));
  assert.strictEqual(d.decision, "APPROVE", "balance == minimum must pass");
}

// 4. Amount overflow -> REJECT.
{
  const d = decideRaw(sampleTask({ amount: "1001" }));
  assert.strictEqual(d.reason_code, "AMOUNT_OVERFLOW");
}

// 4b. Amount exactly at the cap passes.
{
  const d = decideRaw(sampleTask({ amount: "1000" }));
  assert.strictEqual(d.decision, "APPROVE", "amount == max_transfer must pass");
}

// 5. Recipient mismatch -> REJECT.
{
  const d = decideRaw(sampleTask({ recipient: "0x1111000000000000000000000000000000000001" }));
  assert.strictEqual(d.reason_code, "RECIPIENT_MISMATCH");
}

// 5b. Recipient match is case-insensitive.
{
  const d = decideRaw(sampleTask({ recipient: "0xde4200000000000000000000000000000000009f01" }));
  assert.strictEqual(d.decision, "APPROVE", "recipient match must ignore case");
}

// 6. Proof reused -> REJECT when the ref is in the seen-set.
{
  const seen = new SeenSet(path.join(os.tmpdir(), "gk-test-seen-2.json"));
  seen.add("0xa4c1000000000000000000000000000000000000000000000000000000008ff1");
  const d = decideRaw(sampleTask(), seen);
  assert.strictEqual(d.reason_code, "PROOF_REUSED");
}

// 7. Expired condition -> REJECT (current_block at/past expiry).
{
  const d = decideRaw(sampleTask({ current_block: 19842201 }));
  assert.strictEqual(d.reason_code, "EXPIRED_CONDITION", "current == expiry must be expired");
  const d2 = decideRaw(sampleTask({ current_block: 19842200 }));
  assert.strictEqual(d2.decision, "APPROVE", "current == expiry - 1 must be valid");
}

// 8. Priority: VK substitution wins over threshold mismatch when both apply.
{
  const d = decideRaw(sampleTask({
    proof_vk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff",
    public_balance: "1",
  }));
  assert.strictEqual(d.reason_code, "VK_SUBSTITUTION");
}

// 9. Fail closed: missing proof_vk -> REJECT, never APPROVE on uncertainty.
{
  const t = sampleTask();
  delete t.input.proof_vk;
  const d = decideRaw(t);
  assert.strictEqual(d.decision, "REJECT");
  assert.strictEqual(d.reason_code, "VK_SUBSTITUTION");
}

// 10. Fail closed: missing proof_tx -> REJECT (no reference to approve).
{
  const t = sampleTask();
  delete t.input.proof_tx;
  const d = decideRaw(t);
  assert.strictEqual(d.decision, "REJECT");
  assert.strictEqual(d.reason_code, "PROOF_REUSED");
}

// 11. SeenSet persists across instances (restart must not forget refs).
{
  const file = path.join(os.tmpdir(), `gk-seen-persist-${Date.now()}.json`);
  const s1 = new SeenSet(file);
  assert.strictEqual(s1.add("0xabc"), true);
  assert.strictEqual(s1.add("0xabc"), false, "duplicate add returns false");
  const s2 = new SeenSet(file);
  assert.strictEqual(s2.has("0xABC"), true, "reload finds the ref (case-insensitive)");
  assert.strictEqual(s2.size, 1);
  fs.unlinkSync(file);
}

// 12. HMAC: sign/verify round-trip; tampered body fails.
{
  const secret = "test-secret-that-is-long-enough";
  const body = JSON.stringify({ decision: "APPROVE" });
  const sig = signBody(body, secret);
  assert.strictEqual(verifyHmac(body, sig, secret), true);
  assert.strictEqual(verifyHmac(body + "x", sig, secret), false);
  assert.strictEqual(verifyHmac(body, sig, "wrong-secret"), false);
}

// 13. Server end-to-end: signed valid task -> APPROVE + proof ref recorded;
// retry of the same task_id returns the identical cached body; unsigned
// request -> 401; trap task -> REJECT with the right reason code.
(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-server-"));
  const seenFile = path.join(tmpDir, "seen.json");
  const port = 18082;
  const secret = "integration-test-secret-long-enough";
  const child = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: {
      ...process.env,
      PORT: String(port),
      AGENT_GAMES_HMAC_SECRET: secret,
      SEEN_REFS_PATH: seenFile,
    },
    stdio: "ignore",
  });
  try {
    // Wait for /health.
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try {
        const r = await fetch(`http://127.0.0.1:${port}/health`);
        if (r.ok) {
          const h = await r.json();
          assert.strictEqual(h.agent, "CUNONG-1");
          assert.strictEqual(h.event, "proof_gatekeeper");
          up = true;
        }
      } catch { /* not up yet */ }
      if (!up) await new Promise((r) => setTimeout(r, 200));
    }
    assert.ok(up, "server did not come up");

    const post = async (bodyObj, sign = true) => {
      const body = JSON.stringify(bodyObj);
      const headers = { "content-type": "application/json" };
      if (sign) headers["x-agent-games-signature"] = signBody(body, secret);
      return fetch(`http://127.0.0.1:${port}/gatekeeper`, { method: "POST", headers, body });
    };

    // Valid task -> APPROVE.
    const valid = sampleTask();
    const r1 = await post(valid);
    assert.strictEqual(r1.status, 200, "valid signed task must be 200");
    const b1 = await r1.text();
    const j1 = JSON.parse(b1);
    assert.strictEqual(j1.decision, "APPROVE");
    assert.strictEqual(j1.reason_code, "VALID_CONDITION");
    assert.strictEqual(j1.proof_tx, valid.input.proof_tx);
    assert.ok(!("proof" in j1), "no proof yet: INPUT_MAPPING unfilled (expected)");
    // Response is HMAC-signed.
    assert.ok(r1.headers.get("x-agent-games-signature"), "response must be signed");

    // Retry same task_id -> identical cached body, no double record.
    const r2 = await post(valid);
    assert.strictEqual(await r2.text(), b1, "retry must return the cached body");

    // Proof ref recorded on disk (APPROVE + competition mode).
    const seen = JSON.parse(fs.readFileSync(seenFile, "utf8"));
    assert.ok(
      seen.refs.includes(valid.input.proof_tx.toLowerCase()),
      "approved proof_tx must be persisted in the seen-set"
    );

    // Same proof_tx, new task_id -> PROOF_REUSED.
    const reused = sampleTask();
    reused.task_id = "gk_24_9d2";
    const r3 = await post(reused);
    assert.strictEqual(JSON.parse(await r3.text()).reason_code, "PROOF_REUSED");

    // Trap task -> REJECT with the trap's reason code.
    const trap = sampleTask({ public_balance: "10" });
    trap.task_id = "gk_24_9d3";
    const r4 = await post(trap);
    const j4 = JSON.parse(await r4.text());
    assert.strictEqual(j4.decision, "REJECT");
    assert.strictEqual(j4.reason_code, "THRESHOLD_MISMATCH");

    // Unsigned request -> 401.
    const r5 = await post(sampleTask(), false);
    assert.strictEqual(r5.status, 401, "unsigned request must be 401");

    console.log("all policy + server tests passed");
  } finally {
    child.kill("SIGTERM");
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
