// Proof Gatekeeper policy: the 7 checks from the official trap encyclopedia.
// Source: https://agentgames.zkverify.io/events/proof-gatekeeper
// ("Trap encyclopedia" + "Agent build checklist" + "Score model")
//
// Every task is a structured decision over these input fields:
//   registered_vk, proof_vk, minimum, public_balance, expiry_block,
//   current_block, recipient, condition_recipient, amount, max_transfer,
//   proof_tx
//
// Trap varieties (published frequencies) and the reason_code each maps to:
//   VALID_CONDITION    ~50%  Approve — everything checks out.
//   VK_SUBSTITUTION    ~13%  Reject — proof verifies on-chain but its VK
//                             does not match the registered condition VK.
//   THRESHOLD_MISMATCH ~8%   Reject — public balance < required minimum.
//   PROOF_REUSED       ~11%  Reject — proof_tx already accepted before.
//   EXPIRED_CONDITION  ~6%   Reject — current_block past expiry_block.
//   RECIPIENT_MISMATCH ~6%   Reject — recipient != condition_recipient.
//   AMOUNT_OVERFLOW    ~6%   Reject — amount > max_transfer cap.
//
// Check priority (documented convention — the public pages describe
// single-trap tasks, so the order only matters if a task ever carries two
// traps at once): the build checklist's order (VK -> threshold -> recipient
// -> reuse -> expiry), with the amount-cap check grouped with the other
// numeric field checks, i.e. VK -> THRESHOLD -> AMOUNT -> RECIPIENT ->
// REUSED -> EXPIRY.
//
// Fail-closed: a required field that is missing or unparseable is treated
// as that check failing (never approved on uncertainty — "Reject on
// timeout or uncertainty", /build section 02). The `checks` array in the
// result records every check's pass/fail + detail for debugging; it is
// NOT sent to the platform (the response carries only decision,
// reason_code and proof_tx, per the official response shape).
//
// Seen-set rule (PROOF_REUSED): only proof refs of tasks this agent
// APPROVED in competition mode are recorded. A proof that was rejected
// for another trap was never "accepted", so a second sighting of it is
// rejected for the same original trap, not for reuse. Practice-mode
// approvals are never recorded (practice tasks must not poison scored
// rounds that happen to reuse a reference).
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const REASON_CODES = {
  VALID_CONDITION: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
};

function normHex(v) {
  return String(v ?? "").trim().toLowerCase();
}

function toBigInt(v) {
  try {
    if (v === null || v === undefined || String(v).trim() === "") return null;
    return BigInt(String(v).trim());
  } catch {
    return null;
  }
}

// Normalize the task envelope. The official sample payload uses snake_case
// keys; accept the camelCase variants too (the exact keys are confirmed
// from the first practice task — see README "Open items").
function normalizeTask(raw) {
  const e = raw || {};
  const input = e.input || e.task || {};
  return {
    taskId: e.task_id ?? e.taskId ?? e.id ?? null,
    type: e.type ?? null,
    mode: String(e.mode ?? "competition").toLowerCase(),
    issuedAt: e.issued_at ?? e.issuedAt ?? null,
    deadlineAt: e.deadline_at ?? e.deadlineAt ?? null,
    registeredVk: input.registered_vk ?? input.registeredVk ?? null,
    proofVk: input.proof_vk ?? input.proofVk ?? null,
    minimum: input.minimum ?? null,
    publicBalance: input.public_balance ?? input.publicBalance ?? null,
    expiryBlock: input.expiry_block ?? input.expiryBlock ?? null,
    currentBlock: input.current_block ?? input.currentBlock ?? null,
    recipient: input.recipient ?? null,
    conditionRecipient: input.condition_recipient ?? input.conditionRecipient ?? null,
    amount: input.amount ?? null,
    maxTransfer: input.max_transfer ?? input.maxTransfer ?? null,
    proofTx: input.proof_tx ?? input.proofTx ?? null,
    raw: e,
  };
}

// Decide a normalized task against the seen-set.
// Returns { decision: "APPROVE"|"REJECT", reason_code, checks: [...] }.
function decide(task, seenSet) {
  const checks = [];
  const fail = (code, detail) => {
    checks.push({ code, pass: false, detail });
    return { decision: "REJECT", reason_code: code, checks };
  };
  const pass = (code, detail) => checks.push({ code, pass: true, detail });

  // 1. VK match — proof validity is not condition compliance.
  if (!task.registeredVk || !task.proofVk) {
    return fail(
      REASON_CODES.VK_SUBSTITUTION,
      "registered_vk or proof_vk missing: cannot confirm the proof matches the registered condition"
    );
  }
  if (normHex(task.proofVk) !== normHex(task.registeredVk)) {
    return fail(
      REASON_CODES.VK_SUBSTITUTION,
      `proof_vk ${task.proofVk} != registered_vk ${task.registeredVk}`
    );
  }
  pass(REASON_CODES.VK_SUBSTITUTION, "proof_vk matches registered_vk");

  // 2. Threshold — public balance must meet the minimum.
  const minimum = toBigInt(task.minimum);
  const balance = toBigInt(task.publicBalance);
  if (minimum === null || balance === null) {
    return fail(
      REASON_CODES.THRESHOLD_MISMATCH,
      "minimum or public_balance missing/unparseable"
    );
  }
  if (balance < minimum) {
    return fail(
      REASON_CODES.THRESHOLD_MISMATCH,
      `public_balance ${balance} < minimum ${minimum}`
    );
  }
  pass(REASON_CODES.THRESHOLD_MISMATCH, `public_balance ${balance} >= minimum ${minimum}`);

  // 3. Amount cap — approve only up to max_transfer.
  const amount = toBigInt(task.amount);
  const maxTransfer = toBigInt(task.maxTransfer);
  if (amount === null || maxTransfer === null) {
    return fail(
      REASON_CODES.AMOUNT_OVERFLOW,
      "amount or max_transfer missing/unparseable"
    );
  }
  if (amount > maxTransfer) {
    return fail(
      REASON_CODES.AMOUNT_OVERFLOW,
      `amount ${amount} > max_transfer ${maxTransfer}`
    );
  }
  pass(REASON_CODES.AMOUNT_OVERFLOW, `amount ${amount} <= max_transfer ${maxTransfer}`);

  // 4. Recipient — the payment must go to the conditioned party.
  // Addresses compare case-insensitively (checksummed vs lowercase).
  if (!task.recipient || !task.conditionRecipient) {
    return fail(
      REASON_CODES.RECIPIENT_MISMATCH,
      "recipient or condition_recipient missing"
    );
  }
  if (normHex(task.recipient) !== normHex(task.conditionRecipient)) {
    return fail(
      REASON_CODES.RECIPIENT_MISMATCH,
      `recipient ${task.recipient} != condition_recipient ${task.conditionRecipient}`
    );
  }
  pass(REASON_CODES.RECIPIENT_MISMATCH, "recipient matches condition_recipient");

  // 5. Reuse — the proof reference must not have been accepted before.
  if (!task.proofTx) {
    return fail(
      REASON_CODES.PROOF_REUSED,
      "proof_tx missing: no proof reference to check or approve against"
    );
  }
  if (seenSet && seenSet.has(task.proofTx)) {
    return fail(
      REASON_CODES.PROOF_REUSED,
      `proof_tx ${task.proofTx} already accepted in a previous task`
    );
  }
  pass(REASON_CODES.PROOF_REUSED, "proof_tx not seen before");

  // 6. Expiry — the condition is dead once current_block reaches
  // expiry_block (a confirmation at a later block does not revive it).
  const expiry = toBigInt(task.expiryBlock);
  const current = toBigInt(task.currentBlock);
  if (expiry === null || current === null) {
    return fail(
      REASON_CODES.EXPIRED_CONDITION,
      "expiry_block or current_block missing/unparseable"
    );
  }
  if (current >= expiry) {
    return fail(
      REASON_CODES.EXPIRED_CONDITION,
      `current_block ${current} >= expiry_block ${expiry}`
    );
  }
  pass(REASON_CODES.EXPIRED_CONDITION, `current_block ${current} < expiry_block ${expiry}`);

  return { decision: "APPROVE", reason_code: REASON_CODES.VALID_CONDITION, checks };
}

// Persistent seen-set of accepted proof references (proof_tx).
// Stored as JSON so a restart/redeploy does not forget what was already
// accepted — a reused proof must still be caught after a redeploy
// between rounds. Writes are atomic (tmp file + rename).
class SeenSet {
  constructor(filePath) {
    this.filePath = filePath;
    this.set = new Set();
    this.load();
  }

  load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
        if (Array.isArray(data.refs)) {
          for (const r of data.refs) this.set.add(normHex(r));
        }
      }
    } catch (err) {
      console.error("seen-set load failed:", err.message);
    }
  }

  save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ refs: [...this.set].sort() }, null, 2));
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("seen-set save failed:", err.message);
    }
  }

  has(ref) {
    return this.set.has(normHex(ref));
  }

  // Returns true if the ref was newly added.
  add(ref) {
    const key = normHex(ref);
    if (!key || this.set.has(key)) return false;
    this.set.add(key);
    this.save();
    return true;
  }

  get size() {
    return this.set.size;
  }
}

module.exports = { REASON_CODES, normalizeTask, decide, SeenSet, normHex, toBigInt };
