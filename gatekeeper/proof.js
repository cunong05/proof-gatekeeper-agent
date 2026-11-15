// Groth16 decision-proof generation for Proof Gatekeeper.
//
// Circuit (official): gatekeeper, Groth16/BN128, Circom 2.x.
// Artifacts (official, agentgames.zkverify.io):
//   circuits/gatekeeper.wasm
//   circuits/gatekeeper_final.zkey
//   circuits/gatekeeper-vk.json (exported locally with snarkjs 0.7.6)
// Registered vkHash (from /api/circuit-info):
//   0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
// The platform re-verifies every proof against its OWN registered key —
// you cannot swap in your own.
//
// Verified circuit facts (measured locally 2026-11-15, not guessed):
//   - template: GatekeeperEvaluation (Poseidon hashing inside)
//   - curve bn128, protocol groth16
//   - 13 public inputs (vk IC length 14; fullProve({}) fails with
//     "Not all inputs have been set. Only 0 out of 13")
//   - wasm 1,755,820 bytes, zkey 309,750 bytes
//
// === OPEN ITEM — INPUT_MAPPING (read this before going live) ===
// The 13 input SIGNAL NAMES are not published on the public pages and
// are not recoverable from the wasm/zkey (Circom stores names in the
// .sym file, which is not published). They are revealed by the
// dashboard's practice flow (the first practice task + the preflight
// response show the exact shapes). Fill in INPUT_MAPPING below from that
// first practice task, then run
//   node -e "require('./gatekeeper/proof').selfTest()"
// which generates a proof for a synthetic task and verifies it locally
// with snarkjs before you ever send one to the platform.
//
// HYPOTHESIS ONLY (do NOT fill from this — it is an unconfirmed guess):
// the 13 public inputs are plausibly the 11 task fields + the decision +
// the reason code:
//   registered_vk, proof_vk, minimum, public_balance, expiry_block,
//   current_block, recipient, condition_recipient, amount, max_transfer,
//   proof_tx, decision, reason_code
// (11 + 2 = 13 — the count fits exactly, but the exact signal names,
// their field encoding — raw address/vk bytes vs hashed — and their
// ORDER are all unknown until practice reveals them.)
//
// Until INPUT_MAPPING is filled, generateDecisionProof() throws a clear
// error and server.js answers with the decision but NO proof (the
// decision still scores; a missing proof costs -2, while a timeout costs
// -2 AND loses the decision).
"use strict";

const path = require("node:path");
const fs = require("node:fs");

const CIRCUIT_VERSION = process.env.CIRCUIT_VERSION || "gatekeeper-v1";
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const WASM_PATH = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(__dirname, "..", "circuits", "gatekeeper-vk.json");

// TODO (from practice): map task fields + decision to the circuit's input
// signals, e.g.:
//   INPUT_MAPPING = {
//     registeredVk: (task) => fieldOf(task.registeredVk),
//     proofVk: (task) => fieldOf(task.proofVk),
//     minimum: (task) => task.minimum,
//     publicBalance: (task) => task.publicBalance,
//     expiryBlock: (task) => task.expiryBlock,
//     currentBlock: (task) => task.currentBlock,
//     recipient: (task) => fieldOf(task.recipient),
//     conditionRecipient: (task) => fieldOf(task.conditionRecipient),
//     amount: (task) => task.amount,
//     maxTransfer: (task) => task.maxTransfer,
//     proofTx: (task) => fieldOf(task.proofTx),
//     decision: (task, d) => d.decision === "APPROVE" ? 1 : 0,
//     reasonCode: (task, d) => REASON_CODE_NUMBER[d.reason_code],
//   };
// The key names must match the circuit's input signal names exactly, and
// the values must be in the field encoding the circuit expects (raw
// numbers, Poseidon hashes, or 0/1 flags — confirm from practice).
const INPUT_MAPPING = null;

async function generateDecisionProof(task, decision) {
  if (!INPUT_MAPPING) {
    throw new Error(
      "INPUT_MAPPING not filled: confirm the circuit input signal names + encoding from the first practice task (see gatekeeper/proof.js header)"
    );
  }
  if (!fs.existsSync(WASM_PATH) || !fs.existsSync(ZKEY_PATH)) {
    throw new Error("circuit artifacts missing in circuits/");
  }
  const snarkjs = require("snarkjs");
  const input = {};
  for (const [signal, fn] of Object.entries(INPUT_MAPPING)) {
    input[signal] = fn(task, decision);
  }
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    WASM_PATH,
    ZKEY_PATH
  );
  // Local verification against the exported verification key before sending.
  const vk = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
  if (!ok) throw new Error("local proof verification failed");
  return { proof, publicSignals, circuitVersion: CIRCUIT_VERSION };
}

async function selfTest() {
  console.log("vkHash:", VK_HASH);
  console.log("artifacts present:", fs.existsSync(WASM_PATH), fs.existsSync(ZKEY_PATH));
  console.log("INPUT_MAPPING filled:", !!INPUT_MAPPING);
  if (!INPUT_MAPPING) {
    console.log("selfTest: fill INPUT_MAPPING first (see header).");
    return false;
  }
  const task = {
    taskId: "selftest",
    registeredVk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
    proofVk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: 19842201,
    currentBlock: 19832000,
    recipient: "0xDe4200000000000000000000000000000000009f01",
    conditionRecipient: "0xDe4200000000000000000000000000000000009f01",
    amount: "500",
    maxTransfer: "1000",
    proofTx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
  };
  const t0 = Date.now();
  const out = await generateDecisionProof(task, { decision: "APPROVE", reason_code: "VALID_CONDITION" });
  console.log(`selfTest: proof OK in ${Date.now() - t0}ms, publicSignals=${out.publicSignals.length}`);
  return true;
}

module.exports = { generateDecisionProof, selfTest, CIRCUIT_VERSION, VK_HASH };
