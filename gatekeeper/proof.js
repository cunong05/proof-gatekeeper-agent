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
// === INPUT MAPPING — SOLVED 2026-11-16 ===
// The 13 circuit inputs (names verified empirically against
// gatekeeper.wasm; proofs generated with this mapping verify locally
// against the official VK):
//   taskId (sha256 of the task_id string), minimum, publicBalance,
//   expiryBlock, currentBlock, recipient, conditionRecipient, amount,
//   maxTransfer, registeredVkHash, proofVkHash (raw integers, reduced
//   mod p by the witness calculator), salt (random private input;
//   public signal [0] is the circuit's commitment binding salt + task),
//   decision (1 = APPROVE, 0 = REJECT).
// There are NO reason-code or proof-tx inputs. The circuit
// (GatekeeperEvaluation) re-evaluates the field checks itself: a
// decision contradicting the field checks fails witness generation,
// so PROOF_REUSED rejections (a seen-set fact the circuit cannot
// know) are answered without a proof via the server.js fallback.
"use strict";

const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");

const CIRCUIT_VERSION = process.env.CIRCUIT_VERSION || "gatekeeper-v1";
const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const WASM_PATH = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(__dirname, "..", "circuits", "gatekeeper-vk.json");

// Map a normalized task + decision to the circuit's 13 input signals
// (see the solved-mapping note in the file header).
function buildCircuitInputs(task, decision) {
  const taskIdHash = crypto
    .createHash("sha256")
    .update(String(task.taskId), "utf8")
    .digest("hex");
  return {
    taskId: BigInt("0x" + taskIdHash).toString(),
    minimum: String(task.minimum),
    publicBalance: String(task.publicBalance),
    expiryBlock: String(task.expiryBlock),
    currentBlock: String(task.currentBlock),
    recipient: BigInt(task.recipient).toString(),
    conditionRecipient: BigInt(task.conditionRecipient).toString(),
    amount: String(task.amount),
    maxTransfer: String(task.maxTransfer),
    registeredVkHash: BigInt(task.registeredVk).toString(),
    proofVkHash: BigInt(task.proofVk).toString(),
    salt: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(),
    decision: decision.decision === "APPROVE" ? "1" : "0",
  };
}

async function generateDecisionProof(task, decision) {
  if (!fs.existsSync(WASM_PATH) || !fs.existsSync(ZKEY_PATH)) {
    throw new Error("circuit artifacts missing in circuits/");
  }
  const snarkjs = require("snarkjs");
  const input = buildCircuitInputs(task, decision);
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
  console.log("input mapping: built-in (buildCircuitInputs)");
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
