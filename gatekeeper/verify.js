// Optional on-chain confirmation of a task's proof via Kurier.
// Source: https://docs.zkverify.io/overview/getting-started/kurier
// (Kurier REST API: POST register-vk / submit-proof, GET job-status.)
//
// What this is for (build checklist step 02, /build): "Call zkVerifyJS to
// confirm the proof is on-chain and its VK matches the registered
// condition VK." The trap encyclopedia's seven traps are ALL detectable
// from the task payload alone (proof_vk vs registered_vk, balances,
// blocks, addresses, seen-set) — the platform only dispatches tasks whose
// proofs already verified on-chain, including every trap task. This
// module is defense-in-depth for the case the platform ever sends a proof
// reference that is not actually finalized on-chain.
//
// How it works: Kurier tracks verification jobs by the jobId returned at
// submit-proof time, polled via GET /job-status/{API_KEY}/{jobId} until
// "Finalized" (or "Failed"). This lookup only runs when
// ZKVERIFY_KURIER_API_KEY is set AND the task's proof_tx is a Kurier
// jobId. A proof_tx that is a chain transaction hash (not a jobId) cannot
// be looked up this way — the lookup returns "unknown" and the payload
// checks decide alone.
//
// Failure semantics (fail-closed only on a definitive answer):
//   - "finalized" -> proof is on-chain, proceed.
//   - "failed"    -> proof never verified -> reject (mapped to
//                    VK_SUBSTITUTION: the proof is not what it claims).
//   - "unknown" / "not_configured" / network error / timeout -> proceed
//     on the payload checks and log it. A flaky lookup must never reject
//     a valid task.
// Lookup is capped at 5s so it can never eat the 60s response deadline.
"use strict";

const KURIER_API_URL =
  process.env.ZKVERIFY_KURIER_API_URL || "https://api.kurier.xyz/api/v1";

async function checkProofOnChain(proofTx) {
  const apiKey = process.env.ZKVERIFY_KURIER_API_KEY || "";
  if (!apiKey) return { status: "not_configured" };
  if (!proofTx) return { status: "unknown", detail: "no proof_tx" };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const url = `${KURIER_API_URL}/job-status/${apiKey}/${encodeURIComponent(proofTx)}`;
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) return { status: "unknown", detail: `kurier HTTP ${res.status}` };
    const data = await res.json();
    const s = String(data.status || "").toLowerCase();
    if (s === "finalized") return { status: "finalized" };
    if (s === "failed") return { status: "failed", detail: "kurier job failed" };
    return { status: "unknown", detail: `kurier status ${data.status}` };
  } catch (err) {
    return { status: "unknown", detail: err.message };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { checkProofOnChain, KURIER_API_URL };
