// Proof Gatekeeper agent — server
// Node.js, no framework, plain http. See README.md for the protocol.
//
//   GET  /health      -> readiness (hmac configured? proof artifacts present? seen refs?)
//   POST /gatekeeper  -> signed task envelope in, signed decision+proof out
//   POST /agent       -> same (alias; the dashboard registers one URL)
//
// Env (see .env.example):
//   PORT, AGENT_GAMES_HMAC_SECRET, AGENT_GAMES_HMAC_FORMAT,
//   CIRCUIT_VERSION, SEEN_REFS_PATH, ZKVERIFY_KURIER_API_KEY
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const { verifyHmac, signBody, timingSafeEqualHex } = require("./gatekeeper/protocol");
const { normalizeTask, decide, SeenSet } = require("./gatekeeper/policy");
const { checkProofOnChain } = require("./gatekeeper/verify");
const { generateDecisionProof, CIRCUIT_VERSION } = require("./gatekeeper/proof");

const PORT = Number(process.env.PORT || 8080);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const HMAC_FORMAT = (process.env.AGENT_GAMES_HMAC_FORMAT || "hex").toLowerCase();
const SEEN_REFS_PATH =
  process.env.SEEN_REFS_PATH || path.join(__dirname, "data", "seen-proof-refs.json");

// The platform's hard response deadline is 60 seconds. Proof generation
// is the only slow step, so it gets 45s; if it fails or times out, the
// decision is still returned without a proof (a correct decision without
// a proof scores +12-2, a timeout scores -2 and loses the decision).
const PROOF_TIMEOUT_MS = Number(process.env.PROOF_TIMEOUT_MS || 45000);

const CIRCUITS_DIR = path.join(__dirname, "circuits");
const WASM_PATH = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY_PATH = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");

const seenSet = new SeenSet(SEEN_REFS_PATH);

// Idempotency: task_id -> cached response body (string).
// The platform may retry after a network failure; a retry of the same
// task is NOT a new task, and the idempotency key must never be reused
// for a different task.
const seenTasks = new Map();
let tasksSeen = 0;

function hmacConfigured() {
  return HMAC_SECRET.length >= 16;
}

function circuitsPresent() {
  return fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res, status, obj, sign = false) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign && hmacConfigured()) {
    headers["x-agent-games-signature"] = signBody(body, HMAC_SECRET, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(body);
}

function healthPayload() {
  return {
    status: "ok",
    agent: "CUNONG-1",
    event: "proof_gatekeeper",
    hmacConfigured: hmacConfigured(),
    circuitsPresent: circuitsPresent(),
    circuitVersion: CIRCUIT_VERSION,
    seenRefs: seenSet.size,
    tasksSeen,
    uptimeSec: Math.floor(process.uptime()),
  };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/health") {
      return sendJson(res, 200, healthPayload());
    }

    if (req.method === "POST" && (req.url === "/gatekeeper" || req.url === "/agent")) {
      const rawBody = await readBody(req);

      // 1. Verify the HMAC over the RAW body before parsing anything.
      if (hmacConfigured()) {
        const sig = req.headers["x-agent-games-signature"] || "";
        if (!sig || !timingSafeEqualHex(sig, signBody(rawBody, HMAC_SECRET, HMAC_FORMAT))) {
          return sendJson(res, 401, { error: "bad signature" });
        }
      }

      let parsed;
      try {
        parsed = JSON.parse(rawBody.toString("utf8"));
      } catch {
        return sendJson(res, 400, { error: "invalid json" });
      }

      const task = normalizeTask(parsed);
      if (!task.taskId) {
        return sendJson(res, 400, { error: "missing task_id" });
      }

      // Retry of the same task: return the exact cached response. The
      // seen-set is NOT touched again — a retry must not double-record.
      if (seenTasks.has(task.taskId)) {
        const cached = seenTasks.get(task.taskId);
        res.writeHead(200, {
          "content-type": "application/json",
          ...(hmacConfigured()
            ? { "x-agent-games-signature": signBody(cached, HMAC_SECRET, HMAC_FORMAT) }
            : {}),
        });
        return res.end(cached);
      }
      tasksSeen += 1;

      // 2. Optional on-chain confirmation (Kurier, only when configured).
      // A definitive "failed" overrides the payload decision to REJECT;
      // anything inconclusive leaves the payload checks in charge.
      let decision = null;
      const onchain = await checkProofOnChain(task.proofTx);
      if (onchain.status === "failed") {
        console.error(`[task ${task.taskId}] proof not on-chain (${onchain.detail}), rejecting`);
        decision = { decision: "REJECT", reason_code: "VK_SUBSTITUTION", checks: [] };
      } else {
        if (onchain.status !== "not_configured") {
          console.log(`[task ${task.taskId}] on-chain check: ${onchain.status}`);
        }
        // 3. Decide from the 7 policy checks.
        decision = decide(task, seenSet);
      }

      // 4. Record an APPROVED competition task's proof reference so a
      // later re-submission is caught as PROOF_REUSED. Practice approvals
      // are never recorded.
      if (decision.decision === "APPROVE" && task.mode === "competition" && task.proofTx) {
        seenSet.add(task.proofTx);
      }

      // 5. Prove the decision. On failure (or if the deadline already
      // passed) answer with the decision but no proof rather than timing
      // out: the decision still scores, the missing proof costs -2.
      let proof = null;
      const deadlineMs = task.deadlineAt ? Date.parse(task.deadlineAt) : NaN;
      if (Number.isFinite(deadlineMs) && Date.now() > deadlineMs) {
        console.error(`[task ${task.taskId}] deadline already passed, answering without proof`);
      } else {
        try {
          proof = await Promise.race([
            generateDecisionProof(task, decision),
            new Promise((_, reject) =>
              setTimeout(() => reject(new Error("proof timeout")), PROOF_TIMEOUT_MS)
            ),
          ]);
        } catch (err) {
          console.error(`[task ${task.taskId}] proof failed, answering without proof:`, err.message);
          proof = null;
        }
      }

      // Response shape (official): decision + reason_code + proof_tx.
      // The decision proof rides along as `proof` when generatable —
      // the score model penalizes a provable task answered without one.
      const response = {
        decision: decision.decision,
        reason_code: decision.reason_code,
        ...(task.proofTx ? { proof_tx: task.proofTx } : {}),
        ...(proof
          ? {
              proof: {
                circuitVersion: CIRCUIT_VERSION,
                proof: proof.proof,
                publicSignals: proof.publicSignals,
              },
            }
          : {}),
      };

      const body = JSON.stringify(response);
      seenTasks.set(task.taskId, body);
      res.writeHead(200, {
        "content-type": "application/json",
        ...(hmacConfigured()
          ? { "x-agent-games-signature": signBody(body, HMAC_SECRET, HMAC_FORMAT) }
          : {}),
      });
      return res.end(body);
    }

    return sendJson(res, 404, { error: "not found" });
  } catch (err) {
    console.error("server error:", err);
    return sendJson(res, 500, { error: "internal error" });
  }
});

server.listen(PORT, () => {
  console.log(`CUNONG-1 proof-gatekeeper agent listening on :${PORT}`);
  console.log(
    `health: hmacConfigured=${hmacConfigured()} circuitsPresent=${circuitsPresent()} seenRefs=${seenSet.size}`
  );
});
