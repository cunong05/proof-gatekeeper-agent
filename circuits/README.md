# Circuit artifacts — Proof Gatekeeper (official, agentgames.zkverify.io)

- `gatekeeper.wasm` (1,755,820 bytes) and `gatekeeper_final.zkey`
  (309,750 bytes) downloaded from https://agentgames.zkverify.io/circuits/
  on 2026-11-15.
- `gatekeeper-vk.json` — verification key exported locally with snarkjs
  0.7.6 (`snarkjs zkey export verificationkey`).
- Groth16 / BN128, Circom 2.x. Template name in the wasm:
  `GatekeeperEvaluation` (Poseidon hashing inside).
- Registered vkHash (from https://agentgames.zkverify.io/api/circuit-info):
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- Verification key: curve bn128, **13 public inputs** (vk IC length 14;
  `fullProve({})` fails with "Not all inputs have been set. Only 0 out
  of 13", so all 13 inputs are public).

The platform re-verifies every proof against its own registered key — never
swap in a different key. Do not edit these files; re-download from the
official URLs if they change.

Note: the 13 input SIGNAL NAMES are not in the wasm/zkey (Circom stores
names in the .sym file, which is not published) and are not published on
the public pages. They come from the dashboard's practice flow — see
`gatekeeper/proof.js` (INPUT_MAPPING).
