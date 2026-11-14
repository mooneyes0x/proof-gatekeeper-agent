#!/usr/bin/env bash
# Download the official Groth16/BN128 circuit artifacts for Proof Gatekeeper.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p circuits
BASE="https://agentgames.zkverify.io/circuits"
curl -sL -o circuits/gatekeeper.wasm "$BASE/gatekeeper.wasm"
curl -sL -o circuits/gatekeeper_final.zkey "$BASE/gatekeeper_final.zkey"
curl -sL -o circuits/vfy-policy.wasm "$BASE/vfy-policy.wasm"
curl -sL -o circuits/vfy-policy_final.zkey "$BASE/vfy-policy_final.zkey"
ls -lh circuits/
