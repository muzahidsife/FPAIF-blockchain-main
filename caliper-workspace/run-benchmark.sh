#!/bin/bash
# Run the FPAIF AgentIdentityContract Caliper benchmark (Fabric Gateway connector).
# Prereq: Fabric network up and AgentIdentityContract committed on mychannel.
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
docker ps --format '{{.Names}}' | grep -q '^peer0.org1.example.com$' || { echo "Fabric network is not running"; exit 1; }
[ -d node_modules/@hyperledger/caliper-core ] || npm install
npx caliper launch manager \
  --caliper-workspace . \
  --caliper-benchconfig benchmarks/config.yaml \
  --caliper-networkconfig networks/agent-identity-network.yaml \
  --caliper-fabric-gateway-enabled \
  --caliper-flow-only-test 2>&1 | tee benchmark-output.log
echo "Report: $(pwd)/report.html"
