#!/bin/bash

# Caliper Benchmark Runner - SDK Connector Version
# This script runs the Caliper benchmark using the Fabric SDK connector

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$SCRIPT_DIR"
FABRIC_DIR="$SCRIPT_DIR/../fabric-samples/test-network"

echo "============================================"
echo "  Caliper Benchmark - SDK Connector"
echo "============================================"
echo ""

# Step 1: Check if Fabric network is running
echo "📋 Step 1: Checking Fabric Network Status..."
cd "$FABRIC_DIR"

if ! docker ps | grep -q "peer0.org1.example.com"; then
    echo "❌ ERROR: Fabric network is not running!"
    echo ""
    echo "Please start the network first:"
    echo "  cd $FABRIC_DIR"
    echo "  ./network.sh up createChannel -c mychannel -ca"
    echo "  ./network.sh deployCC -ccn SensorContract -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript"
    exit 1
fi

echo "✅ Fabric network is running"
echo ""

# Step 2: Check if chaincode is deployed
echo "📋 Step 2: Checking Chaincode Deployment..."
export PATH=${PWD}/../bin:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

if ! peer lifecycle chaincode querycommitted --channelID mychannel 2>&1 | grep -q "SensorContract"; then
    echo "❌ ERROR: SensorContract chaincode is not deployed!"
    echo ""
    echo "Please deploy the chaincode first:"
    echo "  cd $FABRIC_DIR"
    echo "  ./network.sh deployCC -ccn SensorContract -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript"
    exit 1
fi

echo "✅ SensorContract is deployed"
echo ""

# Step 3: Navigate to Caliper workspace
echo "📋 Step 3: Navigating to Caliper Workspace..."
cd "$WORKSPACE_DIR"
echo "✅ In workspace: $(pwd)"
echo ""

# Step 4: Check if SDK connector is bound
echo "📋 Step 4: Checking Caliper SDK Binding..."
if ! npm list @hyperledger/caliper-fabric 2>/dev/null | grep -q "caliper-fabric"; then
    echo "⚠️  SDK connector not found. Installing..."
    npx caliper bind --caliper-bind-sut fabric:2.2
    echo "✅ SDK connector installed"
else
    echo "✅ SDK connector is already installed"
fi
echo ""

# Step 5: Run the benchmark
echo "============================================"
echo "  Starting Benchmark Execution"
echo "============================================"
echo ""
echo "Configuration:"
echo "  - Benchmark Config: benchmarks/config.yaml"
echo "  - Network Config: networks/fabric-network-sdk.yaml"
echo "  - Workers: 2"
echo "  - Rounds: 2"
echo "  - Transactions per round: 100"
echo "  - Target TPS: 50"
echo ""
echo "⏳ Running benchmark (this will take ~20 seconds)..."
echo ""

npx caliper launch manager \
    --caliper-workspace . \
    --caliper-benchconfig benchmarks/config.yaml \
    --caliper-networkconfig networks/fabric-network-sdk.yaml

echo ""
echo "============================================"
echo "  Benchmark Complete!"
echo "============================================"
echo ""

# Step 6: Check if report was generated
if [ -f "report.html" ]; then
    REPORT_PATH=$(realpath report.html)
    echo "✅ SUCCESS! Report generated:"
    echo "   $REPORT_PATH"
    echo ""
    echo "📊 To view the report:"
    echo "   xdg-open report.html"
    echo "   OR"
    echo "   firefox report.html"
    echo ""
else
    echo "⚠️  WARNING: report.html was not generated"
    echo "Please check the console output above for errors"
fi

echo "Done! 🎉"
