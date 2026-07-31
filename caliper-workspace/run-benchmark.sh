#!/bin/bash

echo "======================================"
echo "Hyperledger Caliper Benchmark Runner"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Fabric network is running
echo -e "${YELLOW}Checking if Fabric network is running...${NC}"
if ! docker ps | grep -q "peer0.org1.example.com"; then
    echo -e "${RED}ERROR: Fabric network is not running!${NC}"
    echo ""
    echo "Please start your Fabric network first:"
    echo "  cd ../fabric-samples/test-network"
    echo "  ./network.sh up createChannel -c mychannel -ca"
    echo "  ./network.sh deployCC -ccn basic -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript"
    exit 1
fi
echo -e "${GREEN}✓ Fabric network is running${NC}"
echo ""

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install
    echo -e "${GREEN}✓ Dependencies installed${NC}"
    echo ""
fi

# Bind Caliper to Fabric (if not already done)
echo -e "${YELLOW}Binding Caliper to Fabric v2.5...${NC}"
npx caliper bind --caliper-bind-sut fabric:2.5
echo -e "${GREEN}✓ Caliper bound to Fabric${NC}"
echo ""

# Run the benchmark
echo -e "${YELLOW}Starting benchmark...${NC}"
echo "This may take several minutes depending on the test configuration."
echo ""

npx caliper launch manager \
  --caliper-workspace . \
  --caliper-benchconfig benchmarks/config.yaml \
  --caliper-networkconfig networks/fabric-network.yaml

# Check if benchmark completed successfully
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}======================================"
    echo "✓ Benchmark completed successfully!"
    echo "======================================${NC}"
    echo ""
    echo "View the report:"
    echo "  xdg-open report.html"
    echo ""
    echo "Or open manually in your browser:"
    echo "  file://$(pwd)/report.html"
else
    echo ""
    echo -e "${RED}======================================"
    echo "✗ Benchmark failed!"
    echo "======================================${NC}"
    echo ""
    echo "Check the logs above for errors."
    echo "See CALIPER_GUIDE.md for troubleshooting."
    exit 1
fi
