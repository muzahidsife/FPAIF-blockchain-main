# Quick Start: FPAIF + Fabric Integration

Complete guide to run FPAIF with Hyperledger Fabric backend.

---

## 📋 Prerequisites

- **Node.js** >= 18 (Fabric gateway and Caliper)
- **Python** >= 3.8 (for FPAIF)
- **Docker & Docker Compose** (Fabric network and Explorer)
- **Git**

### Docker internet check (do this first)

Containers must reach the internet or chaincode install fails with
`npm error Exit handler never called`. If your network drops packets with
TTL < 64 (Docker NAT lowers TTL by 1), apply this once per boot:

```bash
sudo iptables -t mangle -I POSTROUTING -o eth0 -j TTL --ttl-set 64
docker run --rm hyperledger/fabric-nodeenv:2.5 sh -c 'ping -c1 -W3 8.8.8.8'   # expect 0% loss
```

Permanent fix and details: [DOCKER_TTL_FIX.md](fabric-samples/test-network/DOCKER_TTL_FIX.md)

---

## 🚀 Quick Setup (5 minutes)

### Step 1: Start Fabric Network

```bash
cd fabric-samples/test-network

# Clean up any previous runs
./network.sh down

# Start the network and create the channel (with Certificate Authorities)
./network.sh up createChannel -c mychannel -ca

# Deploy the AgentIdentityContract chaincode
./network.sh deployCC -ccn AgentIdentityContract \
  -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript
```

Wait for deployment to complete. You should see:
```
Committed chaincode definition for chaincode 'AgentIdentityContract' on channel 'mychannel'
... Approvals: [Org1MSP: true, Org2MSP: true]
```

### Step 2: Start Fabric Gateway (Node.js)

Open a **new terminal**:

```bash
cd fabric-gateway
npm install
npm start
```

You should see:
```
╔════════════════════════════════════════════════════════════╗
║   FPAIF Fabric Gateway — REST API Server Running          ║
╠════════════════════════════════════════════════════════════╣
║ 🚀 Server: http://0.0.0.0:3000
║ 🔗 Channel: mychannel
║ 📜 Chaincode: AgentIdentityContract
║ 👤 Organization: Org1MSP
╚════════════════════════════════════════════════════════════╝
```

### Step 3: Start FPAIF (Python)

Open a **third terminal**:

```bash
cd FPAIF
python3 -m venv .venv && source .venv/bin/activate   # first time only
pip install -r requirements.txt                       # first time only
python app.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

## ✅ Verify Everything Works

### 1. Health Check

**Terminal 1:** Gateway health
```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "healthy",
  "gateway": "connected",
  "channel": "mychannel",
  "chaincode": "AgentIdentityContract",
  "timestamp": "2026-07-30T10:30:00.000Z"
}
```

**Terminal 2:** FPAIF health
```bash
curl http://localhost:8000/
```

Should load the FPAIF home page.

### 2. Test Agent Registration

Register an agent via the gateway directly:

```bash
curl -X POST http://localhost:3000/agents \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:example:test-agent-001",
    "publicKey": "test-public-key-data",
    "role": "user",
    "credentialHash": "abc123sha256hashvalue"
  }'
```

Expected response:
```json
{
  "success": true,
  "message": "Agent registered successfully",
  "agent": {
    "did": "did:example:test-agent-001",
    "publicKey": "test-public-key-data",
    "role": "user",
    "credentialHash": "abc123sha256hashvalue",
    "status": "active",
    "createdAt": "2026-07-30T10:30:00.000Z"
  }
}
```

### 3. Test Revocation Check

```bash
curl http://localhost:3000/agents/did:example:test-agent-001/revoked
```

Expected response:
```json
{
  "success": true,
  "did": "did:example:test-agent-001",
  "isRevoked": false
}
```

### 4. Test Agent Revocation

```bash
curl -X POST http://localhost:3000/agents/did:example:test-agent-001/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "Testing revocation"}'
```

Expected response:
```json
{
  "success": true,
  "message": "Agent revoked successfully",
  "agent": {
    "did": "did:example:test-agent-001",
    "status": "revoked",
    "revokedAt": "2026-07-30T10:35:00.000Z",
    "revokeReason": "Testing revocation"
  }
}
```

Check revocation again:
```bash
curl http://localhost:3000/agents/did:example:test-agent-001/revoked
```

Should now return `"isRevoked": true`

---

## 📊 Metrics & Analysis

Four independent tools. Run each on its own; start with the Fabric network up.

| Tool | What it measures | Output |
|---|---|---|
| `FPAIF/run_tests.py` | Off-chain: auth rate, DDoS, hijack, log time, load | `FPAIF/metrics_numbers.json` |
| Caliper | On-chain: TPS, latency, success rate per chaincode function | `caliper-workspace/report.html` |
| Explorer | Ledger: blocks, transactions, orgs, chaincode activity | http://localhost:8080 |
| `FPAIF/blockchain_metrics.py` | Caliper + Explorer numbers as one table | `FPAIF/blockchain_metrics.json` |

### A. Off-chain metrics (`run_tests.py`)

Needs the FPAIF server running (Step 3).

```bash
cd FPAIF
python run_tests.py                # 1000 users
python run_tests.py --users 100    # lighter run
```

### B. On-chain performance (Caliper)

```bash
cd caliper-workspace
./run-benchmark.sh        # ~3-4 min, first run installs npm packages
xdg-open report.html
```

- Benchmarks `registerAgent`, `getAgent`, `isRevoked`, `revokeAgent`, `anchorAuditBatch`.
- Change TPS or transaction counts in `benchmarks/config.yaml`.

### C. Ledger view (Blockchain Explorer)

```bash
cd explorer
docker compose up -d      # first sync takes ~1 min
```

Open http://localhost:8080 and log in with `exploreradmin` / `exploreradminpw`.

```bash
docker compose down       # stop
docker compose down -v    # stop and wipe its database (required after ./network.sh down)
```

### D. On-chain metrics table

Run B and C first. If one is missing, that section prints `SKIPPED`.

```bash
cd FPAIF
python blockchain_metrics.py
```

---

## 🛠 Troubleshooting

| Problem | Fix |
|---|---|
| `npm error Exit handler never called` during `deployCC` | Docker has no internet. Apply the TTL rule (Prerequisites). |
| Org2 install fails: `.../org2.example.com/... no such file` | `createOrg2` must be enabled in `fabric-samples/test-network/network.sh` (it is). Run `./network.sh down` and `up` again. |
| `./organizations/ccp-generate.sh: Permission denied` | `chmod +x fabric-samples/test-network/organizations/ccp-generate.sh` |
| Caliper: `Multiple bindings for fabric` | Only `@hyperledger/fabric-gateway` may be installed: `cd caliper-workspace && npm uninstall fabric-network` |
| Explorer shows old or empty data after recreating the network | `cd explorer && docker compose down -v && docker compose up -d` |
| Containers lose internet after reboot or Docker restart | Re-apply the TTL rule. |

### Full reset

```bash
cd explorer && docker compose down -v
cd ../fabric-samples/test-network && ./network.sh down
./network.sh up createChannel -c mychannel -ca
./network.sh deployCC -ccn AgentIdentityContract \
  -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript
```
