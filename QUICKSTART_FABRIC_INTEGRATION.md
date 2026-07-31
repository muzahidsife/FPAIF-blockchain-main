# Quick Start: FPAIF + Fabric Integration

Complete guide to run FPAIF with Hyperledger Fabric backend.

---

## 📋 Prerequisites

- **Node.js** >= 14.x (for Fabric gateway)
- **Python** >= 3.8 (for FPAIF)
- **Docker & Docker Compose** (for Fabric network)
- **Git** (obviously)

---

## 🚀 Quick Setup (5 minutes)

### Step 1: Start Fabric Network

```bash
cd fabric-samples/test-network

# Clean up any previous runs
./network.sh down

# Start the network
./network.sh up

# Create the channel
./network.sh createChannel

# Deploy the AgentIdentityContract chaincode
./network.sh deployCC -ccn AgentIdentityContract \
  -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript
```

Wait for deployment to complete. You should see:
```
✓ Chaincode 'AgentIdentityContract' successfully deployed on channel 'mychannel'
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
python -m pip install -r requirements.txt
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
