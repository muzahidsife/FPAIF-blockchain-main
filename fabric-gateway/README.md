# FPAIF Fabric Gateway

REST API gateway that bridges FastAPI (Python) and Hyperledger Fabric. Wraps the Fabric Gateway SDK to expose chaincode functions as HTTP endpoints.

---

## Prerequisites

- **Node.js** >= 14.x
- **Docker** (for Fabric network)
- **Fabric test network** running in `../fabric-samples/test-network/`
- **AgentIdentityChaincode** deployed to the channel

---

## Setup

### 1. Install Dependencies

```bash
cd fabric-gateway
npm install
```

### 2. Verify Fabric Network

Ensure the Fabric test network is running:

```bash
cd ../fabric-samples/test-network
./network.sh up
./network.sh createChannel
./network.sh deployCC -ccn AgentIdentityContract -ccp ../asset-transfer-basic/chaincode-typescript -ccl typescript
```

### 3. Configure Environment

Edit `.env.local` to match your Fabric setup. Paths are relative to the `fabric-gateway` directory.

**Key variables:**
- `FABRIC_MSP_ID` — Org MSP ID (default: `Org1MSP`)
- `FABRIC_CHANNEL_NAME` — Channel name (default: `mychannel`)
- `FABRIC_CHAINCODE_NAME` — Chaincode name (default: `AgentIdentityContract`)
- `FABRIC_PEER_ENDPOINT` — Peer gRPC address (default: `localhost:7051`)
- `FABRIC_CERT_PATH` — Path to user certificate
- `FABRIC_KEY_PATH` — Path to user private key
- `FABRIC_TLS_CERT_PATH` — Path to TLS CA certificate
- `GATEWAY_PORT` — Server port (default: `3000`)

---

## Running

### Development Mode (with auto-reload)

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

The server will start and display:

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

---

## API Endpoints

All endpoints return JSON responses.

### Health Check

```
GET /health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "gateway": "connected",
  "channel": "mychannel",
  "chaincode": "AgentIdentityContract",
  "timestamp": "2026-07-30T10:30:00.000Z"
}
```

### Register Agent

```
POST /agents
Content-Type: application/json

{
  "did": "did:example:abc123xyz",
  "publicKey": "-----BEGIN PUBLIC KEY-----...",
  "role": "user",
  "credentialHash": "sha256hash..."
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Agent registered successfully",
  "agent": {
    "did": "did:example:abc123xyz",
    "publicKey": "-----BEGIN PUBLIC KEY-----...",
    "role": "user",
    "credentialHash": "sha256hash...",
    "status": "active",
    "createdAt": "2026-07-30T10:30:00.000Z"
  }
}
```

**Errors:**
- `400` — Missing required fields
- `409` — Agent already registered
- `500` — Ledger error

---

### Get All Agents

```
GET /agents
```

**Response (200 OK):**
```json
{
  "success": true,
  "count": 5,
  "agents": [
    {
      "did": "did:example:abc123xyz",
      "publicKey": "...",
      "role": "user",
      "status": "active",
      "credentialHash": "...",
      "createdAt": "2026-07-30T10:30:00.000Z"
    }
  ]
}
```

---

### Get Agent Details

```
GET /agents/:did
```

**Response (200 OK):**
```json
{
  "success": true,
  "agent": {
    "did": "did:example:abc123xyz",
    "publicKey": "...",
    "role": "user",
    "status": "active",
    "credentialHash": "...",
    "createdAt": "2026-07-30T10:30:00.000Z"
  }
}
```

**Errors:**
- `400` — DID required
- `404` — Agent not found
- `500` — Ledger error

---

### Check Revocation Status

```
GET /agents/:did/revoked
```

**Response (200 OK):**
```json
{
  "success": true,
  "did": "did:example:abc123xyz",
  "isRevoked": false
}
```

**Used by:** FastAPI `/authenticate` endpoint to fast-check if agent is revoked before issuing session token.

---

### Revoke Agent

```
POST /agents/:did/revoke
Content-Type: application/json

{
  "reason": "Compromised credentials"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Agent revoked successfully",
  "agent": {
    "did": "did:example:abc123xyz",
    "publicKey": "...",
    "role": "user",
    "status": "revoked",
    "credentialHash": "...",
    "createdAt": "2026-07-30T10:30:00.000Z",
    "revokedAt": "2026-07-30T10:35:00.000Z",
    "revokeReason": "Compromised credentials"
  }
}
```

**Errors:**
- `400` — DID required
- `404` — Agent not found
- `409` — Agent already revoked
- `500` — Ledger error

---

### Anchor Audit Batch

```
POST /audit-anchors
Content-Type: application/json

{
  "rootHash": "sha256_hash_of_audit_log_chain",
  "eventCount": 150,
  "periodStart": "2026-07-30T10:00:00Z",
  "periodEnd": "2026-07-30T10:05:00Z"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Audit batch anchored successfully",
  "anchor": {
    "batchId": "2026-07-30T10:00:00Z_2026-07-30T10:05:00Z",
    "rootHash": "sha256_hash_of_audit_log_chain",
    "eventCount": 150,
    "periodStart": "2026-07-30T10:00:00Z",
    "periodEnd": "2026-07-30T10:05:00Z",
    "anchoredAt": "2026-07-30T10:35:00.000Z"
  }
}
```

**Used by:** FPAIF background task to periodically anchor audit log batches to the ledger for tamper-evidence.

---

### Get Audit Anchors

```
GET /audit-anchors
```

**Response (200 OK):**
```json
{
  "success": true,
  "count": 12,
  "anchors": [
    {
      "batchId": "2026-07-30T10:00:00Z_2026-07-30T10:05:00Z",
      "rootHash": "sha256_hash_of_audit_log_chain",
      "eventCount": 150,
      "periodStart": "2026-07-30T10:00:00Z",
      "periodEnd": "2026-07-30T10:05:00Z",
      "anchoredAt": "2026-07-30T10:35:00.000Z"
    }
  ]
}
```

---

## Integration with FastAPI (FPAIF)

The Python FastAPI app calls this gateway for identity operations:

### 1. Registration (in `identity.py`)

```python
import requests

FABRIC_GATEWAY_URL = "http://localhost:3000"

def register_agent_on_fabric(did, public_key, role, credential_hash):
    response = requests.post(
        f"{FABRIC_GATEWAY_URL}/agents",
        json={
            "did": did,
            "publicKey": public_key,
            "role": role,
            "credentialHash": credential_hash
        },
        timeout=10
    )
    return response.json()
```

### 2. Revocation Check (in `app.py` → `/authenticate`)

```python
def authenticate_agent(did: str):
    response = requests.get(
        f"{FABRIC_GATEWAY_URL}/agents/{did}/revoked",
        timeout=5
    )
    data = response.json()
    if data.get("isRevoked"):
        raise HTTPException(status_code=403, detail="Agent revoked")
```

### 3. Audit Batch Anchoring (background task in `app.py`)

```python
import hashlib
import hmac

def anchor_audit_logs():
    logs = db.get_audit_logs_since(last_anchor_time)
    
    # Compute HMAC-SHA256 chain root
    root_hash = compute_chain_root(logs)
    
    response = requests.post(
        f"{FABRIC_GATEWAY_URL}/audit-anchors",
        json={
            "rootHash": root_hash,
            "eventCount": len(logs),
            "periodStart": last_anchor_time.isoformat(),
            "periodEnd": datetime.now().isoformat()
        },
        timeout=30
    )
    return response.json()
```

---

## Testing

### 1. Health Check

```bash
curl http://localhost:3000/health
```

### 2. Register an Agent

```bash
curl -X POST http://localhost:3000/agents \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:example:test123",
    "publicKey": "test-public-key",
    "role": "user",
    "credentialHash": "abc123sha256hash"
  }'
```

### 3. Check Revocation Status

```bash
curl http://localhost:3000/agents/did:example:test123/revoked
```

### 4. Revoke Agent

```bash
curl -X POST http://localhost:3000/agents/did:example:test123/revoke \
  -H "Content-Type: application/json" \
  -d '{"reason": "Compromised"}'
```

### 5. Anchor Audit Batch

```bash
curl -X POST http://localhost:3000/audit-anchors \
  -H "Content-Type: application/json" \
  -d '{
    "rootHash": "sha256hash",
    "eventCount": 50,
    "periodStart": "2026-07-30T10:00:00Z",
    "periodEnd": "2026-07-30T10:05:00Z"
  }'
```

---

## Troubleshooting

### Connection Refused
- Ensure Fabric network is running: `cd ../fabric-samples/test-network && ./network.sh up`
- Check peer is listening on `localhost:7051`

### Certificate Not Found
- Verify `.env.local` paths are correct and relative to `fabric-gateway/` directory
- Run Fabric network setup to generate certificates

### Chaincode Not Found
- Ensure `AgentIdentityContract` is deployed: `./network.sh deployCC ...`
- Check chaincode name matches `FABRIC_CHAINCODE_NAME` in `.env.local`

### Timeout Errors
- Increase deadline timeouts in `gateway.js` if network is slow
- Check Fabric peer logs: `docker logs peer0.org1.example.com`

---

## Architecture

```
FastAPI (Python)
    ↓ HTTP/REST
Node.js Express Gateway
    ↓ gRPC + Fabric Gateway SDK
Hyperledger Fabric Network
    ├─ Orderer
    ├─ Peer0.Org1 + AgentIdentityChaincode
    └─ Peer0.Org2
```

---

## License

Apache-2.0
