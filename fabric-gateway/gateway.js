/**
 * FPAIF Fabric Gateway — REST API for Hyperledger Fabric Integration
 * Wraps AgentIdentityChaincode and exposes HTTP endpoints for Python FastAPI
 */

// Prefer .env.local if present, otherwise fall back to .env
require('dotenv').config({
    path: require('fs').existsSync(require('path').resolve(__dirname, '.env.local'))
        ? '.env.local'
        : '.env',
});

const express = require('express');
const {
    connect,
    signers,
    hash,
} = require('@hyperledger/fabric-gateway');
const grpc = require('@grpc/grpc-js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { TextDecoder } = require('util');

const app = express();
app.use(express.json());

// ──────────────────────────────────────────────────────────────────────────────
// Configuration & Environment Variables
// ──────────────────────────────────────────────────────────────────────────────

const config = {
    orgName: process.env.FABRIC_ORG_NAME || 'org1',
    channelName: process.env.FABRIC_CHANNEL_NAME || 'mychannel',
    chaincodeName: process.env.FABRIC_CHAINCODE_NAME || 'AgentIdentityContract',
    caName: process.env.FABRIC_CA_NAME || 'ca.org1.example.com',
    peerId: process.env.FABRIC_PEER_ID || 'peer0.org1.example.com',
    peerEndpoint: process.env.FABRIC_PEER_ENDPOINT || 'localhost:7051',
    // Hostname the peer's TLS certificate was issued for. Required because we
    // connect via localhost/host-mapped ports, which won't match the cert's SAN.
    peerHostAlias: process.env.FABRIC_PEER_HOST_ALIAS || process.env.FABRIC_PEER_ID || 'peer0.org1.example.com',
    tlsCertPath: process.env.FABRIC_TLS_CERT_PATH || '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt',
    mspId: process.env.FABRIC_MSP_ID || 'Org1MSP',
    certPath: process.env.FABRIC_CERT_PATH || '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem',
    keyPath: process.env.FABRIC_KEY_PATH || '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore/priv_sk',
    gatewayHost: process.env.GATEWAY_HOST || '0.0.0.0',
    gatewayPort: process.env.GATEWAY_PORT || 3000,
};

let grpcClient = null;
let gateway = null;
let network = null;
let contract = null;

// ──────────────────────────────────────────────────────────────────────────────
// Fabric Gateway Connection Setup
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Fabric Gateway talks to the peer over a raw gRPC connection; the SDK does
 * NOT create this for you. This must be built separately (with TLS) and
 * handed to connect({ client, ... }) below, or connect() throws
 * "No client connection supplied".
 */
function newGrpcConnection() {
    const tlsCertPath = path.resolve(config.tlsCertPath);
    if (!fs.existsSync(tlsCertPath)) {
        throw new Error(`TLS certificate not found at: ${tlsCertPath}`);
    }
    const tlsRootCert = fs.readFileSync(tlsCertPath);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);

    return new grpc.Client(config.peerEndpoint, tlsCredentials, {
        'grpc.ssl_target_name_override': config.peerHostAlias,
    });
}

async function initializeFabricConnection() {
    try {
        console.log('🔗 Initializing Fabric Gateway connection...');

        // Load user credentials
        const certPath = path.resolve(config.certPath);
        const keyPath = path.resolve(config.keyPath);

        if (!fs.existsSync(certPath)) {
            throw new Error(`User certificate not found at: ${certPath}`);
        }
        if (!fs.existsSync(keyPath)) {
            throw new Error(`User private key not found at: ${keyPath}`);
        }

        const userCertBuffer = fs.readFileSync(certPath);
        const userKeyBuffer = fs.readFileSync(keyPath);

        // Create signer
        const signer = signers.newPrivateKeySigner(
            crypto.createPrivateKey({
                key: userKeyBuffer,
                format: 'pem',
            })
        );

        // Identity.credentials must be the raw certificate bytes (Uint8Array),
        // not an object — the private key is only used by the signer above.
        const identity = {
            mspId: config.mspId,
            credentials: userCertBuffer,
        };

        // Raw gRPC connection to the peer (required by connect()).
        grpcClient = newGrpcConnection();

        // Connect to gateway
        gateway = connect({
            client: grpcClient,
            identity,
            signer,
            evaluateOptions: () => ({
                deadline: Date.now() + 5000,
            }),
            endorseOptions: () => ({
                deadline: Date.now() + 15000,
            }),
            submitOptions: () => ({
                deadline: Date.now() + 30000,
            }),
            commitStatusOptions: () => ({
                deadline: Date.now() + 60000,
            }),
        });

        // Get network and contract
        network = gateway.getNetwork(config.channelName);
        contract = network.getContract(config.chaincodeName);

        console.log('✅ Fabric Gateway connected successfully');
        return true;
    } catch (error) {
        console.error('❌ Failed to initialize Fabric connection:', error.message);
        return false;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ──────────────────────────────────────────────────────────────────────────────

function getUtf8String(uint8array) {
    return new TextDecoder().decode(uint8array);
}

function handleFabricError(error) {
    const errorMessage = error.message || String(error);
    console.error('Fabric error:', errorMessage);

    if (errorMessage.includes('already registered')) {
        return { status: 409, message: errorMessage };
    }
    if (errorMessage.includes('not found') || errorMessage.includes('No agent found')) {
        return { status: 404, message: errorMessage };
    }
    if (errorMessage.includes('already revoked')) {
        return { status: 409, message: errorMessage };
    }

    return { status: 500, message: errorMessage };
}

// ──────────────────────────────────────────────────────────────────────────────
// REST API Endpoints
// ──────────────────────────────────────────────────────────────────────────────

// Health check endpoint
app.get('/health', (req, res) => {
    if (gateway && network && contract) {
        res.json({
            status: 'healthy',
            gateway: 'connected',
            channel: config.channelName,
            chaincode: config.chaincodeName,
            timestamp: new Date().toISOString(),
        });
    } else {
        res.status(503).json({
            status: 'unhealthy',
            gateway: 'disconnected',
            message: 'Gateway not initialized',
        });
    }
});

// ── Agent Registration ───────────────────────────────────────────────────────

/**
 * POST /agents
 * Register a new agent on the Fabric ledger
 * Body: { did, publicKey, role, credentialHash }
 */
app.post('/agents', async (req, res) => {
    try {
        const { did, publicKey, role, credentialHash } = req.body;

        if (!did || !publicKey || !role || !credentialHash) {
            return res.status(400).json({
                error: 'Missing required fields: did, publicKey, role, credentialHash',
            });
        }

        console.log(`📝 Registering agent: ${did}`);

        const result = await contract.submitTransaction(
            'registerAgent',
            did,
            publicKey,
            role,
            credentialHash
        );

        const agentData = JSON.parse(getUtf8String(result));

        res.status(201).json({
            success: true,
            message: 'Agent registered successfully',
            agent: agentData,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Get Agent ────────────────────────────────────────────────────────────────

/**
 * GET /agents/:did
 * Retrieve agent details from the Fabric ledger
 */
app.get('/agents/:did', async (req, res) => {
    try {
        const { did } = req.params;

        if (!did) {
            return res.status(400).json({ error: 'DID is required' });
        }

        console.log(`📖 Fetching agent: ${did}`);

        const result = await contract.evaluateTransaction(
            'getAgent',
            did
        );

        const agentData = JSON.parse(getUtf8String(result));

        res.json({
            success: true,
            agent: agentData,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Check if Agent is Revoked ────────────────────────────────────────────────

/**
 * GET /agents/:did/revoked
 * Fast query to check if an agent is revoked
 * Used during authentication flow
 */
app.get('/agents/:did/revoked', async (req, res) => {
    try {
        const { did } = req.params;

        if (!did) {
            return res.status(400).json({ error: 'DID is required' });
        }

        console.log(`🔍 Checking revocation status: ${did}`);

        const result = await contract.evaluateTransaction(
            'isRevoked',
            did
        );

        const isRevoked = getUtf8String(result) === 'true';

        res.json({
            success: true,
            did,
            isRevoked,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Get All Agents ───────────────────────────────────────────────────────────

/**
 * GET /agents
 * Retrieve all registered agents
 */
app.get('/agents', async (req, res) => {
    try {
        console.log('📋 Fetching all agents');

        const result = await contract.evaluateTransaction(
            'getAllAgents'
        );

        const agents = JSON.parse(getUtf8String(result));

        res.json({
            success: true,
            count: agents.length,
            agents,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Revoke Agent ─────────────────────────────────────────────────────────────

/**
 * POST /agents/:did/revoke
 * Revoke an agent on the Fabric ledger
 * Body: { reason }
 */
app.post('/agents/:did/revoke', async (req, res) => {
    try {
        const { did } = req.params;
        const { reason } = req.body;

        if (!did) {
            return res.status(400).json({ error: 'DID is required' });
        }

        console.log(`🚫 Revoking agent: ${did}`);

        const result = await contract.submitTransaction(
            'revokeAgent',
            did,
            reason || 'Not specified'
        );

        const agentData = JSON.parse(getUtf8String(result));

        res.json({
            success: true,
            message: 'Agent revoked successfully',
            agent: agentData,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Anchor Audit Batch ───────────────────────────────────────────────────────

/**
 * POST /audit-anchors
 * Anchor a batch of audit logs to the Fabric ledger
 * Body: { rootHash, eventCount, periodStart, periodEnd }
 */
app.post('/audit-anchors', async (req, res) => {
    try {
        const { rootHash, eventCount, periodStart, periodEnd } = req.body;

        if (!rootHash || !periodStart || !periodEnd) {
            return res.status(400).json({
                error: 'Missing required fields: rootHash, periodStart, periodEnd',
            });
        }

        console.log(`📌 Anchoring audit batch: ${rootHash}`);

        const result = await contract.submitTransaction(
            'anchorAuditBatch',
            rootHash,
            String(eventCount || 0),
            periodStart,
            periodEnd
        );

        const anchorData = JSON.parse(getUtf8String(result));

        res.status(201).json({
            success: true,
            message: 'Audit batch anchored successfully',
            anchor: anchorData,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Get Audit Anchors ────────────────────────────────────────────────────────

/**
 * GET /audit-anchors
 * Retrieve all audit batch anchors from the Fabric ledger
 */
app.get('/audit-anchors', async (req, res) => {
    try {
        console.log('📊 Fetching all audit anchors');

        const result = await contract.evaluateTransaction(
            'getAuditAnchors'
        );

        const anchors = JSON.parse(getUtf8String(result));

        res.json({
            success: true,
            count: anchors.length,
            anchors,
        });
    } catch (error) {
        const { status, message } = handleFabricError(error);
        res.status(status).json({ error: message });
    }
});

// ── Error Handler ────────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message,
    });
});

// ──────────────────────────────────────────────────────────────────────────────
// Server Startup
// ──────────────────────────────────────────────────────────────────────────────

async function startServer() {
    try {
        // Initialize Fabric connection
        const connected = await initializeFabricConnection();
        if (!connected) {
            console.error('Failed to connect to Fabric network. Exiting.');
            process.exit(1);
        }

        // Start Express server
        app.listen(config.gatewayPort, config.gatewayHost, () => {
            console.log(`
╔════════════════════════════════════════════════════════════╗
║   FPAIF Fabric Gateway — REST API Server Running          ║
╠════════════════════════════════════════════════════════════╣
║ 🚀 Server: http://${config.gatewayHost}:${config.gatewayPort}
║ 🔗 Channel: ${config.channelName}
║ 📜 Chaincode: ${config.chaincodeName}
║ 👤 Organization: ${config.mspId}
╚════════════════════════════════════════════════════════════╝

📚 API Endpoints:
  GET  /health                  — Health check
  POST /agents                  — Register agent
  GET  /agents                  — List all agents
  GET  /agents/:did             — Get agent details
  GET  /agents/:did/revoked     — Check revocation status
  POST /agents/:did/revoke      — Revoke agent
  POST /audit-anchors           — Anchor audit batch
  GET  /audit-anchors           — Get all audit anchors
            `);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down gracefully...');
    if (gateway) {
        gateway.close();
    }
    if (grpcClient) {
        grpcClient.close();
    }
    process.exit(0);
});

// Start the server
startServer();
