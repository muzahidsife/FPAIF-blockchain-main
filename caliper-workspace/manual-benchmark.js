#!/usr/bin/env node

/**
 * Manual Benchmark Script for Water Sensor Blockchain
 *
 * This script bypasses Caliper and directly benchmarks the chaincode
 * using the Fabric Node SDK. Use this if Caliper continues to have issues.
 *
 * Usage:
 *   npm install fabric-network fabric-ca-client
 *   node manual-benchmark.js
 */

import { Gateway, Wallets } from 'fabric-network';
import { resolve, join } from 'path';
import { existsSync, readFileSync, readdirSync } from 'fs';

// Configuration
const CONFIG = {
    channelName: 'mychannel',
    chaincodeName: 'SensorContract',
    connectionProfilePath: '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/connection-org1.json',
    walletPath: './wallet-manual',
    identityLabel: 'appUser',
    mspId: 'Org1MSP',
    txCount: 200,
    batchSize: 5,
    reportToConsole: true
};

class ManualBenchmark {
    constructor() {
        this.gateway = null;
        this.network = null;
        this.contract = null;
        this.results = {
            total: 0,
            success: 0,
            failed: 0,
            latencies: [],
            errors: []
        };
    }

    async setup() {
        console.log('🔧 Setting up benchmark...\n');

        // Load connection profile
        const ccpPath = resolve(__dirname, CONFIG.connectionProfilePath);
        if (!existsSync(ccpPath)) {
            throw new Error(`Connection profile not found at: ${ccpPath}`);
        }
        const ccp = JSON.parse(readFileSync(ccpPath, 'utf8'));
        console.log(`✅ Loaded connection profile from: ${ccpPath}`);

        // Setup wallet
        const walletPath = join(__dirname, CONFIG.walletPath);
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        console.log(`✅ Wallet path: ${walletPath}`);

        // Check if identity exists
        const identity = await wallet.get(CONFIG.identityLabel);
        if (!identity) {
            console.log(`⚠️  Identity '${CONFIG.identityLabel}' not found in wallet`);
            console.log('   Creating identity from User1 certificates...');
            await this.createIdentity(wallet);
        } else {
            console.log(`✅ Identity '${CONFIG.identityLabel}' found in wallet`);
        }

        // Connect to gateway
        this.gateway = new Gateway();
        await this.gateway.connect(ccp, {
            wallet,
            identity: CONFIG.identityLabel,
            discovery: { enabled: true, asLocalhost: true }
        });
        console.log('✅ Connected to Fabric gateway');

        // Get network and contract
        this.network = await this.gateway.getNetwork(CONFIG.channelName);
        console.log(`✅ Got network: ${CONFIG.channelName}`);

        this.contract = this.network.getContract(CONFIG.chaincodeName);
        console.log(`✅ Got contract: ${CONFIG.chaincodeName}`);
        console.log('');
    }

    async createIdentity(wallet) {
        // Load User1 credentials from test-network
        const certPath = resolve(__dirname, '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem');
        const keyPath = resolve(__dirname, '../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore');

        if (!existsSync(certPath)) {
            throw new Error(`Certificate not found at: ${certPath}`);
        }

        const certificate = readFileSync(certPath, 'utf8');

        // Find private key file
        const keyFiles = readdirSync(keyPath);
        if (keyFiles.length === 0) {
            throw new Error(`No private key found in: ${keyPath}`);
        }
        const privateKey = readFileSync(join(keyPath, keyFiles[0]), 'utf8');

        const identity = {
            credentials: {
                certificate,
                privateKey
            },
            mspId: CONFIG.mspId,
            type: 'X.509'
        };

        await wallet.put(CONFIG.identityLabel, identity);
        console.log(`   ✅ Created identity '${CONFIG.identityLabel}' from User1 credentials`);
    }

    generateSensorReadings(count) {
        const readings = [];
        for (let i = 0; i < count; i++) {
            readings.push({
                SensorID: `SENSOR-${Math.floor(Math.random() * 1000)}`,
                Temp: (Math.random() * 15 + 20).toFixed(2),        // 20-35°C
                Salinity: (Math.random() * 10 + 30).toFixed(2),   // 30-40 ppt
                PH: (Math.random() * 2 + 6).toFixed(2),            // 6-8 pH
                NH4: (Math.random() * 0.5).toFixed(2),             // 0-0.5 mg/L
                DO: (Math.random() * 5 + 5).toFixed(2),            // 5-10 mg/L
                CA: (Math.random() * 100 + 100).toFixed(2)         // 100-200 mg/L
            });
        }
        return readings;
    }

    async runBenchmark() {
        console.log('============================================');
        console.log('  Starting Benchmark');
        console.log('============================================');
        console.log(`Configuration:`);
        console.log(`  - Total Transactions: ${CONFIG.txCount}`);
        console.log(`  - Batch Size: ${CONFIG.batchSize} sensors per tx`);
        console.log(`  - Channel: ${CONFIG.channelName}`);
        console.log(`  - Chaincode: ${CONFIG.chaincodeName}`);
        console.log('');
        console.log('Running...');
        console.log('');

        const startTime = Date.now();

        for (let i = 0; i < CONFIG.txCount; i++) {
            const txStart = Date.now();
            this.results.total++;

            try {
                const readings = this.generateSensorReadings(CONFIG.batchSize);
                const timestamp = Date.now().toString();

                await this.contract.submitTransaction(
                    'addBatchSensorReadings',
                    JSON.stringify(readings),
                    timestamp
                );

                this.results.success++;
                const latency = Date.now() - txStart;
                this.results.latencies.push(latency);

                // Progress indicator
                if ((i + 1) % 50 === 0) {
                    const current = Date.now();
                    const elapsed = (current - startTime) / 1000;
                    const tps = (i + 1) / elapsed;
                    console.log(`Progress: ${i + 1}/${CONFIG.txCount} | TPS: ${tps.toFixed(2)} | Avg Latency: ${(this.results.latencies.reduce((a, b) => a + b, 0) / this.results.latencies.length).toFixed(0)}ms`);
                }

            } catch (error) {
                this.results.failed++;
                this.results.errors.push({
                    tx: i + 1,
                    error: error.message
                });
                if (CONFIG.reportToConsole && this.results.failed <= 5) {
                    console.error(`❌ Transaction ${i + 1} failed: ${error.message}`);
                }
            }
        }

        const endTime = Date.now();
        const duration = (endTime - startTime) / 1000;

        this.printResults(duration);
    }

    printResults(duration) {
        console.log('');
        console.log('============================================');
        console.log('  📊 Benchmark Results');
        console.log('============================================');
        console.log('');

        // Summary
        console.log('📋 Summary:');
        console.log(`   Total Transactions:     ${this.results.total}`);
        console.log(`   ✅ Successful:          ${this.results.success}`);
        console.log(`   ❌ Failed:              ${this.results.failed}`);
        console.log(`   Success Rate:           ${((this.results.success / this.results.total) * 100).toFixed(2)}%`);
        console.log('');

        // Performance
        const tps = this.results.success / duration;
        console.log('⚡ Performance:');
        console.log(`   Duration:               ${duration.toFixed(2)} seconds`);
        console.log(`   Throughput:             ${tps.toFixed(2)} TPS`);
        console.log('');

        // Latency
        if (this.results.latencies.length > 0) {
            const sorted = this.results.latencies.sort((a, b) => a - b);
            const avg = sorted.reduce((a, b) => a + b, 0) / sorted.length;
            const p50 = sorted[Math.floor(sorted.length * 0.5)];
            const p90 = sorted[Math.floor(sorted.length * 0.9)];
            const p95 = sorted[Math.floor(sorted.length * 0.95)];
            const p99 = sorted[Math.floor(sorted.length * 0.99)];

            console.log('⏱️  Latency:');
            console.log(`   Min:                    ${Math.min(...sorted)} ms`);
            console.log(`   Average:                ${avg.toFixed(2)} ms`);
            console.log(`   p50 (median):           ${p50} ms`);
            console.log(`   p90:                    ${p90} ms`);
            console.log(`   p95:                    ${p95} ms`);
            console.log(`   p99:                    ${p99} ms`);
            console.log(`   Max:                    ${Math.max(...sorted)} ms`);
            console.log('');
        }

        // Error summary
        if (this.results.errors.length > 0) {
            console.log('❌ Errors:');
            const errorCounts = {};
            this.results.errors.forEach(e => {
                errorCounts[e.error] = (errorCounts[e.error] || 0) + 1;
            });
            Object.entries(errorCounts).forEach(([error, count]) => {
                console.log(`   ${count}x: ${error}`);
            });
            console.log('');
        }

        console.log('============================================');
        console.log('');
    }

    async cleanup() {
        if (this.gateway) {
            await this.gateway.disconnect();
            console.log('✅ Disconnected from gateway');
        }
    }
}

// Main execution
async function main() {
    const benchmark = new ManualBenchmark();

    try {
        await benchmark.setup();
        await benchmark.runBenchmark();
    } catch (error) {
        console.error('❌ Benchmark failed:', error);
        process.exit(1);
    } finally {
        await benchmark.cleanup();
    }
}

// Run if executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}

export default ManualBenchmark;
