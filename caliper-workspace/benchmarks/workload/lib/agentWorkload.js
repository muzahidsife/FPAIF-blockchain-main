'use strict';

const crypto = require('crypto');
const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

const CONTRACT = 'AgentIdentityContract';
const ROLES = ['admin', 'user', 'auditor'];

/**
 * Base class for the FPAIF AgentIdentityContract workloads.
 * Subclasses implement submitTransaction() and may override prepare().
 */
class AgentWorkloadBase extends WorkloadModuleBase {
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
        this.counter = 0;
        // run-unique prefix so repeated runs never collide with existing DIDs
        this.runId = `${Date.now().toString(36)}${roundIndex}`;
        this.prefix = `did:fpaif:bench:${this.runId}:w${workerIndex}`;
        await this.prepare(roundArguments);
    }

    async prepare() {}

    did(i) {
        return `${this.prefix}:${i}`;
    }

    agentArgs(did) {
        const publicKey = crypto.randomBytes(32).toString('hex');
        const credentialHash = crypto.createHash('sha256').update(did + publicKey).digest('hex');
        return [did, publicKey, ROLES[this.counter % ROLES.length], credentialHash];
    }

    invoke(fn, args, readOnly = false) {
        return this.sutAdapter.sendRequests({
            contractId: CONTRACT,
            contractFunction: fn,
            contractArguments: args,
            readOnly,
        });
    }

    async registerMany(count) {
        for (let i = 0; i < count; i++) {
            await this.invoke('registerAgent', this.agentArgs(this.did(i)));
            this.counter++;
        }
        this.counter = 0;
    }

    async cleanupWorkloadModule() {}
}

module.exports = { AgentWorkloadBase };
