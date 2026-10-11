'use strict';
const { AgentWorkloadBase } = require('./lib/agentWorkload');

// Each agent can only be revoked once, so pre-register `agents` DIDs per worker
// (set `agents` >= txNumber / workers in the round config).
class RevokeAgent extends AgentWorkloadBase {
    async prepare(args) {
        this.pool = args.agents || 50;
        await this.registerMany(this.pool);
    }
    async submitTransaction() {
        if (this.counter >= this.pool) {
            throw new Error('revokeAgent workload ran out of pre-registered agents; raise "agents"');
        }
        return this.invoke('revokeAgent', [this.did(this.counter++), 'caliper benchmark']);
    }
}
module.exports.createWorkloadModule = () => new RevokeAgent();
