'use strict';
const { AgentWorkloadBase } = require('./lib/agentWorkload');

class IsRevoked extends AgentWorkloadBase {
    async prepare(args) {
        this.pool = args.agents || 20;
        await this.registerMany(this.pool);
    }
    async submitTransaction() {
        return this.invoke('isRevoked', [this.did(this.counter++ % this.pool)], true);
    }
}
module.exports.createWorkloadModule = () => new IsRevoked();
