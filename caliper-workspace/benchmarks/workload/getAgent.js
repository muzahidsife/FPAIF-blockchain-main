'use strict';
const { AgentWorkloadBase } = require('./lib/agentWorkload');

class GetAgent extends AgentWorkloadBase {
    async prepare(args) {
        this.pool = args.agents || 20;
        await this.registerMany(this.pool);
    }
    async submitTransaction() {
        return this.invoke('getAgent', [this.did(this.counter++ % this.pool)], true);
    }
}
module.exports.createWorkloadModule = () => new GetAgent();
