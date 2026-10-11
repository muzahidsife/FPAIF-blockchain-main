'use strict';
const { AgentWorkloadBase } = require('./lib/agentWorkload');

class RegisterAgent extends AgentWorkloadBase {
    async submitTransaction() {
        const did = this.did(this.counter++);
        return this.invoke('registerAgent', this.agentArgs(did));
    }
}
module.exports.createWorkloadModule = () => new RegisterAgent();
