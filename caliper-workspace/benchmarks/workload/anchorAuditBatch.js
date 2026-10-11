'use strict';
const crypto = require('crypto');
const { AgentWorkloadBase } = require('./lib/agentWorkload');

class AnchorAuditBatch extends AgentWorkloadBase {
    async submitTransaction() {
        const i = this.counter++;
        const start = `${this.runId}-w${this.workerIndex}-${i}-s`;
        const end = `${this.runId}-w${this.workerIndex}-${i}-e`;
        const rootHash = crypto.createHash('sha256').update(start + end).digest('hex');
        return this.invoke('anchorAuditBatch', [rootHash, '100', start, end]);
    }
}
module.exports.createWorkloadModule = () => new AnchorAuditBatch();
