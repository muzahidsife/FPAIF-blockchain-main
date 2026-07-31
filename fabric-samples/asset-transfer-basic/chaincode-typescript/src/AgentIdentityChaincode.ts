import {
    Context,
    Contract,
    Info,
    Returns,
    Transaction,
} from 'fabric-contract-api';

interface AgentIdentity {
    did: string;
    publicKey: string;
    role: string;
    credentialHash: string;
    status: 'active' | 'revoked';
    createdAt: string;
    revokedAt?: string;
    revokeReason?: string;
}

interface AuditAnchor {
    batchId: string;
    rootHash: string;
    eventCount: number;
    periodStart: string;
    periodEnd: string;
    anchoredAt: string;
    txId: string;
}

@Info({
    title: 'AgentIdentityContract',
    description:
        'Smart contract for AI agent DID registration, revocation, and tamper-evident audit anchoring (FPAIF Identity + Governance layers)',
})
export class AgentIdentityContract extends Contract {
    // ── Identity Layer ──────────────────────────────────────────────────────

    @Transaction()
    @Returns('string')
    public async registerAgent(
        ctx: Context,
        did: string,
        publicKey: string,
        role: string,
        credentialHash: string
    ): Promise<string> {
        if (!did || !publicKey || !role || !credentialHash) {
            throw new Error(
                'did, publicKey, role and credentialHash are all required.'
            );
        }

        const agentKey = ctx.stub.createCompositeKey('AGENT', [did]);
        const existing = await ctx.stub.getState(agentKey);
        if (existing && existing.length > 0) {
            throw new Error(`Agent with DID ${did} is already registered.`);
        }

        const createdAt = this.txTimeIso(ctx);

        const agent: AgentIdentity = {
            did,
            publicKey,
            role,
            credentialHash,
            status: 'active',
            createdAt,
        };

        await ctx.stub.putState(agentKey, Buffer.from(JSON.stringify(agent)));

        return JSON.stringify(agent);
    }

    @Transaction(false)
    @Returns('string')
    public async getAgent(ctx: Context, did: string): Promise<string> {
        const data = await this.mustGetAgent(ctx, did);
        return JSON.stringify(data);
    }

    @Transaction(false)
    @Returns('boolean')
    public async isRevoked(ctx: Context, did: string): Promise<boolean> {
        const agent = await this.mustGetAgent(ctx, did);
        return agent.status === 'revoked';
    }

    @Transaction(false)
    @Returns('string')
    public async getAllAgents(ctx: Context): Promise<string> {
        const iterator = await ctx.stub.getStateByPartialCompositeKey(
            'AGENT',
            []
        );
        const agents: AgentIdentity[] = [];

        let result = await iterator.next();
        while (!result.done) {
            agents.push(
                JSON.parse(result.value.value.toString()) as AgentIdentity
            );
            result = await iterator.next();
        }
        await iterator.close();

        return JSON.stringify(agents);
    }

    // ── Trust / Governance Layer — Revocation ───────────────────────────────

    @Transaction()
    @Returns('string')
    public async revokeAgent(
        ctx: Context,
        did: string,
        reason: string
    ): Promise<string> {
        const agentKey = ctx.stub.createCompositeKey('AGENT', [did]);
        const agent = await this.mustGetAgent(ctx, did);

        if (agent.status === 'revoked') {
            throw new Error(`Agent ${did} is already revoked.`);
        }

        agent.status = 'revoked';
        agent.revokedAt = this.txTimeIso(ctx);
        agent.revokeReason = reason || 'Not specified';

        await ctx.stub.putState(agentKey, Buffer.from(JSON.stringify(agent)));

        return JSON.stringify(agent);
    }

    // ── Governance Layer — Audit Log Anchoring ──────────────────────────────
    // Called periodically (batched), not per-event. Anchors the current
    // top hash of the off-chain HMAC-SHA256 audit chain so it becomes
    // tamper-evident without writing every log line on-chain.

    @Transaction()
    @Returns('string')
    public async anchorAuditBatch(
        ctx: Context,
        rootHash: string,
        eventCount: string,
        periodStart: string,
        periodEnd: string
    ): Promise<string> {
        if (!rootHash || !periodStart || !periodEnd) {
            throw new Error(
                'rootHash, periodStart and periodEnd are required to anchor a batch.'
            );
        }

        const batchId = `${periodStart}_${periodEnd}`;
        const anchorKey = ctx.stub.createCompositeKey('AUDIT_ANCHOR', [
            batchId,
        ]);

        const anchor: AuditAnchor = {
            batchId,
            rootHash,
            eventCount: parseInt(eventCount, 10) || 0,
            periodStart,
            periodEnd,
            anchoredAt: this.txTimeIso(ctx),
            txId: ctx.stub.getTxID(),
        };

        await ctx.stub.putState(anchorKey, Buffer.from(JSON.stringify(anchor)));

        return JSON.stringify(anchor);
    }

    @Transaction(false)
    @Returns('string')
    public async getAuditAnchors(ctx: Context): Promise<string> {
        const iterator = await ctx.stub.getStateByPartialCompositeKey(
            'AUDIT_ANCHOR',
            []
        );
        const anchors: AuditAnchor[] = [];

        let result = await iterator.next();
        while (!result.done) {
            anchors.push(
                JSON.parse(result.value.value.toString()) as AuditAnchor
            );
            result = await iterator.next();
        }
        await iterator.close();

        anchors.sort(
            (a, b) =>
                new Date(a.anchoredAt).getTime() -
                new Date(b.anchoredAt).getTime()
        );

        return JSON.stringify(anchors);
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private async mustGetAgent(
        ctx: Context,
        did: string
    ): Promise<AgentIdentity> {
        const agentKey = ctx.stub.createCompositeKey('AGENT', [did]);
        const data = await ctx.stub.getState(agentKey);
        if (!data || data.length === 0) {
            throw new Error(`No agent found with DID ${did}.`);
        }
        return JSON.parse(data.toString()) as AgentIdentity;
    }

    private txTimeIso(ctx: Context): string {
        const ts = ctx.stub.getTxTimestamp();
        return new Date(ts.seconds.low * 1000).toISOString();
    }
}
