'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * Workload module for adding sensor readings to the blockchain
 * SDK Connector Compatible Version
 */
class AddSensorReadingsWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
    }

    /**
     * Initialize the workload module
     */
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

        this.workerIndex = workerIndex;
        this.totalWorkers = totalWorkers;
        this.roundIndex = roundIndex;
        this.batchSize = roundArguments.batchSize || 5;
    }

    /**
     * Generate random sensor reading data
     */
    generateSensorReading(sensorID) {
        return {
            SensorID: sensorID,
            Temp: (Math.random() * 15 + 20).toFixed(2),        // 20-35°C
            Salinity: (Math.random() * 10 + 30).toFixed(2),   // 30-40 ppt
            PH: (Math.random() * 2 + 6).toFixed(2),            // 6-8 pH
            NH4: (Math.random() * 0.5).toFixed(2),             // 0-0.5 mg/L
            DO: (Math.random() * 5 + 5).toFixed(2),            // 5-10 mg/L
            CA: (Math.random() * 100 + 100).toFixed(2)         // 100-200 mg/L
        };
    }

    /**
     * Submit a transaction to add batch sensor readings
     * SDK Connector Version - No explicit channel parameter
     */
    async submitTransaction() {
        this.txIndex++;

        const timestamp = Date.now().toString();
        const sensorIDBase = `sensor-${this.workerIndex}-${this.txIndex}`;

        // Generate batch of sensor readings
        const readings = [];
        for (let i = 0; i < this.batchSize; i++) {
            const sensorID = `${sensorIDBase}-${i}`;
            readings.push(this.generateSensorReading(sensorID));
        }

        const jsonData = JSON.stringify(readings);

        // SDK connector request format - channel is handled by connector
        const request = {
            contractId: 'SensorContract',
            contractFunction: 'addBatchSensorReadings',
            invokerIdentity: 'User1',
            contractArguments: [jsonData, timestamp],
            readOnly: false
        };

        await this.sutAdapter.sendRequests(request);
    }

    /**
     * Clean up the workload module
     */
    async cleanupWorkloadModule() {
        // No cleanup needed
    }
}

/**
 * Create a new instance of the workload module
 */
function createWorkloadModule() {
    return new AddSensorReadingsWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
