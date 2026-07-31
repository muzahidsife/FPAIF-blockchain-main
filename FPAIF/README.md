# Framework for AI Agent Identification (FPAIF)

**Research Prototype — v2.0**  
Department of Software Engineering, Daffodil International University  

---

## Overview

FPAIF is a prototype implementation of a framework for identifying and authenticating autonomous AI agents in multi-agent environments. The system combines Decentralized Identifiers (DID), SHA-256 Verifiable Credentials, Attribute-Based Access Control (ABAC), and session management to provide a structured identity layer for AI agents.

This repository serves as the experimental prototype for the accompanying research paper. All metrics reported in the paper were collected by running `run_tests.py` against this implementation.

---

## Repository Structure

```
FPAIF/
├── app.py              # FastAPI server — endpoints for registration, authentication, gateway
├── db.py               # SQLite database and metrics logging
├── identity.py         # DID generation and SHA-256 Verifiable Credentials
├── trust.py            # ABAC policy engine
├── run_tests.py        # Full metric test suite (13 metrics)
├── metrics_numbers.json# Test output — raw numbers used in the paper
├── requirements.txt
└── templates/
    └── audit_logs.html
```

---

## System Design

The framework operates through a three-stage pipeline:

1. **Registration** — Each agent is assigned a unique DID and a SHA-256 credential hash.
2. **Authentication** — Agents authenticate by presenting their DID and credential hash. On success, a time-limited session token is issued.
3. **Gateway Access** — Protected resources are accessed via the session token, which is validated on every request.

All events are logged to a local SQLite database with timestamps, enabling post-hoc audit and metric extraction.

---

## Running the Prototype

**Requirements**

```
pip install -r requirements.txt
```

**Start the server**

```
uvicorn app:app --reload
```

**Run the full test suite** (in a second terminal)

```
python run_tests.py
```

Results are printed to the terminal and saved to `metrics_numbers.json`.

**Custom user count**

```
python run_tests.py --users 1000
```

---

## Web Interface

| Route             | Description                        |
|-------------------|------------------------------------|
| `/`               | Home page                          |
| `/register_agent` | Agent registration form            |
| `/audit_logs`     | Audit log viewer with timing data  |
| `/docs`           | Swagger API documentation          |
| `/test_flow`      | Quick end-to-end flow test         |
| `/api/audit_logs` | Audit logs in JSON format          |

---

## Metrics Evaluated

The test suite covers 13 metrics used in the paper's evaluation section:

| #  | Metric                           | Test Method                                          |
|----|----------------------------------|------------------------------------------------------|
| 1  | Auth Success Rate                | 80 valid credentials + 20 invalid, success counted  |
| 2  | Auth Failure Rate                | Same batch, failures counted                        |
| 3  | Auth Time (ms)                   | Measured per call using `time.time()`               |
| 4  | Authorized vs Unauthorized Ratio | Controlled access attempts with mixed roles         |
| 5  | DDoS Block Rate                  | 200 rapid requests from a single attacker IP        |
| 6  | Session Hijacking Denial Rate    | 50 fabricated session tokens submitted to gateway   |
| 7  | Audit Log Write Latency (ms)     | Server-side measurement of database write time      |
| 8  | Auth Time by Agent Name Length   | 4 scenarios: 15, 42, 89, 161 character names        |
| 9  | Encryption Algorithm             | SHA-256 hash output verified                        |
| 10 | Load — Registration (1000 users) | Concurrent registrations via ThreadPoolExecutor     |
| 11 | Load — Auth Throughput (req/sec) | Concurrent authentications after bulk registration  |
| 12 | Load — Response Time Under Load  | Min / Avg / Median / P95 / Max                      |
| 13 | Session Token Expiry             | `expires_at` field tracked and validated per token  |

> **Note on Auth Success Rate:** The 80% success rate is intentional by design. The test submits 80 requests with valid credentials and 20 with deliberately incorrect credentials. This is a controlled evaluation scenario, not a system limitation. It is documented as such in the paper.

---

## Test Results

The following results were obtained by running `run_tests.py` on a 4-core GitHub Codespaces environment.

### Authentication

| Metric                  | Value     |
|-------------------------|-----------|
| Auth Success Rate       | 80.0%     |
| Auth Failure Rate       | 20.0%     |
| Auth Time — Min         | 1.798 ms  |
| Auth Time — Avg         | 2.72 ms   |
| Auth Time — Median      | 2.584 ms  |
| Auth Time — P95         | 4.189 ms  |
| Auth Time — Max         | 6.494 ms  |

### Security

| Metric                        | Value         |
|-------------------------------|---------------|
| DDoS Block Rate               | 97.5%         |
| Requests Blocked / Total      | 195 / 200     |
| Session Hijacking Denial Rate | 100.0%        |
| Avg Hijack Detection Time     | 2.313 ms      |
| Authorized Accesses           | 20            |
| Unauthorized Attempts         | 20            |

### Audit Logging

| Metric              | Value      |
|---------------------|------------|
| Log Time — Min      | 0.0002 ms  |
| Log Time — Avg      | 0.0012 ms  |
| Log Time — Max      | 0.037 ms   |

### Auth Time by Agent Name Length

| Agent Type    | Name Length | Avg Auth Time |
|---------------|-------------|---------------|
| Normal Agent  | 15 chars    | 2.592 ms      |
| Medium Agent  | 42 chars    | 3.116 ms      |
| Big Agent     | 89 chars    | 3.439 ms      |
| Giant Agent   | 161 chars   | 4.452 ms      |

### Load Test (1000 Concurrent Users)

| Metric                         | Value        |
|--------------------------------|--------------|
| Registration Success Rate      | 100.0%       |
| Registration Throughput        | 404.9 reg/s  |
| Registration Avg Time          | 188.99 ms    |
| Authentication Success Rate    | 100.0%       |
| Authentication Throughput      | 408.2 req/s  |
| Authentication Avg Time        | 76.37 ms     |

### Encryption

| Property              | Value   |
|-----------------------|---------|
| Algorithm             | SHA-256 |
| Credential Hash Length| 64 chars|


## Prototype Archive

Zenodo DOI: [10.5281/zenodo.20354949](https://doi.org/10.5281/zenodo.20354949)
