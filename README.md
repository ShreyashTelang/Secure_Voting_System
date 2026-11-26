# SecureVote

**A cryptographically protected electronic voting system.**  
*Integrating RSA Public-Key Cryptography, HMAC-SHA256, and Fault-Tolerant Application Architecture to guarantee Confidentiality, Integrity, and Availability.*

---

## 1. Product Overview

**SecureVote** is a production-style electronic voting web application designed with a modern, minimal, enterprise-grade aesthetic. It cleanly separates the voter journey from an in-depth **Security Center** that exposes the cryptographic pipeline without looking like an academic slideshow or artificial dashboard.

### Core Security Guarantees:
- **Confidentiality:** Achieved using **RSA Public-Key Cryptography** ($C = M^e \bmod n$). Only the Election Authority holding the private exponent $d$ can recover ballot choices.
- **Integrity & Authentication:** Achieved using **HMAC-SHA256** (RFC 2104). Every ballot is authenticated with a 256-bit tag using the voter's shared secret key. Any alteration in transit triggers immediate tag mismatch and safe rejection.
- **Availability:** Achieved through **resilient application design**, schema validation, duplicate-voting prevention, and graceful error handling without stack trace leakage.

---

## 2. Technology Stack

- **Backend:** Python 3 (Tested on Python 3.10+) with Flask 3.x
- **Database:** SQLite 3 (ACID-compliant storage located in `instance/securevote.db`)
- **Cryptography:**
  - Python `hmac` & `hashlib` (RFC 2104 / FIPS 198-1 standard)
  - Python `secrets` (Cryptographically secure pseudo-random numbers)
  - Custom modular exponentiation engine (`pow(base, exp, mod)`)
- **Frontend:** Vanilla HTML5, Clean Modern CSS3 (Fintech / Enterprise Security design system), and Vanilla JavaScript (No heavy frameworks)

---

## 3. Architecture & Modular Structure

```
Voting_System/
├── app.py                      # Flask Application Controller & Route Handlers
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
├── README.md                   # System documentation & evaluation guide
├── test_system.py              # Automated 6-point test suite
│
├── crypto/                     # Cryptographic Security Layer
│   ├── __init__.py
│   ├── rsa.py                  # Modular arithmetic, key generation, encryption/decryption
│   ├── hmac_sha256.py          # RFC 2104 padding, constant-time compare, avalanche simulator
│   └── key_manager.py          # Hybrid key transport & ballot envelope packaging
│
├── services/                   # Business Logic & Orchestration
│   ├── __init__.py
│   ├── voting_service.py       # Ballot formulation, validation, and submission
│   ├── election_service.py     # Candidate management and certified result tallies
│   └── security_service.py     # CIA health monitoring and audit event logging
│
├── database/                   # Persistence Layer
│   ├── __init__.py
│   ├── db.py                   # SQLite connection helpers and salted password hashing
│   └── schema.sql              # Database DDL schema
│
├── static/                     # Frontend Assets
│   ├── css/
│   │   └── style.css           # Restrained, accessible enterprise styling
│   └── js/
│       ├── app.js              # Core UI interactions & flash handling
│       ├── rsa.js              # Interactive RSA mathematical visualizer
│       └── security.js         # Security pipeline animation & tamper test sandbox
│
├── templates/                  # Jinja2 Templates
│   ├── base.html               # Clean master layout
│   ├── index.html              # Landing page
│   ├── login.html              # Voter authentication
│   ├── register.html           # Voter registration & HMAC key issuance
│   ├── election.html           # Election overview & candidate selection
│   ├── vote-review.html        # Ballot review & live processing pipeline
│   ├── vote-success.html       # Official confirmation receipt
│   ├── security.html           # Security Center home (CIA overview & hybrid flow)
│   ├── rsa.html                # Dedicated RSA mathematical panel
│   ├── hmac.html               # Dedicated HMAC-SHA256 authentication panel
│   ├── integrity-demo.html     # Dedicated Tampering Demonstration sandbox
│   ├── availability.html       # System availability & resilience dashboard
│   └── results.html            # Certified election tallies & ballot ledger
│
└── instance/
    └── securevote.db           # SQLite database file
```

---

## 4. Quick Start & Execution

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run the Automated Test Suite
```bash
python test_system.py
```
*Expected Output:*
```
Ran 6 tests in 2.371s
OK
✓ Test 01 Passed: RSA Mathematical Derivation & Modular Exponentiation Verified.
✓ Test 02 Passed: HMAC-SHA256 RFC 2104 & Avalanche Metrics Verified.
✓ Test 03 Passed: Hybrid Key Management (RSA Session Key Transport) Verified.
✓ Test 04 Passed: All 10 Core Application Web Routes Returned HTTP 200 OK.
✓ Test 05 Passed: Complete Voting Workflow & Duplicate-Vote Prevention Verified.
✓ Test 06 Passed: Active Tampering Attack Detected & Ballot Safely Rejected.
```

### Step 3: Launch the Web Application
```bash
python app.py
```
Open your browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

---

## 5. Demonstration Walkthrough

### Pre-Configured Demonstration Accounts:
- **`voter1`** | Password: `VoterPass123!` (Sarah Jenkins &bull; `VTR-2026-081`)
- **`voter2`** | Password: `VoterPass123!` (Michael Torres &bull; `VTR-2026-144`)
- **`auditor`** | Password: `AuditPass123!` (Dr. Robert Vance &bull; `AUD-2026-001`)

*(Autofill buttons are available on the Sign In page for rapid evaluation).*

---

### A. The Voter Journey
1. **Enter Election (`/election`):** View the active election (*Student Council General Election 2026*) and candidate platforms.
2. **Select Candidate:** Click on any candidate (e.g. **Elena Rostova**) and click **Review Selected Candidate**.
3. **Review Ballot (`/vote/review`):** Inspect the ballot summary.
4. **Cast Vote Securely:** Click **Cast Vote Securely**. The interface displays the live 6-stage security pipeline:
   $$\text{Vote Created} \longrightarrow \text{RSA Protection} \longrightarrow \text{HMAC-SHA256} \longrightarrow \text{Secure Request} \longrightarrow \text{Server Verification} \longrightarrow \text{Vote Accepted}$$
5. **Vote Success (`/vote/success`):** Review the transaction reference ID (e.g. `TXN-8F92-4C10-E7A1`) and cryptographic verification checklist.

---

### B. Demonstrating the 3 Security Goals (CIA Triad)

Navigate to the **Security Center** (`/security`):

#### 1. Confidentiality (RSA Public-Key Cryptography)
- Go to `/security/rsa`.
- Point out the active parameters: $p=61, q=53 \implies n=3233, \phi(n)=3120, e=17, d=2753$.
- Point out the clear distinction between **PUBLIC KEY $(17, 3233)$** and **PRIVATE KEY $(2753, 3233)$**.
- Test the interactive mathematical calculator:
  - Input $M = 42 \implies C = 42^{17} \bmod 3233 = 2557$.
  - Decrypt $C = 2557 \implies M = 2557^{2753} \bmod 3233 = 42$.
- Explain: RSA protects sensitive ballot information and session keys. Eavesdroppers intercepting ciphertext cannot read the choice without private exponent $d$.

#### 2. Integrity & Authentication (HMAC-SHA256)
- Go to `/security/hmac`.
- Review the RFC 2104 mathematical construction:
  $$\text{HMAC}(K, M) = \text{SHA-256}\Big((K' \oplus 0x5C) \;\|\; \text{SHA-256}\big((K' \oplus 0x36) \;\|\; M\big)\Big)$$
- Inspect the 5-step intermediate breakdown showing $K'$, inner pad $K' \oplus 0x36$, inner hash, outer pad $K' \oplus 0x5C$, and the final 256-bit authentication tag.
- Explain: HMAC binds the ballot to the voter's shared secret. Constant-time verification (`hmac.compare_digest`) prevents timing attacks.

#### 3. Availability (Reliable System Design)
- Go to `/security/availability`.
- Inspect the real-time operational status of all 4 services:
  - Voting Service: Operational
  - Database Storage: Operational (ACID SQLite)
  - Cryptographic Layer: Operational (RSA & HMAC engines)
  - Election Registry: Open
- Demonstrate:
  - **Duplicate Voting Prevention:** Attempting to vote twice returns a structured error: *"Vote already recorded. You cannot submit another vote."* The system remains 100% operational rather than crashing.
  - **Malformed Request Handling:** Sending malformed data returns a safe HTTP 400 Bad Request.
  - Core principle: *Availability is supported by reliable application design, schema validation, and fault isolation—not by RSA or HMAC themselves.*

---

### C. Demonstrating Vote Tampering (Active MITM Attack)
1. Sign in as **`voter2`** (Password: `VoterPass123!`).
2. Go to `/election` and choose **Elena Rostova**.
3. On `/vote/review`, click the red button: **"Simulate Packet Tampering (Test Defense)"**.
4. The system executes the following:
   - An adversary intercepts the packet in transit.
   - The candidate choice is flipped from **Elena Rostova** to **Marcus Vance**, but the original HMAC tag is left unchanged.
   - The server recomputes $\text{HMAC-SHA256}(K, \text{tampered\_payload})$.
   - The received tag does not match the recalculated tag.
5. The server immediately halts and displays:
   ```
   ✕ Request Rejected: Integrity Check Failed
   Request integrity check failed. The vote was not stored.
   Received HMAC Tag:     2a979ceb3620...
   Recalculated HMAC Tag: 7f814de102a9...
   Tag Match Result:      FALSE (MISMATCH)
   Server Decision:       REJECT VOTE IMMEDIATELY
   ```
6. Check `/results` to confirm the tampered ballot was **never recorded**.

---

### D. Demonstrating Hybrid Key Management
In `/security`, review the **Hybrid Key Transport** visualizer:
$$\text{Generate Session Key} \longrightarrow \text{RSA Public Key} \longrightarrow \text{Encrypted Key} \longrightarrow \text{Server} \longrightarrow \text{RSA Private Key} \longrightarrow \text{Recovered Key}$$
$$\text{Vote Payload} + \text{Session Key} \longrightarrow \text{HMAC-SHA256} \longrightarrow \text{Authentication Tag}$$
- **RSA protects the key** (Confidentiality).
- **HMAC protects the message** (Integrity & Authentication).

---

## 6. Official Results Ledger (`/results`)
- Candidate vote counts, percentage progress bars, and total ballots cast.
- Cryptographic Ballot Box Ledger showing anonymous SHA-256 voter hashes, candidate IDs, encrypted payload snippets, and HMAC-SHA256 tags.
- Voter identities are strictly decoupled from vote choices (Ballot Secrecy).
- An administrative reset button is available to reset all ballots for repeat demonstrations.
