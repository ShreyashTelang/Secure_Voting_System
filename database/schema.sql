-- SecureVote Enterprise Schema with Auditor Support

DROP TABLE IF EXISTS voters;
DROP TABLE IF EXISTS candidates;
DROP TABLE IF EXISTS votes;
DROP TABLE IF EXISTS audit_logs;

CREATE TABLE voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    voter_id TEXT UNIQUE NOT NULL,
    hmac_secret TEXT NOT NULL,
    has_voted INTEGER DEFAULT 0,
    role TEXT DEFAULT 'voter',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE candidates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    position TEXT NOT NULL,
    affiliation TEXT NOT NULL,
    manifesto TEXT NOT NULL
);

CREATE TABLE votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference_id TEXT UNIQUE NOT NULL,
    voter_hash TEXT UNIQUE NOT NULL,
    candidate_id INTEGER NOT NULL,
    encrypted_vote TEXT NOT NULL,
    hmac_tag TEXT NOT NULL,
    rsa_status TEXT DEFAULT 'PROTECTED',
    hmac_status TEXT DEFAULT 'VERIFIED',
    eligibility_check TEXT DEFAULT 'PASSED',
    duplicate_check TEXT DEFAULT 'PASSED',
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACCEPTED',
    FOREIGN KEY (candidate_id) REFERENCES candidates(id)
);

CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_name TEXT NOT NULL,
    actor_id TEXT,
    request_reference TEXT,
    received_tag TEXT,
    calculated_tag TEXT,
    description TEXT NOT NULL,
    status TEXT NOT NULL
);
