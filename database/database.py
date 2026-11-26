"""
=============================================================================
Module: database/database.py
Project: Secure Electronic Voting System using RSA and HMAC-SHA256
Course: Cryptography and Information Security (CIS) End Semester Examination

Description:
    SQLite database management for voters, candidates, encrypted vote ledgers,
    and security audit logging. Employs salted SHA-256 password hashing.
=============================================================================
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "voting.db")


def hash_password(password: str, salt: str = None) -> str:
    """
    Secure password hashing using SHA-256 with a unique random salt.
    Format stored: salt$hash
    Clearly distinguished from HMAC (which uses a secret key to authenticate messages).
    """
    if salt is None:
        salt = secrets.token_hex(16)
    combined = salt + password
    digest = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return f"{salt}${digest}"


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verify provided password against stored salt$hash."""
    try:
        salt, original_digest = stored_hash.split("$")
        calculated = hashlib.sha256((salt + provided_password).encode('utf-8')).hexdigest()
        import hmac
        return hmac.compare_digest(original_digest, calculated)
    except Exception:
        return False


def get_db_connection():
    """Create a database connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables and seed initial candidates and demo accounts."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        voter_id TEXT UNIQUE NOT NULL,
        hmac_secret TEXT NOT NULL,
        has_voted INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Candidates Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS candidates (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        party TEXT NOT NULL,
        symbol TEXT NOT NULL,
        manifesto TEXT
    );
    """)

    # 3. Votes Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        voter_hash TEXT UNIQUE NOT NULL,
        encrypted_vote TEXT NOT NULL,
        hmac_tag TEXT NOT NULL,
        candidate_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (candidate_id) REFERENCES candidates(id)
    );
    """)

    # 4. Security Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        voter_id TEXT,
        details TEXT,
        status TEXT
    );
    """)

    # Seed Candidates if empty
    cursor.execute("SELECT COUNT(*) as count FROM candidates;")
    if cursor.fetchone()["count"] == 0:
        candidates_data = [
            (1, "Alice Johnson", "Cyber Freedom Party", "🛡️", "Advocating for digital rights, end-to-end encryption, and open cybersecurity standards."),
            (2, "Bob Smith", "Digital Privacy Alliance", "🔒", "Promoting data protection laws, algorithmic transparency, and citizen privacy protections."),
            (3, "Charlie Davis", "Tech Innovation Coalition", "⚡", "Fostering blockchain, secure cloud infrastructure, and quantum-resistant cryptography."),
            (4, "Diana Prince", "Open Democracy Forum", "🌐", "Ensuring verifiable voting protocols, open source public systems, and cybersecurity education.")
        ]
        cursor.executemany("""
            INSERT INTO candidates (id, name, party, symbol, manifesto)
            VALUES (?, ?, ?, ?, ?);
        """, candidates_data)

    # Seed Default Demonstration Users if empty
    cursor.execute("SELECT COUNT(*) as count FROM users;")
    if cursor.fetchone()["count"] == 0:
        demo_users = [
            ("student1", hash_password("Password@123"), "VOTER-101", "SecretKey_Voter101", 0),
            ("student2", hash_password("Password@123"), "VOTER-102", "SecretKey_Voter102", 0),
            ("examiner", hash_password("Examiner@2026"), "VOTER-999", "SecretKey_Examiner999", 0)
        ]
        cursor.executemany("""
            INSERT INTO users (username, password_hash, voter_id, hmac_secret, has_voted)
            VALUES (?, ?, ?, ?, ?);
        """, demo_users)

        # Log system initialization in audit log
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, event_type, voter_id, details, status)
            VALUES (?, ?, ?, ?, ?);
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SYSTEM_INIT", "SYSTEM", "Database initialized with seed candidates and demo accounts.", "SUCCESS"))

    conn.commit()
    conn.close()


def log_security_event(event_type: str, voter_id: str, details: str, status: str):
    """Insert a security event into audit logs."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, event_type, voter_id, details, status)
            VALUES (?, ?, ?, ?, ?);
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type, voter_id, details, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging security event: {e}")


def get_all_candidates():
    """Retrieve all candidate records."""
    conn = get_db_connection()
    candidates = conn.execute("SELECT * FROM candidates ORDER BY id ASC;").fetchall()
    conn.close()
    return candidates


def get_user_by_username(username: str):
    """Retrieve user record by username."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
    conn.close()
    return user


def get_user_by_voter_id(voter_id: str):
    """Retrieve user record by voter ID."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE voter_id = ?;", (voter_id,)).fetchone()
    conn.close()
    return user


def record_vote(voter_id: str, encrypted_vote: str, hmac_tag: str, candidate_id: int, timestamp: str) -> bool:
    """
    Store vote in SQLite database.
    Calculates pseudonymous voter_hash = SHA256(voter_id + election_salt)
    to enforce strictly one vote per voter without linking ballot to identity.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Pseudonymous hash for voter
    voter_hash = hashlib.sha256(f"ELECTION_SALT_{voter_id}".encode('utf-8')).hexdigest()

    try:
        cursor.execute("""
            INSERT INTO votes (voter_hash, encrypted_vote, hmac_tag, candidate_id, timestamp)
            VALUES (?, ?, ?, ?, ?);
        """, (voter_hash, encrypted_vote, hmac_tag, candidate_id, timestamp))

        cursor.execute("""
            UPDATE users SET has_voted = 1 WHERE voter_id = ?;
        """, (voter_id,))

        conn.commit()
        conn.close()
        log_security_event("VOTE_RECORDED", voter_id, f"Vote recorded with HMAC tag: {hmac_tag[:16]}...", "SUCCESS")
        return True
    except sqlite3.IntegrityError:
        conn.close()
        log_security_event("DOUBLE_VOTING_BLOCKED", voter_id, "Voter has already cast a ballot. Duplicate rejected.", "FAILED")
        return False
    except Exception as e:
        conn.close()
        log_security_event("VOTE_ERROR", voter_id, str(e), "FAILED")
        return False


def get_election_results():
    """
    Retrieve candidate vote tallies and breakdown.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get candidate tallies
    tallies = cursor.execute("""
        SELECT c.id, c.name, c.party, c.symbol, COUNT(v.id) as vote_count
        FROM candidates c
        LEFT JOIN votes v ON c.id = v.candidate_id
        GROUP BY c.id, c.name, c.party, c.symbol
        ORDER BY vote_count DESC, c.id ASC;
    """).fetchall()

    total_votes = cursor.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]

    recent_votes = cursor.execute("""
        SELECT id, voter_hash, encrypted_vote, hmac_tag, candidate_id, timestamp
        FROM votes
        ORDER BY id DESC LIMIT 10;
    """).fetchall()

    audit_logs = cursor.execute("""
        SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20;
    """).fetchall()

    conn.close()
    return {
        "tallies": tallies,
        "total_votes": total_votes,
        "recent_votes": recent_votes,
        "audit_logs": audit_logs
    }


def reset_election_data():
    """Reset votes and voter voting status for repeated ESE demonstrations."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM votes;")
    cursor.execute("UPDATE users SET has_voted = 0;")
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, event_type, voter_id, details, status)
        VALUES (?, ?, ?, ?, ?);
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ELECTION_RESET", "ADMIN", "All votes cleared for new demonstration run.", "SUCCESS"))
    conn.commit()
    conn.close()
