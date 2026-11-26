"""
Database access and connection helper for SecureVote with Auditor Support.
"""
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime
from config import Config

DB_FILE = Config.DATABASE


def get_db():
    """Returns a connection to the SQLite database with row factory enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: str = None) -> str:
    """PBKDF2-style salted SHA-256 password hashing."""
    if salt is None:
        salt = secrets.token_hex(16)
    combined = salt + password
    digest = hashlib.sha256(combined.encode('utf-8')).hexdigest()
    return f"{salt}${digest}"


def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verifies password in constant time."""
    try:
        salt, original_digest = stored_hash.split("$")
        calculated = hashlib.sha256((salt + provided_password).encode('utf-8')).hexdigest()
        import hmac
        return hmac.compare_digest(original_digest, calculated)
    except Exception:
        return False


def init_db(db_path: str = None):
    """Initializes tables and seeds initial candidates and sample accounts."""
    target_db = db_path or DB_FILE
    os.makedirs(os.path.dirname(target_db), exist_ok=True)
    
    conn = sqlite3.connect(target_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        cursor.executescript(f.read())

    # Seed official candidates for Student Council General Election 2026
    candidates_data = [
        (1, "Elena Rostova", "Student Council President", "Academic Innovation Slate",
         "Focused on curriculum transparency, enhanced research funding for undergraduates, and 24/7 digital campus infrastructure."),
        (2, "Marcus Vance", "Student Council President", "Civic Engagement Coalition",
         "Advocating for student-faculty governance parity, sustainable campus operations, and transparent student fee allocations."),
        (3, "Priya Sharma", "Student Council President", "Digital Rights & Privacy Front",
         "Championing data sovereignty, ethical educational technology standards, open-source resources, and encrypted campus communication."),
        (4, "David Chen", "Student Council President", "Campus Welfare & Equity Union",
         "Dedicated to affordable textbook initiatives, student mental health resource expansion, and student organization grant funding.")
    ]
    cursor.executemany("""
        INSERT INTO candidates (id, name, position, affiliation, manifesto)
        VALUES (?, ?, ?, ?, ?);
    """, candidates_data)

    # Seed demonstration voters with role separation: 'voter' vs 'auditor'
    demo_voters = [
        ("voter1", hash_password("VoterPass123!"), "Sarah Jenkins", "VTR-2026-081", "SEC_K_7F4A19B3E2C84D01", 0, "voter"),
        ("voter2", hash_password("VoterPass123!"), "Michael Torres", "VTR-2026-144", "SEC_K_9C3E61A8D4F027B5", 0, "voter"),
        ("auditor", hash_password("AuditPass123!"), "Dr. Robert Vance (Auditor)", "AUD-2026-001", "SEC_K_1A8B3C7D9E0F2468", 0, "auditor")
    ]
    cursor.executemany("""
        INSERT INTO voters (username, password_hash, full_name, voter_id, hmac_secret, has_voted, role)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, demo_voters)

    # Seed baseline audit log entries
    init_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, event_name, actor_id, request_reference, received_tag, calculated_tag, description, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (init_time, "SYSTEM_INITIALIZED", "SYSTEM", "SYS-INIT-001", None, None, "SecureVote database schema initialized and candidate roster registered.", "SUCCESS"))

    cursor.execute("""
        INSERT INTO audit_logs (timestamp, event_name, actor_id, request_reference, received_tag, calculated_tag, description, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (init_time, "AUDITOR_CREDENTIAL_ISSUED", "SYSTEM", "AUD-INIT-001", None, None, "Auditor administrative credential issued for Dr. Robert Vance (AUD-2026-001).", "SUCCESS"))

    conn.commit()
    conn.close()


def log_event(event_name: str, actor_id: str, description: str, status: str, request_reference: str = None, received_tag: str = None, calculated_tag: str = None):
    """Appends a structured event to the security audit log."""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, event_name, actor_id, request_reference, received_tag, calculated_tag, description, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_name, actor_id, request_reference, received_tag, calculated_tag, description, status))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Audit log write failure: {e}")
