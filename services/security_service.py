"""
Security service for SecureVote.
Manages system availability checks, security event audit trail, and cryptographic inspections.
"""
import time
from typing import Dict, Any, List
from database.db import get_db
from crypto.rsa import rsa_engine
from crypto.hmac_sha256 import HMACSHA256
from services.election_service import ElectionService


class SecurityService:
    """Provides CIA status monitoring, security timelines, and interactive cryptographic inspects."""

    @staticmethod
    def get_system_availability() -> Dict[str, Any]:
        """
        Assesses real-time operational availability across all system components.
        Demonstrates that Availability is maintained through reliable design, error handling,
        and fault isolation.
        """
        # Test Database Service
        db_operational = False
        db_latency_ms = 0
        try:
            t0 = time.time()
            conn = get_db()
            conn.execute("SELECT 1;").fetchone()
            conn.close()
            db_latency_ms = round((time.time() - t0) * 1000, 2)
            db_operational = True
        except Exception:
            db_operational = False

        # Test Cryptographic Engine (Active RSA & HMAC self-test)
        crypto_operational = False
        try:
            test_m = 42
            c = pow(test_m, rsa_engine.e, rsa_engine.n)
            m_rec = pow(c, rsa_engine.d, rsa_engine.n)
            test_hmac = HMACSHA256.generate("TEST_KEY", "TEST_MSG")
            crypto_operational = (m_rec == test_m) and (len(test_hmac) == 64)
        except Exception:
            crypto_operational = False

        election_info = ElectionService.get_election_details()

        return {
            "services": [
                {
                    "name": "Voting Service",
                    "status": "Operational",
                    "description": "Receives vote packets, validates schemas, and orchestrates transaction lifecycle.",
                    "is_healthy": True
                },
                {
                    "name": "Database Storage (SQLite)",
                    "status": "Operational" if db_operational else "Degraded",
                    "latency": f"{db_latency_ms} ms",
                    "description": "Persistent ACID storage enforcing unique voter hash single-vote constraints.",
                    "is_healthy": db_operational
                },
                {
                    "name": "Cryptographic Layer",
                    "status": "Operational" if crypto_operational else "Error",
                    "description": "RSA modular exponentiation and RFC 2104 HMAC-SHA256 mathematical engines.",
                    "is_healthy": crypto_operational
                },
                {
                    "name": "Election Registry",
                    "status": election_info["status"],
                    "description": f"{election_info['title']} - Candidate registry and tally ledger.",
                    "is_healthy": (election_info["status"] == "OPEN")
                }
            ],
            "availability_rationale": "Availability is supported by reliable application design, schema validation, duplicate-voting prevention, and graceful error handling—not by RSA or HMAC themselves."
        }

    @staticmethod
    def get_security_timeline(limit: int = 25) -> List[Dict[str, Any]]:
        """Retrieves chronological audit events for security inspection."""
        conn = get_db()
        rows = conn.execute("""
            SELECT id, timestamp, event_name, actor_id, description, status
            FROM audit_logs
            ORDER BY id DESC LIMIT ?;
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_cia_overview() -> Dict[str, Any]:
        """Provides the high-level Confidentiality, Integrity, and Availability summary."""
        conn = get_db()
        vote_count = conn.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]
        tamper_events = conn.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED';").fetchone()["count"]
        conn.close()

        availability = SecurityService.get_system_availability()
        all_services_healthy = all(s["is_healthy"] for s in availability["services"])

        return {
            "confidentiality": {
                "name": "Confidentiality",
                "primitive": "RSA Public-Key Cryptography",
                "mechanism": "Asymmetric modular exponentiation (C = M^e mod n)",
                "status": "Protected",
                "is_active": True,
                "description": "Voter choices are encrypted with the Election Authority public key prior to transmission. An eavesdropper intercepting the traffic cannot recover the ballot choice without the private key d."
            },
            "integrity": {
                "name": "Integrity & Authentication",
                "primitive": "HMAC-SHA256 (RFC 2104)",
                "mechanism": "Keyed-hash with inner/outer padding masks and constant-time verification",
                "status": "Verified",
                "tamper_attempts_blocked": tamper_events,
                "is_active": True,
                "description": "Every submitted ballot carries a 256-bit authentication tag calculated using the voter's shared secret. Any modification to the ballot in transit triggers immediate verification failure."
            },
            "availability": {
                "name": "Availability",
                "primitive": "Reliable Application Architecture",
                "mechanism": "Fault isolation, input validation, duplicate prevention, and operational monitoring",
                "status": "Operational" if all_services_healthy else "Degraded",
                "is_active": all_services_healthy,
                "total_votes_recorded": vote_count,
                "description": "Ensures uninterrupted voting operations through duplicate-voting rejection, sanitization of malformed payloads, and resilient error recovery without crashing."
            }
        }
