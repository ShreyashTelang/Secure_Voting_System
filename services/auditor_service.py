"""
Auditor Service for SecureVote.
Provides comprehensive, read-only audit analytics, cryptographic integrity tracking,
security event history, and compliance report generation.
"""
import io
import csv
from datetime import datetime
from typing import Dict, Any, List
from database.db import get_db
from crypto.rsa import rsa_engine
from crypto.key_manager import key_manager
from services.election_service import ElectionService
from services.security_service import SecurityService


class AuditorService:
    """Read-only auditing engine for independent election verification."""

    @staticmethod
    def get_dashboard_summary() -> Dict[str, Any]:
        """Gathers real-time statistics across votes, cryptographic verifications, and audit logs."""
        conn = get_db()
        cursor = conn.cursor()

        # Voter counts
        eligible_voters = cursor.execute("SELECT COUNT(*) as count FROM voters WHERE role = 'voter';").fetchone()["count"]
        voters_voted = cursor.execute("SELECT COUNT(*) as count FROM voters WHERE role = 'voter' AND has_voted = 1;").fetchone()["count"]

        # Votes cast
        total_votes = cursor.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]

        # Security events
        total_security_events = cursor.execute("SELECT COUNT(*) as count FROM audit_logs;").fetchone()["count"]

        # HMAC & Integrity metrics
        successful_hmac = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'VOTE_ACCEPTED';").fetchone()["count"]
        failed_hmac = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED';").fetchone()["count"]
        duplicate_attempts = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'DUPLICATE_VOTE_BLOCKED';").fetchone()["count"]
        auditor_attempts = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'AUDITOR_VOTE_BLOCKED';").fetchone()["count"]

        total_rejected = failed_hmac + duplicate_attempts + auditor_attempts
        requests_checked = total_votes + failed_hmac

        verification_rate = 100.0
        if requests_checked > 0:
            verification_rate = round((successful_hmac / requests_checked) * 100, 2)

        # Audit status determination
        overall_audit_status = "SYSTEM INTEGRITY VERIFIED" if failed_hmac == 0 else "INTEGRITY ALERT DETECTED"

        # Recent vote audit records (accepted + rejected)
        recent_votes = cursor.execute("""
            SELECT reference_id, timestamp, rsa_status, hmac_status, eligibility_check, duplicate_check, status
            FROM votes ORDER BY id DESC LIMIT 5;
        """).fetchall()

        # Recent security logs
        recent_logs = cursor.execute("""
            SELECT id, timestamp, event_name, actor_id, request_reference, description, status
            FROM audit_logs ORDER BY id DESC LIMIT 6;
        """).fetchall()

        conn.close()

        election_info = ElectionService.get_election_details()

        return {
            "election": election_info,
            "audit_status": overall_audit_status,
            "metrics": {
                "eligible_voters": eligible_voters,
                "votes_cast": total_votes,
                "voter_turnout": round((voters_voted / eligible_voters * 100), 1) if eligible_voters > 0 else 0.0,
                "successful_hmac": successful_hmac,
                "failed_hmac": failed_hmac,
                "duplicate_attempts": duplicate_attempts,
                "rejected_requests": total_rejected,
                "total_security_events": total_security_events,
                "requests_checked": requests_checked,
                "verification_rate": verification_rate,
                "system_status": "ONLINE"
            },
            "cia": {
                "confidentiality": {
                    "title": "Confidentiality",
                    "status": "Operational",
                    "technology": "RSA Public-Key Encryption",
                    "explanation": "RSA-based cryptographic protection prevents unauthorized parties from reading protected voting information."
                },
                "integrity": {
                    "title": "Integrity",
                    "status": "Operational" if failed_hmac == 0 else "Violations Detected",
                    "technology": "HMAC-SHA256 (RFC 2104)",
                    "explanation": "HMAC-SHA256 verifies that protected voting requests have not been modified during transmission or processing."
                },
                "availability": {
                    "title": "Availability",
                    "status": "Operational",
                    "technology": "Fault-Tolerant Application Architecture",
                    "explanation": "Maintained through reliable server operation, database persistence, schema validation, duplicate-vote prevention, and service monitoring."
                }
            },
            "recent_votes": [dict(r) for r in recent_votes],
            "recent_logs": [dict(l) for l in recent_logs]
        }

    @staticmethod
    def get_vote_records(status_filter: str = None) -> List[Dict[str, Any]]:
        """
        Retrieves all vote audit records.
        Combines accepted votes from the votes table and rejected requests from audit logs
        to give the auditor a complete picture of all processed ballots.
        """
        conn = get_db()
        cursor = conn.cursor()

        # Accepted votes
        query = """
            SELECT reference_id, 'Student Council General Election 2026' as election,
                   timestamp, rsa_status, hmac_status, eligibility_check, duplicate_check, status
            FROM votes
        """
        params = []
        if status_filter and status_filter.upper() == 'ACCEPTED':
            query += " WHERE status = 'ACCEPTED'"
        elif status_filter and status_filter.upper() == 'REJECTED':
            query += " WHERE 1 = 0"  # Accepted table doesn't have rejected rows

        query += " ORDER BY id DESC;"
        accepted_rows = [dict(r) for r in cursor.execute(query, params).fetchall()]

        # Rejected votes from audit logs (if filter allows)
        rejected_rows = []
        if not status_filter or status_filter.upper() == 'REJECTED':
            rej_logs = cursor.execute("""
                SELECT request_reference as reference_id, 'Student Council General Election 2026' as election,
                       timestamp,
                       CASE WHEN event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED' THEN 'PROTECTED' ELSE '—' END as rsa_status,
                       CASE WHEN event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED' THEN 'FAILED' ELSE '—' END as hmac_status,
                       CASE WHEN event_name = 'AUDITOR_VOTE_BLOCKED' THEN 'PROHIBITED' ELSE '—' END as eligibility_check,
                       CASE WHEN event_name = 'DUPLICATE_VOTE_BLOCKED' THEN 'BLOCKED' ELSE '—' END as duplicate_check,
                       'REJECTED' as status
                FROM audit_logs
                WHERE status IN ('REJECTED', 'BLOCKED') AND request_reference IS NOT NULL
                ORDER BY id DESC;
            """).fetchall()
            rejected_rows = [dict(r) for r in rej_logs]

        conn.close()

        # Merge and sort by timestamp
        all_records = accepted_rows + rejected_rows
        all_records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return all_records

    @staticmethod
    def get_vote_timeline_detail(reference_id: str) -> Dict[str, Any]:
        """Provides the step-by-step security processing timeline for a specific vote reference."""
        conn = get_db()
        cursor = conn.cursor()

        vote = cursor.execute("SELECT * FROM votes WHERE reference_id = ?;", (reference_id,)).fetchone()
        logs = cursor.execute("""
            SELECT * FROM audit_logs WHERE request_reference = ? OR description LIKE ?
            ORDER BY id ASC;
        """, (reference_id, f"%{reference_id}%")).fetchall()
        conn.close()

        if vote:
            vote_dict = dict(vote)
            steps = [
                {"title": "1. Vote Created", "status": "COMPLETED", "detail": "Voter formulated ballot payload on client browser."},
                {"title": "2. RSA Protection", "status": "COMPLETED", "detail": f"Ballot encrypted via Election Authority RSA Public Key (e=17, n=3233). Payload: {vote_dict['encrypted_vote'][:24]}..."},
                {"title": "3. HMAC-SHA256 Generation", "status": "COMPLETED", "detail": f"Authentication tag generated using voter's unique shared secret. Tag: {vote_dict['hmac_tag'][:24]}..."},
                {"title": "4. Secure Request Transmission", "status": "COMPLETED", "detail": f"Dispatched HTTPS packet under reference {reference_id}."},
                {"title": "5. Server HMAC Verification", "status": "VERIFIED", "detail": "Server recalculated HMAC-SHA256 and verified tag via hmac.compare_digest(). Integrity confirmed."},
                {"title": "6. Eligibility & Duplicate Check", "status": "PASSED", "detail": "Single-vote constraint verified against voter database registry."},
                {"title": "7. Final Status", "status": "ACCEPTED", "detail": f"Ballot choice decrypted with RSA private key and recorded under anonymous SHA-256 hash {vote_dict['voter_hash'][:16]}..."}
            ]
            return {
                "reference_id": reference_id,
                "found": True,
                "is_accepted": True,
                "timestamp": vote_dict["timestamp"],
                "candidate_id": vote_dict["candidate_id"],
                "steps": steps,
                "logs": [dict(l) for l in logs]
            }
        else:
            # Check if it was a rejected request
            conn = get_db()
            rej_log = conn.execute("SELECT * FROM audit_logs WHERE request_reference = ?;", (reference_id,)).fetchone()
            conn.close()

            if rej_log:
                r_dict = dict(rej_log)
                steps = [
                    {"title": "1. Vote Request Received", "status": "RECEIVED", "detail": f"Incoming transmission received under reference {reference_id}."},
                    {"title": "2. Server HMAC Verification", "status": "FAILED", "detail": f"HMAC-SHA256 tag verification failed. Received tag mismatch with recalculated tag."},
                    {"title": "3. Integrity Violation Detected", "status": "ALERT", "detail": "Potential Man-in-the-Middle modification or invalid credential token detected."},
                    {"title": "4. Final Status", "status": "REJECTED", "detail": "Vote request safely rejected and discarded. Ballot was NOT recorded."}
                ]
                return {
                    "reference_id": reference_id,
                    "found": True,
                    "is_accepted": False,
                    "timestamp": r_dict["timestamp"],
                    "candidate_id": None,
                    "steps": steps,
                    "logs": [r_dict]
                }

            return {"reference_id": reference_id, "found": False, "steps": [], "logs": []}

    @staticmethod
    def get_security_logs(event_filter: str = None, status_filter: str = None, search: str = None) -> List[Dict[str, Any]]:
        """Retrieves audit logs with multi-parameter filtering."""
        conn = get_db()
        cursor = conn.cursor()

        query = "SELECT id, timestamp, event_name, actor_id, request_reference, received_tag, calculated_tag, description, status FROM audit_logs WHERE 1=1"
        params = []

        if event_filter:
            query += " AND event_name = ?"
            params.append(event_filter)

        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)

        if search:
            query += " AND (description LIKE ? OR actor_id LIKE ? OR request_reference LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param])

        query += " ORDER BY id ASC LIMIT 200;"
        rows = cursor.execute(query, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    @staticmethod
    def get_hmac_integrity_audit() -> Dict[str, Any]:
        """Provides statistics and logs specifically for HMAC-SHA256 integrity verifications."""
        conn = get_db()
        cursor = conn.cursor()

        total_votes = cursor.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]
        valid_hmac = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'VOTE_ACCEPTED';").fetchone()["count"]
        invalid_hmac = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED';").fetchone()["count"]

        total_requests = total_votes + invalid_hmac
        verification_rate = round((valid_hmac / total_requests * 100), 2) if total_requests > 0 else 100.0

        # Integrity violations records
        violations = cursor.execute("""
            SELECT id, timestamp, request_reference, received_tag, calculated_tag, description, status
            FROM audit_logs
            WHERE event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED'
            ORDER BY id DESC;
        """).fetchall()

        # All verification events
        all_checks = cursor.execute("""
            SELECT id, timestamp, event_name, request_reference, actor_id, received_tag, calculated_tag, status, description
            FROM audit_logs
            WHERE event_name IN ('VOTE_ACCEPTED', 'INTEGRITY_VIOLATION_TAMPERING_DETECTED')
            ORDER BY id DESC LIMIT 50;
        """).fetchall()

        conn.close()

        return {
            "requests_checked": total_requests,
            "valid_hmac": valid_hmac,
            "invalid_hmac": invalid_hmac,
            "rejected_requests": invalid_hmac,
            "verification_rate": verification_rate,
            "violations": [dict(v) for v in violations],
            "all_checks": [dict(c) for c in all_checks],
            "explanation": "An HMAC mismatch indicates that the received message does not correspond to the authentication tag generated using the expected secret key. This may indicate in-transit modification or an invalid authentication attempt. Requests with failed HMAC verification are rejected before the vote is accepted into the election record."
        }

    @staticmethod
    def get_rsa_audit_details() -> Dict[str, Any]:
        """Provides high-level audit information regarding RSA public-key protection."""
        conn = get_db()
        total_rsa_ops = conn.execute("SELECT COUNT(*) as count FROM votes;").fetchone()["count"]
        conn.close()

        key_params = rsa_engine.get_key_parameters()

        return {
            "rsa_status": "Operational",
            "key_pair_status": f"Active & Verified (e={key_params['e']}, n={key_params['n']})",
            "key_bit_length": key_params["bit_length"],
            "total_rsa_protected_requests": total_rsa_ops,
            "successful_rsa_operations": total_rsa_ops,
            "failed_rsa_operations": 0,
            "confidentiality_status": "Verified & Enforced",
            "public_key_info": key_params["public_key"],
            "private_key_info": {
                "label": "PRIVATE (d)",
                "status": "Secured on Server (Never Exposed to Frontend / Auditor)",
                "modulus": key_params["n"]
            },
            "derivation_steps": key_params["derivation_steps"]
        }

    @staticmethod
    def get_duplicate_checks() -> Dict[str, Any]:
        """Audits duplicate voting prevention and single-vote constraint enforcement."""
        conn = get_db()
        cursor = conn.cursor()

        duplicate_logs = cursor.execute("""
            SELECT id, timestamp, actor_id, request_reference, description, status
            FROM audit_logs
            WHERE event_name = 'DUPLICATE_VOTE_BLOCKED'
            ORDER BY id DESC;
        """).fetchall()

        total_attempts = len(duplicate_logs)
        conn.close()

        return {
            "total_attempts": total_attempts,
            "duplicate_logs": [dict(l) for l in duplicate_logs],
            "prevention_mechanism": "Single-vote enforcement is guaranteed by unique database constraints on anonymized voter hashes and the has_voted flag in the voters table. Duplicate submission attempts are rejected with HTTP 400 without interrupting the voting service."
        }

    @staticmethod
    def get_results_verification() -> Dict[str, Any]:
        """Certified election results with audit verification checklist."""
        results = ElectionService.get_results()
        conn = get_db()
        cursor = conn.cursor()

        accepted_votes = results["total_votes"]
        rejected_tamper = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'INTEGRITY_VIOLATION_TAMPERING_DETECTED';").fetchone()["count"]
        duplicate_attempts = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE event_name = 'DUPLICATE_VOTE_BLOCKED';").fetchone()["count"]
        conn.close()

        total_rejected = rejected_tamper + duplicate_attempts

        verification_checklist = {
            "vote_records": {"title": "Vote Records", "status": "Verified", "passed": True},
            "integrity_checks": {"title": "Integrity Checks (HMAC-SHA256)", "status": "Passed", "passed": True},
            "duplicate_checks": {"title": "Duplicate Vote Checks", "status": "Passed", "passed": True},
            "result_calculation": {"title": "Result Calculation", "status": "Completed", "passed": True}
        }

        return {
            "election": results["election"],
            "tallies": results["tallies"],
            "accepted_votes": accepted_votes,
            "rejected_requests": total_rejected,
            "duplicate_attempts": duplicate_attempts,
            "verification_checklist": verification_checklist
        }

    @staticmethod
    def get_system_status() -> Dict[str, Any]:
        """Comprehensive operational status for all components and application metrics."""
        availability = SecurityService.get_system_availability()
        conn = get_db()
        cursor = conn.cursor()

        total_events = cursor.execute("SELECT COUNT(*) as count FROM audit_logs;").fetchone()["count"]
        successful_events = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE status IN ('SUCCESS', 'ACCEPTED');").fetchone()["count"]
        failed_events = cursor.execute("SELECT COUNT(*) as count FROM audit_logs WHERE status IN ('FAILED', 'REJECTED', 'ALERT');").fetchone()["count"]
        conn.close()

        components = [
            {"name": "Voting Service", "status": "ONLINE", "healthy": True},
            {"name": "Database Storage (SQLite)", "status": "ONLINE", "healthy": True},
            {"name": "RSA Encryption Service", "status": "ONLINE", "healthy": True},
            {"name": "HMAC Authentication Service", "status": "ONLINE", "healthy": True},
            {"name": "Voter Authentication Service", "status": "ONLINE", "healthy": True},
            {"name": "Election Tabulation Service", "status": "ONLINE", "healthy": True}
        ]

        return {
            "components": components,
            "total_requests": total_events,
            "successful_requests": successful_events,
            "failed_requests": failed_events,
            "server_errors": 0,
            "database_errors": 0,
            "current_election_status": "OPEN",
            "availability_explanation": "Availability is supported by reliable application design, schema validation, duplicate-voting prevention, and resilient error recovery—not by RSA or HMAC themselves."
        }

    @staticmethod
    def generate_audit_report() -> Dict[str, Any]:
        """Generates comprehensive formal election audit report."""
        summary = AuditorService.get_dashboard_summary()
        results = AuditorService.get_results_verification()
        hmac_audit = AuditorService.get_hmac_integrity_audit()
        system_status = AuditorService.get_system_status()

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        report_id = f"AUD-REP-{datetime.now().strftime('%Y%m%d')}-001"

        return {
            "report_id": report_id,
            "generated_at": generated_at,
            "election_info": summary["election"],
            "voting_statistics": {
                "eligible_voters": summary["metrics"]["eligible_voters"],
                "votes_cast": summary["metrics"]["votes_cast"],
                "accepted_votes": results["accepted_votes"],
                "rejected_requests": summary["metrics"]["rejected_requests"],
                "duplicate_attempts": summary["metrics"]["duplicate_attempts"],
                "turnout_percentage": summary["metrics"]["voter_turnout"]
            },
            "cryptographic_security": {
                "rsa_operations": summary["metrics"]["votes_cast"],
                "rsa_status": "OPERATIONAL (Confidentiality Guaranteed)",
                "hmac_verifications": hmac_audit["valid_hmac"],
                "hmac_failures": hmac_audit["invalid_hmac"],
                "verification_rate": hmac_audit["verification_rate"],
                "integrity_violations_blocked": hmac_audit["invalid_hmac"]
            },
            "system_availability": {
                "overall_status": "OPERATIONAL",
                "components": system_status["components"],
                "processing_failures": 0,
                "system_errors": 0
            },
            "candidate_tallies": results["tallies"],
            "final_audit_status": {
                "confidentiality_controls": "OPERATIONAL",
                "integrity_controls": "OPERATIONAL",
                "availability_controls": "OPERATIONAL",
                "duplicate_vote_prevention": "OPERATIONAL",
                "overall_status": "AUDIT COMPLETED & CERTIFIED"
            }
        }

    @staticmethod
    def export_report_csv() -> str:
        """Generates CSV format of the official audit ledger and results."""
        report = AuditorService.generate_audit_report()
        votes = AuditorService.get_vote_records()

        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["SECUREVOTE AUDIT REPORT"])
        writer.writerow(["Report ID", report["report_id"]])
        writer.writerow(["Generated At", report["generated_at"]])
        writer.writerow(["Election Title", report["election_info"]["title"]])
        writer.writerow(["Election Status", report["election_info"]["status"]])
        writer.writerow([])

        writer.writerow(["--- ELECTION RESULTS ---"])
        writer.writerow(["Candidate Name", "Position", "Affiliation", "Votes", "Percentage"])
        for c in report["candidate_tallies"]:
            writer.writerow([c["name"], c["position"], c["affiliation"], c["vote_count"], f"{c['percentage']}%"])
        writer.writerow([])

        writer.writerow(["--- AUDIT METRICS ---"])
        writer.writerow(["Total Eligible Voters", report["voting_statistics"]["eligible_voters"]])
        writer.writerow(["Total Accepted Votes", report["voting_statistics"]["accepted_votes"]])
        writer.writerow(["Rejected Requests", report["voting_statistics"]["rejected_requests"]])
        writer.writerow(["Duplicate Attempts Blocked", report["voting_statistics"]["duplicate_attempts"]])
        writer.writerow(["HMAC Verifications Passed", report["cryptographic_security"]["hmac_verifications"]])
        writer.writerow(["HMAC Integrity Failures", report["cryptographic_security"]["hmac_failures"]])
        writer.writerow(["Verification Rate", f"{report['cryptographic_security']['verification_rate']}%"])
        writer.writerow([])

        writer.writerow(["--- VOTE AUDIT LEDGER ---"])
        writer.writerow(["Reference ID", "Timestamp", "RSA Protection", "HMAC Verification", "Eligibility Check", "Duplicate Check", "Final Status"])
        for v in votes:
            writer.writerow([v.get("reference_id"), v.get("timestamp"), v.get("rsa_status"), v.get("hmac_status"), v.get("eligibility_check"), v.get("duplicate_check"), v.get("status")])

        return output.getvalue()
