"""
Voting service for SecureVote with Auditor Protections.
Orchestrates ballot formulation, RSA protection, HMAC-SHA256 signing,
server-side validation, duplicate prevention, and persistent ledger recording.
"""
import hashlib
import secrets
from typing import Dict, Any
from database.db import get_db, log_event
from crypto.key_manager import key_manager
from crypto.rsa import rsa_engine
from services.election_service import ElectionService


class VotingService:
    """Manages secure voting transactions and enforces dual-layer cryptographic controls."""

    @staticmethod
    def prepare_ballot_preview(candidate_id: int, voter_id: str, hmac_key: str) -> Dict[str, Any]:
        """Constructs an educational preview of the cryptographic pipeline prior to submission."""
        candidate = ElectionService.get_candidate(candidate_id)
        if not candidate:
            raise ValueError("Candidate not found.")

        packet = key_manager.create_secure_ballot_packet(
            candidate_id=candidate["id"],
            candidate_name=candidate["name"],
            voter_id=voter_id,
            hmac_key=hmac_key
        )
        return {
            "candidate": candidate,
            "packet": packet
        }

    @staticmethod
    def process_vote_submission(voter: Dict[str, Any], candidate_id: int, simulate_tamper: bool = False, tampered_candidate_id: int = None) -> Dict[str, Any]:
        """
        Executes end-to-end voting transaction:
        1. Prohibits auditor role from voting (Strict Separation of Duties).
        2. Validates voter eligibility and prevents duplicate voting (Availability).
        3. Constructs secure vote packet (RSA Encryption + HMAC-SHA256 Tag).
        4. If simulate_tamper is active: modifies payload while keeping original HMAC.
        5. Transmits packet to server verification pipeline.
        6. Verifies HMAC using constant-time comparison (Integrity & Authentication).
        7. Decrypts RSA ciphertext to extract candidate choice (Confidentiality).
        8. Records verified ballot in database with anonymous voter hash.
        """
        voter_id = voter["voter_id"]
        hmac_secret = voter["hmac_secret"]
        role = voter.get("role", "voter")
        request_ref = "REQ-" + secrets.token_hex(3).upper()

        # 1. Auditor Role Prohibition
        if role == "auditor":
            log_event("AUDITOR_VOTE_BLOCKED", voter_id, "Auditor account attempted to submit a ballot. Action blocked by security policy.", "BLOCKED", request_reference=request_ref)
            return {
                "success": False,
                "error": "AUDITOR_PROHIBITED",
                "message": "Auditors are prohibited from casting ballots to maintain independent oversight."
            }

        # 2. Eligibility & Duplicate Check
        conn = get_db()
        current_voter = conn.execute("SELECT * FROM voters WHERE voter_id = ?;", (voter_id,)).fetchone()
        conn.close()

        if not current_voter:
            return {
                "success": False,
                "error": "UNAUTHORIZED_VOTER",
                "message": "Voter record not found."
            }

        if current_voter["has_voted"]:
            log_event("DUPLICATE_VOTE_BLOCKED", voter_id, f"Duplicate voting attempt blocked for voter reference {voter_id}. Request safely rejected.", "BLOCKED", request_reference=request_ref)
            return {
                "success": False,
                "error": "ALREADY_VOTED",
                "message": "Vote already recorded. You cannot submit another vote."
            }

        candidate = ElectionService.get_candidate(candidate_id)
        if not candidate:
            return {
                "success": False,
                "error": "INVALID_CANDIDATE",
                "message": "Selected candidate does not exist."
            }

        # 3. Prepare Legitimate Secure Vote Packet
        legitimate_packet = key_manager.create_secure_ballot_packet(
            candidate_id=candidate["id"],
            candidate_name=candidate["name"],
            voter_id=voter_id,
            hmac_key=hmac_secret
        )

        encrypted_vote_payload = legitimate_packet["encrypted_vote"]
        hmac_tag_to_submit = legitimate_packet["hmac_tag"]
        timestamp = legitimate_packet["timestamp"]

        # 4. Simulate Active Man-in-the-Middle Attack (if requested for demonstration)
        if simulate_tamper:
            target_cand_id = tampered_candidate_id or (2 if candidate["id"] != 2 else 1)
            target_candidate = ElectionService.get_candidate(target_cand_id)
            
            # Attacker creates forged encrypted ballot for target candidate
            fake_ballot_text = f"CANDIDATE:{target_candidate['id']}:{target_candidate['name']}"
            fake_enc = rsa_engine.encrypt_text(fake_ballot_text)
            
            # Tampered envelope: Modified encrypted payload BUT retains the original voter's HMAC tag!
            encrypted_vote_payload = fake_enc["cipher_string"]
            log_event("TAMPER_SIMULATION_INJECTED", voter_id, f"Adversary intercepted packet: modified ballot choice to Candidate #{target_cand_id} without voter secret.", "ALERT", request_reference=request_ref)

        # 5. Server-Side Verification & Processing
        verification = key_manager.verify_and_process_ballot(
            encrypted_vote=encrypted_vote_payload,
            voter_id=voter_id,
            timestamp=timestamp,
            received_hmac=hmac_tag_to_submit,
            hmac_key=hmac_secret
        )

        if not verification["success"]:
            # Tampering or corruption detected
            recalc_tag = verification.get("recalculated_hmac", "")
            log_event(
                event_name="INTEGRITY_VIOLATION_TAMPERING_DETECTED",
                actor_id=voter_id,
                description=f"HMAC verification failed. Received tag mismatch with recalculated tag. Request rejected.",
                status="REJECTED",
                request_reference=request_ref,
                received_tag=hmac_tag_to_submit[:24] + "...",
                calculated_tag=recalc_tag[:24] + "..." if recalc_tag else None
            )
            sim_explanation = (
                "Simulation: the voting request was modified before server verification. "
                "The modified message produced a different HMAC-SHA256 authentication tag. "
                "Because the received tag did not match the server's recalculated tag, the request was rejected."
                if simulate_tamper else
                "The received HMAC-SHA256 authentication tag did not match the server's recalculated digest."
            )
            return {
                "success": False,
                "error": "INTEGRITY_CHECK_FAILED",
                "message": f"Request integrity check failed. {sim_explanation} The vote was not stored.",
                "diagnostics": {
                    "original_intended_candidate": candidate["name"],
                    "received_hmac": hmac_tag_to_submit,
                    "recalculated_hmac": verification["recalculated_hmac"],
                    "canonical_payload": verification["canonical_payload"],
                    "tamper_detected": True,
                    "simulation_note": sim_explanation
                }
            }

        # 6. Record Vote in SQLite Ledger
        decrypted_candidate_id = verification["candidate_id"]
        voter_hash = hashlib.sha256(f"ANON_SALT_2026_{voter_id}".encode("utf-8")).hexdigest()
        reference_id = "TXN-VOTE-" + secrets.token_hex(3).upper()

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO votes (reference_id, voter_hash, candidate_id, encrypted_vote, hmac_tag, rsa_status, hmac_status, eligibility_check, duplicate_check, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (reference_id, voter_hash, decrypted_candidate_id, encrypted_vote_payload, hmac_tag_to_submit, "PROTECTED", "VERIFIED", "PASSED", "PASSED", timestamp, "ACCEPTED"))

            cursor.execute("""
                UPDATE voters SET has_voted = 1 WHERE voter_id = ?;
            """, (voter_id,))

            conn.commit()
            conn.close()

            log_event(
                event_name="VOTE_ACCEPTED",
                actor_id=voter_id,
                description=f"Ballot verified via HMAC-SHA256, decrypted via RSA, and recorded under reference {reference_id}.",
                status="ACCEPTED",
                request_reference=reference_id,
                received_tag=hmac_tag_to_submit[:24] + "...",
                calculated_tag=hmac_tag_to_submit[:24] + "..."
            )

            return {
                "success": True,
                "message": "Vote submitted successfully",
                "reference_id": reference_id,
                "candidate_name": candidate["name"],
                "candidate_position": candidate["position"],
                "timestamp": timestamp,
                "hmac_tag": hmac_tag_to_submit,
                "security_status": {
                    "rsa_protection": "Applied & Verified (Confidentiality)",
                    "hmac_verification": "Verified via constant-time compare (Integrity)",
                    "eligibility_check": "Verified (Single-vote enforced)",
                    "ledger_recording": "Accepted & Persisted"
                }
            }
        except Exception as ex:
            conn.close()
            log_event("VOTE_RECORD_ERROR", voter_id, f"Database transaction error: {str(ex)}", "FAILED", request_reference=request_ref)
            return {
                "success": False,
                "error": "STORAGE_ERROR",
                "message": "Failed to persist ballot record."
            }
