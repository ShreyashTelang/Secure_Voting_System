"""
Key Management and Cryptographic Protocol Coordinator for SecureVote.
Demonstrates the hybrid relationship between RSA Public-Key Cryptography and HMAC-SHA256:
- RSA protects the secret key material (Confidentiality).
- HMAC-SHA256 protects the vote payload against tampering (Integrity & Authentication).
"""
import time
import secrets
from typing import Dict, Any
from crypto.rsa import rsa_engine
from crypto.hmac_sha256 import HMACSHA256


class KeyManager:
    """Coordinates server RSA keypair, voter session key issuance, and hybrid envelope packaging."""

    def __init__(self):
        self.rsa = rsa_engine

    def get_public_key(self) -> Dict[str, Any]:
        """Returns the public key (e, n) accessible to all voters."""
        return {
            "e": self.rsa.e,
            "n": self.rsa.n,
            "bit_length": self.rsa.n.bit_length(),
            "label": "PUBLIC KEY (e, n)",
            "purpose": "Used by voters to encrypt vote ballots and session keys."
        }

    def get_private_key_metadata(self) -> Dict[str, Any]:
        """Returns metadata regarding the server private key (d, n) without exposing secrets."""
        return {
            "d_label": "PRIVATE EXPONENT (d)",
            "n": self.rsa.n,
            "status": "Secured on Server",
            "purpose": "Used exclusively by the election authority to decrypt ballots."
        }

    def generate_voter_session_key(self) -> str:
        """Generates a cryptographically secure 16-byte hex HMAC session secret."""
        return "SEC_K_" + secrets.token_hex(8).upper()

    def demonstrate_hybrid_key_exchange(self, session_key: str) -> Dict[str, Any]:
        """
        Visualizes the hybrid key transport process:
        Session Key -> RSA Public Key Encryption -> Ciphertext -> Server RSA Private Key Decryption -> Recovered Key.
        """
        enc_result = self.rsa.encrypt_text(session_key)
        dec_result = self.rsa.decrypt_text(enc_result["cipher_string"])
        return {
            "original_session_key": session_key,
            "rsa_public_key": f"(e={self.rsa.e}, n={self.rsa.n})",
            "encrypted_session_key": enc_result["cipher_string"][:32] + "...",
            "full_encrypted_key": enc_result["cipher_string"],
            "server_decryption": dec_result["recovered_text"],
            "key_recovered_cleanly": (session_key == dec_result["recovered_text"]),
            "security_rationale": "RSA protects the HMAC session key in transit (Confidentiality). The recovered session key is then used with HMAC-SHA256 to authenticate the ballot (Integrity)."
        }

    def create_secure_ballot_packet(self, candidate_id: int, candidate_name: str, voter_id: str, hmac_key: str) -> Dict[str, Any]:
        """
        Constructs the secure voting submission envelope:
        1. Formats plaintext vote: CANDIDATE:{id}:{name}
        2. Encrypts vote using Server RSA Public Key (e, n) -> Ciphertext C
        3. Assembles canonical payload: C || voter_id || timestamp
        4. Signs canonical payload with HMAC-SHA256 using voter's HMAC secret
        """
        timestamp = str(int(time.time()))
        plaintext_ballot = f"CANDIDATE:{candidate_id}:{candidate_name}"

        # 1. RSA Encryption (Confidentiality)
        rsa_enc = self.rsa.encrypt_text(plaintext_ballot)
        encrypted_vote = rsa_enc["cipher_string"]

        # 2. Canonical serialization for authentication
        canonical_payload = f"{encrypted_vote}|{voter_id}|{timestamp}"

        # 3. HMAC-SHA256 Tag Generation (Integrity & Authentication)
        hmac_tag = HMACSHA256.generate(hmac_key, canonical_payload)

        return {
            "voter_id": voter_id,
            "candidate_id": candidate_id,
            "candidate_name": candidate_name,
            "timestamp": timestamp,
            "plaintext_ballot": plaintext_ballot,
            "encrypted_vote": encrypted_vote,
            "canonical_payload": canonical_payload,
            "hmac_tag": hmac_tag,
            "pipeline_trace": {
                "step_1_created": f"Ballot created for {candidate_name} (ID: {candidate_id})",
                "step_2_rsa": f"Ballot encrypted via RSA (e={self.rsa.e}, n={self.rsa.n})",
                "step_3_hmac": f"HMAC-SHA256 tag computed over canonical envelope",
                "step_4_envelope": "Secure vote packet prepared for transmission"
            }
        }

    def verify_and_process_ballot(self, encrypted_vote: str, voter_id: str, timestamp: str, received_hmac: str, hmac_key: str) -> Dict[str, Any]:
        """
        Server-side ballot verification and processing:
        1. Reconstructs canonical message: encrypted_vote || voter_id || timestamp
        2. Recalculates expected HMAC-SHA256 using server's stored voter key
        3. Performs constant-time comparison via hmac.compare_digest
        4. IF tag mismatches: REJECT IMMEDIATELY (Tampering detected)
        5. IF tag matches: Decrypt ballot using Server RSA Private Key (d, n)
        6. Extracts candidate ID and validates payload format
        """
        canonical_payload = f"{encrypted_vote}|{voter_id}|{timestamp}"

        # Step A: HMAC Verification
        recalculated_hmac = HMACSHA256.generate(hmac_key, canonical_payload)
        is_verified = HMACSHA256.verify(hmac_key, canonical_payload, received_hmac)

        if not is_verified:
            return {
                "success": False,
                "error": "INTEGRITY_CHECK_FAILED",
                "message": "Request integrity check failed. Authentication tag mismatch detected.",
                "canonical_payload": canonical_payload,
                "received_hmac": received_hmac,
                "recalculated_hmac": recalculated_hmac,
                "decrypted_ballot": None,
                "candidate_id": None
            }

        # Step B: RSA Decryption (Only executed if integrity is confirmed)
        try:
            rsa_dec = self.rsa.decrypt_text(encrypted_vote)
            recovered_text = rsa_dec["recovered_text"]

            # Expected format: CANDIDATE:<id>:<name>
            parts = recovered_text.split(":")
            if len(parts) < 3 or parts[0] != "CANDIDATE":
                return {
                    "success": False,
                    "error": "INVALID_BALLOT_PAYLOAD",
                    "message": "Malformed ballot payload structure.",
                    "canonical_payload": canonical_payload,
                    "received_hmac": received_hmac,
                    "recalculated_hmac": recalculated_hmac,
                    "decrypted_ballot": recovered_text,
                    "candidate_id": None
                }

            candidate_id = int(parts[1])
            candidate_name = parts[2]

            return {
                "success": True,
                "error": None,
                "message": "HMAC-SHA256 authentication verified and ballot decrypted successfully.",
                "canonical_payload": canonical_payload,
                "received_hmac": received_hmac,
                "recalculated_hmac": recalculated_hmac,
                "decrypted_ballot": recovered_text,
                "candidate_id": candidate_id,
                "candidate_name": candidate_name
            }
        except Exception as ex:
            return {
                "success": False,
                "error": "DECRYPTION_ERROR",
                "message": f"Server-side RSA decryption error: {str(ex)}",
                "canonical_payload": canonical_payload,
                "received_hmac": received_hmac,
                "recalculated_hmac": recalculated_hmac,
                "decrypted_ballot": None,
                "candidate_id": None
            }


# Singleton key manager instance
key_manager = KeyManager()
