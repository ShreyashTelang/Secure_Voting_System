"""
=============================================================================
Module: crypto/hmac_demo.py
Project: Secure Electronic Voting System using RSA and HMAC-SHA256
Course: Cryptography and Information Security (CIS) End Semester Examination

Description:
    Pure Python educational and standard implementation of HMAC-SHA256.
    Implements RFC 2104 inner/outer pad construction with full step-by-step
    intermediate value visibility, alongside standard hmac.compare_digest()
    verification and vote tampering simulation.
=============================================================================
"""

import hashlib
import hmac


class HMACDemonstration:
    """
    HMAC-SHA256 Cryptographic Engine & Educational Explainer.
    Demonstrates Keyed-Hashing for Message Authentication (RFC 2104).
    """

    BLOCK_SIZE = 64  # SHA-256 block size is 512 bits = 64 bytes
    OUTPUT_SIZE = 32 # SHA-256 output digest size is 256 bits = 32 bytes
    IPAD_BYTE = 0x36 # Inner pad byte defined in RFC 2104
    OPAD_BYTE = 0x5C # Outer pad byte defined in RFC 2104

    @staticmethod
    def generate_hmac(key: str, message: str) -> str:
        """
        Generate standard HMAC-SHA256 authentication tag using Python's hmac library.
        Returns a 64-character hexadecimal digest.
        """
        key_bytes = key.encode('utf-8')
        message_bytes = message.encode('utf-8')
        return hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def verify_hmac(key: str, message: str, received_hmac: str) -> bool:
        """
        Verify HMAC using constant-time comparison to prevent side-channel timing attacks.
        Uses hmac.compare_digest().
        """
        calculated_hmac = HMACDemonstration.generate_hmac(key, message)
        # Constant-time comparison
        return hmac.compare_digest(calculated_hmac, received_hmac)

    @classmethod
    def get_rfc2104_detailed_steps(cls, key: str, message: str) -> dict:
        """
        Detailed RFC 2104 inner/outer padding calculation breakdown.
        Shows exact intermediate byte representations, XOR masks, and hashes.
        
        Formula:
            HMAC(K, M) = H((K' XOR opad) || H((K' XOR ipad) || M))
        """
        key_bytes = key.encode('utf-8')
        msg_bytes = message.encode('utf-8')

        # Step 1: Key Preparation (Pad or Hash)
        # If key is longer than block size (64 bytes), hash it with SHA-256
        if len(key_bytes) > cls.BLOCK_SIZE:
            k_prime = hashlib.sha256(key_bytes).digest()
            key_prep_note = f"Key length ({len(key_bytes)} B) > Block size ({cls.BLOCK_SIZE} B); Hashed to 32 B."
        else:
            k_prime = key_bytes
            key_prep_note = f"Key length ({len(key_bytes)} B) <= Block size ({cls.BLOCK_SIZE} B); Kept as is."

        # Pad k_prime with zeros up to 64 bytes
        k_padded = k_prime + b'\x00' * (cls.BLOCK_SIZE - len(k_prime))

        # Step 2: Inner Pad XOR
        # ipad = 0x36 repeated 64 times
        ipad = bytes([cls.IPAD_BYTE] * cls.BLOCK_SIZE)
        k_xor_ipad = bytes([k ^ p for k, p in zip(k_padded, ipad)])

        # Step 3: Inner Message & Inner Hash
        # inner_data = (k_padded XOR ipad) || message
        inner_data = k_xor_ipad + msg_bytes
        inner_hash = hashlib.sha256(inner_data).digest()

        # Step 4: Outer Pad XOR
        # opad = 0x5C repeated 64 times
        opad = bytes([cls.OPAD_BYTE] * cls.BLOCK_SIZE)
        k_xor_opad = bytes([k ^ p for k, p in zip(k_padded, opad)])

        # Step 5: Outer Message & Final HMAC Tag
        # outer_data = (k_padded XOR opad) || inner_hash
        outer_data = k_xor_opad + inner_hash
        final_hmac = hashlib.sha256(outer_data).hexdigest()

        # Sanity check against standard library
        std_hmac = hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()
        assert final_hmac == std_hmac, "Educational RFC 2104 calculation matches standard library"

        return {
            "input_key": key,
            "input_message": message,
            "key_length_bytes": len(key_bytes),
            "message_length_bytes": len(msg_bytes),
            "step_1": {
                "title": "Step 1: Key Normalization (K')",
                "explanation": key_prep_note,
                "k_padded_hex": k_padded.hex()[:32] + "..." + k_padded.hex()[-16:],
                "k_padded_length": len(k_padded)
            },
            "step_2": {
                "title": "Step 2: Inner Pad XOR (K' ⊕ ipad)",
                "ipad_constant": "0x36 (54 in decimal) repeated 64 times",
                "k_xor_ipad_hex": k_xor_ipad.hex()[:32] + "..." + k_xor_ipad.hex()[-16:],
                "length": len(k_xor_ipad)
            },
            "step_3": {
                "title": "Step 3: Inner Hash H((K' ⊕ ipad) || M)",
                "concatenation": f"(K' ⊕ ipad) [{len(k_xor_ipad)} bytes] + Message '{message}' [{len(msg_bytes)} bytes]",
                "inner_hash_hex": inner_hash.hex(),
                "inner_hash_length": len(inner_hash)
            },
            "step_4": {
                "title": "Step 4: Outer Pad XOR (K' ⊕ opad)",
                "opad_constant": "0x5C (92 in decimal) repeated 64 times",
                "k_xor_opad_hex": k_xor_opad.hex()[:32] + "..." + k_xor_opad.hex()[-16:],
                "length": len(k_xor_opad)
            },
            "step_5": {
                "title": "Step 5: Outer Hash H((K' ⊕ opad) || Inner_Hash)",
                "concatenation": f"(K' ⊕ opad) [{len(k_xor_opad)} bytes] + Inner Hash [{len(inner_hash)} bytes]",
                "final_hmac_tag": final_hmac,
                "tag_bits": 256,
                "tag_hex_chars": len(final_hmac)
            },
            "security_analysis": {
                "integrity": "Guarantees that the message has not been altered in transit by an adversary.",
                "authentication": "Verifies that the tag was generated by someone possessing the shared secret key K.",
                "distinction": "HMAC does NOT encrypt the message. The plaintext message remains readable unless encrypted separately with RSA."
            }
        }

    @classmethod
    def simulate_tampering_scenario(cls, original_message: str, tampered_message: str, secret_key: str) -> dict:
        """
        Simulate an active Man-in-the-Middle (MITM) tampering attack.
        Shows how an attacker modifying the vote payload without knowing the secret key
        is reliably detected by the HMAC verification check.
        """
        # Step 1: Legit voter computes HMAC on original message
        legit_hmac = cls.generate_hmac(secret_key, original_message)

        # Step 2: Attacker intercepts and modifies message, keeping original HMAC or forging without key
        # Step 3: Server receives (tampered_message, legit_hmac)
        # Server calculates expected HMAC using server's copy of shared secret key
        server_recomputed_hmac = cls.generate_hmac(secret_key, tampered_message)

        # Step 4: Server compares using constant-time comparison
        is_valid = hmac.compare_digest(legit_hmac, server_recomputed_hmac)

        # Calculate bit-level differences (Hamming distance) to demonstrate Avalanche Effect
        orig_bytes = bytes.fromhex(legit_hmac)
        tamp_bytes = bytes.fromhex(server_recomputed_hmac)
        differing_bits = 0
        for b1, b2 in zip(orig_bytes, tamp_bytes):
            differing_bits += bin(b1 ^ b2).count('1')

        return {
            "original_message": original_message,
            "tampered_message": tampered_message,
            "secret_key": secret_key,
            "original_hmac": legit_hmac,
            "server_recalculated_hmac": server_recomputed_hmac,
            "hmac_match": is_valid,
            "status": "VALID_VOTE" if is_valid else "TAMPERING_DETECTED",
            "differing_bits": differing_bits,
            "total_bits": 256,
            "bit_change_percentage": round((differing_bits / 256.0) * 100, 2),
            "server_action": "ACCEPT_VOTE" if is_valid else "REJECT_VOTE",
            "alert_message": "🚨 TAMPERING DETECTED: Authentication tag does not match recomputed digest! Vote rejected immediately." if not is_valid else "✓ HMAC VERIFIED: Message integrity and sender authenticity confirmed."
        }
