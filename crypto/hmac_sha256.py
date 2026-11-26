"""
HMAC-SHA256 Cryptographic Authentication Engine for SecureVote.
Implements RFC 2104 / FIPS 198-1 standard keyed-hashing with SHA-256,
inner/outer padding calculations, constant-time verification, and avalanche effect simulation.
"""
import hmac
import hashlib
from typing import Dict, Any


class HMACSHA256:
    """RFC 2104 compliant HMAC-SHA256 implementation and educational inspector."""

    BLOCK_SIZE = 64  # SHA-256 block size: 64 bytes (512 bits)
    IPAD_BYTE = 0x36
    OPAD_BYTE = 0x5C

    @staticmethod
    def generate(key: str, message: str) -> str:
        """Standard HMAC-SHA256 generation returning 64-character hexadecimal digest."""
        key_bytes = key.encode("utf-8")
        msg_bytes = message.encode("utf-8")
        return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

    @staticmethod
    def verify(key: str, message: str, received_tag: str) -> bool:
        """
        Constant-time comparison via hmac.compare_digest.
        Prevents timing side-channel attacks by comparing all bytes in fixed time.
        """
        expected_tag = HMACSHA256.generate(key, message)
        return hmac.compare_digest(expected_tag, received_tag)

    @classmethod
    def get_rfc2104_breakdown(cls, key: str, message: str) -> Dict[str, Any]:
        """
        Step-by-step RFC 2104 inspection showing exact intermediate padding masks,
        inner hash, and outer hash operations.
        """
        key_bytes = key.encode("utf-8")
        msg_bytes = message.encode("utf-8")

        # Step 1: Key normalization
        if len(key_bytes) > cls.BLOCK_SIZE:
            k_prime = hashlib.sha256(key_bytes).digest()
        else:
            k_prime = key_bytes
        k_padded = k_prime + b"\x00" * (cls.BLOCK_SIZE - len(k_prime))

        # Step 2: Inner pad XOR
        k_xor_ipad = bytes(b ^ cls.IPAD_BYTE for b in k_padded)

        # Step 3: Inner hash
        inner_data = k_xor_ipad + msg_bytes
        inner_hash = hashlib.sha256(inner_data).digest()

        # Step 4: Outer pad XOR
        k_xor_opad = bytes(b ^ cls.OPAD_BYTE for b in k_padded)

        # Step 5: Outer hash (Final Authentication Tag)
        outer_data = k_xor_opad + inner_hash
        final_tag = hashlib.sha256(outer_data).hexdigest()

        # Sanity check against standard library
        stdlib_tag = hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

        return {
            "key_input": key,
            "message_input": message,
            "step_1_key_prep": {
                "original_key_bytes": len(key_bytes),
                "padded_key_hex": k_padded.hex()[:32] + "...",
                "block_size_bytes": cls.BLOCK_SIZE
            },
            "step_2_inner_pad": {
                "ipad_constant": "0x36",
                "k_xor_ipad_hex": k_xor_ipad.hex()[:32] + "..."
            },
            "step_3_inner_hash": {
                "formula": "SHA-256((K' ⊕ ipad) || Message)",
                "inner_hash_hex": inner_hash.hex()
            },
            "step_4_outer_pad": {
                "opad_constant": "0x5C",
                "k_xor_opad_hex": k_xor_opad.hex()[:32] + "..."
            },
            "step_5_final_tag": {
                "formula": "SHA-256((K' ⊕ opad) || Inner_Hash)",
                "final_tag_hex": final_tag,
                "verified_with_stdlib": (final_tag == stdlib_tag)
            }
        }

    @staticmethod
    def simulate_tampering(original_msg: str, modified_msg: str, key: str) -> Dict[str, Any]:
        """
        Simulates payload modification without updating the authentication tag.
        Calculates bitwise Hamming distance to demonstrate the Avalanche Effect.
        """
        original_tag = HMACSHA256.generate(key, original_msg)
        recalculated_tag = HMACSHA256.generate(key, modified_msg)

        # Bitwise comparison
        orig_int = int(original_tag, 16)
        mod_int = int(recalculated_tag, 16)
        differing_bits = bin(orig_int ^ mod_int).count("1")
        total_bits = 256
        percent_changed = round((differing_bits / total_bits) * 100, 2)

        is_match = hmac.compare_digest(original_tag, recalculated_tag)

        return {
            "original_message": original_msg,
            "modified_message": modified_msg,
            "key": key,
            "original_tag": original_tag,
            "recalculated_tag": recalculated_tag,
            "is_verified": is_match,
            "differing_bits": differing_bits,
            "total_bits": total_bits,
            "avalanche_percentage": percent_changed,
            "status_message": "✓ Authentication Verified" if is_match else "✕ Integrity Violation: HMAC Mismatch"
        }
