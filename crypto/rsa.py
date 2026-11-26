"""
RSA Cryptographic Engine for SecureVote.
Implements educational and application-level RSA asymmetric mathematics:
p, q, n, phi(n), e, d, encryption (C = M^e mod n), and decryption (M = C^d mod n).
"""
import math
from typing import Dict, Any, Tuple, List


def is_prime(num: int) -> bool:
    """Trial division primality test."""
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for greatest common divisor."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (gcd, x, y) such that a*x + b*y = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Computes private exponent d such that d * e = 1 (mod phi)."""
    g, x, _ = extended_gcd(e, phi)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) != 1")
    return (x % phi + phi) % phi


class RSACryptosystem:
    """
    Manages RSA key generation, modular exponentiation, encryption, and decryption.
    Configured with standard educational parameters p=61, q=53 by default.
    """

    def __init__(self, p: int = 61, q: int = 53, e: int = 17):
        if not is_prime(p) or not is_prime(q):
            raise ValueError("p and q must be prime numbers.")
        if p == q:
            raise ValueError("p and q must be distinct.")

        self.p = p
        self.q = q
        self.n = p * q  # Modulus: 3233
        self.phi = (p - 1) * (q - 1)  # Totient: 3120

        if gcd(e, self.phi) != 1:
            raise ValueError(f"Public exponent e={e} is not coprime to phi={self.phi}.")
        self.e = e  # Public exponent: 17
        self.d = mod_inverse(e, self.phi)  # Private exponent: 2753

    def get_key_parameters(self) -> Dict[str, Any]:
        """Returns the complete set of parameters with educational annotations."""
        return {
            "p": self.p,
            "q": self.q,
            "n": self.n,
            "phi": self.phi,
            "e": self.e,
            "d": self.d,
            "bit_length": self.n.bit_length(),
            "public_key": {"e": self.e, "n": self.n, "label": "PUBLIC"},
            "private_key": {"d": self.d, "n": self.n, "label": "PRIVATE"},
            "derivation_steps": {
                "step_1": f"Selected primes: p = {self.p}, q = {self.q}",
                "step_2": f"Modulus: n = p × q = {self.p} × {self.q} = {self.n}",
                "step_3": f"Euler's Totient: φ(n) = (p - 1)(q - 1) = ({self.p} - 1)({self.q} - 1) = {self.phi}",
                "step_4": f"Public Exponent: e = {self.e} (verifies gcd({self.e}, {self.phi}) = 1)",
                "step_5": f"Private Exponent: d = {self.d} (verifies ({self.d} × {self.e}) mod {self.phi} = {(self.d * self.e) % self.phi})"
            }
        }

    def encrypt_number(self, m: int) -> Dict[str, Any]:
        """Encrypts numerical message M: C = M^e mod n."""
        if m < 0 or m >= self.n:
            raise ValueError(f"Message integer ({m}) must satisfy 0 <= M < n ({self.n}).")
        c = pow(m, self.e, self.n)
        return {
            "plaintext_m": m,
            "public_exponent_e": self.e,
            "modulus_n": self.n,
            "formula": f"C = M^e mod n = {m}^{self.e} mod {self.n}",
            "calculation": f"{m}^{self.e} mod {self.n} = {c}",
            "ciphertext_c": c
        }

    def decrypt_number(self, c: int) -> Dict[str, Any]:
        """Decrypts ciphertext C: M = C^d mod n."""
        if c < 0 or c >= self.n:
            raise ValueError(f"Ciphertext integer ({c}) must satisfy 0 <= C < n ({self.n}).")
        m = pow(c, self.d, self.n)
        return {
            "ciphertext_c": c,
            "private_exponent_d": self.d,
            "modulus_n": self.n,
            "formula": f"M = C^d mod n = {c}^{self.d} mod {self.n}",
            "calculation": f"{c}^{self.d} mod {self.n} = {m}",
            "recovered_plaintext_m": m
        }

    def encrypt_text(self, text: str) -> Dict[str, Any]:
        """
        Encrypts a string by converting each character into its modular ciphertext integer.
        Returns ciphertext string formatted as colon-separated integers.
        """
        cipher_ints = []
        steps = []
        for char in text:
            m = ord(char)
            c = pow(m, self.e, self.n)
            cipher_ints.append(c)
            steps.append({
                "char": char,
                "ascii_m": m,
                "ciphertext_c": c,
                "calc": f"{m}^{self.e} mod {self.n} = {c}"
            })
        return {
            "plaintext": text,
            "cipher_ints": cipher_ints,
            "cipher_string": ":".join(map(str, cipher_ints)),
            "steps": steps
        }

    def decrypt_text(self, cipher_string: str) -> Dict[str, Any]:
        """
        Decrypts colon-separated ciphertext integers back to the original string.
        """
        tokens = cipher_string.strip().split(":")
        recovered_chars = []
        steps = []
        for tok in tokens:
            if not tok:
                continue
            c = int(tok)
            m = pow(c, self.d, self.n)
            char = chr(m)
            recovered_chars.append(char)
            steps.append({
                "ciphertext_c": c,
                "recovered_m": m,
                "char": char,
                "calc": f"{c}^{self.d} mod {self.n} = {m} ('{char}')"
            })
        return {
            "cipher_string": cipher_string,
            "recovered_text": "".join(recovered_chars),
            "steps": steps
        }


# Singleton educational engine instance
rsa_engine = RSACryptosystem()
