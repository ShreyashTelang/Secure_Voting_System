"""
=============================================================================
Module: crypto/rsa_demo.py
Project: Secure Electronic Voting System using RSA and HMAC-SHA256
Course: Cryptography and Information Security (CIS) End Semester Examination

Description:
    Pure Python educational implementation of the RSA Public-Key Cryptosystem.
    Provides complete visibility into key generation, prime multiplication,
    Euler's totient calculation, modular inverse computation, encryption,
    and decryption. Designed specifically for ESE viva and practical demo.
=============================================================================
"""

import math
import random


def is_prime(num: int) -> bool:
    """
    Check if a number is prime using trial division.
    Suitable for educational small to medium primes.
    """
    if num < 2:
        return False
    if num in (2, 3):
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
    """Calculate the Greatest Common Divisor of a and b using Euclidean Algorithm."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that:
        a * x + b * y = gcd(a, b)
    Used to calculate the modular multiplicative inverse of e modulo phi(n).
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Calculate private exponent d such that:
        d * e = 1 (mod phi)
    Raises ValueError if modular inverse does not exist (e.g. gcd(e, phi) != 1).
    """
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist because gcd({e}, {phi}) = {gcd_val} != 1")
    return (x % phi + phi) % phi


class RSADemonstration:
    """
    Educational RSA Cryptosystem Engine.
    Exposes every intermediate arithmetic step for student demonstration and viva.
    """

    DEFAULT_P = 61
    DEFAULT_Q = 53
    DEFAULT_E = 17

    def __init__(self, p: int = DEFAULT_P, q: int = DEFAULT_Q, e: int = DEFAULT_E):
        self.p = p
        self.q = q
        self.requested_e = e
        self.n = 0
        self.phi = 0
        self.e = 0
        self.d = 0
        self.key_steps = {}
        self.generate_keys(p, q, e)

    def generate_keys(self, p: int, q: int, e: int = None) -> dict:
        """
        Step-by-step RSA key generation:
        Step 1: Select primes p and q
        Step 2: Calculate n = p * q
        Step 3: Calculate phi(n) = (p - 1) * (q - 1)
        Step 4: Select public exponent e coprime to phi(n)
        Step 5: Calculate private exponent d = e^-1 mod phi(n)
        Step 6: Output Public Key (e, n) and Private Key (d, n)
        """
        if not is_prime(p):
            raise ValueError(f"p = {p} is not a prime number.")
        if not is_prime(q):
            raise ValueError(f"q = {q} is not a prime number.")
        if p == q:
            raise ValueError("p and q must be distinct primes.")

        self.p = p
        self.q = q

        # Step 2: Modulus n
        self.n = p * q

        # Step 3: Euler's Totient phi(n)
        self.phi = (p - 1) * (q - 1)

        # Step 4: Choose/Validate public exponent e
        if e is None or e <= 1:
            # Pick a common small prime coprime with phi
            possible_es = [3, 5, 17, 65537]
            chosen_e = None
            for cand in possible_es:
                if 1 < cand < self.phi and gcd(cand, self.phi) == 1:
                    chosen_e = cand
                    break
            if chosen_e is None:
                for cand in range(3, self.phi, 2):
                    if gcd(cand, self.phi) == 1:
                        chosen_e = cand
                        break
            self.e = chosen_e
        else:
            if not (1 < e < self.phi):
                raise ValueError(f"e = {e} must satisfy 1 < e < phi(n) (1 < e < {self.phi})")
            g = gcd(e, self.phi)
            if g != 1:
                raise ValueError(f"e = {e} is not coprime to phi(n) = {self.phi}. gcd({e}, {self.phi}) = {g}")
            self.e = e

        # Step 5: Calculate private exponent d
        self.d = mod_inverse(self.e, self.phi)

        # Verification: (d * e) % phi == 1
        verification_val = (self.d * self.e) % self.phi

        self.key_steps = {
            "step_1": {
                "title": "Prime Numbers Selection",
                "p": self.p,
                "q": self.q,
                "explanation": "Two prime numbers p and q are chosen. In real-world systems, p and q are 1024 to 2048-bit numbers. For this demonstration, small primes are used for clear arithmetic visibility."
            },
            "step_2": {
                "title": "Compute Modulus n",
                "formula": "n = p × q",
                "calculation": f"n = {self.p} × {self.q} = {self.n}",
                "n": self.n,
                "bit_length": self.n.bit_length(),
                "explanation": "n is the modulus and forms part of both the public and private keys. The security of RSA relies on the computational hardness of factoring n back into p and q."
            },
            "step_3": {
                "title": "Compute Euler's Totient Function φ(n)",
                "formula": "φ(n) = (p - 1) × (q - 1)",
                "calculation": f"φ({self.n}) = ({self.p} - 1) × ({self.q} - 1) = {self.p - 1} × {self.q - 1} = {self.phi}",
                "phi": self.phi,
                "explanation": "φ(n) counts positive integers up to n that are coprime to n. It determines the cycle length of modular exponentiation by Euler's Totient Theorem: M^φ(n) ≡ 1 (mod n)."
            },
            "step_4": {
                "title": "Select Public Exponent e",
                "condition": "1 < e < φ(n) and gcd(e, φ(n)) = 1",
                "e": self.e,
                "gcd_result": f"gcd({self.e}, {self.phi}) = {gcd(self.e, self.phi)}",
                "explanation": "e is published as part of the public key. It must be coprime to φ(n) to guarantee that a unique modular inverse d exists."
            },
            "step_5": {
                "title": "Calculate Private Exponent d",
                "formula": "d ≡ e^(-1) (mod φ(n))  =>  (d × e) mod φ(n) = 1",
                "calculation": f"d = {self.d}",
                "verification": f"({self.d} × {self.e}) mod {self.phi} = {self.d * self.e} mod {self.phi} = {verification_val}",
                "explanation": "d is computed using the Extended Euclidean Algorithm. It is kept strictly secret on the election server to decrypt the encrypted vote records."
            },
            "step_6": {
                "title": "Final Key Pair",
                "public_key": {"e": self.e, "n": self.n},
                "private_key": {"d": self.d, "n": self.n},
                "explanation": "Public Key (e, n) is distributed to voters to encrypt votes. Private Key (d, n) is preserved strictly on the server to decrypt and tally votes."
            }
        }
        return self.key_steps

    def encrypt_number(self, m: int) -> dict:
        """
        Encrypt a single numeric message:
            C = M^e mod n
        """
        if m < 0:
            raise ValueError(f"Message M={m} cannot be negative.")
        if m >= self.n:
            raise ValueError(f"Message M={m} must be strictly less than modulus n={self.n}.")

        # Modular exponentiation using Python's built-in 3-argument pow()
        c = pow(m, self.e, self.n)

        return {
            "plaintext_m": m,
            "public_key": {"e": self.e, "n": self.n},
            "formula": "C = M^e mod n",
            "calculation": f"C = {m}^{self.e} mod {self.n} = {c}",
            "ciphertext_c": c,
            "security_explanation": (
                "Confidentiality is achieved because computing M from C requires "
                "solving the Discrete Logarithm Problem or factoring n, which is "
                "infeasible without knowing private exponent d."
            )
        }

    def decrypt_number(self, c: int) -> dict:
        """
        Decrypt a single numeric ciphertext:
            M = C^d mod n
        """
        if c < 0:
            raise ValueError(f"Ciphertext C={c} cannot be negative.")
        if c >= self.n:
            raise ValueError(f"Ciphertext C={c} must be strictly less than modulus n={self.n}.")

        m = pow(c, self.d, self.n)

        return {
            "ciphertext_c": c,
            "private_key": {"d": self.d, "n": self.n},
            "formula": "M = C^d mod n",
            "calculation": f"M = {c}^{self.d} mod {self.n} = {m}",
            "recovered_plaintext_m": m,
            "security_explanation": (
                "Only the entity holding private key (d, n) can compute C^d mod n. "
                "By Euler's Totient Theorem, (M^e)^d = M^(k*phi(n) + 1) = M mod n, "
                "recovering the exact original plaintext."
            )
        }

    def encrypt_text(self, text: str) -> dict:
        """
        Encrypt a text string by encrypting ASCII/UTF-8 character integer codes.
        Demonstrates how messages composed of characters are encrypted into
        a sequence of RSA cipher integers.
        """
        char_codes = [ord(char) for char in text]
        cipher_integers = []
        steps = []

        for ch, code in zip(text, char_codes):
            if code >= self.n:
                raise ValueError(
                    f"Character '{ch}' (ASCII {code}) is >= modulus n={self.n}. "
                    "Use larger primes (e.g. p=61, q=53 gives n=3233 > 255)."
                )
            c = pow(code, self.e, self.n)
            cipher_integers.append(c)
            steps.append({
                "char": ch,
                "ascii": code,
                "encrypted": c,
                "formula": f"{code}^{self.e} mod {self.n} = {c}"
            })

        # Serialized ciphertext as hyphen-separated integers
        cipher_string = "-".join(map(str, cipher_integers))

        return {
            "original_text": text,
            "char_codes": char_codes,
            "cipher_integers": cipher_integers,
            "cipher_string": cipher_string,
            "steps": steps,
            "explanation": "Each character code is encrypted using C = M^e mod n. The resulting integer sequence forms the encrypted vote payload."
        }

    def decrypt_text(self, cipher_input) -> dict:
        """
        Decrypt a sequence of RSA cipher integers back into plaintext text.
        Accepts a list of ints or a hyphen-separated string of ints.
        """
        if isinstance(cipher_input, str):
            parts = [p.strip() for p in cipher_input.split("-") if p.strip()]
            cipher_integers = [int(p) for p in parts]
        else:
            cipher_integers = list(cipher_input)

        recovered_codes = []
        recovered_chars = []
        steps = []

        for c in cipher_integers:
            m = pow(c, self.d, self.n)
            recovered_codes.append(m)
            recovered_char = chr(m)
            recovered_chars.append(recovered_char)
            steps.append({
                "ciphertext": c,
                "decrypted_ascii": m,
                "char": recovered_char,
                "formula": f"{c}^{self.d} mod {self.n} = {m}"
            })

        recovered_text = "".join(recovered_chars)

        return {
            "cipher_integers": cipher_integers,
            "recovered_codes": recovered_codes,
            "recovered_text": recovered_text,
            "steps": steps,
            "explanation": "Each cipher integer is decrypted via M = C^d mod n, and ASCII codes are converted back into characters."
        }


# Global singleton instance with standard ESE demonstration defaults
rsa_educational_engine = RSADemonstration(p=61, q=53, e=17)
