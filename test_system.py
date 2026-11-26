"""
Comprehensive Test Suite for SecureVote.
Tests RSA Mathematics, HMAC-SHA256 Authentication, Hybrid Key Management,
Flask Web Routes, Duplicate Vote Rejection, and Tampering Detection.
"""

import unittest
from app import app
from database.db import init_db
from services.election_service import ElectionService
from services.voting_service import VotingService
from services.security_service import SecurityService
from crypto.rsa import rsa_engine, RSACryptosystem
from crypto.hmac_sha256 import HMACSHA256
from crypto.key_manager import key_manager


class SecureVoteSystemTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["SECRET_KEY"] = "test-secret-key-2026"
        self.client = app.test_client()
        init_db()
        ElectionService.reset_election()

    def test_01_rsa_mathematical_derivation(self):
        """Verifies RSA prime selection, totient, public/private keys, and modular exponentiation."""
        rsa = RSACryptosystem(p=61, q=53, e=17)
        self.assertEqual(rsa.n, 3233)
        self.assertEqual(rsa.phi, 3120)
        self.assertEqual(rsa.e, 17)
        self.assertEqual(rsa.d, 2753)
        self.assertEqual((rsa.d * rsa.e) % rsa.phi, 1)

        # Test numerical encryption & decryption: C = M^e mod n, M = C^d mod n
        msg_int = 42
        enc = rsa.encrypt_number(msg_int)
        ciphertext = enc["ciphertext_c"]
        self.assertEqual(ciphertext, pow(42, 17, 3233))
        dec = rsa.decrypt_number(ciphertext)
        self.assertEqual(dec["recovered_plaintext_m"], msg_int)

        # Test text block encryption
        sample_text = "CANDIDATE:1:Elena Rostova"
        enc_txt = rsa.encrypt_text(sample_text)
        dec_txt = rsa.decrypt_text(enc_txt["cipher_string"])
        self.assertEqual(dec_txt["recovered_text"], sample_text)
        print("✓ Test 01 Passed: RSA Mathematical Derivation & Modular Exponentiation Verified.")

    def test_02_hmac_sha256_rfc2104(self):
        """Verifies standard RFC 2104 HMAC-SHA256 generation, verification, and avalanche effect."""
        key = "ElectionAuthoritySecret2026"
        msg = "CANDIDATE:1:Elena Rostova"

        tag = HMACSHA256.generate(key, msg)
        self.assertEqual(len(tag), 64)

        # Positive constant-time match
        self.assertTrue(HMACSHA256.verify(key, msg, tag))

        # Tampered message match failure
        tampered_msg = "CANDIDATE:2:Marcus Vance"
        self.assertFalse(HMACSHA256.verify(key, tampered_msg, tag))

        # RFC 2104 step inspection
        breakdown = HMACSHA256.get_rfc2104_breakdown(key, msg)
        self.assertTrue(breakdown["step_5_final_tag"]["verified_with_stdlib"])

        # Avalanche effect verification
        sim = HMACSHA256.simulate_tampering(msg, tampered_msg, key)
        self.assertFalse(sim["is_verified"])
        self.assertGreater(sim["differing_bits"], 50)  # Strong avalanche spread
        print("✓ Test 02 Passed: HMAC-SHA256 RFC 2104 & Avalanche Metrics Verified.")

    def test_03_hybrid_key_management(self):
        """Verifies hybrid transport: RSA protects session key, HMAC protects message."""
        session_key = "SEC_K_ALPHA_SESSION_99"
        hybrid_trace = key_manager.demonstrate_hybrid_key_exchange(session_key)
        self.assertTrue(hybrid_trace["key_recovered_cleanly"])
        self.assertEqual(hybrid_trace["server_decryption"], session_key)
        print("✓ Test 03 Passed: Hybrid Key Management (RSA Session Key Transport) Verified.")

    def test_04_web_routes_availability(self):
        """Verifies that all primary production web routes return HTTP 200 OK."""
        routes = [
            "/",
            "/login",
            "/register",
            "/election",
            "/results",
            "/security",
            "/security/rsa",
            "/security/hmac",
            "/security/integrity-demo",
            "/security/availability"
        ]
        for route in routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"Route {route} returned status {resp.status_code}")
        print("✓ Test 04 Passed: All 10 Core Application Web Routes Returned HTTP 200 OK.")

    def test_05_authenticated_voting_flow(self):
        """Verifies voter sign-in, review, ballot submission, and double-voting prevention."""
        # 1. Sign in as voter1
        login_resp = self.client.post("/login", data={
            "username": "voter1",
            "password": "VoterPass123!"
        }, follow_redirects=True)
        self.assertEqual(login_resp.status_code, 200)

        # 2. Access ballot review for candidate 1
        review_resp = self.client.get("/vote/review?candidate_id=1")
        self.assertEqual(review_resp.status_code, 200)
        self.assertIn(b"Elena Rostova", review_resp.data)

        # 3. Submit ballot through cryptographic pipeline
        submit_resp = self.client.post("/vote/submit", json={
            "candidate_id": 1,
            "simulate_tamper": False
        })
        self.assertEqual(submit_resp.status_code, 200)
        sub_data = submit_resp.get_json()
        self.assertTrue(sub_data["success"])
        self.assertIn("TXN-", sub_data["reference_id"])

        # 4. Attempt duplicate vote (Availability & Constraint Check)
        duplicate_resp = self.client.post("/vote/submit", json={
            "candidate_id": 2,
            "simulate_tamper": False
        })
        self.assertEqual(duplicate_resp.status_code, 400)
        dup_data = duplicate_resp.get_json()
        self.assertFalse(dup_data["success"])
        self.assertEqual(dup_data["error"], "ALREADY_VOTED")

        # 5. Check certified results
        results = ElectionService.get_results()
        self.assertEqual(results["total_votes"], 1)
        self.assertEqual(results["tallies"][0]["name"], "Elena Rostova")
        self.assertEqual(results["tallies"][0]["vote_count"], 1)
        print("✓ Test 05 Passed: Complete Voting Workflow & Duplicate-Vote Prevention Verified.")

    def test_06_tamper_attack_detection(self):
        """Verifies active Man-in-the-Middle tampering rejection."""
        # Sign in as voter2
        self.client.post("/login", data={
            "username": "voter2",
            "password": "VoterPass123!"
        }, follow_redirects=True)

        # Simulate tampering: candidate modified without updating HMAC
        tamper_resp = self.client.post("/vote/submit", json={
            "candidate_id": 1,
            "simulate_tamper": True,
            "tampered_candidate_id": 2
        })
        self.assertEqual(tamper_resp.status_code, 400)
        t_data = tamper_resp.get_json()
        self.assertFalse(t_data["success"])
        self.assertEqual(t_data["error"], "INTEGRITY_CHECK_FAILED")
        self.assertIn("Request integrity check failed", t_data["message"])
        self.assertTrue(t_data["diagnostics"]["tamper_detected"])
        print("✓ Test 06 Passed: Active Tampering Attack Detected & Ballot Safely Rejected.")


if __name__ == "__main__":
    unittest.main()
