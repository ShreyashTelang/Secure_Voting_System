"""
Comprehensive Automated Test Suite for SecureVote Auditor Section.
Tests role-based access control, read-only prohibitions, all 10 auditor endpoints,
live cryptographic lifecycle verification, and CSV export.
"""
import sys
import unittest
from app import app
from database.db import init_db, get_db, hash_password
from services.election_service import ElectionService


class AuditorSectionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        init_db()

    def setUp(self):
        self.client = app.test_client()
        # Reset election to clean state for each test run
        ElectionService.reset_election()

    def login_as_auditor(self):
        return self.client.post("/login", data={
            "username": "auditor",
            "password": "AuditPass123!"
        }, follow_redirects=False)

    def login_as_voter(self, username="voter1"):
        return self.client.post("/login", data={
            "username": username,
            "password": "VoterPass123!"
        }, follow_redirects=False)

    # -----------------------------------------------------------------------
    # Access Control & Prohibition Tests
    # -----------------------------------------------------------------------
    def test_unauthenticated_cannot_access_auditor_dashboard(self):
        resp = self.client.get("/auditor/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_regular_voter_cannot_access_auditor_dashboard(self):
        self.login_as_voter("voter1")
        resp = self.client.get("/auditor/dashboard", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/", resp.headers["Location"])

    def test_auditor_login_redirects_to_auditor_dashboard(self):
        resp = self.login_as_auditor()
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/auditor/dashboard", resp.headers["Location"])

    def test_auditor_cannot_access_vote_review(self):
        self.login_as_auditor()
        resp = self.client.get("/vote/review?candidate_id=1", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/auditor/dashboard", resp.headers["Location"])

    def test_auditor_cannot_submit_vote(self):
        self.login_as_auditor()
        resp = self.client.post("/vote/submit", json={"candidate_id": 1})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "AUDITOR_PROHIBITED")

    # -----------------------------------------------------------------------
    # All Auditor Endpoints Return HTTP 200
    # -----------------------------------------------------------------------
    def test_auditor_dashboard_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/dashboard")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Auditor Dashboard", resp.data)
        self.assertIn(b"SYSTEM INTEGRITY VERIFIED", resp.data)
        self.assertIn(b"Confidentiality", resp.data)
        self.assertIn(b"Integrity", resp.data)
        self.assertIn(b"Availability", resp.data)

    def test_auditor_elections_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/elections")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Election Oversight", resp.data)
        self.assertIn(b"Student Council General Election 2026", resp.data)
        self.assertIn(b"Official Candidates", resp.data)
        self.assertIn(b"Elena Rostova", resp.data)

    def test_auditor_votes_page_and_filter(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/votes")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Vote Audit", resp.data)

        # Filter accepted
        resp_acc = self.client.get("/auditor/votes?status=ACCEPTED")
        self.assertEqual(resp_acc.status_code, 200)

        # Filter rejected
        resp_rej = self.client.get("/auditor/votes?status=REJECTED")
        self.assertEqual(resp_rej.status_code, 200)

    def test_auditor_security_logs_page_and_search(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/security-logs")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security Logs", resp.data)

        # Search query
        resp_search = self.client.get("/auditor/security-logs?q=VOTER")
        self.assertEqual(resp_search.status_code, 200)

    def test_auditor_integrity_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/integrity")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"HMAC-SHA256", resp.data)
        self.assertIn(b"Integrity Checks", resp.data)

    def test_auditor_rsa_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/rsa")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"RSA Cryptography", resp.data)
        self.assertIn(b"Public Key Audit Information", resp.data)
        self.assertIn(b"Private Key Security", resp.data)

    def test_auditor_duplicate_checks_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/duplicate-checks")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Duplicate Checks", resp.data)

    def test_auditor_results_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/results")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Results Verification", resp.data)
        self.assertIn(b"Auditor Verification Checklist", resp.data)

    def test_auditor_system_status_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/system-status")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"System Status", resp.data)
        self.assertIn(b"Subsystem Health Checks", resp.data)
        self.assertIn(b"Important Cryptographic Clarification", resp.data)

    def test_auditor_reports_page(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/reports")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Official Audit Report", resp.data)
        self.assertIn(b"ELECTION AUDIT CERTIFICATE", resp.data)

    def test_auditor_export_csv(self):
        self.login_as_auditor()
        resp = self.client.get("/auditor/reports/export-csv")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/csv")
        self.assertIn(b"SECUREVOTE AUDIT REPORT", resp.data)
        self.assertIn(b"--- ELECTION RESULTS ---", resp.data)
        self.assertIn(b"--- AUDIT METRICS ---", resp.data)
        self.assertIn(b"--- VOTE AUDIT LEDGER ---", resp.data)

    # -----------------------------------------------------------------------
    # End-to-End Cryptographic Lifecycle & Audit Verification
    # -----------------------------------------------------------------------
    def test_end_to_end_audit_flow(self):
        # 1. voter1 casts authentic vote
        self.login_as_voter("voter1")
        vote_res = self.client.post("/vote/submit", json={"candidate_id": 1})
        self.assertEqual(vote_res.status_code, 200)
        ref_id = vote_res.get_json()["reference_id"]
        self.client.get("/logout")

        # 2. voter2 attempts a tampered vote
        self.login_as_voter("voter2")
        tamper_res = self.client.post("/vote/submit", json={
            "candidate_id": 2,
            "simulate_tamper": True,
            "tampered_candidate_id": 3
        })
        self.assertEqual(tamper_res.status_code, 400)
        self.assertEqual(tamper_res.get_json()["error"], "INTEGRITY_CHECK_FAILED")
        self.client.get("/logout")

        # 3. voter1 attempts duplicate vote
        self.login_as_voter("voter1")
        dup_res = self.client.post("/vote/submit", json={"candidate_id": 2})
        self.assertEqual(dup_res.status_code, 400)
        self.assertEqual(dup_res.get_json()["error"], "ALREADY_VOTED")
        self.client.get("/logout")

        # 4. Auditor inspects the ledger
        self.login_as_auditor()

        # Check API vote detail for Alice's reference
        detail_res = self.client.get(f"/api/auditor/vote-detail/{ref_id}")
        self.assertEqual(detail_res.status_code, 200)
        detail_data = detail_res.get_json()
        self.assertTrue(detail_data["found"])
        self.assertTrue(detail_data["is_accepted"])
        self.assertEqual(len(detail_data["steps"]), 7)

        # Check dashboard summary counters
        dash_res = self.client.get("/auditor/dashboard")
        self.assertEqual(dash_res.status_code, 200)
        self.assertIn(b"INTEGRITY ALERT DETECTED", dash_res.data) # Because Bob's tamper was caught!

        # Check integrity audit page has the tamper failure recorded
        integ_res = self.client.get("/auditor/integrity")
        self.assertEqual(integ_res.status_code, 200)
        self.assertIn(b"REJECTED & DISCARDED", integ_res.data)

        # Check duplicate checks page has the blocked duplicate recorded
        dup_page = self.client.get("/auditor/duplicate-checks")
        self.assertEqual(dup_page.status_code, 200)
        self.assertIn(b"BLOCKED & LOGGED", dup_page.data)

        # Check CSV export has both accepted vote and tamper/duplicate records
        csv_res = self.client.get("/auditor/reports/export-csv")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn(ref_id.encode(), csv_res.data)


if __name__ == "__main__":
    unittest.main()
