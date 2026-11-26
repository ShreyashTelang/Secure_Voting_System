"""
SecureVote Application Controller.
A cryptographically protected electronic voting system demonstrating
Confidentiality (RSA), Integrity (HMAC-SHA256), and Availability (Reliable Design).
"""
import os
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response
)

from config import Config
from database.db import (
    init_db, get_db, hash_password, verify_password, log_event
)
from crypto.rsa import rsa_engine
from crypto.hmac_sha256 import HMACSHA256
from crypto.key_manager import key_manager
from services.election_service import ElectionService
from services.voting_service import VotingService
from services.security_service import SecurityService
from services.auditor_service import AuditorService

app = Flask(__name__)
app.config.from_object(Config)

# Ensure database tables exist
init_db()


# ---------------------------------------------------------------------------
# Session & Context Helpers
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "voter_id" not in session:
            flash("Please sign in to access the voting portal.", "info")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def auditor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "voter_id" not in session:
            flash("Auditor authentication required. Please sign in.", "info")
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "auditor":
            flash("Access denied. Dedicated auditor privileges required.", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_global_context():
    """Provides current voter state, server public key, and active election metadata."""
    voter = None
    is_auditor = False
    if "voter_id" in session:
        conn = get_db()
        row = conn.execute("SELECT * FROM voters WHERE voter_id = ?;", (session["voter_id"],)).fetchone()
        conn.close()
        if row:
            voter = dict(row)
            session["has_voted"] = voter["has_voted"]
            session["role"] = voter.get("role", "voter")
            is_auditor = (voter.get("role") == "auditor")

    return {
        "current_voter": voter,
        "is_authenticated": voter is not None,
        "is_auditor": is_auditor,
        "server_public_key": key_manager.get_public_key(),
        "election_info": ElectionService.ELECTION_METADATA,
        "current_year": datetime.now().year
    }


# ---------------------------------------------------------------------------
# Voter Experience Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Clean Landing Page communicating trust, security, and cryptographic foundations."""
    election = ElectionService.get_election_details()
    cia = SecurityService.get_cia_overview()
    return render_template("index.html", election=election, cia=cia)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Voter sign-in using constant-time salted SHA-256 verification."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        voter = conn.execute("SELECT * FROM voters WHERE username = ?;", (username,)).fetchone()
        conn.close()

        if voter and verify_password(voter["password_hash"], password):
            session["voter_id"] = voter["voter_id"]
            session["username"] = voter["username"]
            session["full_name"] = voter["full_name"]
            session["hmac_secret"] = voter["hmac_secret"]
            session["has_voted"] = voter["has_voted"]
            session["role"] = voter["role"] if "role" in voter.keys() else "voter"

            log_event("VOTER_AUTHENTICATED", voter["voter_id"], f"User {voter['username']} authenticated successfully as {session['role']}.", "SUCCESS")
            
            if session["role"] == "auditor":
                return redirect(url_for("auditor_dashboard"))

            next_url = request.args.get("next") or url_for("election_view")
            return redirect(next_url)
        else:
            log_event("AUTHENTICATION_FAILED", username or "UNKNOWN", "Invalid login credentials provided.", "FAILED")
            flash("Invalid username or password. Please try again.", "error")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Voter registration with automatic cryptographic HMAC secret provisioning."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not full_name or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("register.html")

        conn = get_db()
        existing = conn.execute("SELECT id FROM voters WHERE username = ?;", (username,)).fetchone()
        if existing:
            conn.close()
            flash("That username is already registered. Please choose another.", "error")
            return render_template("register.html")

        # Provision unique Voter ID and HMAC Secret
        voter_id = f"VTR-2026-{datetime.now().strftime('%f')[:4]}"
        hmac_secret = key_manager.generate_voter_session_key()
        pwd_hash = hash_password(password)

        conn.execute("""
            INSERT INTO voters (username, password_hash, full_name, voter_id, hmac_secret, has_voted)
            VALUES (?, ?, ?, ?, ?, 0);
        """, (username, pwd_hash, full_name, voter_id, hmac_secret))
        conn.commit()
        conn.close()

        log_event("VOTER_REGISTERED", voter_id, f"Voter account {username} registered.", "SUCCESS")
        flash("Registration successful. Please sign in with your credentials.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    """Ends voter session securely."""
    voter_id = session.get("voter_id", "ANONYMOUS")
    log_event("VOTER_LOGOUT", voter_id, "Voter session terminated.", "SUCCESS")
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/election")
def election_view():
    """Displays official election details and clean candidate ballot selection."""
    election = ElectionService.get_election_details()
    candidates = ElectionService.get_all_candidates()

    voter_has_voted = False
    if "voter_id" in session:
        conn = get_db()
        v = conn.execute("SELECT has_voted FROM voters WHERE voter_id = ?;", (session["voter_id"],)).fetchone()
        conn.close()
        voter_has_voted = bool(v and v["has_voted"])

    return render_template("election.html", election=election, candidates=candidates, voter_has_voted=voter_has_voted)


@app.route("/vote/review")
@login_required
def vote_review():
    """Ballot Review stage before casting."""
    candidate_id = request.args.get("candidate_id")
    if not candidate_id:
        flash("Please select a candidate first.", "warning")
        return redirect(url_for("election_view"))

    try:
        candidate_id = int(candidate_id)
    except ValueError:
        flash("Invalid candidate selection.", "error")
        return redirect(url_for("election_view"))

    candidate = ElectionService.get_candidate(candidate_id)
    if not candidate:
        flash("Candidate not found.", "error")
        return redirect(url_for("election_view"))

    # Fetch fresh voter record
    conn = get_db()
    voter = conn.execute("SELECT * FROM voters WHERE voter_id = ?;", (session["voter_id"],)).fetchone()
    conn.close()

    if voter and dict(voter).get("role") == "auditor":
        flash("Auditor accounts have read-only inspection access and cannot cast votes.", "error")
        return redirect(url_for("auditor_dashboard"))

    if voter["has_voted"]:
        flash("Vote already recorded. You cannot submit another vote.", "warning")
        return redirect(url_for("election_view"))

    # Prepare preview of cryptographic pipeline
    preview = VotingService.prepare_ballot_preview(
        candidate_id=candidate["id"],
        voter_id=voter["voter_id"],
        hmac_key=voter["hmac_secret"]
    )

    all_candidates = ElectionService.get_all_candidates()

    return render_template("vote-review.html", candidate=candidate, preview=preview, all_candidates=all_candidates)


@app.route("/vote/submit", methods=["POST"])
@login_required
def vote_submit():
    """
    Submits vote through the complete cryptographic pipeline:
    RSA encryption -> HMAC-SHA256 signing -> Constant-time verification -> RSA decryption -> Ledger.
    """
    data = request.get_json() if request.is_json else request.form

    candidate_id = data.get("candidate_id")
    simulate_tamper = data.get("simulate_tamper") in (True, "true", "1")
    tampered_candidate_id = data.get("tampered_candidate_id")

    if not candidate_id:
        return jsonify({"success": False, "error": "MISSING_CANDIDATE", "message": "Candidate selection is required."}), 400

    try:
        candidate_id = int(candidate_id)
        if tampered_candidate_id:
            tampered_candidate_id = int(tampered_candidate_id)
    except ValueError:
        return jsonify({"success": False, "error": "INVALID_ID", "message": "Invalid candidate ID format."}), 400

    conn = get_db()
    voter = conn.execute("SELECT * FROM voters WHERE voter_id = ?;", (session["voter_id"],)).fetchone()
    conn.close()

    result = VotingService.process_vote_submission(
        voter=dict(voter),
        candidate_id=candidate_id,
        simulate_tamper=simulate_tamper,
        tampered_candidate_id=tampered_candidate_id
    )

    if not result["success"]:
        status_code = 400 if result.get("error") != "STORAGE_ERROR" else 500
        return jsonify(result), status_code

    session["has_voted"] = 1
    session["latest_reference_id"] = result["reference_id"]

    if request.is_json:
        return jsonify(result)
    else:
        return redirect(url_for("vote_success", ref=result["reference_id"]))


@app.route("/vote/success")
@login_required
def vote_success():
    """Confirmation page with reference ID and security checklist."""
    ref_id = request.args.get("ref") or session.get("latest_reference_id", "TXN-SECUREVOTE-CONFIRMED")
    election = ElectionService.get_election_details()
    return render_template("vote-success.html", ref_id=ref_id, election=election)


@app.route("/results")
def results_view():
    """Official election results tally with candidate percentages."""
    results = ElectionService.get_results()
    return render_template("results.html", results=results)


# ---------------------------------------------------------------------------
# Security Center Routes
# ---------------------------------------------------------------------------
@app.route("/security")
def security_overview():
    """Security Center Home: CIA Triad Overview & Hybrid Protection Architecture."""
    cia = SecurityService.get_cia_overview()
    timeline = SecurityService.get_security_timeline(limit=15)
    hybrid_demo = key_manager.demonstrate_hybrid_key_exchange("SEC_K_SESSION_ALPHA_99")
    return render_template("security.html", cia=cia, timeline=timeline, hybrid_demo=hybrid_demo)


@app.route("/security/rsa")
def security_rsa():
    """Interactive RSA Cryptography Panel (Key Generation, Formulas, and Calculators)."""
    params = rsa_engine.get_key_parameters()
    sample_enc = rsa_engine.encrypt_number(42)
    sample_dec = rsa_engine.decrypt_number(sample_enc["ciphertext_c"])
    return render_template("rsa.html", params=params, sample_enc=sample_enc, sample_dec=sample_dec)


@app.route("/security/hmac")
def security_hmac():
    """Interactive HMAC-SHA256 Authentication Panel (RFC 2104 Padding & Verification)."""
    sample_key = "ElectionAuthoritySecret2026"
    sample_msg = "CANDIDATE:1:Elena Rostova"
    breakdown = HMACSHA256.get_rfc2104_breakdown(sample_key, sample_msg)
    return render_template("hmac.html", sample_key=sample_key, sample_msg=sample_msg, breakdown=breakdown)


@app.route("/security/integrity-demo")
def security_integrity_demo():
    """Controlled Active Tampering Demonstration & Interactive Step-by-Step HMAC Sandbox."""
    candidates = ElectionService.get_all_candidates()
    
    # Retrieve query parameters if voter navigated from ballot review
    requested_id = request.args.get("candidate_id")
    requested_name = request.args.get("candidate_name")
    
    selected_candidate = None
    if requested_id:
        try:
            cid = int(requested_id)
            selected_candidate = next((c for c in candidates if c["id"] == cid), None)
        except (ValueError, TypeError):
            pass
    if not selected_candidate and requested_name:
        selected_candidate = next((c for c in candidates if c["name"].strip().lower() == requested_name.strip().lower()), None)
    if not selected_candidate:
        selected_candidate = candidates[0] if candidates else {"id": 1, "name": "Elena Rostova", "affiliation": "Academic Innovation Slate"}

    # Select default tampered candidate (different from selected)
    tampered_candidate = next((c for c in candidates if c["id"] != selected_candidate["id"]), None)
    if not tampered_candidate:
        tampered_candidate = {"id": 2, "name": "Marcus Vance", "affiliation": "Civic Engagement Coalition"}

    demo_secret = session.get("hmac_secret") or "DemoSessionSecretKey2026"
    orig_msg = f"candidate={selected_candidate['name']}"
    mod_msg = f"candidate={tampered_candidate['name']}"
    orig_tag = HMACSHA256.generate(demo_secret, orig_msg)

    sample_sim = HMACSHA256.simulate_tampering(
        original_msg=orig_msg,
        modified_msg=mod_msg,
        key=demo_secret
    )
    return render_template(
        "integrity-demo.html",
        candidates=candidates,
        selected_candidate=selected_candidate,
        tampered_candidate=tampered_candidate,
        sample_sim=sample_sim,
        initial_orig_tag=orig_tag,
        demo_secret_masked="••••••••••••••••"
    )


@app.route("/security/availability")
def security_availability():
    """System Availability and Operational Reliability Dashboard."""
    status = SecurityService.get_system_availability()
    return render_template("availability.html", status=status)


# ---------------------------------------------------------------------------
# Interactive AJAX API Endpoints for Live Security Demonstrations
# ---------------------------------------------------------------------------
@app.route("/api/pipeline/preview", methods=["POST"])
def api_pipeline_preview():
    """Generates real-time encryption steps and HMAC tag for a candidate selection."""
    data = request.get_json() or {}
    candidate_id = data.get("candidate_id")
    voter_id = session.get("voter_id", "VTR-DEMO-001")
    hmac_key = session.get("hmac_secret", "SEC_K_DEFAULT_SESSION")

    try:
        preview = VotingService.prepare_ballot_preview(int(candidate_id), voter_id, hmac_key)
        return jsonify({"success": True, "preview": preview})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 400


@app.route("/api/rsa/calculate", methods=["POST"])
def api_rsa_calculate():
    """Executes live RSA modular calculation on user-provided input."""
    data = request.get_json() or {}
    calc_type = data.get("type", "number")
    mode = data.get("mode", "encrypt")
    value = data.get("value", "")

    try:
        if calc_type == "number":
            num = int(value)
            if mode == "encrypt":
                res = rsa_engine.encrypt_number(num)
            else:
                res = rsa_engine.decrypt_number(num)
            return jsonify({"success": True, "result": res})
        else:
            text = str(value)
            if mode == "encrypt":
                res = rsa_engine.encrypt_text(text)
            else:
                res = rsa_engine.decrypt_text(text)
            return jsonify({"success": True, "result": res})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 400


@app.route("/api/hmac/generate", methods=["POST"])
def api_hmac_generate():
    """Computes RFC 2104 breakdown for user-provided key and message."""
    data = request.get_json() or {}
    key = data.get("key", "DefaultKey")
    msg = data.get("message", "DefaultMessage")
    try:
        breakdown = HMACSHA256.get_rfc2104_breakdown(key, msg)
        return jsonify({"success": True, "breakdown": breakdown})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 400


@app.route("/api/hmac/tamper-sim", methods=["POST"])
def api_hmac_tamper_sim():
    """Simulates message tampering and returns avalanche statistics."""
    data = request.get_json() or {}
    orig = data.get("original", "CANDIDATE:1:Elena Rostova")
    mod = data.get("modified", "CANDIDATE:2:Marcus Vance")
    key = data.get("key", "SecureSessionSecret")
    try:
        sim = HMACSHA256.simulate_tampering(orig, mod, key)
        return jsonify({"success": True, "simulation": sim})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 400


@app.route("/api/hmac/sandbox-step", methods=["POST"])
def api_hmac_sandbox_step():
    """
    Executes real HMAC-SHA256 cryptographic steps for the interactive sandbox.
    Supports 'generate', 'tamper', and 'valid' modes using Python's hmac.compare_digest.
    """
    data = request.get_json() or {}
    mode = data.get("mode", "tamper")  # 'generate', 'tamper', 'valid'
    candidate_name = data.get("candidate_name", "Elena Rostova").strip()
    tampered_name = data.get("tampered_candidate_name", "Marcus Vance").strip()
    key = session.get("hmac_secret") or data.get("secret_key") or "DemoSessionSecretKey2026"

    # Step 1: Canonical Message
    orig_msg = f"candidate={candidate_name}"
    orig_tag = HMACSHA256.generate(key, orig_msg)

    if mode == "generate":
        return jsonify({
            "success": True,
            "mode": "generate",
            "candidate_name": candidate_name,
            "message": orig_msg,
            "secret_masked": "••••••••••••••••",
            "tag": orig_tag,
            "tag_bit_length": 256
        })

    if mode == "valid":
        received_msg = orig_msg
        received_tag = orig_tag
        recalculated_tag = HMACSHA256.generate(key, received_msg)
        is_match = HMACSHA256.verify(key, received_msg, received_tag)

        return jsonify({
            "success": True,
            "mode": "valid",
            "original_candidate": candidate_name,
            "original_message": orig_msg,
            "original_tag": orig_tag,
            "secret_masked": "••••••••••••••••",
            "transmitted_payload": orig_msg,
            "transmitted_tag": orig_tag,
            "server_received_payload": received_msg,
            "server_received_tag": received_tag,
            "server_recalculated_tag": recalculated_tag,
            "is_match": is_match,
            "status": "MATCH",
            "status_label": "✓ MATCH / INTEGRITY VERIFIED",
            "security_decision": "INTEGRITY VERIFIED",
            "security_action": "VOTE ACCEPTED",
            "explanation": "The received message matches the authentication tag computed with the shared secret key. Message integrity and origin are confirmed.",
            "differing_bits": 0,
            "avalanche_percentage": 0.0
        })

    # Default: mode == "tamper"
    tampered_msg = f"candidate={tampered_name}"
    received_msg = tampered_msg
    received_tag = orig_tag  # Intercepted request retains original voter HMAC tag
    recalculated_tag = HMACSHA256.generate(key, received_msg)
    is_match = HMACSHA256.verify(key, received_msg, received_tag)

    # Calculate differing bits for avalanche insight
    orig_int = int(orig_tag, 16)
    recalc_int = int(recalculated_tag, 16)
    differing_bits = bin(orig_int ^ recalc_int).count("1")
    avalanche_pct = round((differing_bits / 256) * 100, 2)

    return jsonify({
        "success": True,
        "mode": "tamper",
        "original_candidate": candidate_name,
        "original_message": orig_msg,
        "original_tag": orig_tag,
        "tampered_candidate": tampered_name,
        "tampered_message": tampered_msg,
        "secret_masked": "••••••••••••••••",
        "transmitted_payload": tampered_msg,
        "transmitted_tag": orig_tag,
        "server_received_payload": received_msg,
        "server_received_tag": received_tag,
        "server_recalculated_tag": recalculated_tag,
        "is_match": is_match,
        "status": "MISMATCH",
        "status_label": "✕ MISMATCH",
        "security_decision": "INTEGRITY CHECK FAILED",
        "security_action": "REQUEST REJECTED / VOTE NOT STORED",
        "explanation": "The message was modified in transit. The authentication tag is invalid for the received message. The system safely discards the request before storage.",
        "differing_bits": differing_bits,
        "avalanche_percentage": avalanche_pct
    })


@app.route("/api/system/reset-demo", methods=["POST"])
def api_reset_demo():
    """Resets all vote tallies and eligibility for repeat practical demonstration."""
    try:
        ElectionService.reset_election()
        session["has_voted"] = 0
        return jsonify({"success": True, "message": "Election data reset successfully for new demonstration run."})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


# ---------------------------------------------------------------------------
# Auditor Section Routes (Dedicated Read-Only Election Auditing)
# ---------------------------------------------------------------------------
@app.route("/auditor/dashboard")
@auditor_required
def auditor_dashboard():
    """Auditor Dashboard: Real-time high-level election & cryptographic metrics."""
    summary = AuditorService.get_dashboard_summary()
    return render_template("auditor/dashboard.html", summary=summary)


@app.route("/auditor/elections")
@auditor_required
def auditor_elections():
    """Auditor Election Metadata, Candidates Roster, and Vote Counts."""
    summary = AuditorService.get_dashboard_summary()
    results = ElectionService.get_results()
    return render_template(
        "auditor/elections.html",
        summary=summary,
        candidates=results["tallies"],
        total_votes=results["total_votes"]
    )


@app.route("/auditor/votes")
@auditor_required
def auditor_votes():
    """Auditor Vote Audit Ledger (Anonymized & Cryptographically Indexed)."""
    status_filter = request.args.get("status")
    records = AuditorService.get_vote_records(status_filter=status_filter)
    return render_template("auditor/votes.html", records=records, status_filter=status_filter)


@app.route("/api/auditor/vote-detail/<path:ref_id>")
@auditor_required
def api_auditor_vote_detail(ref_id):
    """API endpoint returning full step-by-step cryptographic timeline for a vote reference."""
    timeline = AuditorService.get_vote_timeline_detail(ref_id)
    return jsonify(timeline)


@app.route("/auditor/security-logs")
@auditor_required
def auditor_security_logs():
    """Auditor Security Logs: Chronological filtered event audit trail."""
    event_filter = request.args.get("event")
    status_filter = request.args.get("status")
    search_query = request.args.get("q")
    logs = AuditorService.get_security_logs(
        event_filter=event_filter,
        status_filter=status_filter,
        search=search_query
    )
    return render_template(
        "auditor/security_logs.html",
        logs=logs,
        event_filter=event_filter,
        status_filter=status_filter,
        search_query=search_query
    )


@app.route("/auditor/integrity")
@auditor_required
def auditor_integrity():
    """Auditor Integrity Checks: HMAC-SHA256 verification and tampering audit."""
    data = AuditorService.get_hmac_integrity_audit()
    return render_template("auditor/integrity.html", data=data)


@app.route("/auditor/rsa")
@auditor_required
def auditor_rsa():
    """Auditor RSA Cryptography: Mathematical key verification and public parameters."""
    data = AuditorService.get_rsa_audit_details()
    return render_template("auditor/rsa.html", data=data)


@app.route("/auditor/duplicate-checks")
@auditor_required
def auditor_duplicate_checks():
    """Auditor Duplicate Vote Verification: Single-vote constraint validation."""
    data = AuditorService.get_duplicate_checks()
    return render_template("auditor/duplicate_checks.html", data=data)


@app.route("/auditor/results")
@auditor_required
def auditor_results():
    """Auditor Certified Results Verification & Tabulation."""
    data = AuditorService.get_results_verification()
    return render_template("auditor/results.html", data=data)


@app.route("/auditor/reports")
@auditor_required
def auditor_reports():
    """Auditor Formal Certified Audit Report view."""
    report = AuditorService.generate_audit_report()
    return render_template("auditor/reports.html", report=report)


@app.route("/auditor/reports/export-csv")
@auditor_required
def auditor_export_csv():
    """Exports full audit report and vote ledger as downloadable CSV."""
    csv_data = AuditorService.export_report_csv()
    filename = f"securevote-audit-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/auditor/system-status")
@auditor_required
def auditor_system_status():
    """Auditor System Status: Component health and availability monitoring."""
    status = AuditorService.get_system_status()
    return render_template("auditor/system_status.html", status=status)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
