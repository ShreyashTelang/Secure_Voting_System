/**
 * SecureVote Security Pipeline & Tamper Simulation Scripts
 */

document.addEventListener("DOMContentLoaded", () => {
    initVoteProcessingPipeline();
    initSecurityTamperSandbox();
    initPipelineStageInspectors();
});

// Cache for active pipeline stage data
const activePipelineData = {
    candidateId: null,
    plaintextBallot: "",
    encryptedVote: "",
    hmacTag: "",
    canonicalPayload: "",
    serverDecryption: "",
    status: "IDLE"
};

function initVoteProcessingPipeline() {
    const btnCastSecure = document.getElementById("btnCastVoteSecure");
    const btnSimTamper = document.getElementById("btnSimulateTamper");

    if (btnCastSecure) {
        btnCastSecure.addEventListener("click", (e) => {
            e.preventDefault();
            executePipelineExecution(false);
        });
    }

    if (btnSimTamper) {
        btnSimTamper.addEventListener("click", (e) => {
            e.preventDefault();
            executePipelineExecution(true);
        });
    }
}

function executePipelineExecution(simulateTamper) {
    const candidateId = document.getElementById("ballotCandidateId").value;
    const pipelineContainer = document.getElementById("securityProcessingPipeline");
    const actionsContainer = document.getElementById("voteActionsContainer");
    const outcomeContainer = document.getElementById("pipelineOutcomeDisplay");
    const statusBadge = document.getElementById("pipelineStatusBadge");

    activePipelineData.candidateId = candidateId;
    activePipelineData.encryptedVote = document.getElementById("previewCiphertext") ? document.getElementById("previewCiphertext").value : "";
    activePipelineData.hmacTag = document.getElementById("previewHmacTag") ? document.getElementById("previewHmacTag").value : "";
    activePipelineData.canonicalPayload = document.getElementById("previewCanonical") ? document.getElementById("previewCanonical").value : "";

    if (actionsContainer) actionsContainer.style.display = "none";
    if (pipelineContainer) pipelineContainer.style.display = "block";
    if (statusBadge) {
        statusBadge.className = "status-pill neutral";
        statusBadge.innerText = simulateTamper ? "Simulating Attack..." : "Processing...";
    }

    // Step 1: Vote Created
    setNodeState("nodeStage1", "active");
    showStageDetail(1, "Stage 1: Vote Created", "The voter's selection was formatted into the canonical ballot structure <code>CANDIDATE:ID:NAME</code> with voter identification metadata.");

    setTimeout(() => {
        setNodeState("nodeStage1", "completed");
        setConnectorState("conn1", true);

        // Step 2: RSA Protection
        setNodeState("nodeStage2", "active");
        showStageDetail(2, "Stage 2: RSA Protection", `Ballot choice encrypted using Election Authority RSA Public Key (e=17, n=3233). Modular exponentiation: <code>C = M^e mod n</code>. Ciphertext: <code>${activePipelineData.encryptedVote.slice(0, 36)}...</code>`);

        setTimeout(() => {
            setNodeState("nodeStage2", "completed");
            setConnectorState("conn2", true);

            // Step 3: HMAC-SHA256
            setNodeState("nodeStage3", "active");
            showStageDetail(3, "Stage 3: HMAC-SHA256 Authentication", `Constructed canonical transmission envelope and generated 256-bit authentication tag using voter's unique shared secret key. Tag: <code>${activePipelineData.hmacTag.slice(0, 32)}...</code>`);

            setTimeout(() => {
                setNodeState("nodeStage3", "completed");
                setConnectorState("conn3", true);

                // Step 4: Secure Request
                setNodeState("nodeStage4", "active");
                showStageDetail(4, "Stage 4: Secure Request", "Packet dispatched to the election server via HTTPS containing the RSA-encrypted ballot, 256-bit authentication tag, and voter identification token.");

                setTimeout(() => {
                    setNodeState("nodeStage4", "completed");
                    setConnectorState("conn4", true);

                    // Step 5: Server Verification
                    setNodeState("nodeStage5", "active");
                    showStageDetail(5, "Stage 5: Server Verification", "Election server received packet. Recomputing HMAC-SHA256 over received payload using stored voter secret key and executing constant-time verification via <code>hmac.compare_digest()</code>...");

                    // Transmit to server
                    fetch("/vote/submit", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            candidate_id: candidateId,
                            simulate_tamper: simulateTamper
                        })
                    })
                    .then(async res => {
                        const data = await res.json();
                        if (data.success) {
                            setNodeState("nodeStage5", "completed");
                            setConnectorState("conn5", true);

                            // Step 6: Vote Accepted
                            setNodeState("nodeStage6", "completed");
                            if (statusBadge) {
                                statusBadge.className = "status-pill success";
                                statusBadge.innerText = "Verified & Accepted";
                            }
                            showStageDetail(6, "Stage 6: Vote Accepted & Ledger Recorded", `HMAC verified with constant-time precision. Server private key (d=2753) decrypted the candidate choice. Ballot recorded in database under anonymous SHA-256 voter hash. Transaction ID: <code>${data.reference_id}</code>.`);
                            renderPipelineSuccess(data, outcomeContainer);
                        } else {
                            // Tampering detected or rejection
                            setNodeState("nodeStage5", "danger");
                            setNodeState("nodeStage6", "rejected");
                            if (statusBadge) {
                                statusBadge.className = "status-pill danger";
                                statusBadge.innerText = "Rejected: Integrity Failure";
                            }
                            showStageDetail(5, "Stage 5: Server Verification FAILED", `HMAC mismatch detected! Received Tag: <code>${data.diagnostics ? data.diagnostics.received_hmac.slice(0, 24) : 'INVALID'}...</code> does not match Recalculated Tag: <code>${data.diagnostics ? data.diagnostics.recalculated_hmac.slice(0, 24) : 'MISMATCH'}...</code>. The vote was discarded.`);
                            renderPipelineFailure(data, outcomeContainer);
                        }
                    })
                    .catch(err => {
                        setNodeState("nodeStage5", "danger");
                        if (outcomeContainer) {
                            outcomeContainer.innerHTML = `<div class="alert alert-error">Network error: ${err.message}</div>`;
                        }
                    });

                }, 400);
            }, 400);
        }, 400);
    }, 400);
}

function setNodeState(nodeId, state) {
    const node = document.getElementById(nodeId);
    if (!node) return;
    node.classList.remove("active", "completed");
    node.style.backgroundColor = "";
    const circle = node.querySelector(".node-circle");

    if (state === "active") {
        node.classList.add("active");
    } else if (state === "completed") {
        node.classList.add("completed");
    } else if (state === "danger") {
        node.style.backgroundColor = "var(--status-danger-bg)";
        if (circle) {
            circle.style.backgroundColor = "var(--status-danger)";
            circle.innerText = "✕";
        }
    } else if (state === "rejected") {
        node.style.opacity = "0.4";
        const title = node.querySelector(".node-title");
        if (title) title.innerText = "Vote Rejected";
    }
}

function setConnectorState(connId, active) {
    const conn = document.getElementById(connId);
    if (conn) {
        if (active) conn.classList.add("active");
        else conn.classList.remove("active");
    }
}

function showStageDetail(stageNum, title, description) {
    const box = document.getElementById("pipelineStageDetailBox");
    const titleElem = document.getElementById("stageDetailTitle");
    const bodyElem = document.getElementById("stageDetailBody");
    const pillElem = document.getElementById("stageDetailPill");

    if (box && titleElem && bodyElem) {
        box.style.display = "block";
        titleElem.innerHTML = title;
        bodyElem.innerHTML = description;
        if (pillElem) pillElem.innerText = `Stage ${stageNum}`;
    }
}

function initPipelineStageInspectors() {
    const nodes = document.querySelectorAll(".pipeline-node");
    nodes.forEach(node => {
        node.addEventListener("click", () => {
            const stage = node.getAttribute("data-stage");
            if (stage === "1") {
                showStageDetail(1, "Stage 1: Vote Created", "Ballot selection formatted: <code>CANDIDATE:ID:NAME</code>. Prepares payload for cryptographic transformation.");
            } else if (stage === "2") {
                showStageDetail(2, "Stage 2: RSA Protection (Confidentiality)", "Plaintext characters converted to ASCII numbers and raised to public exponent e=17 modulo n=3233 (<code>C = M^e mod n</code>). Protects against network snooping.");
            } else if (stage === "3") {
                showStageDetail(3, "Stage 3: HMAC-SHA256 (Integrity & Authentication)", "Constructs canonical message and computes 256-bit tag using RFC 2104 inner/outer pad and voter's secret key. Ensures any bit change is detected.");
            } else if (stage === "4") {
                showStageDetail(4, "Stage 4: Secure Request", "The HTTP request payload is sent to the server containing <code>{candidate_id, encrypted_vote, hmac_tag, voter_id, timestamp}</code>.");
            } else if (stage === "5") {
                showStageDetail(5, "Stage 5: Server Verification", "Election server queries voter secret, recomputes expected HMAC, and runs constant-time verification using <code>hmac.compare_digest</code>.");
            } else if (stage === "6") {
                showStageDetail(6, "Stage 6: Vote Accepted & Decrypted", "If verified, election server decrypts ballot using private key (d=2753), records vote under anonymous SHA-256 hash, and issues transaction reference ID.");
            }
        });
    });
}

function renderPipelineSuccess(data, container) {
    if (!container) return;
    container.innerHTML = `
        <div class="card" style="border-color: var(--status-success-border); background-color: var(--status-success-bg); margin-top: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span class="status-pill success">✓ Vote Accepted</span>
                    <span style="font-weight: 600; font-size: 1.05rem; color: var(--status-success);">Cryptographic Pipeline Complete</span>
                </div>
                <span class="code-inline">${data.reference_id}</span>
            </div>
            <p style="color: #14532d; font-size: 0.95rem; margin-bottom: 16px;">
                The server verified the 256-bit HMAC tag using constant-time comparison (<code>hmac.compare_digest</code>). Integrity confirmed. RSA private key decrypted the ballot candidate choice: <strong>${data.candidate_name}</strong>.
            </p>
            <div class="grid-2" style="font-size: 0.88rem; color: #166534; margin-bottom: 16px;">
                <div>• RSA Encryption: Applied & Decrypted (Confidentiality)</div>
                <div>• HMAC-SHA256: Verified via compare_digest (Integrity)</div>
                <div>• Single-Vote Check: Passed (Availability)</div>
                <div>• Anonymous Ledger: Persisted under SHA-256 Hash</div>
            </div>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <a href="/vote/success?ref=${data.reference_id}" class="btn btn-primary btn-sm">View Official Confirmation Receipt →</a>
                <a href="/results" class="btn btn-secondary btn-sm">View Certified Results</a>
            </div>
        </div>
    `;
}

function renderPipelineFailure(data, container) {
    if (!container) return;
    const candIdInput = document.getElementById("ballotCandidateId");
    const candidateId = candIdInput ? candIdInput.value : "1";
    const candidateName = data.diagnostics && data.diagnostics.original_intended_candidate 
        ? data.diagnostics.original_intended_candidate 
        : "";
    const isSimulated = data.diagnostics && data.diagnostics.simulation_note;

    container.innerHTML = `
        <div class="card" style="border-color: var(--status-danger-border); background-color: var(--status-danger-bg); margin-top: 20px;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
                <span class="status-pill danger">✕ Request Rejected</span>
                <span style="font-weight: 600; color: var(--status-danger);">Integrity Check Failed</span>
            </div>
            <h3 style="color: #991b1b; font-size: 1.1rem; margin-bottom: 8px;">
                Request integrity check failed. The vote was not stored.
            </h3>
            <p style="color: #7f1d1d; font-size: 0.92rem; margin-bottom: 14px; line-height: 1.5;">
                <strong>Simulation:</strong> the voting request was modified before server verification. The modified message produced a different HMAC-SHA256 authentication tag. Because the received tag did not match the server's recalculated tag, the request was rejected.
            </p>
            ${data.diagnostics ? `
                <div class="code-block" style="background: #1e1b24; color: #fca5a5; font-size: 0.82rem;">
                    <div><strong>Original Intended Ballot:</strong> ${data.diagnostics.original_intended_candidate}</div>
                    <div><strong>Received (Tampered) Tag:</strong>   ${data.diagnostics.received_hmac}</div>
                    <div><strong>Server Recalculated Tag:</strong>   ${data.diagnostics.recalculated_hmac}</div>
                    <div><strong>Constant-Time Tag Match:</strong>   <span style="color: #ef4444; font-weight: bold;">FALSE (MISMATCH)</span></div>
                    <div><strong>Server Decision:</strong>          DISCARD BALLOT IMMEDIATELY</div>
                </div>
            ` : ""}
            <div style="margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap;">
                <button onclick="window.location.reload()" class="btn btn-secondary btn-sm">Try Again</button>
                <a href="/security/integrity-demo?candidate_id=${encodeURIComponent(candidateId)}&candidate_name=${encodeURIComponent(candidateName)}" class="btn btn-secondary btn-sm">Inspect Integrity Sandbox &rarr;</a>
            </div>
        </div>
    `;
}

function initSecurityTamperSandbox() {
    const btnRunTamperTest = document.getElementById("btnRunTamperTest");
    if (btnRunTamperTest) {
        btnRunTamperTest.addEventListener("click", () => {
            const orig = document.getElementById("sandboxOrigMsg").value;
            const mod = document.getElementById("sandboxModMsg").value;
            const key = document.getElementById("sandboxKey").value;

            fetch("/api/hmac/tamper-sim", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ original: orig, modified: mod, key: key })
            })
            .then(res => res.json())
            .then(data => {
                const target = document.getElementById("sandboxTamperOutput");
                if (data.success && target) {
                    const sim = data.simulation;
                    target.innerHTML = `
                        <div class="card" style="margin-top: 16px; border-color: ${sim.is_verified ? 'var(--status-success-border)' : 'var(--status-danger-border)'}; background-color: ${sim.is_verified ? 'var(--status-success-bg)' : 'var(--status-danger-bg)'}; margin-bottom: 0;">
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                                <span class="status-pill ${sim.is_verified ? 'success' : 'danger'}">
                                    ${sim.status_message}
                                </span>
                                <span style="font-size: 0.85rem; color: var(--text-muted);">
                                    Hamming Distance: ${sim.differing_bits} / ${sim.total_bits} bits (${sim.avalanche_percentage}% flipped)
                                </span>
                            </div>
                            <div class="code-block" style="background:#0f172a; font-size: 0.82rem; margin: 0;">
                                <div><strong>Original Message:</strong>     "${sim.original_message}"</div>
                                <div><strong>Modified Message:</strong>     "<span style="color:#f87171;">${sim.modified_message}</span>"</div>
                                <div style="margin: 6px 0; border-top: 1px solid #334155;"></div>
                                <div><strong>Original Valid Tag:</strong>    <span style="color:#38bdf8;">${sim.original_tag}</span></div>
                                <div><strong>Recalculated Tag:</strong>      <span style="color:#fca5a5;">${sim.recalculated_tag}</span></div>
                                <div><strong>Constant-Time Match:</strong>   <span style="color: ${sim.is_verified ? '#4ade80' : '#f87171'}; font-weight: bold;">${sim.is_verified ? 'TRUE (MATCH)' : 'FALSE (MISMATCH)'}</span></div>
                                <div><strong>Server Action:</strong>          <strong>${sim.is_verified ? 'Accept Vote' : 'Discard Vote Immediately (Do Not Record)'}</strong></div>
                            </div>
                        </div>
                    `;
                }
            });
        });
    }
}
