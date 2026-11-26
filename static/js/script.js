/* ==========================================================================
   JavaScript: Secure Electronic Voting System using RSA & HMAC-SHA256
   Interactive Cryptography Engine & Demonstration Handlers
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    initFlashCloser();
    initCandidateSelection();
    initVoteSubmissionForms();
    initRSACalculators();
    initHMACCalculators();
    initESETour();
    initVivaAccordions();
    initResetButton();
});

// --------------------------------------------------------------------------
// 1. Flash Message Dismissal
// --------------------------------------------------------------------------
function initFlashCloser() {
    document.querySelectorAll(".close-alert").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const alert = e.target.closest(".alert");
            if (alert) alert.remove();
        });
    });
}

// --------------------------------------------------------------------------
// 2. Candidate Card Selection in Voting Booth
// --------------------------------------------------------------------------
function initCandidateSelection() {
    const cards = document.querySelectorAll(".candidate-card");
    const hiddenInput = document.getElementById("selectedCandidateId");
    const previewName = document.getElementById("previewCandName");
    const liveCryptoPipeline = document.getElementById("liveCryptoPipeline");

    cards.forEach(card => {
        card.addEventListener("click", () => {
            cards.forEach(c => c.classList.remove("selected"));
            card.classList.add("selected");
            const candId = card.getAttribute("data-candidate-id");
            const candName = card.getAttribute("data-candidate-name");

            if (hiddenInput) hiddenInput.value = candId;
            if (previewName) previewName.innerText = candName;
            if (liveCryptoPipeline) {
                liveCryptoPipeline.style.display = "block";
                updateLivePipelinePreview(candId, candName);
            }
        });
    });
}

function updateLivePipelinePreview(candId, candName) {
    const plainElem = document.getElementById("pipelinePlaintext");
    const encElem = document.getElementById("pipelineEncrypted");
    const hmacElem = document.getElementById("pipelineHmac");

    if (!plainElem) return;

    const plaintext = `ID:${candId}|NAME:${candName}`;
    plainElem.innerText = plaintext;

    // Call server to get live educational preview of RSA + HMAC
    fetch("/api/rsa/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "text", value: plaintext })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success && encElem) {
            encElem.innerText = data.result.cipher_string;
            const voterSecretElem = document.getElementById("voterSecretVal");
            const voterIdElem = document.getElementById("voterIdVal");
            const secret = voterSecretElem ? voterSecretElem.innerText : "VoterSecret";
            const vId = voterIdElem ? voterIdElem.innerText : "VOTER-X";
            const canonical = `${data.result.cipher_string}|${vId}|TIMESTAMP`;

            fetch("/api/hmac/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: canonical, key: secret })
            })
            .then(r => r.json())
            .then(hData => {
                if (hData.success && hmacElem) {
                    hmacElem.innerText = hData.steps.step_5.final_hmac_tag;
                }
            });
        }
    })
    .catch(err => console.error("Pipeline preview error:", err));
}

// --------------------------------------------------------------------------
// 3. Voting Submission & Tamper Simulation
// --------------------------------------------------------------------------
function initVoteSubmissionForms() {
    const btnSubmitNormal = document.getElementById("btnSubmitNormal");
    const btnSubmitTamper = document.getElementById("btnSubmitTamper");
    const responseModal = document.getElementById("voteResultDisplay");

    if (btnSubmitNormal) {
        btnSubmitNormal.addEventListener("click", (e) => {
            e.preventDefault();
            executeVoteSubmission(false);
        });
    }

    if (btnSubmitTamper) {
        btnSubmitTamper.addEventListener("click", (e) => {
            e.preventDefault();
            executeVoteSubmission(true);
        });
    }
}

function executeVoteSubmission(simulateTamper) {
    const candInput = document.getElementById("selectedCandidateId");
    if (!candInput || !candInput.value) {
        alert("Please select a candidate first!");
        return;
    }

    const candidateId = candInput.value;
    const payload = {
        candidate_id: candidateId,
        simulate_tamper: simulateTamper
    };

    const statusBox = document.getElementById("submissionStatusBox");
    if (statusBox) {
        statusBox.style.display = "block";
        statusBox.innerHTML = `
            <div class="code-box" style="color: #38bdf8;">
                ⏳ Transmitting vote payload to Election Server over simulated network...<br>
                ${simulateTamper ? "<span style='color: #ef4444;'>⚠️ [ACTIVE MITM ADVERSARY INTERCEPTION INJECTED] Ballot payload modified in transit!</span>" : "🔒 Dual-Layer Protected: RSA Encrypted + HMAC Authenticated"}
            </div>
        `;
    }

    fetch("/vote/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(async response => {
        const data = await response.json();
        renderSubmissionResult(data, simulateTamper);
    })
    .catch(err => {
        console.error("Submission failed:", err);
        if (statusBox) {
            statusBox.innerHTML = `<div class="alert alert-danger">Network Error: ${err.message}</div>`;
        }
    });
}

function renderSubmissionResult(data, isTampered) {
    const statusBox = document.getElementById("submissionStatusBox");
    if (!statusBox) return;

    if (data.success) {
        statusBox.innerHTML = `
            <div class="step-card" style="border-color: #10b981; background: rgba(16, 185, 129, 0.08);">
                <div class="step-header">
                    <span class="step-num-pill" style="background: #10b981; color: white;">ELECTION SERVER DECISION</span>
                    <span style="color: #10b981; font-weight: 700;">✓ VOTE ACCEPTED & RECORDED</span>
                </div>
                <h3 style="color: #ffffff; margin-bottom: 8px;">${data.message}</h3>
                <p style="font-size: 0.9rem; color: #cbd5e1; margin-bottom: 12px;">
                    The server recalculated the HMAC-SHA256 tag using its secure voter credential key. The calculated digest matched the received authentication tag with constant-time precision (<code>compare_digest() == True</code>). The RSA payload was then decrypted using the server's private key <code>(d, n)</code>.
                </p>
                <div class="code-box">
                    <strong>Voter ID:</strong> ${data.data.voter_id}<br>
                    <strong>Decrypted Ballot:</strong> ${data.data.decrypted_ballot}<br>
                    <strong>HMAC Authentication Tag:</strong> ${data.data.hmac_tag}<br>
                    <strong>Timestamp:</strong> ${data.data.timestamp}
                </div>
                <div style="margin-top: 15px; display: flex; gap: 10px;">
                    <a href="/results" class="btn btn-primary btn-sm">View Live Results</a>
                    <a href="/dashboard" class="btn btn-secondary btn-sm">Return to Dashboard</a>
                </div>
            </div>
        `;
    } else {
        // Tampering detected or double vote
        statusBox.innerHTML = `
            <div class="step-card" style="border-color: #ef4444; background: rgba(239, 68, 68, 0.1); box-shadow: var(--shadow-red);">
                <div class="step-header">
                    <span class="step-num-pill" style="background: #ef4444; color: white;">SECURITY ALARM</span>
                    <span style="color: #ef4444; font-weight: 800; font-size: 1.05rem;">🚨 ${data.status || "VOTE REJECTED"}</span>
                </div>
                <h3 style="color: #fca5a5; margin-bottom: 8px;">${data.message}</h3>
                ${data.diagnostics ? `
                    <div style="font-size: 0.9rem; color: #fecaca; margin-bottom: 10px;">
                        <strong>Cryptographic Failure Analysis:</strong><br>
                        The Man-in-the-Middle attacker altered the candidate ballot in transit without possessing the voter's unique HMAC secret key. When the server recomputed <code>HMAC-SHA256(secret, payload)</code>, the result did not match the tag received!
                    </div>
                    <div class="code-box" style="color: #fca5a5; background: #1c1015; border-color: #7f1d1d;">
                        <strong>Received (Forged/Original) HMAC:</strong> ${data.diagnostics.received_hmac}<br>
                        <strong>Server Recalculated HMAC:</strong>       ${data.diagnostics.recalculated_hmac}<br>
                        <strong>Verification Match:</strong>          <span style="color: #ef4444; font-weight: bold;">FALSE (MISMATCH)</span><br>
                        <strong>Decision:</strong>                    <span style="color: #ef4444; font-weight: bold;">DISCARD BALLOT IMMEDIATELY</span>
                    </div>
                ` : `<p style="color: #fca5a5;">${data.message}</p>`}
                <div style="margin-top: 15px;">
                    <button onclick="location.reload()" class="btn btn-secondary btn-sm">Try Again</button>
                    <a href="/security-analysis" class="btn btn-purple btn-sm">View Attack Analysis</a>
                </div>
            </div>
        `;
    }
}

// --------------------------------------------------------------------------
// 4. RSA Interactive Calculators & Key Generation
// --------------------------------------------------------------------------
function initRSACalculators() {
    const btnGenKeys = document.getElementById("btnGenCustomRSA");
    if (btnGenKeys) {
        btnGenKeys.addEventListener("click", () => {
            const p = document.getElementById("customP").value;
            const q = document.getElementById("customQ").value;
            const e = document.getElementById("customE").value;

            fetch("/api/rsa/generate-keys", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ p: p, q: q, e: e })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    location.reload(); // Refresh to show newly loaded educational state
                } else {
                    alert("Key Generation Error: " + data.error);
                }
            })
            .catch(err => alert("Error: " + err.message));
        });
    }

    const btnEncNum = document.getElementById("btnEncryptNumber");
    if (btnEncNum) {
        btnEncNum.addEventListener("click", () => {
            const num = document.getElementById("rsaNumInput").value;
            fetch("/api/rsa/encrypt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ type: "number", value: num })
            })
            .then(r => r.json())
            .then(data => {
                const out = document.getElementById("rsaEncNumResult");
                if (data.success && out) {
                    out.innerHTML = `
                        <div class="code-box">
                            <strong>Formula:</strong> ${data.result.formula}<br>
                            <strong>Step:</strong> ${data.result.calculation}<br>
                            <strong>Ciphertext (C):</strong> <span style="color: #00f5d4; font-size: 1.1rem; font-weight: bold;">${data.result.ciphertext_c}</span>
                        </div>
                    `;
                    // Auto-fill decryption input
                    const decIn = document.getElementById("rsaCipherInput");
                    if (decIn) decIn.value = data.result.ciphertext_c;
                } else if (out) {
                    out.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                }
            });
        });
    }

    const btnDecNum = document.getElementById("btnDecryptNumber");
    if (btnDecNum) {
        btnDecNum.addEventListener("click", () => {
            const c = document.getElementById("rsaCipherInput").value;
            fetch("/api/rsa/decrypt", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ type: "number", value: c })
            })
            .then(r => r.json())
            .then(data => {
                const out = document.getElementById("rsaDecNumResult");
                if (data.success && out) {
                    out.innerHTML = `
                        <div class="code-box">
                            <strong>Formula:</strong> ${data.result.formula}<br>
                            <strong>Step:</strong> ${data.result.calculation}<br>
                            <strong>Recovered Plaintext (M):</strong> <span style="color: #10b981; font-size: 1.1rem; font-weight: bold;">${data.result.recovered_plaintext_m}</span>
                        </div>
                    `;
                } else if (out) {
                    out.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                }
            });
        });
    }
}

// --------------------------------------------------------------------------
// 5. HMAC Interactive Sandbox & Tampering Simulation
// --------------------------------------------------------------------------
function initHMACCalculators() {
    const btnGenHmac = document.getElementById("btnGenHMAC");
    if (btnGenHmac) {
        btnGenHmac.addEventListener("click", () => {
            const msg = document.getElementById("hmacMsgInput").value;
            const key = document.getElementById("hmacKeyInput").value;

            fetch("/api/hmac/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ message: msg, key: key })
            })
            .then(r => r.json())
            .then(data => {
                const out = document.getElementById("hmacGenResult");
                if (data.success && out) {
                    const steps = data.steps;
                    out.innerHTML = `
                        <div class="step-card" style="border-color: #00f5d4;">
                            <div class="formula-card">
                                <div class="formula-title">GENERATED HMAC-SHA256 AUTHENTICATION TAG</div>
                                <div class="formula-content" style="word-break: break-all; color: #00f5d4;">
                                    ${steps.step_5.final_hmac_tag}
                                </div>
                            </div>
                            <div class="code-box" style="font-size: 0.82rem;">
                                <strong>Step 1 (Key Normalization):</strong> ${steps.step_1.explanation} (Length: ${steps.step_1.k_padded_length} B)<br>
                                <strong>Step 2 (Inner Pad XOR):</strong> K' ⊕ 0x36 = ${steps.step_2.k_xor_ipad_hex}<br>
                                <strong>Step 3 (Inner Hash):</strong> SHA-256((K' ⊕ ipad) || M) = ${steps.step_3.inner_hash_hex}<br>
                                <strong>Step 4 (Outer Pad XOR):</strong> K' ⊕ 0x5C = ${steps.step_4.k_xor_opad_hex}<br>
                                <strong>Step 5 (Final Digest):</strong> SHA-256((K' ⊕ opad) || Inner_Hash)
                            </div>
                        </div>
                    `;
                } else if (out) {
                    out.innerHTML = `<div class="alert alert-danger">${data.error}</div>`;
                }
            });
        });
    }

    const btnSimTamper = document.getElementById("btnRunTamperSim");
    if (btnSimTamper) {
        btnSimTamper.addEventListener("click", () => {
            const orig = document.getElementById("tamperOrigMsg").value;
            const tamp = document.getElementById("tamperModMsg").value;
            const key = document.getElementById("tamperKey").value;

            fetch("/api/hmac/tamper-sim", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ original_message: orig, tampered_message: tamp, key: key })
            })
            .then(r => r.json())
            .then(data => {
                const out = document.getElementById("tamperSimResult");
                if (data.success && out) {
                    const sim = data.simulation;
                    out.innerHTML = `
                        <div class="step-card" style="border-color: ${sim.hmac_match ? '#10b981' : '#ef4444'};">
                            <h4 style="color: ${sim.hmac_match ? '#10b981' : '#ef4444'}; margin-bottom: 8px;">
                                ${sim.alert_message}
                            </h4>
                            <div class="code-box" style="font-size: 0.85rem;">
                                <strong>Original Message:</strong> "${sim.original_message}"<br>
                                <strong>Tampered Message:</strong> "<span style="color: #ef4444;">${sim.tampered_message}</span>"<br>
                                <strong>Shared Secret Key:</strong> "${sim.secret_key}"<br><br>
                                <strong>Original Valid HMAC:</strong>    <span style="color: #38bdf8;">${sim.original_hmac}</span><br>
                                <strong>Recalculated Server HMAC:</strong> <span style="color: #fca5a5;">${sim.server_recalculated_hmac}</span><br>
                                <strong>Bit Differences (Hamming):</strong> ${sim.differing_bits} of 256 bits changed (${sim.bit_change_percentage}%) - <em>Avalanche Effect!</em><br>
                                <strong>Constant-Time Match:</strong>      ${sim.hmac_match ? "TRUE" : "<strong style='color:#ef4444;'>FALSE (MISMATCH)</strong>"}<br>
                                <strong>Server Policy:</strong>           <strong style="color: ${sim.hmac_match ? '#10b981' : '#ef4444'};">${sim.server_action}</strong>
                            </div>
                        </div>
                    `;
                }
            });
        });
    }
}

// --------------------------------------------------------------------------
// 6. ESE 10-Screen Examination Tour Mode
// --------------------------------------------------------------------------
function initESETour() {
    const screens = document.querySelectorAll(".ese-screen");
    const dots = document.querySelectorAll(".ese-dot");
    const btnNext = document.getElementById("btnEseNext");
    const btnPrev = document.getElementById("btnEsePrev");
    const screenCounter = document.getElementById("eseCurrentStepNum");

    if (screens.length === 0) return;

    let currentScreenIndex = 0;

    function showScreen(index) {
        if (index < 0) index = 0;
        if (index >= screens.length) index = screens.length - 1;
        currentScreenIndex = index;

        screens.forEach((s, idx) => {
            s.style.display = (idx === currentScreenIndex) ? "block" : "none";
        });

        dots.forEach((d, idx) => {
            if (idx === currentScreenIndex) {
                d.classList.add("active");
            } else {
                d.classList.remove("active");
            }
        });

        if (screenCounter) {
            screenCounter.innerText = `${currentScreenIndex + 1} / ${screens.length}`;
        }

        if (btnPrev) btnPrev.disabled = (currentScreenIndex === 0);
        if (btnNext) {
            if (currentScreenIndex === screens.length - 1) {
                btnNext.innerText = "Finish Demo";
                btnNext.onclick = () => window.location.href = "/results";
            } else {
                btnNext.innerText = "Next Step →";
                btnNext.onclick = () => showScreen(currentScreenIndex + 1);
            }
        }
    }

    if (btnPrev) {
        btnPrev.addEventListener("click", () => showScreen(currentScreenIndex - 1));
    }

    dots.forEach((dot, idx) => {
        dot.addEventListener("click", () => showScreen(idx));
    });

    // Start on first screen
    showScreen(0);
}

// --------------------------------------------------------------------------
// 7. Viva Q&A Accordions
// --------------------------------------------------------------------------
function initVivaAccordions() {
    const headers = document.querySelectorAll(".viva-header");
    headers.forEach(h => {
        h.addEventListener("click", () => {
            const ans = h.nextElementSibling;
            if (ans && ans.classList.contains("viva-answer")) {
                const isHidden = ans.style.display === "none";
                ans.style.display = isHidden ? "block" : "none";
                const arrow = h.querySelector(".viva-toggle-icon");
                if (arrow) arrow.innerText = isHidden ? "▲" : "▼";
            }
        });
    });
}

// --------------------------------------------------------------------------
// 8. Reset Election Data (for repeated ESE demonstration)
// --------------------------------------------------------------------------
function initResetButton() {
    const btnReset = document.getElementById("btnResetElection");
    if (btnReset) {
        btnReset.addEventListener("click", () => {
            if (confirm("Reset all cast votes and audit states for a fresh demonstration?")) {
                fetch("/api/reset-demo", { method: "POST" })
                .then(r => r.json())
                .then(data => {
                    alert(data.message);
                    location.reload();
                });
            }
        });
    }
}
