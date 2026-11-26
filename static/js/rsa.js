/**
 * SecureVote RSA Mathematics Interactive Visualizer
 */

document.addEventListener("DOMContentLoaded", () => {
    initRSACalculators();
});

function initRSACalculators() {
    const btnNumEnc = document.getElementById("btnRSANumEncrypt");
    const btnNumDec = document.getElementById("btnRSANumDecrypt");

    if (btnNumEnc) {
        btnNumEnc.addEventListener("click", () => {
            const inputVal = document.getElementById("rsaNumInput").value;
            fetch("/api/rsa/calculate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ type: "number", mode: "encrypt", value: inputVal })
            })
            .then(res => res.json())
            .then(data => {
                const target = document.getElementById("rsaNumEncOutput");
                if (data.success && target) {
                    target.innerHTML = `
                        <div class="code-block" style="background:#0f172a; margin-top:8px;">
                            <div><strong>Plaintext (M):</strong> ${data.result.plaintext_m}</div>
                            <div><strong>Formula:</strong> ${data.result.formula}</div>
                            <div><strong>Calculation:</strong> ${data.result.calculation}</div>
                            <div style="color:#38bdf8; font-size:1.05rem; margin-top:4px;">
                                <strong>Ciphertext (C):</strong> ${data.result.ciphertext_c}
                            </div>
                        </div>
                    `;
                    // Auto-fill decryption input
                    const decInput = document.getElementById("rsaCipherInput");
                    if (decInput) decInput.value = data.result.ciphertext_c;
                } else if (target) {
                    target.innerHTML = `<div class="alert alert-error">${data.error}</div>`;
                }
            });
        });
    }

    if (btnNumDec) {
        btnNumDec.addEventListener("click", () => {
            const inputVal = document.getElementById("rsaCipherInput").value;
            fetch("/api/rsa/calculate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ type: "number", mode: "decrypt", value: inputVal })
            })
            .then(res => res.json())
            .then(data => {
                const target = document.getElementById("rsaNumDecOutput");
                if (data.success && target) {
                    target.innerHTML = `
                        <div class="code-block" style="background:#0f172a; margin-top:8px;">
                            <div><strong>Ciphertext (C):</strong> ${data.result.ciphertext_c}</div>
                            <div><strong>Formula:</strong> ${data.result.formula}</div>
                            <div><strong>Calculation:</strong> ${data.result.calculation}</div>
                            <div style="color:#4ade80; font-size:1.05rem; margin-top:4px;">
                                <strong>Recovered Plaintext (M):</strong> ${data.result.recovered_plaintext_m}
                            </div>
                        </div>
                    `;
                } else if (target) {
                    target.innerHTML = `<div class="alert alert-error">${data.error}</div>`;
                }
            });
        });
    }
}
