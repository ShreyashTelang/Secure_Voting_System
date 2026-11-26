/**
 * SecureVote Main Application Script
 */

document.addEventListener("DOMContentLoaded", () => {
    initFlashMessages();
    initCandidateSelection();
    initResetDemo();
});

function initFlashMessages() {
    document.querySelectorAll(".alert").forEach(alert => {
        const closeBtn = document.createElement("button");
        closeBtn.innerHTML = "&times;";
        closeBtn.style.background = "none";
        closeBtn.style.border = "none";
        closeBtn.style.fontSize = "18px";
        closeBtn.style.cursor = "pointer";
        closeBtn.style.marginLeft = "12px";
        closeBtn.style.color = "inherit";
        closeBtn.style.opacity = "0.7";
        closeBtn.onclick = () => alert.remove();
        alert.appendChild(closeBtn);
    });
}

function initCandidateSelection() {
    const cards = document.querySelectorAll(".candidate-selection-card");
    const reviewBtn = document.getElementById("btnReviewSelection");

    if (reviewBtn) {
        reviewBtn.addEventListener("click", (e) => {
            if (reviewBtn.classList.contains("disabled")) {
                e.preventDefault();
                alert("Please select a candidate first before proceeding to review.");
            }
        });
    }

    cards.forEach(card => {
        card.addEventListener("click", () => {
            cards.forEach(c => c.classList.remove("selected"));
            card.classList.add("selected");
            const candId = card.getAttribute("data-candidate-id");
            const candName = card.getAttribute("data-candidate-name");

            if (reviewBtn) {
                reviewBtn.href = `/vote/review?candidate_id=${candId}`;
                reviewBtn.classList.remove("disabled");
                reviewBtn.removeAttribute("aria-disabled");
                reviewBtn.innerText = `Review Selection for ${candName} →`;
            }
        });
    });
}

function initResetDemo() {
    const resetBtn = document.getElementById("btnResetElectionData");
    if (resetBtn) {
        resetBtn.addEventListener("click", () => {
            if (confirm("Reset election ledger and restore voter eligibility for repeat demonstration?")) {
                fetch("/api/system/reset-demo", { method: "POST" })
                    .then(res => res.json())
                    .then(data => {
                        alert(data.message);
                        window.location.reload();
                    })
                    .catch(err => alert("Reset error: " + err.message));
            }
        });
    }
}
