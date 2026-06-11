// Dynamic Base URL Configuration
const API_BASE = window.location.origin + '/api';

console.log("🚀 Portal JavaScript loaded successfully. API Base set to:", API_BASE);

// --- 1. REGISTRATION FORM HANDLER ---
// This handles creating a new test registration profile
const registerForm = document.getElementById('registerForm') || document.querySelector('form[action*="register"]');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(registerForm);
        const submitButton = registerForm.querySelector('button') || registerForm.querySelector('input[type="submit"]');
        if (submitButton) {
            submitButton.innerText = "Processing Transmission...";
            submitButton.disabled = true;
        }

        try {
            const res = await fetch(`${API_BASE}/auth/register`, {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.success) {
                alert(`🎉 Registry Created Successfully!\n\nWrite down your tracking credentials:\nUCI File ID: ${data.uciNumber}\nTracking Reference: ${data.trackingRef}`);
                registerForm.reset();
            } else {
                alert(`Error: ${data.error || 'Submission Refused'}`);
            }
        } catch (err) {
            console.error('System Network Failure:', err);
            alert('CRITICAL ERROR: Connection to backend data nodes lost.');
        } finally {
            if (submitButton) {
                submitButton.innerText = "Execute Processing Enrollment Registry";
                submitButton.disabled = false;
            }
        }
    });
}

// --- 2. LOGIN / TRACKING FORM HANDLER ---
// This handles checking the status using the generated codes
const trackForm = document.getElementById('trackForm') || document.querySelector('form');
const trackingResultDiv = document.getElementById('trackingResult'); 

if (trackForm && trackForm !== registerForm) {
    trackForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Dynamically grab the text input from the form, regardless of its ID
        const uciInput = trackForm.querySelector('input[type="text"]') || document.getElementById('uciInput');
        if (!uciInput || !uciInput.value) {
            alert("Please enter your UCI file identifier to verify status.");
            return;
        }

        try {
            const res = await fetch(`${API_BASE}/auth/track`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uciNumber: uciInput.value.trim() })
            });
            const data = await res.json();

            if (res.status === 200) {
                if (trackingResultDiv) {
                    trackingResultDiv.style.display = 'block';
                    trackingResultDiv.innerHTML = `
                        <div style="background:#e8f5e9; padding:15px; border-left:5px solid #2e7d32; border-radius:4px; margin-top:15px; text-align: left; color: #333;">
                            <h3>File Profile: ${data.name}</h3>
                            <p><strong>Current File Status:</strong> <span style="color:#c8102e; font-weight:bold;">${data.status}</span></p>
                            <p><strong>Officer Assessment Comments:</strong> ${data.adminNotes}</p>
                        </div>
                    `;
                } else {
                    // Fallback alert if there is no results container element in your HTML layout
                    alert(`File Profile: ${data.name}\nCurrent Status: ${data.status}\nNotes: ${data.adminNotes}`);
                }
            } else {
                alert(data.error || 'Tracking entry mismatch.');
            }
        } catch (err) {
            console.error("Tracking error:", err);
            alert('Could not pull tracking status parameters.');
        }
    });
}
