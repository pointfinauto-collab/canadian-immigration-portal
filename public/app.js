// Automatically configures the path based on whether it's local or live on Render
const API_BASE = window.location.origin + '/api';

console.log("🚀 Frontend script loaded perfectly. Routing base set to:", API_BASE);

document.addEventListener('DOMContentLoaded', () => {
    
    // Find the forms automatically even if the IDs change slightly
    const registerForm = document.getElementById('registerForm') || document.querySelector('form[action*="register"]') || document.forms[0];
    
    // --- CREATE ACCOUNT ACTIONS ---
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(registerForm);
            const submitButton = registerForm.querySelector('button') || registerForm.querySelector('input[type="submit"]');
            
            if (submitButton) {
                submitButton.innerText = "Processing System Registration...";
                submitButton.disabled = true;
            }

            try {
                const res = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();

                if (data.success) {
                    alert(`🎉 Security Registry Created!\n\nSave these tracking numbers:\nUCI File ID: ${data.uciNumber}\nTracking Reference: ${data.trackingRef}`);
                    registerForm.reset();
                } else {
                    alert(`Error processing profile: ${data.error}`);
                }
            } catch (err) {
                alert('Connection to database nodes failed.');
            } finally {
                if (submitButton) {
                    submitButton.innerText = "Verify and Sign In";
                    submitButton.disabled = false;
                }
            }
        });
    }

    // --- FILE TRACKING GATEWAY ACTIONS ---
    // If you add a tracking check submission form, this handles the submission perfectly
    const trackForm = document.getElementById('trackForm') || document.getElementById('loginForm');
    if (trackForm) {
        trackForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const uciInput = trackForm.querySelector('input[type="text"]');
            const trackingResultDiv = document.getElementById('trackingResult');

            if (!uciInput || !uciInput.value) {
                alert("Please enter a valid UCI identifier to query files.");
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
                            <div style="background:#f4f6f9; padding:15px; border-left:5px solid #c8102e; margin-top:15px; border-radius: 4px;">
                                <h3 style="margin-top:0;">File: ${data.name}</h3>
                                <p><strong>Status:</strong> <span style="color:#c8102e; font-weight:bold;">${data.status}</span></p>
                                <p><strong>Officer Assessment Notes:</strong> ${data.adminNotes}</p>
                            </div>
                        `;
                    } else {
                        alert(`File: ${data.name}\nStatus: ${data.status}\nNotes: ${data.adminNotes}`);
                    }
                } else {
                    alert(data.error || 'No matching registry found.');
                }
            } catch (err) {
                alert('Network communication fault fetching status parameters.');
            }
        });
    }
});
