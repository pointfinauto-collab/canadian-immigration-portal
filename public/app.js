// Dynamic Base URL Configuration
const API_BASE = window.location.origin + '/api';

// --- HANDLER: USER FORM ENROLLMENT REGISTRATION ---
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(registerForm);
        const submitButton = registerForm.querySelector('button');
        submitButton.innerText = "Processing Transmission...";
        submitButton.disabled = true;

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
            submitButton.innerText = "Execute Processing Enrollment Registry";
            submitButton.disabled = false;
        }
    });
}

// --- HANDLER: USER APPLICATION TRACKING PANEL ---
const trackForm = document.getElementById('trackForm');
const trackingResultDiv = document.getElementById('trackingResult'); // Make sure this id exists in your HTML interface to display results!

if (trackForm) {
    trackForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const uciInput = document.getElementById('uciInput').value;

        try {
            const res = await fetch(`${API_BASE}/auth/track`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ uciNumber: uciInput })
            });
            const data = await res.json();

            if (res.status === 200) {
                trackingResultDiv.style.display = 'block';
                trackingResultDiv.innerHTML = `
                    <div style="background:#e8f5e9; padding:15px; border-left:5px solid #2e7d32; border-radius:4px; margin-top:15px;">
                        <h3>File Profile: ${data.name}</h3>
                        <p><strong>Current File Status:</strong> <span style="color:#c8102e;">${data.status}</span></p>
                        <p><strong>Officer Assessment Comments:</strong> ${data.adminNotes}</p>
                    </div>
                `;
            } else {
                alert(data.error || 'Tracking entry mismatch.');
            }
        } catch (err) {
            alert('Could not pull tracking status parameters.');
        }
    });
}
