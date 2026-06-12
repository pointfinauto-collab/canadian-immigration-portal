const API_BASE = window.location.origin + '/api';

console.log("🚀 Secure Portal Engine Active. Endpoint Target:", API_BASE);

// --- 1. VISUAL NAVIGATION CLICK HANDLERS ---
// This guarantees your top buttons switch between panels cleanly without freezing
window.showPanel = function(panelId) {
    console.log("Switching to panel view:", panelId);
    
    // Hide all panels safely
    const panels = ['loginPanel', 'registerPanel', 'trackPanel'];
    panels.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });

    // Display the targeted panel
    const target = document.getElementById(panelId);
    if (target) {
        target.style.display = 'block';
    } else {
        console.error(`Panel ID "${panelId}" missing from HTML structure.`);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // Initialize view state: Show login page first, hide others
    if (document.getElementById('loginPanel')) window.showPanel('loginPanel');

    // --- 2. AUTHENTICATION LOCK: USER/ADMIN SIGN-IN ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const emailInput = document.getElementById('loginEmail') || loginForm.querySelector('input[type="email"]');
            const passwordInput = document.getElementById('loginPassword') || loginForm.querySelector('input[type="password"]');
            
            if (!emailInput || !passwordInput) {
                alert("Form input nodes could not be resolved.");
                return;
            }

            try {
                const res = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: emailInput.value.trim(), password: passwordInput.value })
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    localStorage.setItem('adminToken', data.token);
                    localStorage.setItem('userRole', data.role);
                    
                    if (data.role === 'admin') {
                        alert('🔑 Administrative Authorization Confirmed. Accessing Console...');
                        window.location.href = '/admin';
                    } else {
                        alert(`Verification Successful.\nWelcome back, ${data.name}.\n\nYour Record Info:\nUCI: ${data.uciNumber}\nRef: ${data.trackingRef}`);
                    }
                } else {
                    alert(`Access Refused: ${data.error || 'Invalid credentials'}`);
                }
            } catch (err) {
                alert('System failure during verification routing loop.');
            }
        });
    }

    // --- 3. DATA PERSISTENCE: CLIENT ENROLLMENT REGISTRY ---
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = registerForm.querySelector('button') || registerForm.querySelector('input[type="submit"]');
            
            if (btn) {
                btn.innerText = "Transmitting Security Packet...";
                btn.disabled = true;
            }

            try {
                const res = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    body: new FormData(registerForm)
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    alert(`🎉 Security Registry Profile Form Created!\n\nSave these tracking numbers:\nUCI File ID: ${data.uciNumber}\nTracking Key: ${data.trackingRef}`);
                    registerForm.reset();
                    window.showPanel('loginPanel'); // Bounce back to login automatically
                } else {
                    alert(`Registry Exception: ${data.error}`);
                }
            } catch (err) {
                alert('Connection loop interface failure.');
            } finally {
                if (btn) {
                    btn.innerText = "Execute Processing Enrollment Registry";
                    btn.disabled = false;
                }
            }
        });
    }

    // --- 4. DATA FETCHING: USER STATUS QUERY GATEWAY ---
    const trackForm = document.getElementById('trackForm');
    if (trackForm) {
        trackForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const uciInput = document.getElementById('uciInput') || trackForm.querySelector('input[type="text"]');
            const output = document.getElementById('trackingResult');

            if (!uciInput || !uciInput.value) {
                alert("Please input a valid UCI identifier.");
                return;
            }

            try {
                const res = await fetch(`${API_BASE}/auth/track`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uciNumber: uciInput.value.trim() })
                });
                const data = await res.json();

                if (res.ok) {
                    if (output) {
                        output.style.display = 'block';
                        output.innerHTML = `
                            <div style="background:#f4f6f9; padding:15px; border-left:5px solid #c8102e; margin-top:15px; border-radius: 4px; text-align:left;">
                                <h4 style="margin:0 0 10px 0; color:#111;">File Holder: ${data.name}</h4>
                                <p style="margin:5px 0;"><strong>Processing Status:</strong> <span style="color:#c8102e; font-weight:bold;">${data.status}</span></p>
                                <p style="margin:5px 0; color:#555;"><strong>Officer Notes:</strong> ${data.adminNotes}</p>
                            </div>
                        `;
                    } else {
                        alert(`Profile Match: ${data.name}\nStatus: ${data.status}\nNotes: ${data.adminNotes}`);
                    }
                } else {
                    alert(`Query Fault: ${data.error}`);
                }
            } catch (err) {
                alert('Failed to establish contact with cloud database arrays.');
            }
        });
    }
});
