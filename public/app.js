// Automatically detects your live Render domain link dynamically
const API_BASE = window.location.origin + '/api';

console.log("🚀 Secure Portal Engine Active. Target API Base:", API_BASE);

// --- VISUAL PANEL NAVIGATION ---
window.showPanel = function(panelId) {
    const panels = ['loginPanel', 'registerPanel', 'trackPanel'];
    panels.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });
    const target = document.getElementById(panelId);
    if (target) target.style.display = 'block';
};

document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('loginPanel')) window.showPanel('loginPanel');

    // --- GATEWAY ACTION: ACCOUNT SIGN-IN ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const emailInput = document.getElementById('loginEmail');
            const passwordInput = document.getElementById('loginPassword');

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
                        alert(`Verification Successful!\nWelcome back, ${data.name}.\n\nUCI: ${data.uciNumber}\nTracking Ref: ${data.trackingRef}`);
                    }
                } else {
                    alert(`Access Refused: ${data.error || 'Invalid credentials'}`);
                }
            } catch (err) {
                alert('System failure during verification routing loop.');
            }
        });
    }

    // --- GATEWAY ACTION: CLIENT ACCOUNT REGISTRATION ---
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = registerForm.querySelector('button');
            btn.innerText = "Processing System Registration...";
            btn.disabled = true;

            // Collect text inputs safely
            const name = registerForm.querySelector('input[name="name"]').value;
            const email = registerForm.querySelector('input[name="email"]').value;
            const password = registerForm.querySelector('input[name="password"]').value;

            try {
                const res = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, email, password })
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    alert(`🎉 Security Registry Profile Form Created!\n\nSave these tracking numbers:\nUCI File ID: ${data.uciNumber}\nTracking Key: ${data.trackingRef}`);
                    registerForm.reset();
                    window.showPanel('loginPanel');
                } else {
                    alert(`Registry Exception: ${data.error}`);
                }
            } catch (err) {
                alert('Connection loop interface failure.');
            } finally {
                btn.innerText = "Execute Processing Enrollment Registry";
                btn.disabled = false;
            }
        });
    }

    // --- GATEWAY ACTION: USER STATUS QUERY ---
    const trackForm = document.getElementById('trackForm');
    if (trackForm) {
        trackForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const uciInput = document.getElementById('uciInput').value.trim();
            const output = document.getElementById('trackingResult');

            try {
                const res = await fetch(`${API_BASE}/auth/track`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uciNumber: uciInput })
                });
                const data = await res.json();

                if (res.ok) {
                    output.style.display = 'block';
                    output.innerHTML = `
                        <div style="background:#f4f6f9; padding:15px; border-left:5px solid #c8102e; margin-top:15px;">
                            <h4>File Holder: ${data.name}</h4>
                            <p><strong>Processing Status:</strong> <span style="color:#c8102e; font-weight:bold;">${data.status}</span></p>
                            <p><strong>Officer Notes:</strong> ${data.adminNotes}</p>
                        </div>
                    `;
                } else {
                    alert(`Query Fault: ${data.error}`);
                }
            } catch (err) {
                alert('Failed to establish contact with cloud database arrays.');
            }
        });
    }
});
