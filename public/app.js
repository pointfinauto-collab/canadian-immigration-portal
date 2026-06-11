const API_BASE = window.location.origin + '/api';

document.addEventListener('DOMContentLoaded', () => {
    
    // --- GATEWAY ACTION: ACCOUNT REGISTRATION ---
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = registerForm.querySelector('button');
            btn.innerText = "Transmitting Packet...";
            btn.disabled = true;

            try {
                const res = await fetch(`${API_BASE}/auth/register`, {
                    method: 'POST',
                    body: new FormData(registerForm)
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    alert(`🎉 Account Securely Saved to Directory!\n\nWrite down your credential keys:\nUCI ID: ${data.uciNumber}\nTracking Key: ${data.trackingRef}`);
                    registerForm.reset();
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

    // --- GATEWAY ACTION: ACCOUNT SIGN-IN ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;

            try {
                const res = await fetch(`${API_BASE}/auth/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                const data = await res.json();

                if (res.ok && data.success) {
                    localStorage.setItem('adminToken', data.token);
                    localStorage.setItem('userRole', data.role);
                    
                    if (data.role === 'admin') {
                        alert('🔑 Administrative Authorization Confirmed. Redirecting...');
                        window.location.href = '/admin';
                    } else {
                        alert(`Welcome back, ${data.name}.\nUCI: ${data.uciNumber}\nRef: ${data.trackingRef}`);
                    }
                } else {
                    alert(`Access Refused: ${data.error}`);
                }
            } catch (err) {
                alert('System failure during verification routing loop.');
            }
        });
    }

    // --- GATEWAY ACTION: USER PROFILE TRACKING ---
    const trackForm = document.getElementById('trackForm');
    if (trackForm) {
        trackForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const uciNumber = document.getElementById('uciInput').value.trim();
            const output = document.getElementById('trackingResult');

            try {
                const res = await fetch(`${API_BASE}/auth/track`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uciNumber })
                });
                const data = await res.json();

                if (res.ok) {
                    output.style.display = 'block';
                    output.innerHTML = `
                        <h4 style="margin:0 0 10px 0; color:#111;">Profile Database Match: ${data.name}</h4>
                        <p style="margin:5px 0;"><strong>Processing Status:</strong> <span style="color:#c8102e; font-weight:bold;">${data.status}</span></p>
                        <p style="margin:5px 0; color:#555;"><strong>Officer Notes:</strong> ${data.adminNotes}</p>
                    `;
                } else {
                    alert(`Query Fault: ${data.error}`);
                }
            } catch (err) {
                alert('Failed to establish contact with database arrays.');
            }
        });
    }
});
