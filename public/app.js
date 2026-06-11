const API_BASE = 'http://localhost:5000/api';

function showAuthTab(target) {
    if(target === 'login') {
        document.getElementById('login-section').style.display = 'block';
        document.getElementById('register-section').style.display = 'none';
    } else {
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('register-section').style.display = 'block';
    }
}

function logout() {
    localStorage.removeItem('gov_portal_token');
    window.location.href = 'index.html';
}

function switchDashView(tabId) {
    document.querySelectorAll('.dash-view').forEach(view => view.style.display = 'none');
    document.getElementById(tabId).style.display = 'block';
}

function toggleRepPaymentFields() {
    const method = document.getElementById('paymentMethodSelection').value;
    const block = document.getElementById('representativeFieldsBlock');
    block.style.display = (method === 'Representative Payment') ? 'block' : 'none';
}

if(document.getElementById('loginForm')) {
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        const res = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if(res.ok) {
            localStorage.setItem('gov_portal_token', data.token);
            if(data.role === 'admin') {
                window.location.href = 'admin-dashboard.html';
            } else {
                window.location.href = 'client-dashboard.html';
            }
        } else {
            alert(`Authentication Error: ${data.message}`);
        }
    });
}

if(document.getElementById('registerForm')) {
    document.getElementById('registerForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        if(document.getElementById('password').value !== document.getElementById('confirmPassword').value) {
            return alert("Password mismatch verification error.");
        }

        const formData = new FormData();
        formData.append('fullName', document.getElementById('fullName').value);
        formData.append('dob', document.getElementById('dob').value);
        formData.append('gender', document.getElementById('gender').value);
        formData.append('nationality', document.getElementById('nationality').value);
        formData.append('passportNumber', document.getElementById('passportNumber').value);
        formData.append('countryOfResidence', document.getElementById('countryOfResidence').value);
        formData.append('phoneNumber', document.getElementById('phoneNumber').value);
        formData.append('email', document.getElementById('email').value);
        formData.append('password', document.getElementById('password').value);
        
        formData.append('passport', document.getElementById('passportFile').files[0]);
        formData.append('passportPhoto', document.getElementById('photoFile').files[0]);
        if(document.getElementById('nationalIdFile').files[0]) {
            formData.append('nationalId', document.getElementById('nationalIdFile').files[0]);
        }

        const res = await fetch(`${API_BASE}/auth/register`, { method: 'POST', body: formData });
        const data = await res.json();

        if(res.ok) {
            alert(`Account Registered.\nUCI: ${data.uci}\nGC Ref: ${data.gcRef}`);
            showAuthTab('login');
        } else {
            alert(`Registration Failure: ${data.message}`);
        }
    });
}

async function loadClientDashboardData() {
    const token = localStorage.getItem('gov_portal_token');
    if(!token) window.location.href = 'index.html';

    const res = await fetch(`${API_BASE}/client/profile`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if(!res.ok) logout();
    const data = await res.json();

    document.getElementById('welcome-title').innerText = `Welcome: ${data.profile.fullName}`;
    document.getElementById('lbl-uci').innerText = data.profile.uci;
    document.getElementById('lbl-gcref').innerText = data.profile.gcRef;

    document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
    const statusIdStr = `step-${data.profile.applicationStatus.replace(/\s+/g, '')}`;
    const targetStatusEl = document.getElementById(statusIdStr) || document.getElementById('step-Submitted');
    if(targetStatusEl) targetStatusEl.classList.add('active');

    document.getElementById('profile-data-details').innerHTML = `
        <p><strong>Primary Client Email:</strong> ${data.profile.email}</p>
        <p><strong>Phone Registry:</strong> ${data.profile.phoneNumber}</p>
        <p><strong>Nationality:</strong> ${data.profile.nationality}</p>
        <p><strong>Active Assessment Status:</strong> <span class="badge badge-info">${data.profile.applicationStatus}</span></p>
    `;

    const tbody = document.getElementById('document-table-body');
    tbody.innerHTML = '';
    data.documents.forEach(doc => {
        tbody.innerHTML += `<tr><td>${doc.documentType}</td><td>${doc.fileName}</td><td><span class="badge badge-warning">${doc.status}</span></td></tr>`;
    });
}

if(document.getElementById('docUploadForm')) {
    document.getElementById('docUploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = localStorage.getItem('gov_portal_token');
        const formData = new FormData();
        formData.append('documentType', document.getElementById('docTypeSelect').value);
        formData.append('supplementary', document.getElementById('newDocFile').files[0]);

        const res = await fetch(`${API_BASE}/client/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });
        if(res.ok) {
            alert("File successfully submitted.");
            loadClientDashboardData();
        }
    });
}

if(document.getElementById('paymentSystemForm')) {
    document.getElementById('paymentSystemForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = localStorage.getItem('gov_portal_token');
        const method = document.getElementById('paymentMethodSelection').value;
        const repName = document.getElementById('repName').value;
        const repId = document.getElementById('repId').value;

        const res = await fetch(`${API_BASE}/client/pay`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ amount: 1250, method, repName, repId })
        });
        if(res.ok) {
            const val = await res.json();
            alert(`Payment success!\nTransaction ID: ${val.transactionId}\nReceipt Number: ${val.receiptNumber}`);
            loadClientDashboardData();
        }
    });
}

async function loadAdminDashboardData() {
    const token = localStorage.getItem('gov_portal_token');
    if(!token) window.location.href = 'index.html';

    const res = await fetch(`${API_BASE}/admin/applicants`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if(!res.ok) { alert("Access Unauthorized."); logout(); }
    const applicants = await res.json();

    const tbody = document.getElementById('admin-applicants-table');
    tbody.innerHTML = '';
    applicants.forEach(app => {
        tbody.innerHTML += `
            <tr>
                <td>${app.fullName}</td>
                <td>${app.uci}</td>
                <td>${app.gcRef}</td>
                <td><span class="badge badge-info">${app.applicationStatus}</span></td>
                <td>
                    <select onchange="updateApplicantStatusFromAdminDesk('${app._id}', this.value)">
                        <option value="">-- Alter Status --</option>
                        <option value="Under Review">Under Review</option>
                        <option value="Additional Documents Required">Additional Documents Required</option>
                        <option value="Approved">Approved</option>
                        <option value="Refused">Refused</option>
                    </select>
                </td>
            </tr>
        `;
    });
}

async function updateApplicantStatusFromAdminDesk(userId, newStatus) {
    if(!newStatus) return;
    const token = localStorage.getItem('gov_portal_token');
    const res = await fetch(`${API_BASE}/admin/applicant/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ applicationStatus: newStatus })
    });
    if(res.ok) {
        alert("Applicant status updated.");
        loadAdminDashboardData();
    }
}