const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// MIDDLEWARE
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// DATABASE CONNECTION WITH FALLBACK PROTECTION
const fallbackURI = "mongodb+srv://testuser:testpass@cluster0.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = process.env.MONGO_URI || fallbackURI;

mongoose.connect(MONGO_URI)
  .then(() => console.log('🚀 Database Node Connected Successfully'))
  .catch(err => console.error('❌ Database Initialization Warning:', err.message));

// COMPLETE DESIGN USER SCHEMA
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    dob: { type: String, default: '' },
    gender: { type: String, default: '' },
    citizenship: { type: String, default: '' },
    passportNumber: { type: String, default: '' },
    residence: { type: String, default: '' },
    phone: { type: String, default: '' },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    uciNumber: { type: String, unique: true },
    trackingRef: { type: String, unique: true },
    status: { type: String, default: 'Submitted / Review Pending' },
    adminNotes: { type: String, default: 'Your application file is undergoing preliminary verification.' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// API ENDPOINTS
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, dob, gender, citizenship, passportNumber, residence, phone } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'Primary missing fields.' });

        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) return res.status(409).json({ error: 'Account already registered.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (email.toLowerCase().trim() === systemAdminEmail) ? 'admin' : 'user';

        const newUser = new User({
            name, email: email.toLowerCase().trim(), password: hashedPassword,
            dob, gender, citizenship, passportNumber, residence, phone, role, uciNumber, trackingRef
        });

        await newUser.save();
        res.status(201).json({ success: true, uciNumber, trackingRef });
    } catch (error) {
        res.status(500).json({ error: 'Server registration failure.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token, role: user.role, name: user.name, uciNumber: user.uciNumber, trackingRef: user.trackingRef });
    } catch (error) {
        res.status(500).json({ error: 'Login error.' });
    }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const record = await User.findOne({ uciNumber: req.body.uciNumber.trim() });
        if (!record) return res.status(404).json({ error: 'No matching records found.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) {
        res.status(500).json({ error: 'Query error.' });
    }
});

const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    res.json(await User.find().sort({ createdAt: -1 }));
});

app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    await User.findByIdAndUpdate(req.body.id, { status: req.body.status, adminNotes: req.body.adminNotes });
    res.json({ success: true });
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ==========================================
// RENDERING PREMIUM USER INTERFACE (`ffffffff.png`)
// ==========================================

app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔒 System Administration Panel</title>
        <style>
            body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f4f6f9; padding: 20px; margin:0; }
            .box { max-width: 1200px; margin: 30px auto; background: white; padding: 30px; border-radius: 4px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-top: 4px solid #c8102e; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }
            th { background: #0f3460; color: white; }
            .save-btn { background: #2e7d32; color: white; border: none; padding: 6px 12px; cursor: pointer; border-radius: 3px; }
            .del-btn { background: #c8102e; color: white; border: none; padding: 6px 12px; cursor: pointer; border-radius: 3px; }
            select, textarea { width: 100%; padding: 5px; box-sizing: border-box; }
        </style>
    </head>
    <body>
        <div class="box">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h2>🔒 Portal Administrative Management Console</h2>
                <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 12px; cursor:pointer; background:#333; color:#fff; border:none; border-radius:3px;">Log Out</button>
            </div>
            <table>
                <thead>
                    <tr><th>Applicant Metrics</th><th>Identifiers</th><th>Status Updates</th><th>Processing Notes</th><th>Actions</th></tr>
                </thead>
                <tbody id="rows"><tr><td colspan="5" style="text-align:center;">Querying Database Records...</td></tr></tbody>
            </table>
        </div>
        <script>
            const token = localStorage.getItem('adminToken');
            if (!token || localStorage.getItem('userRole') !== 'admin') { window.location.href = '/'; }

            async function loadGrid() {
                const res = await fetch('/api/admin/enrollments', { headers: { 'Authorization': 'Bearer ' + token } });
                if (!res.ok) { window.location.href='/'; return; }
                const users = await res.json();
                const tbody = document.getElementById('rows');
                tbody.innerHTML = '';
                
                users.forEach(u => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = \`
                        <td>
                            <strong>\${u.name}</strong><br>
                            <span style="font-size:12px; color:#555;">
                                Email: \${u.email}<br>
                                DOB: \${u.dob || 'N/A'} | Gen: \${u.gender || 'N/A'}<br>
                                Pass: \${u.passportNumber || 'N/A'}<br>
                                Citizen: \${u.citizenship || 'N/A'}
                            </span>
                        </td>
                        <td>UCI: <strong>\${u.uciNumber || 'N/A'}</strong><br>Ref: <strong>\${u.trackingRef || 'N/A'}</strong></td>
                        <td>
                            <select id="s-\${u._id}">
                                <option value="Submitted / Review Pending" \${u.status === 'Submitted / Review Pending'?'selected':''}>Submitted / Review Pending</option>
                                <option value="Biometrics Verification Stage" \${u.status === 'Biometrics Verification Stage'?'selected':''}>Biometrics Verification Stage</option>
                                <option value="Background Eligibility Check" \${u.status === 'Background Eligibility Check'?'selected':''}>Background Eligibility Check</option>
                                <option value="Registry Profile Approved" \${u.status === 'Registry Profile Approved'?'selected':''}>Registry Profile Approved</option>
                                <option value="Refusal Issued" \${u.status === 'Refusal Issued'?'selected':''}>Refusal Issued</option>
                            </select>
                        </td>
                        <td><textarea id="n-\${u._id}" rows="3">\${u.adminNotes || ''}</textarea></td>
                        <td>
                            <button class="save-btn" onclick="save('\${u._id}')">Save</button><br><br>
                            <button class="del-btn" onclick="del('\${u._id}')">Delete</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }
            async function save(id) {
                const status = document.getElementById('s-'+id).value;
                const adminNotes = document.getElementById('n-'+id).value;
                await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status, adminNotes })
                });
                alert('Database Updated.');
                loadGrid();
            }
            async function del(id) {
                if(confirm('Delete file entry?')) {
                    await fetch('/api/admin/user/' + id, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } });
                    loadGrid();
                }
            }
            window.onload = loadGrid;
        </script>
    </body>
    </html>
    `);
});

app.get('*', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Immigration and Secure Client Portal Terminal</title>
        <style>
            body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background: #ffffff; color: #333; margin: 0; padding: 0; }
            
            /* High Fidelity Header Layout matching ffffffff.png */
            .gov-banner { background: #f5f5f5; border-bottom: 4px solid #c8102e; padding: 12px 40px; display: flex; align-items: center; gap: 20px; }
            .gov-badge { background: #c8102e; color: white; padding: 6px 12px; font-weight: bold; font-size: 14px; border-radius: 3px; text-transform: uppercase; }
            .portal-title { font-size: 18px; font-weight: bold; color: #222; }
            
            .content-container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
            
            /* Premium Tab Interface */
            .tab-box { display: flex; gap: 5px; margin-bottom: 25px; background: #eef2f5; padding: 8px; border-radius: 4px; }
            .tab-box button { padding: 10px 20px; background: transparent; border: none; font-size: 14px; font-weight: bold; cursor: pointer; color: #444; border-radius: 4px; transition: all 0.2s; }
            .tab-box button.active { background: #0f3460; color: white; }
            
            .panel { display: none; background: #ffffff; border: 1px solid #dcdcdc; border-radius: 4px; padding: 25px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
            .panel.active { display: block; }
            
            h2 { font-size: 22px; color: #0f3460; margin-top: 0; border-bottom: 2px solid #eef2f5; padding-bottom: 10px; margin-bottom: 20px; }
            h3 { font-size: 15px; color: #333; margin-top: 20px; margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
            
            /* Responsive Grid Form Layout */
            .form-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px 20px; margin-bottom: 15px; }
            @media(max-width: 768px){ .form-grid { grid-template-columns: 1fr; } }
            
            .field-group { display: flex; flex-direction: column; }
            label { font-size: 13px; font-weight: bold; margin-bottom: 6px; color: #444; }
            input, select { padding: 8px 12px; border: 1px solid #b5b5b5; font-size: 14px; border-radius: 4px; width: 100%; box-sizing: border-box; }
            input:focus, select:focus { border-color: #0f3460; outline: none; }
            
            .submit-btn { padding: 10px 24px; background: #0f3460; color: white; border: none; font-size: 14px; font-weight: bold; cursor: pointer; border-radius: 4px; margin-top: 15px; transition: background 0.2s; }
            .submit-btn:hover { background: #16467a; }
            
            .status-display { display: none; margin-top: 25px; padding: 20px; border-left: 6px solid #c8102e; background: #f8fafc; border-radius: 4px; border-top: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0; border-bottom: 1px solid #e2e8f0; }
        </style>
    </head>
    <body>

        <div class="gov-banner">
            <div class="gov-badge">Government of Canada</div>
            <div class="portal-title">Immigration and Secure Client Portal Terminal</div>
        </div>
        
        <div class="content-container">
            <div class="tab-box">
                <button type="button" id="btn-login" class="active" onclick="setView('loginPanel', 'btn-login')">Access Existing Account</button>
                <button type="button" id="btn-register" onclick="setView('registerPanel', 'btn-register')">Create Secure Account Profiling File</button>
                <button type="button" id="btn-track" onclick="setView('trackPanel', 'btn-track')">Track File Status</button>
            </div>

            <div id="loginPanel" class="panel active">
                <h2>Account Secure Gateway Sign-In</h2>
                <form id="lForm">
                    <div style="max-width: 400px;">
                        <div class="field-group" style="margin-bottom:15px;">
                            <label>Email Address</label>
                            <input type="email" id="lEmail" required>
                        </div>
                        <div class="field-group" style="margin-bottom:15px;">
                            <label>Account Security Password</label>
                            <input type="password" id="lPass" required>
                        </div>
                        <button type="submit" class="submit-btn">Verify and Sign In</button>
                    </div>
                </form>
            </div>

            <div id="registerPanel" class="panel">
                <h2>Secure System Enrollment Registry</h2>
                <form id="rForm">
                    
                    <h3>Personal File Metrics</h3>
                    <div class="form-grid">
                        <div class="field-group">
                            <label>Legal Full Name (As written in Passport)</label>
                            <input type="text" id="rName" required placeholder="e.g. John Doe">
                        </div>
                        <div class="field-group">
                            <label>Date of Birth</label>
                            <input type="date" id="rDob" required>
                        </div>
                        <div class="field-group">
                            <label>Gender File Metric</label>
                            <select id="rGender">
                                <option value="Male">Male</option>
                                <option value="Female">Female</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                        <div class="field-group">
                            <label>Country of Core Citizenship Nationality</label>
                            <input type="text" id="rCitizenship" required>
                        </div>
                        <div class="field-group">
                            <label>Passport Document Serial Number</label>
                            <input type="text" id="rPassport" required>
                        </div>
                        <div class="field-group">
                            <label>Current Legal Country of Residence</label>
                            <input type="text" id="rResidence" required>
                        </div>
                    </div>

                    <h3>Contact Parameters & Secure Access Setup</h3>
                    <div class="form-grid">
                        <div class="field-group">
                            <label>Primary Telephone Contact Base Line</label>
                            <input type="text" id="rPhone" required>
                        </div>
                        <div class="field-group">
                            <label>Account Communication Email Access Point</label>
                            <input type="email" id="rEmail" required>
                        </div>
                        <div class="field-group">
                            <label>Create Security Access Password</label>
                            <input type="password" id="rPass" required>
                        </div>
                    </div>

                    <button type="submit" class="submit-btn">Execute Processing Enrollment Registry</button>
                </form>
            </div>

            <div id="trackPanel" class="panel">
                <h2>File Status Tracking Gateway</h2>
                <form id="tForm">
                    <div style="max-width:400px;">
                        <div class="field-group">
                            <label>Unique Client ID (UCI)</label>
                            <input type="text" id="tUci" placeholder="UCI-XXXXXXXX" required>
                        </div>
                        <button type="submit" class="submit-btn">Query Directory Archives</button>
                    </div>
                </form>
                <div id="tResult" class="status-display"></div>
            </div>
        </div>

        <script>
            function setView(panelId, btnId) {
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.tab-box button').forEach(b => b.classList.remove('active'));
                
                document.getElementById(panelId).classList.add('active');
                document.getElementById(btnId).classList.add('active');
            }

            // REGISTER SYSTEM REQUEST LOOP
            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = e.target.querySelector('button');
                btn.innerText = "Transmitting Core File Registry...";
                btn.disabled = true;

                try {
                    const res = await fetch('/api/auth/register', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            name: document.getElementById('rName').value,
                            dob: document.getElementById('rDob').value,
                            gender: document.getElementById('rGender').value,
                            citizenship: document.getElementById('rCitizenship').value,
                            passportNumber: document.getElementById('rPassport').value,
                            residence: document.getElementById('rResidence').value,
                            phone: document.getElementById('rPhone').value,
                            email: document.getElementById('rEmail').value,
                            password: document.getElementById('rPass').value
                        })
                    });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        alert('🎉 Security Registry File Generated Successfully!\\n\\nSave your official application tracking IDs:\\nUCI File ID: ' + data.uciNumber + '\\nTracking Reference: ' + data.trackingRef);
                        document.getElementById('rForm').reset();
                        setView('loginPanel', 'btn-login');
                    } else { alert('Registry Blocked: ' + data.error); }
                } catch(err) { alert('Network connection lost.'); }
                finally { btn.innerText = "Execute Processing Enrollment Registry"; btn.disabled = false; }
            });

            // LOGIN SYSTEM REQUEST LOOP
            document.getElementById('lForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const res = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            email: document.getElementById('lEmail').value,
                            password: document.getElementById('lPass').value
                        })
                    });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        localStorage.setItem('adminToken', data.token);
                        localStorage.setItem('userRole', data.role);
                        if(data.role === 'admin') {
                            alert('🔑 Administrative Access Granted. Launching Panel Interface Console...');
                            window.location.href = '/admin';
                        } else {
                            alert('Identity Verification Approved!\\n\\nHolder: ' + data.name + '\\nUCI: ' + data.uciNumber + '\\nRef: ' + data.trackingRef);
                        }
                    } else { alert('Access Denied: ' + data.error); }
                } catch(err) { alert('Server query exception loop.'); }
            });

            // TRACK SYSTEM REQUEST LOOP
            document.getElementById('tForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const res = await fetch('/api/auth/track', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ uciNumber: document.getElementById('tUci').value })
                    });
                    const data = await res.json();
                    const out = document.getElementById('tResult');
                    if(res.ok) {
                        out.style.display = 'block';
                        out.innerHTML = '<h3 style="color:#0f3460; margin-top:0;">File Identity Verified: ' + data.name + '</h3><p style="font-size:15px;"><strong>Processing File Status:</strong> <span style="color:#c8102e; font-weight:bold;">' + data.status + '</span></p><p style="color:#555; font-size:14px; background:#fff; padding:10px; border:1px solid #e2e8f0;"><strong>Officer Remarks:</strong> ' + data.adminNotes + '</p>';
                    } else { alert('Tracking Search Failed: ' + data.error); }
                } catch(err) { alert('Failed to query repository indices.'); }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server execution smoothly online on port \${PORT}`));
