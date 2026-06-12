const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// 1. GLOBAL PRODUCTION MIDDLEWARE
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 2. MONGODB ATLAS CLUSTER CONNECTION WITH CRASH PROTECTION
const fallbackURI = "mongodb+srv://testuser:testpass@cluster0.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = process.env.MONGO_URI || fallbackURI;

mongoose.connect(MONGO_URI)
  .then(() => console.log('🚀 Database Node Connected Successfully'))
  .catch(err => console.error('❌ Database Initialization Warning:', err.message));

// 3. PERSISTENT DATA SCHEMAS
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    uciNumber: { type: String, unique: true },
    trackingRef: { type: String, unique: true },
    status: { type: String, default: 'Submitted / Review Pending' },
    adminNotes: { type: String, default: 'Your application file is undergoing preliminary verification.' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// 4. CLIENT & AUTHENTICATION ENDPOINTS
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required.' });

        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) return res.status(409).json({ error: 'An account with this email is already registered.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (email.toLowerCase().trim() === systemAdminEmail) ? 'admin' : 'user';

        const newUser = new User({
            name,
            email: email.toLowerCase().trim(),
            password: hashedPassword,
            role,
            uciNumber,
            trackingRef
        });

        await newUser.save();
        res.status(201).json({ success: true, uciNumber, trackingRef });
    } catch (error) {
        res.status(500).json({ error: 'Internal server registration failure.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Missing login fields.' });

        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token, role: user.role, name: user.name, uciNumber: user.uciNumber, trackingRef: user.trackingRef });
    } catch (error) {
        res.status(500).json({ error: 'Server authentication subsystem error.' });
    }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const { uciNumber } = req.body;
        const record = await User.findOne({ uciNumber: uciNumber.trim() });
        if (!record) return res.status(404).json({ error: 'No matching records found.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) {
        res.status(500).json({ error: 'Query loop failure.' });
    }
});

// ==========================================
// 5. PROTECTED ADMINISTRATIVE ENDPOINTS
// ==========================================

const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: 'Unauthorized.' });
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    try { res.json(await User.find().sort({ createdAt: -1 })); } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    try {
        const { id, status, adminNotes } = req.body;
        await User.findByIdAndUpdate(id, { status, adminNotes });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    try { await User.findByIdAndDelete(req.params.id); res.json({ success: true }); } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

// ==========================================
// 6. ALL-IN-ONE SYSTEM FRONTEND INTERFACE
// ==========================================

app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔒 System Administration Panel</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f4f6f9; padding: 20px; margin:0; }
            .box { max-width: 1100px; margin: 30px auto; background: white; padding: 30px; border-radius: 6px; box-shadow: 0 4px 10px rgba(0,0,0,0.06); border-top: 6px solid #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; font-size: 14px; }
            th { background: #333; color: white; }
            .save-btn { background: #2e7d32; color: white; border: none; padding: 6px 12px; cursor: pointer; border-radius: 3px; font-weight: bold; }
            .del-btn { background: #c8102e; color: white; border: none; padding: 6px 12px; cursor: pointer; border-radius: 3px; font-weight: bold; }
            select, textarea { width: 100%; padding: 5px; box-sizing: border-box; }
        </style>
    </head>
    <body>
        <div class="box">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h2>🔒 System Administration Panel</h2>
                <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 12px; cursor:pointer;">Exit Console</button>
            </div>
            <table>
                <thead>
                    <tr><th>Applicant</th><th>Identifiers</th><th>Status Options</th><th>Officer Notes</th><th>Actions</th></tr>
                </thead>
                <tbody id="rows"><tr><td colspan="5" style="text-align:center;">Loading directory registry matrix...</td></tr></tbody>
            </table>
        </div>
        <script>
            const token = localStorage.getItem('adminToken');
            if (!token || localStorage.getItem('userRole') !== 'admin') { window.location.href = '/'; }

            async function loadGrid() {
                const res = await fetch('/api/admin/enrollments', { headers: { 'Authorization': 'Bearer ' + token } });
                if (!res.ok) { alert('Session validation expired.'); return; }
                const users = await res.json();
                const tbody = document.getElementById('rows');
                tbody.innerHTML = '';
                
                if(users.length === 0) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No records inside database cluster.</td></tr>'; return; }
                
                users.forEach(u => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = \`
                        <td><strong>\${u.name}</strong><br>\${u.email}</td>
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
                        <td><textarea id="n-\${u._id}">\${u.adminNotes || ''}</textarea></td>
                        <td>
                            <button class="save-btn" onclick="save('\${u._id}')">Save</button>
                            <button class="del-btn" onclick="del('\${u._id}')">Delete</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }
            async function save(id) {
                const status = document.getElementById('s-'+id).value;
                const adminNotes = document.getElementById('n-'+id).value;
                const res = await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status, adminNotes })
                });
                if (res.ok) { alert('Record updated successfully.'); loadGrid(); }
            }
            async function del(id) {
                if(!confirm('Purge record?')) return;
                const res = await fetch('/api/admin/user/' + id, { method: 'DELETE', headers: { 'Authorization': 'Bearer ' + token } });
                if (res.ok) { loadGrid(); }
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
            body { font-family: Arial, sans-serif; padding: 30px; background: #ffffff; color: #000; }
            .wrapper { max-width: 750px; margin: 0 auto; }
            .gov-brand { font-size: 15px; color: #444; margin-bottom: 15px; text-transform: uppercase; letter-spacing:0.5px; }
            h1 { font-family: Georgia, serif; font-size: 30px; font-weight: bold; margin-bottom: 25px; }
            .nav-tabs { display: flex; gap: 10px; margin-bottom: 30px; border-bottom: 1px solid #ccc; padding-bottom: 10px; }
            .nav-tabs button { padding: 8px 16px; background: #efefef; border: 1px solid #767676; font-size: 14px; cursor: pointer; border-radius: 3px; font-weight: 500; }
            .nav-tabs button:hover { background: #e5e5e5; }
            .panel { display: none; }
            .panel.active { display: block; }
            .form-group { margin-bottom: 15px; display: flex; align-items: center; }
            label { width: 220px; font-size: 15px; font-weight: bold; }
            input { padding: 6px 10px; width: 320px; border: 1px solid #767676; font-size: 14px; border-radius: 2px; }
            .action-btn { padding: 6px 16px; background: #efefef; border: 1px solid #767676; font-size: 14px; cursor: pointer; border-radius: 3px; margin-top: 15px; }
            .action-btn:hover { background: #e5e5e5; }
            .status-box { display: none; margin-top: 25px; padding: 20px; border-left: 5px solid #c8102e; background: #f9f9f9; max-width: 550px; }
        </style>
    </head>
    <body>
        <div class="wrapper">
            <div class="gov-brand">Government of Canada</div>
            <h1>Immigration and Secure Client Portal Terminal</h1>
            
            <div class="nav-tabs">
                <button type="button" onclick="showPanel('loginPanel')">Access Existing Account</button>
                <button type="button" onclick="showPanel('registerPanel')">Create Secure Account Profiling File</button>
                <button type="button" onclick="showPanel('trackPanel')">Track File Status</button>
            </div>

            <div id="loginPanel" class="panel active">
                <h2>Account Secure Gateway Sign-In</h2>
                <form id="lForm">
                    <div class="form-group"><label>Email Address</label><input type="email" id="lEmail" required></div>
                    <div class="form-group"><label>Account Security Password</label><input type="password" id="lPass" required></div>
                    <button type="submit" class="action-btn">Verify and Sign In</button>
                </form>
            </div>

            <div id="registerPanel" class="panel">
                <h2>Create Secure Account File Registry</h2>
                <form id="rForm">
                    <div class="form-group"><label>Legal Full Name</label><input type="text" id="rName" required></div>
                    <div class="form-group"><label>Email Address</label><input type="email" id="rEmail" required></div>
                    <div class="form-group"><label>Account Security Password</label><input type="password" id="rPass" required></div>
                    <button type="submit" class="action-btn">Execute Processing Enrollment Registry</button>
                </form>
            </div>

            <div id="trackPanel" class="panel">
                <h2>File Status Tracking Gateway</h2>
                <form id="tForm">
                    <div class="form-group"><label>Unique Client ID (UCI)</label><input type="text" id="tUci" placeholder="UCI-XXXXXXXX" required></div>
                    <button type="submit" class="action-btn">Query Directory Archives</button>
                </form>
                <div id="tResult" class="status-box"></div>
            </div>
        </div>

        <script>
            function showPanel(id) {
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                document.getElementById(id).classList.add('active');
            }

            // Handle Register
            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: document.getElementById('rName').value,
                        email: document.getElementById('rEmail').value,
                        password: document.getElementById('rPass').value
                    })
                });
                const data = await res.json();
                if(res.ok && data.success) {
                    alert('🎉 Profile Created Successfully!\\n\\nSave your login tracking details:\\nUCI ID: ' + data.uciNumber + '\\nTracking Ref: ' + data.trackingRef);
                    document.getElementById('rForm').reset();
                    showPanel('loginPanel');
                } else { alert('Error: ' + data.error); }
            });

            // Handle Login
            document.getElementById('lForm').addEventListener('submit', async (e) => {
                e.preventDefault();
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
                        alert('🔑 Admin Verified. Redirecting...');
                        window.location.href = '/admin';
                    } else {
                        alert('Welcome back, ' + data.name + '\\nUCI: ' + data.uciNumber + '\\nRef: ' + data.trackingRef);
                    }
                } else { alert('Access Refused: ' + data.error); }
            });

            // Handle Track
            document.getElementById('tForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const res = await fetch('/api/auth/track', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uciNumber: document.getElementById('tUci').value })
                });
                const data = await res.json();
                const out = document.getElementById('tResult');
                if(res.ok) {
                    out.style.display = 'block';
                    out.innerHTML = '<h3>File Status Profile: ' + data.name + '</h3><p><strong>Status:</strong> ' + data.status + '</p><p><strong>Officer Notes:</strong> ' + data.adminNotes + '</p>';
                } else { alert('Query Failed: ' + data.error); }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server execution smoothly online on port \${PORT}`));
