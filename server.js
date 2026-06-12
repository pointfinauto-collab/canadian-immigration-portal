const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// ==========================================
// 1. SECURITY & STREAM MIDDLEWARES
// ==========================================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many authentication attempts. Please try again later.' }
});

// Memory storage helper to process file buffers seamlessly
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB Limit
});

// ==========================================
// 2. DATABASE INTEGRATION & DATA SCHEMA
// ==========================================
const MONGO_URI = process.env.MONGO_URI || "mongodb://usrtest:canada2026secure@cluster0-shard-00-00.q9tcm7y.mongodb.net:27017,cluster0-shard-00-01.q9tcm7y.mongodb.net:27017,cluster0-shard-00-02.q9tcm7y.mongodb.net:27017/immigration?ssl=true&replicaSet=atlas-13w7g2-shard-0&authSource=admin&retryWrites=true&w=majority";

mongoose.connect(MONGO_URI, { maxPoolSize: 10, serverSelectionTimeoutMS: 10000 })
  .then(() => console.log('🚀 Base Registry Database Connected'))
  .catch(err => console.error('❌ Database Connection Failure:', err.message));

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    dob: { type: String, default: '' },
    gender: { type: String, default: '' },
    citizenship: { type: String, default: '' },
    passportNumber: { type: String, uppercase: true, trim: true, default: '' },
    residence: { type: String, default: '' },
    phone: { type: String, default: '' },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    uciNumber: { type: String, unique: true },
    trackingRef: { type: String, unique: true },
    status: { type: String, default: 'Submitted / Review Pending' },
    adminNotes: { type: String, default: 'Your application file is undergoing preliminary verification.' },
    attachedFile: { type: String, default: '' },     
    attachedFileName: { type: String, default: '' }, 
    attachedMimeType: { type: String, default: '' }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// 3. SECURITY MIDDLEWARE FOR ADMIN CONSOLE
// ==========================================
const checkAdminPrivileges = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing security token.' });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized configuration clearance.' });
        }
        req.user = decoded;
        next();
    });
};

// ==========================================
// 4. API ROUTING PIPELINES
// ==========================================

app.post('/api/auth/register', upload.single('clientDocument'), async (req, res) => {
    try {
        const { name, email, password, dob, gender, citizenship, passportNumber, residence, phone } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'Primary validation parameters missing.' });

        const normalizedEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) return res.status(409).json({ error: 'Account already registered in system.' });

        const salt = await bcrypt.genSalt(12);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Your custom randomized generation keys
        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "TRK-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        const systemAdminEmail = (process.env.ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (normalizedEmail === systemAdminEmail) ? 'admin' : 'user';

        let attachedFile = '';
        let attachedFileName = '';
        let attachedMimeType = '';

        if (req.file) {
            attachedFile = req.file.buffer.toString('base64');
            attachedFileName = req.file.originalname;
            attachedMimeType = req.file.mimetype;
        }

        const newUser = new User({
            name, email: normalizedEmail, password: hashedPassword,
            dob, gender, citizenship, passportNumber, residence, phone, role, uciNumber, trackingRef,
            attachedFile, attachedFileName, attachedMimeType
        });

        await newUser.save();
        res.status(201).json({ success: true, uciNumber, trackingRef });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Registration pipeline deployment failure.' });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid identification credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid identification credentials.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, token, role: user.role, name: user.name, uciNumber: user.uciNumber, trackingRef: user.trackingRef });
    } catch (error) {
        res.status(500).json({ error: 'Login verification error.' });
    }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const record = await User.findOne({ uciNumber: req.body.uciNumber.trim() });
        if (!record) return res.status(404).json({ error: 'No matching records found within tracking grid.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) {
        res.status(500).json({ error: 'Query tracking execution error.' });
    }
});

app.get('/api/admin/enrollments', checkAdminPrivileges, async (req, res) => {
    try {
        const enrollments = await User.find().sort({ createdAt: -1 });
        res.json(enrollments);
    } catch (err) {
        res.status(500).json({ error: 'Failed to access system records.' });
    }
});

app.post('/api/admin/decision', checkAdminPrivileges, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.body.id, { 
            status: req.body.status, 
            adminNotes: req.body.adminNotes 
        }, { runValidators: true });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to commit updates to backend database.' });
    }
});

app.delete('/api/admin/user/:id', checkAdminPrivileges, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Purge file matrix execution error.' });
    }
});

// ==========================================
// 5. NEUTRAL ADMIN MANAGEMENT LAYOUT
// ==========================================
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Identity Registry Administration</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #f8fafc; color: #1e293b; }
            .navbar { background: #0f172a; padding: 20px 40px; color: #fff; display: flex; justify-content: space-between; align-items: center; }
            .container { padding: 40px; max-width: 1600px; margin: 0 auto; }
            table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
            th, td { padding: 16px; border-bottom: 1px solid #e2e8f0; text-align: left; font-size: 14px; vertical-align: top; }
            th { background: #334155; color: #fff; font-weight: 600; text-transform: uppercase; font-size: 12px; }
            .badge { display: inline-block; padding: 4px 8px; font-weight: bold; font-size: 11px; border-radius: 4px; text-transform: uppercase; color: white; background: #f0ad4e; }
            .btn { background: #0284c7; color: white; border: none; padding: 8px 14px; cursor: pointer; border-radius: 6px; font-weight: 600; transition: background 0.15s; }
            .btn:hover { background: #0369a1; }
            .btn-danger { background: #ef4444; }
            .btn-danger:hover { background: #dc2626; }
            select, textarea { width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 6px; background: #f8fafc; box-sizing: border-box; }
            .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); justify-content: center; align-items: center; }
            .modal-content { background: white; padding: 25px; max-width: 70%; max-height: 80%; overflow: auto; border-radius: 8px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <h3 style="margin:0;">Global Registry Case Management Dashboard</h3>
            <button class="btn btn-danger" onclick="localStorage.clear(); window.location.href='/'">Sign Out</button>
        </div>
        <div class="container">
            <table>
                <thead>
                    <tr>
                        <th style="width:25%;">Applicant Parameters</th>
                        <th style="width:20%;">Document Node</th>
                        <th style="width:20%;">System Context</th>
                        <th style="width:15%;">Adjudication Matrix</th>
                        <th style="width:15%;">Internal Log Notes</th>
                        <th style="width:5%;">Action</th>
                    </tr>
                </thead>
                <tbody id="rows"><tr><td colspan="6" style="text-align:center;">Synchronizing Data Streams...</td></tr></tbody>
            </table>
        </div>

        <div id="fileModal" class="modal">
            <div class="modal-content">
                <h3 id="modalTitle">Document Viewer</h3>
                <div id="modalBody" style="margin: 20px 0;"></div>
                <button class="btn" onclick="document.getElementById('fileModal').style.display = 'none'">Close Window</button>
            </div>
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
                    if (u.role === 'admin') return;
                    const tr = document.createElement('tr');
                    
                    let fileSectionHtml = '<span style="color:#94a3b8; font-style:italic;">No binary document uploaded</span>';
                    if (u.attachedFile) {
                        fileSectionHtml = \`
                            <div>
                                <strong>\${u.attachedFileName}</strong><br><br>
                                <button class="btn" style="padding:4px 10px; font-size:12px; margin-right:5px;" onclick="viewFile('\${u.attachedFile}', '\${u.attachedMimeType}', '\${u.attachedFileName}')">Inspect</button>
                                <a class="btn" style="padding:4px 10px; font-size:12px; background:#475569;" href="data:\${u.attachedMimeType};base64,\${u.attachedFile}" download="\${u.attachedFileName}">Download</a>
                            </div>
                        \`;
                    }

                    tr.innerHTML = \`
                        <td>
                            <strong>\${u.name}</strong><br>
                            <span style="font-size:12px; color:#64748b; line-height:1.5;">
                                Mail: \${u.email}<br>Phone: \${u.phone || 'N/A'}<br>Residence: \${u.residence || 'N/A'}
                            </span>
                        </td>
                        <td>\${fileSectionHtml}</td>
                        <td>
                            <span class="badge">\${u.status}</span><br>
                            <span style="font-size:12px; color:#475569; line-height:1.5;">
                                UCI ID: <code>\${u.uciNumber || 'N/A'}</code><br>Ref Code: <code>\${u.trackingRef || 'N/A'}</code><br>Passport: <strong>\${u.passportNumber || 'N/A'}</strong>
                            </span>
                        </td>
                        <td>
                            <select id="s-\${u._id}">
                                <option value="Submitted / Review Pending" \${u.status === 'Submitted / Review Pending'?'selected':''}>Review Pending</option>
                                <option value="Under Active Officer Review" \${u.status === 'Under Active Officer Review'?'selected':''}>Under Active Review</option>
                                <option value="Biometrics Verification Stage" \${u.status === 'Biometrics Verification Stage'?'selected':''}>Biometrics Stage</option>
                                <option value="Registry Profile Approved" \${u.status === 'Registry Profile Approved'?'selected':''}>Approved</option>
                                <option value="Refusal Issued" \${u.status === 'Refusal Issued'?'selected':''}>Refusal Issued</option>
                            </select>
                        </td>
                        <td><textarea id="n-\${u._id}" rows="3">\${u.adminNotes || ''}</textarea></td>
                        <td>
                            <button class="btn" style="margin-bottom:5px; width:100%;" onclick="save('\${u._id}')">Save</button>
                            <button class="btn btn-danger" style="width:100%; font-size:12px; padding:6px;" onclick="del('\${u._id}')">Purge</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }

            function viewFile(base64, mime, filename) {
                const modal = document.getElementById('fileModal');
                const body = document.getElementById('modalBody');
                document.getElementById('modalTitle').innerText = filename;
                
                if (mime.includes('image')) {
                    body.innerHTML = \`<img src="data:\${mime};base64,\${base64}" style="max-width:100%; max-height:500px; border-radius:6px;">\`;
                } else if (mime.includes('pdf')) {
                    body.innerHTML = \`<iframe src="data:\${mime};base64,\${base64}" style="width:100%; height:500px; border:none;"></iframe>\`;
                } else {
                    body.innerHTML = \`<p>MIME preview window unsupported. Please download file asset directly.</p>\`;
                }
                modal.style.display = 'flex';
            }

            async function save(id) {
                const res = await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status: document.getElementById('s-'+id).value, adminNotes: document.getElementById('n-'+id).value })
                });
                if(res.ok) { alert('Updates successfully committed.'); loadGrid(); }
                else { alert('Error updating data array.'); }
            }

            async function del(id) {
                if(confirm('Purge profile matrix record permanently?')) {
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

// ==========================================
// 6. NEUTRAL REGISTRATION FRONTEND HUB
// ==========================================
app.get('*', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Global Travel Registration System</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #f1f5f9; color: #1e293b; margin: 0; padding: 0; }
            .header-bar { background: #0f172a; padding: 20px 40px; color: white; font-weight: bold; font-size: 18px; }
            .wrapper { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
            .tabs { display: flex; background: #e2e8f0; padding: 6px; border-radius: 8px; margin-bottom: 25px; }
            .tabs button { flex: 1; padding: 12px; border: none; font-size: 15px; font-weight: 600; cursor: pointer; background: transparent; border-radius: 6px; color: #475569; }
            .tabs button.active { background: #0f172a; color: white; }
            .card { background: white; padding: 35px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); display: none; border: 1px solid #e2e8f0; }
            .card.active { display: block; }
            .form-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; margin-bottom: 20px; }
            @media(max-width: 600px) { .form-grid { grid-template-columns: 1fr; } }
            label { font-size: 13px; font-weight: 600; color: #475569; display: block; margin-bottom: 6px; }
            input, select { padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; width: 100%; box-sizing: border-box; background: #f8fafc; }
            input:focus, select:focus { border-color: #0284c7; outline: none; background: #fff; }
            .btn-primary { padding: 12px 24px; background: #0284c7; color: white; border: none; font-size: 15px; font-weight: bold; cursor: pointer; border-radius: 6px; width: 100%; }
            .btn-primary:hover { background: #0369a1; }
            .status-box { display: none; margin-top: 25px; padding: 20px; border-left: 5px solid #0284c7; background: #f0f9ff; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="header-bar">Global Travel Enrollment Console</div>
        <div class="wrapper">
            <div class="tabs">
                <button id="tab-l" class="active" onclick="setView('loginCard', 'tab-l')">Account Login</button>
                <button id="tab-r" onclick="setView('registerCard', 'tab-r')">Create Application File</button>
                <button id="tab-t" onclick="setView('trackCard', 'tab-t')">Track File Status</button>
            </div>

            <div id="loginCard" class="card active">
                <h3 style="margin-top:0;">Secure Gateway Sign-In</h3>
                <form id="lForm" style="max-width:400px;">
                    <div style="margin-bottom:15px;">
                        <label>Email Address</label>
                        <input type="email" id="lEmail" required>
                    </div>
                    <div style="margin-bottom:20px;">
                        <label>Password</label>
                        <input type="password" id="lPass" required>
                    </div>
                    <button type="submit" class="btn-primary">Sign In</button>
                </form>
            </div>

            <div id="registerCard" class="card">
                <h3 style="margin-top:0;">Dossier Creation Form</h3>
                <form id="rForm">
                    <div class="form-grid">
                        <div>
                            <label>Legal Full Name</label>
                            <input type="text" id="rName" required>
                        </div>
                        <div>
                            <label>Date of Birth</label>
                            <input type="date" id="rDob" required>
                        </div>
                        <div>
                            <label>Gender</label>
                            <select id="rGender">
                                <option value="Male">Male</option>
                                <option value="Female">Female</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                        <div>
                            <label>Country of Citizenship</label>
                            <input type="text" id="rCitizenship" required>
                        </div>
                        <div>
                            <label>Passport Serial Number</label>
                            <input type="text" id="rPassport" required>
                        </div>
                        <div>
                            <label>Country of Residence</label>
                            <input type="text" id="rResidence" required>
                        </div>
                        <div>
                            <label>Telephone Number</label>
                            <input type="tel" id="rPhone" required>
                        </div>
                        <div>
                            <label>Email Address</label>
                            <input type="email" id="rEmail" required>
                        </div>
                    </div>
                    <div style="margin-bottom:20px; max-width:49%;">
                        <label>Create Secure Password</label>
                        <input type="password" id="rPass" required>
                    </div>
                    <div style="margin-bottom:25px;">
                        <label>Upload Supporting ID Verification Document (PDF/Image)</label>
                        <input type="file" id="rFile" name="clientDocument" required style="border: 2px dashed #cbd5e1; padding: 15px; background: #fafafa;">
                    </div>
                    <button type="submit" class="btn-primary">Submit Application Dossier</button>
                </form>
            </div>

            <div id="trackCard" class="card">
                <h3 style="margin-top:0;">Application Status Verification</h3>
                <form id="tForm" style="max-width:400px;">
                    <div style="margin-bottom:15px;">
                        <label>Enter Unique Client ID (UCI)</label>
                        <input type="text" id="tUci" placeholder="UCI-XXXXXXXX" required>
                    </div>
                    <button type="submit" class="btn-primary">Query Tracking Registry</button>
                </form>
                <div id="tResult" class="status-box"></div>
            </div>
        </div>

        <script>
            function setView(cardId, tabId) {
                document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
                document.querySelectorAll('.tabs button').forEach(t => t.classList.remove('active'));
                document.getElementById(cardId).classList.add('active');
                document.getElementById(tabId).classList.add('active');
            }

            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const fd = new FormData();
                fd.append('name', document.getElementById('rName').value);
                fd.append('dob', document.getElementById('rDob').value);
                fd.append('gender', document.getElementById('rGender').value);
                fd.append('citizenship', document.getElementById('rCitizenship').value);
                fd.append('passportNumber', document.getElementById('rPassport').value);
                fd.append('residence', document.getElementById('rResidence').value);
                fd.append('phone', document.getElementById('rPhone').value);
                fd.append('email', document.getElementById('rEmail').value);
                fd.append('password', document.getElementById('rPass').value);
                
                const fileInput = document.getElementById('rFile');
                if(fileInput.files.length > 0) fd.append('clientDocument', fileInput.files[0]);

                try {
                    const res = await fetch('/api/auth/register', { method: 'POST', body: fd });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        alert('🎉 Profile File Logged Successfully!\\n\\nUCI ID: ' + data.uciNumber + '\\nTracking Reference: ' + data.trackingRef);
                        document.getElementById('rForm').reset();
                        setView('loginCard', 'tab-l');
                    } else { alert('System Exception: ' + data.error); }
                } catch(err) { alert('Transport configuration error.'); }
            });

            document.getElementById('lForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const res = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: document.getElementById('lEmail').value, password: document.getElementById('lPass').value })
                    });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        localStorage.setItem('adminToken', data.token);
                        localStorage.setItem('userRole', data.role);
                        if(data.role === 'admin') {
                            alert('Administrative Access Granted.');
                            window.location.href = '/admin';
                        } else {
                            alert('Session established for: ' + data.name + '\\nUCI: ' + data.uciNumber + '\\nRef Code: ' + data.trackingRef);
                        }
                    } else { alert('Access Denied: ' + data.error); }
                } catch(err) { alert('Authentication endpoint timed out.'); }
            });

            document.getElementById('tForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const res = await fetch('/api/auth/track', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ uciNumber: document.getElementById('tUci').value })
                    });
                    const data = await res.json();
                    const target = document.getElementById('tResult');
                    if(res.ok) {
                        target.style.display = 'block';
                        target.innerHTML = \`<h4 style="margin-top:0; color:#0284c7;">File Records Found: \${data.name}</h4><p><strong>Tracking Status:</strong> \s\${data.status}</p><p style="background:white; padding:10px; border:1px solid #e2e8f0; font-size:14px;"><strong>Administrative Log Remarks:</strong> \s\${data.adminNotes}</p>\`;
                    } else { alert('No matching record found: ' + data.error); }
                } catch(err) { alert('Stream synchronization error.'); }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`[SYS-INFO] Operational cluster node deployed successfully on interface port: ${PORT}`));
