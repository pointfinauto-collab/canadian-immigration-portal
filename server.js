const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// 1. GLOBAL SYSTEM ENGINE MIDDLEWARES
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ limit: '30mb', extended: true }));

// 2. BUFFER MEMORY CAPACITY FOR UPLOADS
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } // Enforces a safe 5MB cap per profile image/document
});

// 3. DATABASE INFRASTRUCTURE AND LIVE INITIALIZATION
const fallbackURI = "mongodb+srv://testuser:testpass@cluster0.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = process.env.MONGO_URI || fallbackURI;

mongoose.connect(MONGO_URI)
  .then(async () => {
      console.log('🚀 Database Node Connected Successfully');
      try {
          // Self-Healing Trigger: Force-clears hidden legacy indexes that crash newer schema requests
          await mongoose.connection.db.collection('users').dropIndexes();
          console.log('🧹 Legacy MongoDB Indexes Purged Successfully.');
      } catch (e) {
          // Silent catch if collection doesn't exist yet
      }
  })
  .catch(err => console.error('❌ Database Initialization Warning:', err.message));

// 4. DATABASE SCHEMATIC Blueprints
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
    uciNumber: { type: String, default: null }, 
    trackingRef: { type: String, default: null },
    status: { type: String, default: 'Awaiting Initial Review (UCI Pending)' },
    adminNotes: { type: String, default: 'Your profile registration has been received. A case officer is reviewing your uploaded identification documents to generate your official Unique Client ID (UCI).' },
    attachedFile: { type: String, default: '' },     
    attachedFileName: { type: String, default: '' }, 
    attachedMimeType: { type: String, default: '' }, 
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// 5. RESTFUL TRANSACTIONS & WEB GATEWAYS
// ==========================================

// A. REVISED BACKEND USER REGISTRATION PIPELINE
app.post('/api/auth/register', upload.single('clientDocument'), async (req, res) => {
    try {
        const { name, email, password, dob, gender, citizenship, passportNumber, residence, phone } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Primary required registration values are missing.' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: cleanEmail });
        if (existingUser) return res.status(409).json({ error: 'This email account has already been registered.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (cleanEmail === systemAdminEmail) ? 'admin' : 'user';

        let attachedFile = '';
        let attachedFileName = '';
        let attachedMimeType = '';

        if (req.file) {
            attachedFile = req.file.buffer.toString('base64');
            attachedFileName = req.file.originalname;
            attachedMimeType = req.file.mimetype;
        }

        const newUser = new User({
            name, email: cleanEmail, password: hashedPassword,
            dob, gender, citizenship, passportNumber, residence, phone, role,
            attachedFile, attachedFileName, attachedMimeType
        });

        await newUser.save();
        res.status(201).json({ success: true, message: 'Intake application created.' });
    } catch (error) {
        console.error('CRITICAL ERROR REGISTRATION PIPE:', error);
        res.status(500).json({ error: 'Database ingestion failure. Check connection parameters.' });
    }
});

// B. REVISED ACCURATE LOGIN VERIFIER
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'No matching user found with those credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Password authentication verified false.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '4h' });
        res.json({ success: true, token, role: user.role, name: user.name });
    } catch (error) {
        res.status(500).json({ error: 'Server authentication verification process failed.' });
    }
});

// C. REAL-TIME MULTI-TAB TRACKING CONTROLLER
app.post('/api/auth/track', async (req, res) => {
    try {
        const targetUCI = req.body.uciNumber.trim();
        if(!targetUCI) return res.status(400).json({ error: 'UCI lookup parameter cannot be empty.' });

        const record = await User.findOne({ uciNumber: targetUCI });
        if (!record) return res.status(404).json({ error: 'This UCI does not match any official issued file.' });
        
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) {
        res.status(500).json({ error: 'Tracking system interface failure.' });
    }
});

// D. ADMINISTRATIVE SECURITY MIDDLEWARE
const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token missing.' });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied. Administrative credentials mandatory.' });
        }
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    res.json(await User.find().sort({ createdAt: -1 }));
});

// E. DYNAMIC UCI SYSTEM ALLOCATOR & OUTGOING LOGGER
app.post('/api/admin/generate-uci', checkAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.body.id);
        if(!user) return res.status(404).json({ error: 'Target record missing.' });
        if(user.uciNumber) return res.status(400).json({ error: 'This account already has a UCI issued.' });

        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        user.uciNumber = uciNumber;
        user.trackingRef = trackingRef;
        user.status = "Under Active Officer Review (UCI Dispatched)";
        user.adminNotes = `Official profile processing active. Profile allocated Unique Client ID (UCI): ${uciNumber}. Direct status dashboard query streams are now active.`;
        
        await user.save();

        console.log(`
========================================================================
✉️ SIMULATED SYSTEM DISPATCH GENERATED SUCCESS
========================================================================
To: ${user.email}
Subject: Official Immigration Portal Status Update - UCI Allocated
Your Unique Tracking ID is: ${uciNumber}
========================================================================
        `);

        res.json({ success: true, uciNumber, trackingRef });
    } catch (err) {
        res.status(500).json({ error: 'Failed to safely store generated UCI identifiers.' });
    }
});

// F. ADJUDICATION UPDATE COMMITTER
app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.body.id, { 
            status: req.body.status, 
            adminNotes: req.body.adminNotes 
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Adjudication modification push crash.' });
    }
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ==========================================
// 6. RENDER DIRECT ADJUDICATION FRONTEND VIEW
// ==========================================
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>🔒 Case Management Decision Console - Canada.ca</title>
        <style>
            body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #f9f9f9; color: #333; margin: 0; padding: 0; }
            .gov-header { background: #fff; border-bottom: 2px solid #e16262; padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
            .brand-text { font-size: 22px; font-weight: 700; color: #333; }
            .red-flag { color: #c8102e; }
            .box { max-width: 1550px; margin: 30px auto; background: white; padding: 30px; border: 1px solid #dcdee1; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dcdcdc; font-size: 14px; vertical-align: top; }
            th { background: #26374a; color: white; }
            tr:nth-child(even) { background: #f8fafc; }
            .badge { display: inline-block; padding: 4px 8px; font-weight: bold; font-size: 11px; border-radius: 3px; text-transform: uppercase; margin-bottom: 5px; background: #777; color: white; }
            .uci-btn { background: #d9534f; color: white; border: none; padding: 8px 12px; font-weight: bold; border-radius: 4px; cursor: pointer; border-bottom: 2px solid #b52b27; width: 100%; text-transform: uppercase; font-size: 11px; margin-bottom:5px;}
            .save-btn { background: #264a28; color: white; border: none; padding: 8px 14px; cursor: pointer; font-weight: bold; width: 100%; margin-bottom: 6px; border-radius: 4px; }
            .del-btn { background: #bc1c1c; color: white; border: none; padding: 6px 14px; cursor: pointer; font-size: 12px; width: 100%; border-radius: 4px; }
            .file-btn { display: inline-block; background: #2572b4; color: white; text-decoration: none; padding: 6px 12px; font-size: 12px; font-weight: bold; margin-top: 5px; border-radius: 4px; text-align: center; width: 100%; box-sizing: border-box; }
            select, textarea { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #767676; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="gov-header">
            <div class="brand-text">Government of Can<span class="red-flag">ada</span> — Case Officer System Desktop</div>
            <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 16px; background:#333; color:#fff; border:none; cursor:pointer; font-weight:bold; border-radius:4px;">Sign Out</button>
        </div>
        
        <div class="box">
            <h2>📋 Document Review & Strategic UCI Assignment Engine</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width:25%;">Applicant Legal Identity</th>
                        <th style="width:20%;">Transmitted Documents</th>
                        <th style="width:25%;">Allocated System Identifiers</th>
                        <th style="width:15%;">Status Pipeline Vector</th>
                        <th style="width:15%;">Live Visible Remarks</th>
                        <th style="width:10%;">Directives</th>
                    </tr>
                </thead>
                <tbody id="rows"><tr><td colspan="6" style="text-align:center;">Querying Secure Database Streams...</td></tr></tbody>
            </table>
        </div>

        <script>
            const token = localStorage.getItem('adminToken');
            if (!token || localStorage.getItem('userRole') !== 'admin') { window.location.href = '/'; }

            async function loadGrid() {
                try {
                    const res = await fetch('/api/admin/enrollments', { headers: { 'Authorization': 'Bearer ' + token } });
                    if (!res.ok) { window.location.href='/'; return; }
                    const users = await res.json();
                    const tbody = document.getElementById('rows');
                    tbody.innerHTML = '';
                    
                    users.forEach(u => {
                        if(u.role === 'admin') return; 
                        const tr = document.createElement('tr');
                        
                        let fileSectionHtml = '<span style="color:#777; font-style:italic;">No attachment uploaded</span>';
                        if (u.attachedFile) {
                            fileSectionHtml = \`
                                <div>
                                    📁 <span style="font-size:11px; font-weight:bold; word-break:break-all;">\this.attachedFileName || 'Identity_File'}\</span><br>
                                    <a class="file-btn" href="data:\${u.attachedMimeType};base64,\${u.attachedFile}" download="\${u.attachedFileName || 'identity_doc'}">💾 Download Asset</a>
                                </div>
                            \`;
                        }

                        let uciActionColumnHtml = !u.uciNumber 
                            ? \`<button class="uci-btn" onclick="generateUCI('\${u._id}')">🎟️ Generate UCI</button>\`
                            : \`<span style="color:#264a28; font-weight:bold; font-size:11px; display:block; text-align:center; margin-bottom:5px;">✅ Dispatched</span>\`;

                        tr.innerHTML = \`
                            <td><strong>\${u.name}</strong><br><small><code>\${u.email}</code><br>DOB: \${u.dob || 'N/A'}</small></td>
                            <td>\${fileSectionHtml}</td>
                            <td>
                                <span class="badge">\${u.status}</span><br>
                                <small>UCI: <strong style="color:#bc1c1c;">\${u.uciNumber || 'AWAITING GENERAL'}</strong><br>Ref: <code>\${u.trackingRef || 'N/A'}</code></small>
                            </td>
                            <td>
                                <select id="s-\${u._id}" \${!u.uciNumber ? 'disabled' : ''}>
                                    <option value="Under Active Officer Review" \${u.status.includes('Review')?'selected':''}>Under Active Officer Review</option>
                                    <option value="Biometrics Verification Stage" \${u.status.includes('Biometrics')?'selected':''}>Biometrics Verification Stage</option>
                                    <option value="Background Eligibility Check" \${u.status.includes('Background')?'selected':''}>Background Eligibility Check</option>
                                    <option value="Registry Profile Approved" \${u.status.includes('Approved')?'selected':''}>Registry Profile Approved</option>
                                </select>
                            </td>
                            <td><textarea id="n-\${u._id}" rows="2">\${u.adminNotes || ''}</textarea></td>
                            <td>
                                \${uciActionColumnHtml}
                                <button class="save-btn" onclick="save('\${u._id}')">Commit</button>
                                <button class="del-btn" onclick="del('\${u._id}')">Purge</button>
                            </td>
                        \`;
                        tbody.appendChild(tr);
                    });
                } catch(e) { alert("Error generating table grid visual blocks."); }
            }

            async function generateUCI(id) {
                const res = await fetch('/api/admin/generate-uci', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id })
                });
                if(res.ok) { alert('🎉 Unique Identifier Generated & Simulated Email Queued.'); loadGrid(); }
                else { alert('UCI Assignment Failure.'); }
            }

            async function save(id) {
                const selectEl = document.getElementById('s-'+id);
                const status = selectEl ? selectEl.value : "Awaiting Initial Review (UCI Pending)";
                const adminNotes = document.getElementById('n-'+id).value;
                const res = await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status, adminNotes })
                });
                if(res.ok) { alert('🎉 Core changes saved cleanly.'); loadGrid(); }
                else { alert('Error updating changes.'); }
            }

            async function del(id) {
                if(confirm('Purge completely?')) {
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
// 7. HIGH-FIDELITY MAIN SYSTEM LANDING PATHWAY
// ==========================================
app.get('*', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Immigration and citizenship - Canada.ca</title>
        <style>
            body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #ffffff; color: #333333; margin: 0; padding: 0; }
            .top-utility { background-color: #26374a; padding: 8px 40px; display: flex; justify-content: flex-end; }
            .top-utility a { color: #ffffff; text-decoration: none; font-size: 13px; font-weight:600;}
            .gov-brand-bar { padding: 25px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e1e4e7; }
            .signature-logo { font-size: 26px; font-weight: bold; color: #000; }
            .signature-logo span { color: #c8102e; }
            .red-accent-strip { background-color: #c8102e; height: 4px; width: 100%; }
            .main-content { max-width: 1140px; margin: 30px auto; padding: 0 40px; }
            h1 { font-size: 38px; border-bottom: 1px solid #afb7c0; padding-bottom: 12px; margin-top: 0; }
            .wet-tabs { display: flex; background: #eaebed; padding: 6px; border-radius: 4px; margin-bottom: 30px; }
            .wet-tabs button { padding: 12px 24px; background: transparent; border: none; font-size: 15px; font-weight: bold; cursor: pointer; color: #26374a; }
            .wet-tabs button.active { background: #26374a; color: #ffffff; border-radius: 4px; }
            .portal-panel { display: none; background: #ffffff; border: 1px solid #dcdcdc; border-radius: 4px; padding: 30px; }
            .portal-panel.active { display: block; }
            .form-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
            @media (max-width: 768px) { .form-grid { grid-template-columns: 1fr; } }
            .input-group { display: flex; flex-direction: column; margin-bottom: 15px; }
            label { font-size: 15px; font-weight: 600; margin-bottom: 6px; }
            .required-mark { color: #bc1c1c; }
            input, select { padding: 8px 12px; border: 1px solid #444444; font-size: 15px; border-radius: 4px; width: 100%; box-sizing: border-box; height: 40px; }
            input[type="file"] { border: 2px dashed #26374a; background: #fafafa; padding: 6px; height: auto; }
            .btn-primary { padding: 11px 24px; background-color: #2572b4; color: #ffffff; border: 1px solid #2369a5; font-size: 16px; font-weight: 700; cursor: pointer; border-radius: 4px; border-bottom: 3px solid #1b5180; }
            .status-display-card { display: none; margin-top: 30px; padding: 25px; border-left: 6px solid #bc1c1c; background-color: #fcf8f8; border-top:1px solid #e3cbcb; border-right:1px solid #e3cbcb; border-bottom:1px solid #e3cbcb;}
        </style>
    </head>
    <body>
        <div class="top-utility"><a href="#">Français</a></div>
        <div class="gov-brand-bar">
            <div class="signature-logo">Government of Canada</div>
        </div>
        <div class="red-accent-strip"></div>
        
        <div class="main-content">
            <h1>Immigration and Secure Client Portal Terminal</h1>
            
            <div class="wet-tabs">
                <button type="button" id="btn-login" class="active" onclick="setView('loginPanel', 'btn-login')">Access Existing Account</button>
                <button type="button" id="btn-register" onclick="setView('registerPanel', 'btn-register')">Submit Secure Profiling Intake File</button>
                <button type="button" id="btn-track" onclick="setView('trackPanel', 'btn-track')">Track File Status Gateway</button>
            </div>

            <div id="loginPanel" class="portal-panel active">
                <h2>Account Secure Gateway Sign-In</h2>
                <form id="lForm">
                    <div style="max-width: 440px;">
                        <div class="input-group">
                            <label>Email Address <span class="required-mark">*</span></label>
                            <input type="email" id="lEmail" required autocomplete="email">
                        </div>
                        <div class="input-group">
                            <label>Account Security Password <span class="required-mark">*</span></label>
                            <input type="password" id="lPass" required autocomplete="current-password">
                        </div>
                        <button type="submit" class="btn-primary">Verify and Sign In</button>
                    </div>
                </form>
            </div>

            <div id="registerPanel" class="portal-panel">
                <h2>Secure System Intake Enrollment Registry</h2>
                <form id="rForm" enctype="multipart/form-data">
                    <div class="form-grid">
                        <div class="input-group">
                            <label>Legal Full Name <span class="required-mark">*</span></label>
                            <input type="text" id="rName" required>
                        </div>
                        <div class="input-group">
                            <label>Email Access Point <span class="required-mark">*</span></label>
                            <input type="email" id="rEmail" required autocomplete="email">
                        </div>
                        <div class="input-group">
                            <label>Create Password <span class="required-mark">*</span></label>
                            <input type="password" id="rPass" required autocomplete="new-password">
                        </div>
                        <div class="input-group">
                            <label>Date of Birth <span class="required-mark">*</span></label>
                            <input type="date" id="rDob" required>
                        </div>
                        <div class="input-group">
                            <label>Country of Citizenship <span class="required-mark">*</span></label>
                            <input type="text" id="rCitizenship" required>
                        </div>
                        <div class="input-group">
                            <label>Passport Serial Number <span class="required-mark">*</span></label>
                            <input type="text" id="rPassport" required>
                        </div>
                    </div>
                    <div class="input-group" style="max-width:500px;">
                        <label>Upload Identification Passport Document (Max 5MB) <span class="required-mark">*</span></label>
                        <input type="file" id="rFile" name="clientDocument" accept=".pdf,.png,.jpg,.jpeg" required>
                    </div>
                    <button type="submit" class="btn-primary">Submit Ingestion Intake File</button>
                </form>
            </div>

            <div id="trackPanel" class="portal-panel">
                <h2>File Status Tracking Gateway</h2>
                <form id="tForm">
                    <div style="max-width:440px;">
                        <div class="input-group">
                            <label>Official Unique Client ID (UCI)</label>
                            <input type="text" id="tUci" placeholder="UCI-XXXXXXXX" required>
                        </div>
                        <button type="submit" class="btn-primary">Query Directory</button>
                    </div>
                </form>
                <div id="tResult" class="status-display-card"></div>
            </div>
        </div>

        <script>
            function setView(panelId, btnId) {
                document.querySelectorAll('.portal-panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.wet-tabs button').forEach(b => b.classList.remove('active'));
                document.getElementById(panelId).classList.add('active');
                document.getElementById(btnId).classList.add('active');
            }

            // EXECUTING AND VERIFYING FRONTEND SUBMISSIONS TO BACKEND
            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = e.target.querySelector('.btn-primary');
                btn.innerText = "Transmitting Security Packet Data...";
                btn.disabled = true;

                const formData = new FormData();
                formData.append('name', document.getElementById('rName').value);
                formData.append('email', document.getElementById('rEmail').value);
                formData.append('password', document.getElementById('rPass').value);
                formData.append('dob', document.getElementById('rDob').value);
                formData.append('citizenship', document.getElementById('rCitizenship').value);
                formData.append('passportNumber', document.getElementById('rPassport').value);
                
                const fileInput = document.getElementById('rFile');
                if(fileInput.files.length > 0) formData.append('clientDocument', fileInput.files[0]);

                try {
                    const res = await fetch('/api/auth/register', { method: 'POST', body: formData });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        alert('🎉 Profile Logged Successfully! Form cleared. Switching view to Tracking Gateway.');
                        document.getElementById('rForm').reset();
                        setView('trackPanel', 'btn-track');
                    } else { alert('Intake System Refusal: ' + (data.error || 'Check server logs.')); }
                } catch(err) { alert('Network transaction path routing failure.'); }
                finally { btn.innerText = "Submit Ingestion Intake File"; btn.disabled = false; }
            });

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
                            alert('🔑 Master Admin Authentication Confirmed. Directing to Case Console Matrix dashboard...');
                            window.location.href = '/admin';
                        } else {
                            alert('Access Token Authorized! Profile currently placed in verification queue waiting for Officer UCI allocation.');
                        }
                    } else { alert('Authorization Refused: ' + data.error); }
                } catch(err) { alert('Authentication processing connection failure.'); }
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
                    const out = document.getElementById('tResult');
                    if(res.ok) {
                        out.style.display = 'block';
                        out.innerHTML = \`
                            <h3 style="color:#bc1c1c; margin:0 0 10px 0;">File Status for: \${data.name}</h3>
                            <p><strong>Current Active Vector Stage:</strong> <span style="color:#bc1c1c; font-weight:bold;">\${data.status}</span></p>
                            <p style="background:#fff; padding:10px; border:1px solid #ccc; font-size:14px;"><strong>Officer Notes:</strong> \${data.adminNotes}</p>
                        \`;
                    } else { alert('Query Failed: ' + data.error); }
                } catch(err) { alert('Could not complete pipeline tracking query.'); }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server execution smoothly online on port ${PORT}`));
