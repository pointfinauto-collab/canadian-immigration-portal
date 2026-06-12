const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// 1. DYNAMIC GLOBAL SYSTEM MIDDLEWARES
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' })); 
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// 2. UPGRADED MULTI-FILE BUFFER ENGINE
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB individual file limit
});

// 3. DATABASE INITIALIZATION
const fallbackURI = "mongodb+srv://testuser:testpass@cluster0.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = process.env.MONGO_URI || fallbackURI;

mongoose.connect(MONGO_URI)
  .then(async () => {
      console.log('🚀 Database Node Connected Successfully');
      try {
          await mongoose.connection.db.collection('users').dropIndexes();
          console.log('🧹 Legacy MongoDB Validation Locks Cleared.');
      } catch (e) {}
  })
  .catch(err => console.error('❌ Database Initialization Warning:', err.message));

// 4. REVISED SCHEMATIC: EXPANDED FOR ALL CANADIAN TRAVEL DOCUMENTS
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
    status: { type: String, default: 'Awaiting Document Review (UCI Pending)' },
    adminNotes: { type: String, default: 'Your profile has been received. A case officer is evaluating your complete package of travel documents (Passport, Visa, and Financial Records).' },
    
    // Upgraded array structure to hold multiple files safely in one profile packet
    documents: [{
        docType: { type: String }, // 'passport', 'visa', 'financial', 'supporting'
        fileName: { type: String },
        mimeType: { type: String },
        fileData: { type: String } // Base64 Text String
    }],
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ==========================================
// 5. TRANSACTIONS & MULTI-UPLOAD ENDPOINTS
// ==========================================

// REVISED: Accepts an array of up to 5 documents simultaneously 
app.post('/api/auth/register', upload.any(), async (req, res) => {
    try {
        const { name, email, password, dob, citizenship, passportNumber } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Primary registration identification fields are required.' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: cleanEmail });
        if (existingUser) return res.status(409).json({ error: 'This email account is already registered.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (cleanEmail === systemAdminEmail) ? 'admin' : 'user';

        // Process all arriving files and categorize them by form attachment keys
        const processedDocuments = [];
        if (req.files && req.files.length > 0) {
            req.files.forEach(file => {
                processedDocuments.push({
                    docType: file.fieldname, // Captures 'passportFile', 'visaFile', 'financialFile' from frontend
                    fileName: file.originalname,
                    mimeType: file.mimetype,
                    fileData: file.buffer.toString('base64')
                });
            });
        }

        const newUser = new User({
            name, email: cleanEmail, password: hashedPassword,
            dob, citizenship, passportNumber, role,
            documents: processedDocuments
        });

        await newUser.save();
        res.status(201).json({ success: true, message: 'Comprehensive travel profile registered.' });
    } catch (error) {
        console.error('REGISTRATION PIPELINE EXCEPTION:', error);
        res.status(500).json({ error: 'Database transaction capacity error. Ensure file payloads do not exceed BSON size caps.' });
    }
});

// AUTHENTICATED SYSTEM LOGIN GATES
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid verification credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid verification credentials.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '4h' });
        res.json({ success: true, token, role: user.role, name: user.name });
    } catch (error) {
        res.status(500).json({ error: 'System log-in processing fault.' });
    }
});

// STATUS CHECK PIPELINE
app.post('/api/auth/track', async (req, res) => {
    try {
        const targetUCI = req.body.uciNumber.trim();
        const record = await User.findOne({ uciNumber: targetUCI });
        if (!record) return res.status(404).json({ error: 'UCI lookup parameter match not found.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) {
        res.status(500).json({ error: 'Registry tracking access error.' });
    }
});

// ADMIN VERIFICATION CORE
const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing.' });
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: 'Clearance denied.' });
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    res.json(await User.find().sort({ createdAt: -1 }));
});

app.post('/api/admin/generate-uci', checkAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.body.id);
        if(!user) return res.status(404).json({ error: 'File record missing.' });

        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        user.uciNumber = uciNumber;
        user.trackingRef = trackingRef;
        user.status = "Under Active Officer Review (UCI Dispatched)";
        user.adminNotes = `Travel documentation verified. Profile allocated Unique Client ID (UCI): ${uciNumber}. Use this code to view status changes live.`;
        
        await user.save();
        res.json({ success: true, uciNumber, trackingRef });
    } catch (err) {
        res.status(500).json({ error: 'UCI allocation storage crash.' });
    }
});

app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.body.id, { status: req.body.status, adminNotes: req.body.adminNotes });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Fault pushing status update.' }); }
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
});

// ==========================================
// 6. ADMIN GRAPHICAL INTERFACE GENERATOR
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
            .gov-header { background: #fff; border-bottom: 2px solid #e16262; padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; }
            .brand-text { font-size: 22px; font-weight: 700; }
            .box { max-width: 1550px; margin: 30px auto; background: white; padding: 30px; border: 1px solid #dcdee1; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dcdcdc; font-size: 14px; vertical-align: top; }
            th { background: #26374a; color: white; }
            tr:nth-child(even) { background: #f8fafc; }
            .badge { display: inline-block; padding: 4px 8px; font-weight: bold; font-size: 11px; border-radius: 3px; text-transform: uppercase; background: #777; color: white; margin-bottom:5px; }
            .uci-btn { background: #d9534f; color: white; border: none; padding: 8px 12px; font-weight: bold; border-radius: 4px; cursor: pointer; width: 100%; text-transform: uppercase; font-size: 11px; margin-bottom:5px;}
            .save-btn { background: #264a28; color: white; border: none; padding: 8px 14px; cursor: pointer; font-weight: bold; width: 100%; margin-bottom: 6px; border-radius: 4px; }
            .file-btn { display: block; background: #2572b4; color: white; text-decoration: none; padding: 4px 8px; font-size: 11px; font-weight: bold; margin-top: 4px; border-radius: 3px; text-align: center; box-sizing: border-box; }
            select, textarea { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #767676; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="gov-header">
            <div class="brand-text">Government of Canada — Case Officer System</div>
            <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 16px; background:#333; color:#fff; border:none; cursor:pointer; font-weight:bold; border-radius:4px;">Sign Out</button>
        </div>
        
        <div class="box">
            <h2>📋 Document Package Evaluation Panel</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width:22%;">Applicant Legal Identity</th>
                        <th style="width:25%;">Transmitted Travel Documents Bundle</th>
                        <th style="width:23%;">Allocated System Identifiers</th>
                        <th style="width:15%;">Adjudication Stage</th>
                        <th style="width:15%;">Remarks</th>
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
                const res = await fetch('/api/admin/enrollments', { headers: { 'Authorization': 'Bearer ' + token } });
                if (!res.ok) { window.location.href='/'; return; }
                const users = await res.json();
                const tbody = document.getElementById('rows');
                tbody.innerHTML = '';
                
                users.forEach(u => {
                    if(u.role === 'admin') return; 
                    const tr = document.createElement('tr');
                    
                    // Generate UI elements for every document uploaded in the user's travel stack
                    let filesHtml = '';
                    if(u.documents && u.documents.length > 0) {
                        u.documents.forEach(doc => {
                            let labels = { 'passportFile': '🛂 Passport', 'visaFile': '📄 Entry Visa', 'financialFile': '💰 Funds Proof' };
                            let displayLabel = labels[doc.docType] || '📁 Document';
                            filesHtml += \`
                                <div style="margin-bottom:8px; background:#f1f5f9; padding:6px; border-radius:4px; border:1px solid #cbd5e1;">
                                    <strong>\${displayLabel}</strong>: <span style="font-size:11px; color:#444; word-break:break-all;">\${doc.fileName}</span>
                                    <a class="file-btn" href="data:\${doc.mimeType};base64,\${doc.fileData}" download="\${doc.fileName}">💾 Download File</a>
                                </div>
                            \`;
                        });
                    } else { filesHtml = '<span style="color:#999; font-style:italic;">No files attached</span>'; }

                    let uciActionColumnHtml = !u.uciNumber 
                        ? \`<button class="uci-btn" onclick="generateUCI('\${u._id}')">🎟️ Issue UCI ID</button>\`
                        : \`<span style="color:#264a28; font-weight:bold; font-size:11px; display:block; text-align:center; margin-bottom:5px;">✅ UCI Active</span>\`;

                    tr.innerHTML = \`
                        <td><strong>\${u.name}</strong><br><small><code>\${u.email}</code><br>DOB: \${u.dob}</small></td>
                        <td>\${filesHtml}</td>
                        <td>
                            <span class="badge">\${u.status}</span><br>
                            <small>UCI: <strong style="color:#bc1c1c;">\${u.uciNumber || 'PENDING'}</strong><br>Passport Ref: <strong>\${u.passportNumber || 'N/A'}</strong></small>
                        </td>
                        <td>
                            <select id="s-\${u._id}" \${!u.uciNumber ? 'disabled' : ''}>
                                <option value="Under Active Officer Review" \${u.status.includes('Review')?'selected':''}>Under Active Officer Review</option>
                                <option value="Biometrics Verification Stage" \${u.status.includes('Biometrics')?'selected':''}>Biometrics Verification Stage</option>
                                <option value="Background Eligibility Check" \${u.status.includes('Background')?'selected':''}>Background Eligibility Check</option>
                                <option value="Registry Profile Approved" \${u.status.includes('Approved')?'selected':''}>Registry Profile Approved</option>
                            </select>
                        </td>
                        <td><textarea id="n-\${u._id}" rows="3">\${u.adminNotes || ''}</textarea></td>
                        <td>
                            \${uciActionColumnHtml}
                            <button class="save-btn" onclick="save('\${u._id}')">Commit</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }

            async function generateUCI(id) {
                const res = await fetch('/api/admin/generate-uci', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id })
                });
                if(res.ok) { alert('UCI Assigned and client log printed.'); loadGrid(); }
                else { alert('UCI Generation Fault.'); }
            }

            async function save(id) {
                const status = document.getElementById('s-'+id).value;
                const adminNotes = document.getElementById('n-'+id).value;
                const res = await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status, adminNotes })
                });
                if(res.ok) { alert('🎉 Adjudication metrics updated.'); loadGrid(); }
            }
            window.onload = loadGrid;
        </script>
    </body>
    </html>
    `);
});

// ==========================================
// 7. MAIN IMMIGRATION FRONTEND SUB-SYSTEM
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
            input[type="file"] { border: 1px solid #26374a; background: #fafafa; padding: 6px; height: auto; }
            .btn-primary { padding: 11px 24px; background-color: #2572b4; color: #ffffff; border: 1px solid #2369a5; font-size: 16px; font-weight: 700; cursor: pointer; border-radius: 4px; border-bottom: 3px solid #1b5180; }
            .status-display-card { display: none; margin-top: 30px; padding: 25px; border-left: 6px solid #bc1c1c; background-color: #fcf8f8; border: 1px solid #e3cbcb; border-left: 6px solid #bc1c1c;}
            .doc-section { background: #f8fafc; padding: 15px; border: 1px solid #e2e8f0; border-radius: 6px; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="top-utility"><a href="#">Français</a></div>
        <div class="gov-brand-bar"><div class="signature-logo">Government of Canada</div></div>
        <div class="red-accent-strip"></div>
        
        <div class="main-content">
            <h1>Immigration and Travel Eligibility Entry Portal</h1>
            
            <div class="wet-tabs">
                <button type="button" id="btn-login" class="active" onclick="setView('loginPanel', 'btn-login')">Access Existing Account</button>
                <button type="button" id="btn-register" onclick="setView('registerPanel', 'btn-register')">Submit Comprehensive Travel Document Stack</button>
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
                <h2>Secure Travel Registry Enrollment System</h2>
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
                            <label>Create Account Password <span class="required-mark">*</span></label>
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

                    <div class="doc-section">
                        <h3 style="margin-top:0; color:#26374a;">Required Travel Identification Packages</h3>
                        <p style="font-size:13px; color:#666; margin-top:-8px;">Upload clear digital copies of your complete international travel verification assets.</p>
                        
                        <div style="display:grid; grid-template-columns: repeat(2, 1fr); gap:15px;">
                            <div class="input-group">
                                <label>1. Passport Data Bio-Page <span class="required-mark">*</span></label>
                                <input type="file" id="filePassport" required>
                            </div>
                            <div class="input-group">
                                <label>2. Current Visa / Travel Authorization <span class="required-mark">*</span></label>
                                <input type="file" id="fileVisa" required>
                            </div>
                            <div class="input-group">
                                <label>3. Proof of Economic Settlement Funds <span class="required-mark">*</span></label>
                                <input type="file" id="fileFinancial" required>
                            </div>
                            <div class="input-group">
                                <label>4. Optional Supporting Travel Manifests</label>
                                <input type="file" id="fileSupporting">
                            </div>
                        </div>
                    </div>
                    
                    <br>
                    <button type="submit" class="btn-primary">Submit Profile & Documents Bundle</button>
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

            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const btn = e.target.querySelector('.btn-primary');
                btn.innerText = "Processing Multi-Document File Vector Blocks...";
                btn.disabled = true;

                const formData = new FormData();
                formData.append('name', document.getElementById('rName').value);
                formData.append('email', document.getElementById('rEmail').value);
                formData.append('password', document.getElementById('rPass').value);
                formData.append('dob', document.getElementById('rDob').value);
                formData.append('citizenship', document.getElementById('rCitizenship').value);
                formData.append('passportNumber', document.getElementById('rPassport').value);
                
                // Maps files safely to different field targets inside our server array parser
                const pFile = document.getElementById('filePassport').files[0];
                const vFile = document.getElementById('fileVisa').files[0];
                const fFile = document.getElementById('fileFinancial').files[0];
                const sFile = document.getElementById('fileSupporting').files[0];

                if(pFile) formData.append('passportFile', pFile);
                if(vFile) formData.append('visaFile', vFile);
                if(fFile) formData.append('financialFile', fFile);
                if(sFile) formData.append('supportingFile', sFile);

                try {
                    const res = await fetch('/api/auth/register', { method: 'POST', body: formData });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        alert('🎉 Profile and travel file collection package saved successfully with zero exceptions! Form reset.');
                        document.getElementById('rForm').reset();
                        setView('trackPanel', 'btn-track');
                    } else { alert('Intake Failure Exception: ' + data.error); }
                } catch(err) { alert('Network connection lost during high capacity bundle transfer.'); }
                finally { btn.innerText = "Submit Profile & Documents Bundle"; btn.disabled = false; }
            });

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
                    if(data.role === 'admin') { window.location.href = '/admin'; } 
                    else { alert('Sign-in verified. Package awaiting file review.'); }
                } else { alert('Auth Error: ' + data.error); }
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
                if(res.ok) {
                    out.style.display = 'block';
                    out.innerHTML = \`<h3>File Name: \${data.name}</h3><p><strong>Status:</strong> \${data.status}</p><p style="background:#fff; padding:10px; border:1px solid #ccc;"><strong>Notes:</strong> \${data.adminNotes}</p>\`;
                } else { alert('Query Handle Match Error.'); }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server execution smoothly online on port ${PORT}`));
