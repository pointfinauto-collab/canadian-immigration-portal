const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000; // Matches your cloud hosting deployment port
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// ==========================================
// 1. GLOBAL SYSTEM ROUTING & MEMORY CONTROLS
// ==========================================
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '20mb' })); 
app.use(express.urlencoded({ limit: '20mb', extended: true }));

// Establish a permanent safe folder on disk to spool binary parts
const uploadDir = path.join(__dirname, 'tmp_payloads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// ==========================================
// 2. MULTIPART PACKET SPOOL ENGINE
// ==========================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 } // Strict 50MB protection ceiling
});

// ==========================================
// 3. BULLETPROOF DATABASE CONNECTION ENGINE
// ==========================================
// TO FIX ENOTFOUND: If your srv string fails, replace this fallback with the 
// Standard Connection String from Atlas (looks like: mongodb://username:password@ac-xxxx-shard-00-00.xxxx.mongodb.net:27017/...)
const FALLBACK_CONNECTION_STRING = "mongodb+srv://testuser:testpass@cluster0.xxxx.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = (process.env.MONGO_URI || FALLBACK_CONNECTION_STRING).trim();

let bucket;

console.log('⏳ Initializing connection to database cluster routing layer...');

mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: 8000, // Break the connection hang after 8 seconds
    connectTimeoutMS: 10000
})
  .then(() => {
      console.log('🚀 ==========================================');
      console.log('🚀 DATABASE SUBSYSTEM ONLINE: Pipeline Connected cleanly.');
      console.log('🚀 ==========================================');
      
      bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
          bucketName: 'visa_payload_chunks'
      });
  })
  .catch(err => {
      console.log('❌ ==========================================');
      console.log('❌ CRITICAL DATABASE CONNECTION FAULT!');
      console.log('❌ ERROR TYPE:', err.code || 'UNKNOWN_CODE');
      console.log('❌ REASON:', err.message);
      console.log('❌ HELP: If error is ENOTFOUND, go to Atlas -> Connect -> Drivers.');
      console.log('❌ Toggle "Select your driver version" to Node.js ver 2.2.12 or older.');
      console.log('❌ Copy the standard connection string format starting with "mongodb://" instead.');
      console.log('❌ ==========================================');
  });

// ==========================================
// 4. ARCHITECTURE BLUEPRINTS
// ==========================================
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
    adminNotes: { type: String, default: 'Your application package is logged. A case officer is validating your documentation stack.' },
    createdAt: { type: Date, default: Date.now }
});

const DocumentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    gridFileId: { type: mongoose.Schema.Types.ObjectId, required: true }, 
    docType: { type: String, required: true },
    docLabel: { type: String, required: true },
    fileName: { type: String, required: true },
    mimeType: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Document = mongoose.models.Document || mongoose.model('Document', DocumentSchema);

// ==========================================
// 5. TRANSACTION ROUTE MANAGEMENT
// ==========================================
app.post('/api/auth/register', upload.any(), async (req, res) => {
    // Pipeline Fail-Safe System Check
    if (!bucket) {
        if (req.files) req.files.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
        return res.status(503).json({ error: 'Database subsystem is initializing or down. Please resubmit in a few seconds.' });
    }

    try {
        const { name, email, password, dob, citizenship, passportNumber, docTypes } = req.body;
        
        if (!name || !email || !password) {
            if (req.files) req.files.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
            return res.status(400).json({ error: 'Primary registration attributes missing.' });
        }

        const cleanEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: cleanEmail });
        if (existingUser) {
            if (req.files) req.files.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
            return res.status(409).json({ error: 'This email account is already registered.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const systemAdminEmail = (process.env.SYSTEM_ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (cleanEmail === systemAdminEmail) ? 'admin' : 'user';

        const newUser = new User({
            name, email: cleanEmail, password: hashedPassword,
            dob, citizenship, passportNumber, role
        });
        const savedUser = await newUser.save();

        if (req.files && req.files.length > 0) {
            const typesArray = Array.isArray(docTypes) ? docTypes : [docTypes];
            
            const labelMap = {
                'passport': 'Passport Bio-Page Scan',
                'photo': 'Official Passport Photograph',
                'payment': 'Application Payment Slip',
                'education': 'Educational Degrees / Certificates',
                'job_offer': 'Official Canadian Job Offer Letter',
                'experience': 'Employment Reference & Experience Letters'
            };

            for (let i = 0; i < req.files.length; i++) {
                const file = req.files[i];
                const specificType = typesArray[i] || 'supporting';

                await new Promise((resolve, reject) => {
                    const uploadStream = bucket.openUploadStream(file.originalname, {
                        contentType: file.mimetype
                    });

                    fs.createReadStream(file.path)
                        .pipe(uploadStream)
                        .on('error', (err) => reject(err))
                        .on('finish', async () => {
                            try {
                                const newDoc = new Document({
                                    userId: savedUser._id,
                                    gridFileId: uploadStream.id, 
                                    docType: specificType,
                                    docLabel: labelMap[specificType] || 'Supporting Documentation',
                                    fileName: file.originalname,
                                    mimeType: file.mimetype
                                });
                                await newDoc.save();
                                
                                if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
                                resolve();
                            } catch (e) {
                                reject(e);
                            }
                        });
                });
            }
        }

        res.status(201).json({ success: true, message: 'Application package processed cleanly.' });
    } catch (error) {
        console.error('CRITICAL TRANSACTION FAULT SYSTEM LOG:', error);
        if (req.files) req.files.forEach(f => { if (fs.existsSync(f.path)) fs.unlinkSync(f.path); });
        res.status(500).json({ error: 'Internal storage transaction fault. Data streaming pipeline rejected.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials.' });

        const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '4h' });
        res.json({ success: true, token, role: user.role, name: user.name });
    } catch (error) { res.status(500).json({ error: 'Login verification fault.' }); }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const record = await User.findOne({ uciNumber: req.body.uciNumber.trim() });
        if (!record) return res.status(404).json({ error: 'UCI search query matched zero records.' });
        res.json({ name: record.name, status: record.status, adminNotes: record.adminNotes });
    } catch (error) { res.status(500).json({ error: 'Tracking database lookup fault.' }); }
});

// ==========================================
// 6. ADMINISTRATION SECURE POLICIES
// ==========================================
const checkAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing security token.' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ error: 'Clearance refused.' });
        req.user = decoded;
        next();
    });
};

app.get('/api/admin/enrollments', checkAdmin, async (req, res) => {
    try {
        const users = await User.find().sort({ createdAt: -1 }).lean();
        const fullPackages = [];
        for(let user of users) {
            if(user.role === 'admin') continue;
            const docs = await Document.find({ userId: user._id }).lean(); 
            user.documents = docs;
            fullPackages.push(user);
        }
        res.json(fullPackages);
    } catch (err) { res.status(500).json({ error: "Failed to assemble dashboard matrix." }); }
});

app.get('/api/admin/document/:gridFileId', checkAdmin, async (req, res) => {
    try {
        if (!bucket) return res.status(503).send("Database streaming node detached.");
        const fileId = new mongoose.Types.ObjectId(req.params.gridFileId);
        res.setHeader('Content-Type', 'application/octet-stream');
        
        const downloadStream = bucket.openDownloadStream(fileId);
        downloadStream.on('error', () => res.status(444).send("Target stream asset lost."));
        downloadStream.pipe(res);
    } catch (err) {
        res.status(500).send("Stream mapping error.");
    }
});

app.post('/api/admin/generate-uci', checkAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.body.id);
        if(!user) return res.status(404).json({ error: 'User file missing.' });

        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        user.uciNumber = uciNumber;
        user.trackingRef = trackingRef;
        user.status = "Under Active Officer Review (UCI Dispatched)";
        user.adminNotes = `Profile assigned Unique Client ID (UCI): ${uciNumber}. Direct tracking updates are open.`;
        
        await user.save();
        res.json({ success: true, uciNumber, trackingRef });
    } catch (err) { res.status(500).json({ error: 'Failed to assign tracking codes.' }); }
});

app.post('/api/admin/decision', checkAdmin, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.body.id, { status: req.body.status, adminNotes: req.body.adminNotes });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Decision update crash.' }); }
});

app.delete('/api/admin/user/:id', checkAdmin, async (req, res) => {
    try {
        const docs = await Document.find({ userId: req.params.id });
        for(let doc of docs) {
            try {
                if (bucket) await bucket.delete(doc.gridFileId);
            } catch(e) {}
        }
        await Document.deleteMany({ userId: req.params.id });
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch(err) { res.status(500).json({ error: "Purge process failure." }); }
});

// ==========================================
// 7. USER AND ADMINISTRATIVE INTERFACES
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
            .badge { display: inline-block; padding: 4px 8px; font-weight: bold; font-size: 11px; border-radius: 3px; text-transform: uppercase; background: #777; color: white; margin-bottom: 5px; }
            .uci-btn { background: #d9534f; color: white; border: none; padding: 8px 12px; font-weight: bold; border-radius: 4px; cursor: pointer; width: 100%; text-transform: uppercase; font-size: 11px; margin-bottom:5px;}
            .save-btn { background: #264a28; color: white; border: none; padding: 8px 14px; cursor: pointer; font-weight: bold; width: 100%; margin-bottom: 6px; border-radius: 4px; }
            .file-btn { display: block; background: #2572b4; color: white; text-decoration: none; padding: 6px 8px; font-size: 11px; font-weight: bold; margin-top: 4px; border-radius: 3px; text-align: center; }
            select, textarea { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #767676; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="gov-header">
            <div class="brand-text">Government of Canada — Case Officer Adjudication Desktop</div>
            <button onclick="localStorage.clear(); window.location.href='/'" style="padding:8px 16px; background:#333; color:#fff; border:none; cursor:pointer; font-weight:bold; border-radius:4px;">Sign Out</button>
        </div>
        <div class="box">
            <h2>📋 Visa Documents Package Evaluation Matrix</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width:22%;">Applicant Legal Identity</th>
                        <th style="width:28%;">Submitted Travel Payload Package</th>
                        <th style="width:20%;">Allocated System Identifiers</th>
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
                    let filesHtml = '';
                    if(u.documents && u.documents.length > 0) {
                        u.documents.forEach(doc => {
                            filesHtml += \`
                                <div style="margin-bottom:6px; background:#f8fafc; padding:6px; border:1px solid #cbd5e1; border-left:3px solid #2572b4; border-radius:3px;">
                                    <strong style="font-size:12px; color:#1e293b;">\${doc.docLabel}</strong><br>
                                    <span style="font-size:11px; color:#64748b; word-break:break-all;">File: \${doc.fileName}</span>
                                    <button class="file-btn" style="width:100%; border:none; cursor:pointer;" onclick="downloadStreamFile('\strid', '\${doc.fileName}')">💾 Download File</button>
                                </div>
                            \`.replace('\\strid', doc.gridFileId);
                        });
                    } else { filesHtml = '<span style="color:#999; font-style:italic;">No files attached</span>'; }

                    let uciActionColumnHtml = !u.uciNumber 
                        ? \`<button class="uci-btn" onclick="generateUCI('\strid')">🎟️ Issue UCI ID</button>\`
                        : \`<span style="color:#264a28; font-weight:bold; font-size:11px; display:block; text-align:center; margin-bottom:5px;">✅ UCI Active</span>\`;

                    const tr = document.createElement('tr');
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
                        <td><textarea id="n-\${u._id}" rows="4">\${u.adminNotes || ''}</textarea></td>
                        <td>
                            \${uciActionColumnHtml.replace('\\strid', u._id)}
                            <button class="save-btn" onclick="save('\${u._id}')">Commit</button>
                        </td>
                    \`;
                    tbody.appendChild(tr);
                });
            }

            async function downloadStreamFile(gridId, name) {
                const response = await fetch('/api/admin/document/' + gridId, {
                    headers: { 'Authorization': 'Bearer ' + token }
                });
                if(response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = name;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                } else { alert("Could not fetch file stream blocks."); }
            }

            async function generateUCI(id) {
                await fetch('/api/admin/generate-uci', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id })
                });
                loadGrid();
            }

            async function save(id) {
                const status = document.getElementById('s-'+id).value;
                const adminNotes = document.getElementById('n-'+id).value;
                await fetch('/api/admin/decision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                    body: JSON.stringify({ id, status, adminNotes })
                });
                alert('🎉 Changes committed live.');
                loadGrid();
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
            .uploader-framework { background: #f8fafc; border: 2px dashed #94a3b8; padding: 25px; border-radius: 6px; margin-top: 20px; }
            .controls-row { display: flex; gap: 15px; align-items: flex-end; margin-bottom: 20px; background: #fff; padding: 15px; border: 1px solid #e2e8f0; border-radius: 4px; }
            .plus-btn { width: 40px; height: 40px; background: #2572b4; color: white; border: none; font-size: 24px; font-weight: bold; cursor: pointer; border-radius: 4px; display: flex; justify-content: center; align-items: center; border-bottom: 3px solid #1b5180; }
            .queue-list { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
            .queue-item { background: #fff; border: 1px solid #cbd5e1; padding: 12px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border-left: 4px solid #2572b4; }
            .remove-file-btn { background: #dc2626; color: white; border: none; padding: 4px 8px; cursor: pointer; font-size: 11px; font-weight: bold; border-radius: 3px; }
            .btn-primary { padding: 11px 24px; background-color: #2572b4; color: #ffffff; border: 1px solid #2369a5; font-size: 16px; font-weight: 700; cursor: pointer; border-radius: 4px; border-bottom: 3px solid #1b5180; }
            .status-display-card { display: none; margin-top: 30px; padding: 25px; border-left: 6px solid #bc1c1c; background-color: #fcf8f8; border: 1px solid #e3cbcb; }
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
                <button type="button" id="btn-register" onclick="setView('registerPanel', 'btn-register')">Submit Application Package</button>
                <button type="button" id="btn-track" onclick="setView('trackPanel', 'btn-track')">Track File Status Gateway</button>
            </div>

            <div id="loginPanel" class="portal-panel active">
                <h2>Account Secure Gateway Sign-In</h2>
                <form id="lForm">
                    <div style="max-width: 440px;">
                        <div class="input-group">
                            <label>Email Address <span class="required-mark">*</span></label>
                            <input type="email" id="lEmail" required>
                        </div>
                        <div class="input-group">
                            <label>Account Password <span class="required-mark">*</span></label>
                            <input type="password" id="lPass" required>
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
                        <h3>Required Travel Verification Assets Registry Stack</h3>
                        <div class="controls-row">
                            <div class="input-group" style="flex:1; margin-bottom:0;">
                                <label>1. Select Specific Document Type Category</label>
                                <select id="docTypeSelector">
                                    <option value="passport">🛂 Passport Bio-Page Scan</option>
                                    <option value="photo">📸 Official Passport Photograph</option>
                                    <option value="payment">💰 Application Payment Slip</option>
                                    <option value="education">🎓 Educational Degrees / Certificates</option>
                                    <option value="job_offer">📄 Official Canadian Job Offer Letter</option>
                                    <option value="experience">💼 Employment Reference & Experience Letters</option>
                                </select>
                            </div>
                            <div class="input-group" style="flex:1; margin-bottom:0;">
                                <label>2. Choose Digital Scan Asset File</label>
                                <input type="file" id="fileSelector">
                            </div>
                            <button type="button" class="plus-btn" onclick="addAssetToQueue()">+</button>
                        </div>
                        <div class="queue-list" id="visualQueue"></div>
                    </div>
                    <br>
                    <button type="submit" class="btn-primary">Submit Profile & All Stacked Documents</button>
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
            let uploadedAssetsQueue = [];

            function setView(panelId, btnId) {
                document.querySelectorAll('.portal-panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.wet-tabs button').forEach(b => b.classList.remove('active'));
                document.getElementById(panelId).classList.add('active');
                document.getElementById(btnId).classList.add('active');
            }

            function addAssetToQueue() {
                const selector = document.getElementById('docTypeSelector');
                const fileInput = document.getElementById('fileSelector');
                if(fileInput.files.length === 0) { alert('Please choose a file first.'); return; }
                
                const rawFile = fileInput.files[0];
                
                if (rawFile.type.startsWith('image/')) {
                    const reader = new FileReader();
                    reader.readAsDataURL(rawFile);
                    reader.onload = function (event) {
                        const img = new Image();
                        img.src = event.target.result;
                        img.onload = function () {
                            const canvas = document.createElement('canvas');
                            let width = img.width;
                            let height = img.height;
                            
                            if (width > 1200) { height *= 1200 / width; width = 1200; }
                            canvas.width = width;
                            canvas.height = height;
                            
                            const ctx = canvas.getContext('2d');
                            ctx.drawImage(img, 0, 0, width, height);
                            
                            canvas.toBlob(function (blob) {
                                const compressedFile = new File([blob], rawFile.name, { type: 'image/jpeg', lastModified: Date.now() });
                                pushToMasterQueue(selector.value, selector.options[selector.selectedIndex].text, compressedFile);
                            }, 'image/jpeg', 0.65); 
                        };
                    };
                } else {
                    pushToMasterQueue(selector.value, selector.options[selector.selectedIndex].text, rawFile);
                }
                fileInput.value = '';
            }

            function pushToMasterQueue(type, label, fileObj) {
                uploadedAssetsQueue.push({
                    id: Date.now() + Math.random().toString(36).substr(2, 5),
                    type: type,
                    label: label,
                    fileObject: fileObj
                });
                renderVisualQueue();
            }

            function removeAssetFromQueue(id) {
                uploadedAssetsQueue = uploadedAssetsQueue.filter(item => item.id !== id);
                renderVisualQueue();
            }

            function renderVisualQueue() {
                const container = document.getElementById('visualQueue');
                container.innerHTML = '';
                if(uploadedAssetsQueue.length === 0) {
                    container.innerHTML = '<div style="grid-column:1/-1; text-align:center; padding:15px; color:#64748b; font-style:italic;">No files stacked. Click (+) to add.</div>';
                    return;
                }
                uploadedAssetsQueue.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'queue-item';
                    div.innerHTML = \`<div><strong>\${item.label}</strong><br><small>\${item.fileObject.name} (\text_mb MB)</small></div>
                                      <button type="button" class="remove-file-btn" onclick="removeAssetFromQueue('\${item.id}')">Remove</button>\`
                                      .replace('\text_mb', (item.fileObject.size / 1024 / 1024).toFixed(2));
                    container.appendChild(div);
                });
            }

            document.getElementById('rForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                if(uploadedAssetsQueue.length === 0) { alert('Please stack at least one file using (+).'); return; }

                const btn = e.target.querySelector('.btn-primary');
                btn.innerText = "Streaming Packages into Vault Enclaves...";
                btn.disabled = true;

                const formData = new FormData();
                formData.append('name', document.getElementById('rName').value);
                formData.append('email', document.getElementById('rEmail').value);
                formData.append('password', document.getElementById('rPass').value);
                formData.append('dob', document.getElementById('rDob').value);
                formData.append('citizenship', document.getElementById('rCitizenship').value);
                formData.append('passportNumber', document.getElementById('rPassport').value);
                
                uploadedAssetsQueue.forEach(item => {
                    formData.append('files', item.fileObject);
                    formData.append('docTypes', item.type);
                });

                try {
                    const res = await fetch('/api/auth/register', { method: 'POST', body: formData });
                    const data = await res.json();
                    if(res.ok && data.success) {
                        alert('🎉 Stream Connection Complete: Profile and files compiled successfully.');
                        uploadedAssetsQueue = [];
                        document.getElementById('rForm').reset();
                        renderVisualQueue();
                        setView('trackPanel', 'btn-track');
                    } else { alert('Refusal Exception: ' + data.error); }
                } catch(err) { alert('Transfer pipeline interrupted.'); }
                finally { btn.innerText = "Submit Profile & All Stacked Documents"; btn.disabled = false; }
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
                    else { alert('Sign-in verified.'); }
                } else { alert('Error: ' + data.error); }
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
                    out.innerHTML = \`<h3>Applicant Holder: \${data.name}</h3><p><strong>Status:</strong> \${data.status}</p><p style="background:#fff; padding:12px; border:1px solid #ccc;"><strong>Notes:</strong> \${data.adminNotes}</p>\`;
                } else { alert('UCI Lookup Error.'); }
            });
            renderVisualQueue();
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`Server execution smoothly online on port ${PORT}`));
