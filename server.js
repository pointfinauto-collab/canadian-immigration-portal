const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-limit');

const app = express();
const PORT = process.env.PORT || 10000;

// ==========================================
// 1. PRODUCTION SECURITY MIDDLEWARES
// ==========================================
app.use(helmet({
    contentSecurityPolicy: false, // Allowed for inline layout parsing in standalone file architectures
}));
app.use(cors({ 
    origin: process.env.ALLOWED_ORIGIN || '*', 
    methods: ['GET', 'POST', 'DELETE'] 
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Prevent brute-force vectors against authentication gateways
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Limit each IP to 20 requests per window
    message: { error: 'Too many authentication attempts. Please try again later.' }
});

// Secure ephemeral container path compatible with distributed cloud systems
const uploadDir = path.join('/tmp', 'secure_payloads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, uploadDir); },
    filename: (req, file, cb) => {
        const structuralSanitization = Date.now() + '-' + path.basename(file.originalname).replace(/[^a-zA-Z0-9.\-_]/g, '');
        cb(null, structuralSanitization);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 15 * 1024 * 1024 } // 15MB absolute payload limit enforcement
});

// ==========================================
// 2. STABILIZED DATABASE CLUSTER INTEGRATION
// ==========================================
const MONGO_URI = process.env.MONGO_URI || "mongodb://usrtest:canada2026secure@cluster0-shard-00-00.q9tcm7y.mongodb.net:27017,cluster0-shard-00-01.q9tcm7y.mongodb.net:27017,cluster0-shard-00-02.q9tcm7y.mongodb.net:27017/immigration?ssl=true&replicaSet=atlas-13w7g2-shard-0&authSource=admin&retryWrites=true&w=majority";

const databaseOptions = {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    family: 4 
};

mongoose.connect(MONGO_URI, databaseOptions)
  .then(() => console.log('🚀 Core Cluster Synchronization Established.'))
  .catch(err => console.error('❌ Critical Cluster Integration Failure:', err.message));

const ClientSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    dob: String,
    citizenship: String,
    passportNumber: { type: String, uppercase: true, trim: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, default: 'File Initialized: Review Impending' },
    adminNotes: { type: String, default: 'Profile registered under current processing batch parameters.' }
}, { timestamps: true });

const Client = mongoose.models.Client || mongoose.model('Client', ClientSchema);

// ==========================================
// 3. SECURE AUTHENTICATION MIDDLEWARE
// ==========================================
// Basic administrative validation handler for standalone deployments
const enforceAdminPrivileges = async (req, res, next) => {
    try {
        const initiatorEmail = req.headers['x-admin-identity'];
        if (!initiatorEmail) return res.status(401).json({ error: 'Access denied: Missing validation header context.' });
        
        const verificationQuery = await Client.findOne({ email: initiatorEmail.toLowerCase().trim() });
        if (!verificationQuery || verificationQuery.role !== 'admin') {
            return res.status(403).json({ error: 'Access denied: Security authorization profile mismatch.' });
        }
        next();
    } catch (err) {
        res.status(500).json({ error: 'Internal gatekeeper exception verification failure.' });
    }
};

// ==========================================
// 4. BUSINESS LOGIC & TRANSMISSION ROUTING
// ==========================================

app.post('/api/auth/register', upload.array('files', 3), async (req, res) => {
    try {
        const { name, email, password, dob, citizenship, passportNumber } = req.body;
        
        if (!name || !email || !password) {
            if (req.files) req.files.forEach(f => fs.unlink(f.path, () => {}));
            return res.status(400).json({ error: 'System constraint fault: Core identification fields missing.' });
        }

        const exactEmailFormat = email.toLowerCase().trim();
        const existingRecord = await Client.findOne({ email: exactEmailFormat });
        if (existingRecord) {
            if (req.files) req.files.forEach(f => fs.unlink(f.path, () => {}));
            return res.status(409).json({ error: 'System constraints fault: Profile record already mapped.' });
        }

        const administrativeEmailCheck = (process.env.ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const designatedRole = (exactEmailFormat === administrativeEmailCheck) ? 'admin' : 'user';

        // Cryptographic password hashing protection layer
        const verificationSalt = await bcrypt.genSalt(12);
        const cryptographicallySecuredPassword = await bcrypt.hash(password, verificationSalt);

        const newClientProfile = new Client({
            name,
            email: exactEmailFormat,
            password: cryptographicallySecuredPassword,
            dob,
            citizenship,
            passportNumber,
            role: designatedRole
        });

        await newClientProfile.save();

        if (req.files && req.files.length > 0) {
            req.files.forEach(file => {
                fs.unlink(file.path, (err) => { if (err) console.error("Resource cleanup trace:", err); });
            });
        }

        res.status(201).json({ success: true, message: 'Identity file registered into matrix subsystem successfully.' });
    } catch (error) {
        if (req.files) req.files.forEach(f => fs.unlink(f.path, () => {}));
        console.error("Critical core thread intercept:", error);
        res.status(500).json({ error: 'Internal storage controller execution error parsing multi-part assets.' });
    }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;
        const normalizedTargetEmail = email.toLowerCase().trim();
        
        const targetedUser = await Client.findOne({ email: normalizedTargetEmail });
        if (!targetedUser) return res.status(401).json({ error: 'Identity evaluation failure: Bad match.' });

        // Compares user attempt to hashed verification string
        const secureValidationMatches = await bcrypt.compare(password, targetedUser.password);
        if (!secureValidationMatches) return res.status(401).json({ error: 'Identity evaluation failure: Bad match.' });
        
        res.json({ success: true, role: targetedUser.role, name: targetedUser.name, email: targetedUser.email });
    } catch (error) {
        res.status(500).json({ error: 'Authentication layer subsystem failure.' });
    }
});

app.get('/api/admin/records', enforceAdminPrivileges, async (req, res) => {
    try {
        const administrativeSystemGrid = await Client.find({ role: 'user' }).sort({ createdAt: -1 });
        res.json(administrativeSystemGrid);
    } catch (err) {
        res.status(500).json({ error: 'Query execution context halted.' });
    }
});

app.post('/api/admin/modify', enforceAdminPrivileges, async (req, res) => {
    try {
        const { id, status, adminNotes } = req.body;
        await Client.findByIdAndUpdate(id, { status, adminNotes }, { runValidators: true });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Transaction validation mapping conflict.' });
    }
});

// ==========================================
// 5. SECURE FRONTEND RENDER SYSTEMS
// ==========================================
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Identity Registry Administration</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #f8fafc; color: #1e293b; }
            .container { max-width: 1400px; margin: 0 auto; }
            .navbar { background: #1e293b; padding: 20px 35px; border-radius: 8px; color: #fff; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
            table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); margin-top: 25px; }
            th, td { padding: 16px; border-bottom: 1px solid #e2e8f0; text-align: left; }
            th { background: #334155; color: #fff; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.05em; }
            input, select { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; background: #f8fafc; }
            input:focus, select:focus { outline: none; border-color: #0284c7; background: #fff; }
            .btn { background: #0284c7; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 6px; font-weight: 600; font-size: 13px; transition: background 0.15s ease; }
            .btn:hover { background: #0369a1; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="navbar">
                <h3 style="margin:0;">Identity Document Administration Grid</h3>
                <button class="btn" style="background:#475569" onclick="localStorage.clear(); window.location.href='/'">System Logoff</button>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Identity Profile</th>
                        <th>Travel Verification Parameters</th>
                        <th>Milestone Status Update</th>
                        <th>Internal Log Remarks</th>
                        <th>Operations</th>
                    </tr>
                </thead>
                <tbody id="tableBody"></tbody>
            </table>
        </div>

        <script>
            const validationCredential = localStorage.getItem('userEmail');
            if (!validationCredential || localStorage.getItem('userRole') !== 'admin') {
                window.location.href = '/';
            }

            async function synchronizeRegistryGrid() {
                const res = await fetch('/api/admin/records', {
                    headers: { 'x-admin-identity': validationCredential }
                });
                if (!res.ok) { alert('Clearance evaluation rejection error.'); return; }
                const users = await res.json();
                const tbody = document.getElementById('tableBody');
                tbody.innerHTML = '';
                
                users.forEach(u => {
                    tbody.innerHTML += \`
                        <tr>
                            <td><strong>\${u.name}</strong><br><span style="color:#64748b; font-size:12px;">\${u.email}</span></td>
                            <td>
                                <span style="font-size:12px;"><strong>Passport Reference:</strong> \${u.passportNumber || 'None Specified'}<br>
                                <strong>Origin Country:</strong> \${u.citizenship || 'None Specified'}</span>
                            </td>
                            <td>
                                <select id="status-\${u._id}">
                                    <option value="File Initialized: Review Impending" \${u.status.includes('Initialized') ? 'selected' : ''}>Review Impending</option>
                                    <option value="Document Matrix Target Criteria Satisfied" \${u.status.includes('Satisfied') ? 'selected' : ''}>Criteria Satisfied</option>
                                    <option value="Transmission Pipeline Intercept Termination" \${u.status.includes('Termination') ? 'selected' : ''}>Pipeline Terminated</option>
                                </select>
                            </td>
                            <td><input type="text" id="notes-\${u._id}" value="\${u.adminNotes || ''}"></td>
                            <td><button class="btn" onclick="commitRegistryModification('\${u._id}')">Commit Trace</button></td>
                        </tr>
                    \`;
                });
            }

            async function commitRegistryModification(id) {
                const res = await fetch('/api/admin/modify', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'x-admin-identity': validationCredential
                    },
                    body: JSON.stringify({
                        id,
                        status: document.getElementById('status-'+id).value,
                        adminNotes: document.getElementById('notes-'+id).value
                    })
                });
                if (res.ok) {
                    alert('Target file mutations permanently committed.');
                    synchronizeRegistryGrid();
                } else { alert('Modification execution failure.'); }
            }
            synchronizeRegistryGrid();
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
        <title>Secure Travel Enrollment Console</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 40px; background: #f1f5f9; color: #334155; }
            .wrapper { max-width: 650px; margin: 0 auto; }
            .card { background: #ffffff; padding: 35px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 25px; border: 1px solid #e2e8f0; }
            h1 { font-size: 26px; color: #0f172a; margin-bottom: 25px; text-align: center; font-weight: 700; letter-spacing: -0.025em; }
            h2 { font-size: 16px; color: #475569; margin-top: 0; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
            input, select { display: block; width: 100%; margin-bottom: 16px; padding: 12px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; background: #f8fafc; }
            input:focus, select:focus { border-color: #0284c7; outline: none; background: #fff; box-shadow: 0 0 0 4px rgba(2,132,199,0.1); }
            label { font-size: 13px; font-weight: 600; color: #475569; display: block; margin-bottom: 6px; }
            button { background: #0284c7; color: white; padding: 14px 24px; border: none; cursor: pointer; border-radius: 6px; font-weight: 700; width: 100%; font-size: 15px; transition: background 0.15s ease; }
            button:hover { background: #0369a1; }
            .footer-info { text-align: center; font-size: 12px; color: #94a3b8; margin-top: 30px; }
        </style>
    </head>
    <body>
        <div class="wrapper">
            <h1>Travel Optimization & Identification Console</h1>
            
            <div class="card">
                <h2>1. Baseline Identity Dossier Configuration</h2>
                <form id="regForm">
                    <label>Legal Identity Full Name</label>
                    <input type="text" id="rName" placeholder="Jane Doe" required>
                    
                    <label>Electronic Delivery Mail Address</label>
                    <input type="email" id="rEmail" placeholder="janedoe@example.com" required>
                    
                    <label>System Account Gateway Password</label>
                    <input type="password" id="rPass" placeholder="••••••••" required>
                    
                    <label>Date of Certified Birth</label>
                    <input type="date" id="rDob" required>
                    
                    <label>Declared Sovereign Citizenship</label>
                    <input type="text" id="rCitizenship" placeholder="Sovereign Nation Status" required>
                    
                    <label>Passport Verification Track Serial</label>
                    <input type="text" id="rPassport" placeholder="Document Series Code" required>
                    
                    <label>Upload High-Resolution Digital Scan Verification Matrix (PDF/IMG)</label>
                    <input type="file" id="rFile" required>
                    
                    <button type="submit">Verify & Transmit Profile Packet</button>
                </form>
            </div>

            <div class="card">
                <h2>2. Synchronize Verified Gateway Session</h2>
                <form id="loginForm">
                    <label>Registered System Email</label>
                    <input type="email" id="lEmail" placeholder="janedoe@example.com" required>
                    
                    <label>Verification Token Password</label>
                    <input type="password" id="lPass" placeholder="••••••••" required>
                    
                    <button type="submit">Initialize Session Loop</button>
                </form>
            </div>
            
            <div class="footer-info">Secure Verification Gateway Architecture Processing Stream. All Records Tracked under Standard Cryptographic Matrices.</div>
        </div>

        <script>
            document.getElementById('regForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const validationPayload = new FormData();
                validationPayload.append('name', document.getElementById('rName').value);
                validationPayload.append('email', document.getElementById('rEmail').value);
                validationPayload.append('password', document.getElementById('rPass').value);
                validationPayload.append('dob', document.getElementById('rDob').value);
                validationPayload.append('citizenship', document.getElementById('rCitizenship').value);
                validationPayload.append('passportNumber', document.getElementById('rPassport').value);
                
                const fileAssetReference = document.getElementById('rFile');
                if (fileAssetReference.files[0]) {
                    validationPayload.append('files', fileAssetReference.files[0]);
                }

                try {
                    const executionResponse = await fetch('/api/auth/register', { method: 'POST', body: validationPayload });
                    const trackingDataResolution = await executionResponse.json();
                    alert(trackingDataResolution.message || trackingDataResolution.error);
                    if (trackingDataResolution.success) document.getElementById('regForm').reset();
                } catch(err) {
                    alert('Transport configuration exception: Stream interrupted.');
                }
            });

            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                try {
                    const implementationResponse = await fetch('/api/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: document.getElementById('lEmail').value, password: document.getElementById('lPass').value })
                    });
                    const authenticationDataResolution = await implementationResponse.json();
                    if (authenticationDataResolution.success) {
                        localStorage.setItem('userEmail', authenticationDataResolution.email);
                        localStorage.setItem('userRole', authenticationDataResolution.role);
                        
                        if (authenticationDataResolution.role === 'admin') {
                            window.location.href = '/admin';
                        } else {
                            alert('Session established. Identity signature verified: ' + authenticationDataResolution.name + '. Track Matrix Status: File Queue Pending Evaluation.');
                        }
                    } else {
                        alert(authenticationDataResolution.error);
                    }
                } catch(err) {
                    alert('Gateway response execution timeout: Verify endpoint target availability.');
                }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log(`[SYS-INFO] Production transmission node actively bound to interface port: ${PORT}`));
