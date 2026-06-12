const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 10000;

// 1. Middlewares
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 2. Ensure temporary upload folder exists safely on Render
const uploadDir = path.join('/tmp', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// 3. Simple File Upload Config
const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, uploadDir); },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// 4. Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI || "mongodb://usrtest:canada2026secure@cluster0-shard-00-00.q9tcm7y.mongodb.net:27017,cluster0-shard-00-01.q9tcm7y.mongodb.net:27017,cluster0-shard-00-02.q9tcm7y.mongodb.net:27017/immigration?ssl=true&replicaSet=atlas-13w7g2-shard-0&authSource=admin&retryWrites=true&w=majority";

mongoose.connect(MONGO_URI)
  .then(() => console.log('🚀 MongoDB Connected Successfully'))
  .catch(err => console.log('❌ Database Connection Error:', err.message));

// 5. Database Schema
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    dob: String,
    citizenship: String,
    passportNumber: String,
    role: { type: String, default: 'user' },
    uciNumber: { type: String, default: '' },
    trackingRef: { type: String, default: '' },
    status: { type: String, default: 'Document Verification Stage' },
    adminNotes: { type: String, default: 'Application received.' }
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// 6. Submit File & Register Route
app.post('/api/auth/register', upload.any(), async (req, res) => {
    try {
        const { name, email, password, dob, citizenship, passportNumber } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Missing required fields.' });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) {
            return res.status(409).json({ error: 'This email is already registered.' });
        }

        // Set role to admin if it matches our designated admin email
        const adminEmail = (process.env.ADMIN_EMAIL || 'admin@portal.com').toLowerCase().trim();
        const role = (email.toLowerCase().trim() === adminEmail) ? 'admin' : 'user';

        const newUser = new User({
            name,
            email: email.toLowerCase().trim(),
            password, // Stored as plain text for simplicity per your setup
            dob,
            citizenship,
            passportNumber,
            role
        });

        await newUser.save();

        // Safe background cleanup of uploaded files so Render disk doesn't fill up
        if (req.files) {
            req.files.forEach(file => {
                fs.unlink(file.path, (err) => { if (err) console.error(err); });
            });
        }

        res.status(201).json({ success: true, message: 'Submission successful!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error processing your files.' });
    }
});

// 7. Login Route
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email.toLowerCase().trim(), password });
        
        if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
        
        res.json({ success: true, role: user.role, name: user.name, email: user.email });
    } catch (error) {
        res.status(500).json({ error: 'Login error.' });
    }
});

// 8. Admin Dashboard Data Route
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find({ role: 'user' });
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch data.' });
    }
});

// 9. Admin Update Route
app.post('/api/admin/update', async (req, res) => {
    try {
        const { id, status, adminNotes, uciNumber, trackingRef } = req.body;
        await User.findByIdAndUpdate(id, { status, adminNotes, uciNumber, trackingRef });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to update record.' });
    }
});

// 10. Serve the Admin View
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f4f6f8; }
            table { width: 100%; border-collapse: collapse; background: white; margin-top: 20px; }
            th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
            th { background: #26374a; color: white; }
            input, select { width: 100%; padding: 6px; box-sizing: border-box; }
            .btn { background: #2572b4; color: white; border: none; padding: 8px 12px; cursor: pointer; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h2>System Administration Dashboard</h2>
        <table>
            <thead>
                <tr>
                    <th>Applicant</th>
                    <th>Tracking Numbers</th>
                    <th>Status</th>
                    <th>Notes</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody id="tableBody"></tbody>
        </table>

        <script>
            async function loadUsers() {
                const res = await fetch('/api/admin/users');
                const users = await res.json();
                const tbody = document.getElementById('tableBody');
                tbody.innerHTML = '';
                
                users.forEach(u => {
                    tbody.innerHTML += \`
                        <tr>
                            <td><strong>\${u.name}</strong><br>\s\${u.email}</td>
                            <td>
                                UCI: <input type="text" id="uci-\${u._id}" value="\${u.uciNumber || ''}"><br>
                                Ref: <input type="text" id="ref-\${u._id}" value="\${u.trackingRef || ''}">
                            </td>
                            <td>
                                <select id="status-\${u._id}">
                                    <option value="Document Verification Stage" \${u.status == 'Document Verification Stage' ? 'selected' : ''}>Document Verification Stage</option>
                                    <option value="Approved" \${u.status == 'Approved' ? 'selected' : ''}>Approved</option>
                                </select>
                            </td>
                            <td><input type="text" id="notes-\${u._id}" value="\${u.adminNotes || ''}"></td>
                            <td><button class="btn" onclick="updateUser('\${u._id}')">Save</button></td>
                        </tr>
                    \`;
                });
            }

            async function updateUser(id) {
                await fetch('/api/admin/update', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id,
                        uciNumber: document.getElementById('uci-'+id).value,
                        trackingRef: document.getElementById('ref-'+id).value,
                        status: document.getElementById('status-'+id).value,
                        adminNotes: document.getElementById('notes-'+id).value
                    })
                });
                alert('Record updated!');
                loadUsers();
            }
            loadUsers();
        </script>
    </body>
    </html>
    `);
});

// 11. Main Frontend Portal
app.get('*', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Portal Gateway</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 40px; }
            .form-section { border: 1px solid #ccc; padding: 20px; border-radius: 4px; max-width: 500px; margin-bottom: 20px; }
            input, select { display: block; width: 100%; margin-bottom: 10px; padding: 8px; box-sizing: border-box; }
            button { background: #2572b4; color: white; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Immigration and Travel Eligibility Portal</h1>
        
        <div class="form-section">
            <h2>Step 1: Document Submission & Enrollment</h2>
            <form id="regForm">
                <input type="text" id="rName" placeholder="Full Name" required>
                <input type="email" id="rEmail" placeholder="Email" required>
                <input type="password" id="rPass" placeholder="Create Password" required>
                <input type="text" id="rCitizenship" placeholder="Citizenship">
                <input type="text" id="rPassport" placeholder="Passport Number">
                <label>Upload Document:</label>
                <input type="file" id="rFile">
                <button type="submit">Submit Application</button>
            </form>
        </div>

        <div class="form-section">
            <h2>Step 2: Sign-In to Access Dashboard</h2>
            <form id="loginForm">
                <input type="email" id="lEmail" placeholder="Email" required>
                <input type="password" id="lPass" placeholder="Password" required>
                <button type="submit">Sign In</button>
            </form>
        </div>

        <script>
            document.getElementById('regForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const fd = new FormData();
                fd.append('name', document.getElementById('rName').value);
                fd.append('email', document.getElementById('rEmail').value);
                fd.append('password', document.getElementById('rPass').value);
                fd.append('citizenship', document.getElementById('rCitizenship').value);
                fd.append('passportNumber', document.getElementById('rPassport').value);
                
                const fileInput = document.getElementById('rFile');
                if(fileInput.files[0]) {
                    fd.append('files', fileInput.files[0]);
                }

                const res = await fetch('/api/auth/register', { method: 'POST', body: fd });
                const data = await res.json();
                alert(data.message || data.error);
                if(data.success) document.getElementById('regForm').reset();
            });

            document.getElementById('loginForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: document.getElementById('lEmail').value, password: document.getElementById('lPass').value })
                });
                const data = await res.json();
                if(data.success) {
                    if(data.role === 'admin') {
                        window.location.href = '/admin';
                    } else {
                        alert('Welcome back, ' + data.name + '! Your files are under review.');
                    }
                } else {
                    alert(data.error);
                }
            });
        </script>
    </body>
    </html>
    `);
});

app.listen(PORT, () => console.log('Server running...'));
