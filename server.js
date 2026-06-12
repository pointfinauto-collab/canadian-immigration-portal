const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SYS_SECRET_CORE_NODE_FALLBACK';

// 1. GLOBAL PRODUCTION MIDDLEWARE
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.'))); // Set to root directory lookup

// 2. MONGODB ATLAS CLUSTER CONNECTION WITH CRASH PROTECTION
// If process.env.MONGO_URI is missing, it falls back to a temporary testing database string
const fallbackURI = "mongodb+srv://testuser:testpass@cluster0.mongodb.net/immigration?retryWrites=true&w=majority";
const MONGO_URI = process.env.MONGO_URI || fallbackURI;

mongoose.connect(MONGO_URI)
  .then(() => console.log('🚀 Database Node Connected Successfully'))
  .catch(err => {
      console.error('❌ Database Initialization Warning:', err.message);
      // Removed process.exit(1) so Render is forced to stay online no matter what!
  });

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

// Avoid compiling compilation errors if model already compiled
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// 4. MULTIPART FILE UPLOAD MIDDLEWARE
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }
});

// 5. SECURITY ROUTE PROTECTION MIDDLEWARE
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Access token signature missing.' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Token signature manipulation detected.' });
        req.user = decoded;
        next();
    });
};

const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: 'Privilege escalation block: Unauthorized role access.' });
        }
        next();
    };
};

// ==========================================
// 6. CLIENT & AUTHENTICATION ENDPOINTS
// ==========================================

app.post('/api/auth/register', upload.any(), async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All primary identity fields are required.' });
        }

        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        if (existingUser) {
            return res.status(409).json({ error: 'An account with this email is already registered.' });
        }

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
        console.error('System Register Error:', error);
        res.status(500).json({ error: 'Internal pipeline fault compiling registration record.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Missing account login fields.' });

        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) return res.status(401).json({ error: 'Authentication challenge failed: Mismatched credentials.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Authentication challenge failed: Mismatched credentials.' });

        const token = jwt.sign(
            { id: user._id, role: user.role, name: user.name },
            JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({
            success: true,
            token,
            role: user.role,
            name: user.name,
            uciNumber: user.uciNumber,
            trackingRef: user.trackingRef
        });
    } catch (error) {
        res.status(500).json({ error: 'Server authentication subsystem exception.' });
    }
});

app.post('/api/auth/track', async (req, res) => {
    try {
        const { uciNumber } = req.body;
        if (!uciNumber) return res.status(400).json({ error: 'UCI lookup handle missing.' });

        const record = await User.findOne({ uciNumber: uciNumber.trim() });
        if (!record) return res.status(404).json({ error: 'No matching records in active directory.' });

        res.json({
            name: record.name,
            status: record.status,
            adminNotes: record.adminNotes
        });
    } catch (error) {
        res.status(500).json({ error: 'Query loop terminal fault.' });
    }
});

// ==========================================
// 7. PROTECTED ADMINISTRATIVE CONTROLS
// ==========================================

app.get('/api/admin/enrollments', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const records = await User.find().sort({ createdAt: -1 });
        res.json(records);
    } catch (error) {
        res.status(500).json({ error: 'Failed to access database collections.' });
    }
});

app.post('/api/admin/decision', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        const { id, status, adminNotes } = req.body;
        const updatedFile = await User.findByIdAndUpdate(id, { status, adminNotes }, { new: true });
        if (!updatedFile) return res.status(404).json({ error: 'Target registry item missing.' });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Data write loop crash.' });
    }
});

app.delete('/api/admin/user/:id', authenticateToken, requireRole('admin'), async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Delete execution fault.' });
    }
});

// 8. INTERFACE PATH TRANSLATIONS
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server execution online on port ${PORT}`);
});
