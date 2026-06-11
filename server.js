const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const { connectDB, User, Document, Payment, Notification, AuditLog } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'SUPER_SECRET_GOV_KEY_2026';

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', apiLimiter);

if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, './uploads/'); },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Only PDFs and Images (JPG, PNG) are allowed.'));
};

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: fileFilter
});

function generateUCI() {
    return `UCI-${Math.floor(1000 + Math.random() * 9000)}-${Math.floor(1000 + Math.random() * 9000)}`;
}
function generateGCRef() {
    return `GC-2026-${Math.floor(100000 + Math.random() * 900000)}`;
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access Denied: Token Missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden: Invalid Token' });
        req.user = user;
        next();
    });
};

const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access Denied: Admins Only' });
    next();
};

app.post('/api/auth/register', upload.fields([
    { name: 'passport', maxCount: 1 },
    { name: 'nationalId', maxCount: 1 },
    { name: 'passportPhoto', maxCount: 1 }
]), async (req, res) => {
    try {
        const { fullName, dob, gender, nationality, passportNumber, countryOfResidence, phoneNumber, email, password } = req.body;
        
        const userExists = await User.findOne({ email });
        if (userExists) return res.status(400).json({ message: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const uci = generateUCI();
        const gcRef = generateGCRef();

        const newUser = new User({
            fullName, dob, gender, nationality, passportNumber, countryOfResidence, phoneNumber, email,
            password: hashedPassword, uci, gcRef, role: 'client'
        });
        const savedUser = await newUser.save();

        const filesToSave = [];
        if (req.files['passport']) filesToSave.push({ userId: savedUser._id, documentType: 'Passport', fileName: req.files['passport'][0].originalname, filePath: req.files['passport'][0].path });
        if (req.files['nationalId']) filesToSave.push({ userId: savedUser._id, documentType: 'National ID', fileName: req.files['nationalId'][0].originalname, filePath: req.files['nationalId'][0].path });
        if (req.files['passportPhoto']) filesToSave.push({ userId: savedUser._id, documentType: 'Passport Photo', fileName: req.files['passportPhoto'][0].originalname, filePath: req.files['passportPhoto'][0].path });

        if (filesToSave.length > 0) {
            await Document.insertMany(filesToSave);
        }

        await new Notification({ userId: savedUser._id, message: `Welcome ${fullName}. Your account has been generated with UCI: ${uci}` }).save();
        await new AuditLog({ action: 'USER_REGISTER', performedBy: email, details: `Account created successfully with identifier ${uci}.` }).save();

        res.status(201).json({ message: 'Registration complete', uci, gcRef });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: 'User not found' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
        
        await new AuditLog({ action: 'USER_LOGIN', performedBy: user.email, details: 'Logged into portal access point' }).save();
        res.json({ token, role: user.role });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/client/profile', authenticateToken, async (req, res) => {
    try {
        const profile = await User.findById(req.user.id).select('-password');
        const documents = await Document.find({ userId: req.user.id });
        const payments = await Payment.find({ userId: req.user.id });
        const notifications = await Notification.find({ userId: req.user.id }).sort({ createdAt: -1 });
        res.json({ profile, documents, payments, notifications });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/client/upload', authenticateToken, upload.single('supplementary'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'No file explicitly attached' });
        
        const newDoc = new Document({
            userId: req.user.id,
            documentType: req.body.documentType || 'Supplemental File',
            fileName: req.file.originalname,
            filePath: req.file.path
        });
        await newDoc.save();
        await new Notification({ userId: req.user.id, message: `New structural document uploaded: ${req.file.originalname}` }).save();
        res.status(201).json({ message: 'Document added to client record file database layer successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/client/pay', authenticateToken, async (req, res) => {
    try {
        const { amount, method, repName, repId } = req.body;
        const txId = 'TXN-' + Math.floor(10000000 + Math.random() * 90000000);
        const receiptNo = 'REC-' + Math.floor(100000 + Math.random() * 900000);

        const newPayment = new Payment({
            userId: req.user.id,
            transactionId: txId,
            amount,
            paymentMethod: method,
            status: method === 'Representative Payment' ? 'Pending' : 'Completed',
            receiptNumber: receiptNo,
            representativeInfo: method === 'Representative Payment' ? { name: repName, membershipId: repId } : undefined
        });

        await newPayment.save();
        
        if(newPayment.status === 'Completed') {
            await new Notification({ userId: req.user.id, message: `Payment of $${amount} verified successfully. Receipt: ${receiptNo}` }).save();
        }
        res.status(201).json({ message: 'Payment structure registered successfully', transactionId: txId, receiptNumber: receiptNo });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/admin/applicants', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await User.find({ role: 'client' }).select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/applicant/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { applicationStatus } = req.body;
        const updatedUser = await User.findByIdAndUpdate(req.params.id, { applicationStatus }, { new: true });
        
        await new Notification({
            userId: updatedUser._id,
            message: `Your Global Application file processing updates status has changed to: ${applicationStatus}`
        }).save();

        res.json({ message: 'Status processing parameter written successfully to schema layout layer' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

connectDB().then(() => {
    app.listen(PORT, () => console.log(`Immigration Cloud Services running securely on system port ${PORT}`));
});