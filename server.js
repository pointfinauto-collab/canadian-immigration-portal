const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// 1. MIDDLEWARE PIPELINE
app.use(cors({ origin: '*' })); // Allows your frontend to connect seamlessly
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

// 2. MONGODB CLUSTER CONNECTION
const MONGO_URI = process.env.MONGO_URI || "your_mongodb_connection_string_here";
mongoose.connect(MONGO_URI)
  .then(() => console.log('🚀 Connected smoothly to MongoDB Cluster'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// 3. DATABASE SCHEMA & MODEL
const EnrollmentSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    uciNumber: { type: String, unique: true },
    trackingRef: { type: String, unique: true },
    status: { type: String, default: 'Submitted / Review Pending' },
    adminNotes: { type: String, default: 'Your application file is currently undergoing preliminary verification.' },
    createdAt: { type: Date, default: Date.now }
});

const Enrollment = mongoose.model('Enrollment', EnrollmentSchema);

// 4. MULTER FILE UPLOAD CONFIGURATION (Max 5MB per file)
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 } 
});

// 5. USER ROUTE: SUBMIT ENROLLMENT & GENERATE CODES
app.post('/api/auth/register', upload.any(), async (req, res) => {
    try {
        const { name, email } = req.body;
        if (!name || !email) {
            return res.status(400).json({ error: 'Name and Email fields are strictly required.' });
        }

        // Generate authentic-looking tracking parameters
        const uciNumber = "UCI-" + Math.floor(10000000 + Math.random() * 90000000);
        const trackingRef = "CAN-" + Math.floor(100000 + Math.random() * 900000) + "-REG";

        const newEnrollment = new Enrollment({
            name,
            email,
            uciNumber,
            trackingRef
        });

        await newEnrollment.save();
        res.status(201).json({ success: true, uciNumber, trackingRef });
    } catch (error) {
        console.error('Registration Error:', error);
        res.status(500).json({ error: 'Failed to process registry save entry.' });
    }
});

// 6. USER ROUTE: TRACK PROFILE STATUS VIA UCI
app.post('/api/auth/track', async (req, res) => {
    try {
        const { uciNumber } = req.body;
        const file = await Enrollment.findOne({ uciNumber: uciNumber.trim() });
        
        if (!file) {
            return res.status(404).json({ error: 'No application registry found matching this UCI File ID.' });
        }
        
        res.json({ status: file.status, adminNotes: file.adminNotes, name: file.name });
    } catch (error) {
        res.status(500).json({ error: 'System tracking node execution failure.' });
    }
});

// 7. ADMIN ROUTE: FETCH ALL SUBMISSIONS FOR PANEL VIEW
app.get('/api/admin/enrollments', async (req, res) => {
    try {
        const records = await Enrollment.find().sort({ createdAt: -1 });
        res.json(records);
    } catch (error) {
        res.status(500).json({ error: 'Administrative data fetch failure.' });
    }
});

// 8. ADMIN ROUTE: UPDATE DECISION STATUS & NOTES
app.post('/api/admin/decision', async (req, res) => {
    try {
        const { id, status, adminNotes } = req.body;
        const updatedFile = await Enrollment.findByIdAndUpdate(
            id, 
            { status, adminNotes }, 
            { new: true }
        );
        if (!updatedFile) return res.status(404).json({ error: 'File profile entry not found.' });
        res.json({ success: true, message: 'Registry status updated successfully!' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to write decision parameters.' });
    }
});

// Catch-all route to serve pages neatly
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, () => {
    console.log(`Server executing securely on port ${PORT}`);
});
