const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/ircc_portal');
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Database Connection Error: ${error.message}`);
        process.exit(1);
    }
};

const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    dob: { type: Date, required: true },
    gender: { type: String, required: true },
    nationality: { type: String, required: true },
    passportNumber: { type: String, required: true, unique: true },
    countryOfResidence: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['client', 'admin'], default: 'client' },
    uci: { type: String, unique: true },
    gcRef: { type: String, unique: true },
    applicationStatus: { 
        type: String, 
        enum: ['Draft', 'Submitted', 'Under Review', 'Additional Documents Required', 'Approved', 'Refused', 'Completed'], 
        default: 'Submitted' 
    },
    assignedOfficer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    createdAt: { type: Date, default: Date.now }
});

const DocumentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    documentType: { type: String, required: true },
    fileName: { type: String, required: true },
    filePath: { type: String, required: true },
    status: { type: String, enum: ['Pending', 'Approved', 'Rejected'], default: 'Pending' },
    comments: { type: String, default: '' },
    uploadedAt: { type: Date, default: Date.now }
});

const PaymentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    transactionId: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    paymentMethod: { type: String, enum: ['Visa', 'Mastercard', 'Amex', 'Bank Transfer', 'Representative Payment'], required: true },
    status: { type: String, enum: ['Pending', 'Completed', 'Failed'], default: 'Pending' },
    receiptNumber: { type: String, unique: true },
    representativeInfo: {
        name: String,
        membershipId: String
    },
    paidAt: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    message: { type: String, required: true },
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const AuditLogSchema = new mongoose.Schema({
    action: { type: String, required: true },
    performedBy: { type: String, required: true },
    details: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});

module.exports = {
    connectDB,
    User: mongoose.model('User', UserSchema),
    Document: mongoose.model('Document', DocumentSchema),
    Payment: mongoose.model('Payment', PaymentSchema),
    Notification: mongoose.model('Notification', NotificationSchema),
    AuditLog: mongoose.model('AuditLog', AuditLogSchema)
};