const User = require('../models/User');
const Application = require('../models/Application');
const DocumentRecord = require('../models/Document');
const Payment = require('../models/Payment');
const AdminUser = require('../models/AdminUser');
const AuditLog = require('../models/AuditLog');
const Notification = require('../models/Notification');
const {
  generateReceiptNumber
} = require('../utils/generateIds');
const { createNotification } = require('../utils/notifications');
const { recordAuditLog } = require('../utils/auditLogger');

/**
 * @route GET /api/admin/applicants
 * @desc  View all applicants with search/filter/pagination
 */
const getApplicants = async (req, res, next) => {
  try {
    const { search, status, page = 1, limit = 20 } = req.query;

    const query = {};
    if (status) {
      query.applicationStatus = status;
    }
    if (search) {
      const regex = new RegExp(search, 'i');
      query.$or = [
        { fullName: regex },
        { email: regex },
        { ucinNumber: regex },
        { gcReferenceNumber: regex },
        { passportNumber: regex }
      ];
    }

    const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    const [applicants, total] = await Promise.all([
      User.find(query)
        .select('-documents')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit, 10)),
      User.countDocuments(query)
    ]);

    res.json({
      success: true,
      data: {
        applicants,
        pagination: {
          total,
          page: parseInt(page, 10),
          limit: parseInt(limit, 10),
          pages: Math.ceil(total / parseInt(limit, 10))
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route GET /api/admin/applicants/:id
 * @desc  View a single applicant's full profile, application, documents, payments
 */
const getApplicantDetail = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'Applicant not found.' });
    }

    const application = await Application.findOne({ user: user._id }).populate('assignedOfficer', 'fullName email role');
    const documents = await DocumentRecord.find({ user: user._id }).sort({ createdAt: -1 });
    const payments = await Payment.find({ user: user._id }).sort({ createdAt: -1 });

    res.json({
      success: true,
      data: {
        user: user.toSafeObject(),
        application,
        documents,
        payments
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route PUT /api/admin/applicants/:id/assign-officer
 */
const assignOfficer = async (req, res, next) => {
  try {
    const { officerId } = req.body;

    const officer = await AdminUser.findById(officerId);
    if (!officer) {
      return res.status(404).json({ success: false, message: 'Officer not found.' });
    }

    const application = await Application.findOneAndUpdate(
      { user: req.params.id },
      { assignedOfficer: officerId },
      { new: true }
    );

    if (!application) {
      return res.status(404).json({ success: false, message: 'Application not found.' });
    }

    await User.findByIdAndUpdate(req.params.id, { assignedOfficer: officerId });

    await recordAuditLog({
      actorType: 'AdminUser',
      actorId: req.admin._id,
      actorEmail: req.admin.email,
      action: 'OFFICER_ASSIGNED',
      targetType: 'Application',
      targetId: application._id,
      details: { officerId },
      req
    });

    res.json({ success: true, message: 'Officer assigned successfully.', data: { application } });
  } catch (error) {
    next(error);
  }
};

/**
 * @route PUT /api/admin/applicants/:id/status
 * @desc  Update application status (Submitted -> Under Review -> Approved/Refused/Completed etc.)
 */
const updateApplicationStatus = async (req, res, next) => {
  try {
    const { status, note } = req.body;

    const validStatuses = [
      'Draft',
      'Submitted',
      'Under Review',
      'Additional Documents Required',
      'Approved',
      'Refused',
      'Completed'
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status value.' });
    }

    const application = await Application.findOne({ user: req.params.id });
    if (!application) {
      return res.status(404).json({ success: false, message: 'Application not found.' });
    }

    application.status = status;
    application.statusHistory.push({ status, changedBy: req.admin._id, note: note || '' });

    if (status === 'Approved' || status === 'Refused') {
      application.decisionAt = new Date();
      application.decisionNote = note || '';
    }

    await application.save();

    await User.findByIdAndUpdate(req.params.id, { applicationStatus: status });

    // Notifications based on status
    if (status === 'Additional Documents Required') {
      await createNotification(req.params.id, 'additional_documents_requested', {
        message: note
          ? `Additional documents requested: ${note}`
          : 'Additional documents are required for your application. Please check the document section.'
      });
    } else if (status === 'Approved' || status === 'Refused') {
      await createNotification(req.params.id, 'application_decision', {
        message: `Your application has been ${status.toLowerCase()}.${note ? ` Note: ${note}` : ''}`
      });
    } else {
      await createNotification(req.params.id, 'status_update', {
        message: `Your application status has been updated to: ${status}.`
      });
    }

    await recordAuditLog({
      actorType: 'AdminUser',
      actorId: req.admin._id,
      actorEmail: req.admin.email,
      action: 'STATUS_UPDATED',
      targetType: 'Application',
      targetId: application._id,
      details: { status, note },
      req
    });

    res.json({ success: true, message: 'Application status updated.', data: { application } });
  } catch (error) {
    next(error);
  }
};

/**
 * @route GET /api/admin/documents
 * @desc  View documents, optionally filtered by status or user
 */
const getDocuments = async (req, res, next) => {
  try {
    const { status, userId, page = 1, limit = 50 } = req.query;
    const query = {};
    if (status) query.status = status;
    if (userId) query.user = userId;

    const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    const [documents, total] = await Promise.all([
      DocumentRecord.find(query)
        .populate('user', 'fullName email ucinNumber gcReferenceNumber')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit, 10)),
      DocumentRecord.countDocuments(query)
    ]);

    res.json({
      success: true,
      data: {
        documents,
        pagination: { total, page: parseInt(page, 10), limit: parseInt(limit, 10), pages: Math.ceil(total / parseInt(limit, 10)) }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route PUT /api/admin/documents/:id/review
 * @desc  Approve, reject, or comment on a document
 */
const reviewDocument = async (req, res, next) => {
  try {
    const { decision, comment } = req.body; // decision: 'Approved' | 'Rejected'

    if (!['Approved', 'Rejected'].includes(decision)) {
      return res.status(400).json({ success: false, message: 'Decision must be Approved or Rejected.' });
    }

    const document = await DocumentRecord.findById(req.params.id);
    if (!document) {
      return res.status(404).json({ success: false, message: 'Document not found.' });
    }

    document.status = decision;
    document.adminComment = comment || '';
    document.reviewedAt = new Date();
    document.reviewedBy = req.admin._id;
    await document.save();

    // Sync embedded copy on user record (best-effort match by storedFileName)
    await User.updateOne(
      { _id: document.user, 'documents.storedFileName': document.storedFileName },
      {
        $set: {
          'documents.$.status': decision,
          'documents.$.adminComment': comment || '',
          'documents.$.reviewedAt': new Date(),
          'documents.$.reviewedBy': req.admin._id
        }
      }
    );

    await createNotification(document.user, decision === 'Approved' ? 'document_approved' : 'document_rejected', {
      message: comment
        ? `Document "${document.originalName}" was ${decision.toLowerCase()}. Comment: ${comment}`
        : `Document "${document.originalName}" was ${decision.toLowerCase()}.`
    });

    await recordAuditLog({
      actorType: 'AdminUser',
      actorId: req.admin._id,
      actorEmail: req.admin.email,
      action: 'DOCUMENT_REVIEWED',
      targetType: 'DocumentRecord',
      targetId: document._id,
      details: { decision, comment },
      req
    });

    res.json({ success: true, message: `Document ${decision.toLowerCase()}.`, data: { document } });
  } catch (error) {
    next(error);
  }
};

/**
 * @route POST /api/admin/documents/:userId/request
 * @desc  Request a new document type from a client
 */
const requestNewDocument = async (req, res, next) => {
  try {
    const { documentType, note } = req.body;

    await createNotification(req.params.userId, 'additional_documents_requested', {
      title: 'New Document Requested',
      message: `Please upload a new ${documentType || 'document'}.${note ? ` Note: ${note}` : ''}`
    });

    await recordAuditLog({
      actorType: 'AdminUser',
      actorId: req.admin._id,
      actorEmail: req.admin.email,
      action: 'DOCUMENT_REQUESTED',
      targetType: 'User',
      targetId: req.params.userId,
      details: { documentType, note },
      req
    });

    res.json({ success: true, message: 'Document request sent to applicant.' });
  } catch (error) {
    next(error);
  }
};

/**
 * @route GET /api/admin/payments
 * @desc  View/manage all payments
 */
const getPayments = async (req, res, next) => {
  try {
    const { status, paymentMethod, page = 1, limit = 50 } = req.query;
    const query = {};
    if (status) query.status = status;
    if (paymentMethod) query.paymentMethod = paymentMethod;

    const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    const [payments, total] = await Promise.all([
      Payment.find(query)
        .populate('user', 'fullName email ucinNumber gcReferenceNumber')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit, 10)),
      Payment.countDocuments(query)
    ]);

    res.json({
      success: true,
      data: {
        payments,
        pagination: { total, page: parseInt(page, 10), limit: parseInt(limit, 10), pages: Math.ceil(total / parseInt(limit, 10)) }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route PUT /api/admin/payments/:id/mark-received
 * @desc  Mark a Representative Payment or Bank Transfer as received
 */
const markPaymentReceived = async (req, res, next) => {
  try {
    const payment = await Payment.findById(req.params.id);
    if (!payment) {
      return res.status(404).json({ success: false, message: 'Payment not found.' });
    }

    if (payment.status === 'Completed') {
      return res.status(400).json({ success: false, message: 'Payment is already marked as completed.' });
    }

    payment.status = 'Completed';
    payment.receiptNumber = generateReceiptNumber();
    payment.markedReceivedBy = req.admin._id;
    payment.markedReceivedAt = new Date();
    await payment.save();

    await createNotification(payment.user, 'payment_received');

    await recordAuditLog({
      actorType: 'AdminUser',
      actorId: req.admin._id,
      actorEmail: req.admin.email,
      action: 'PAYMENT_MARKED_RECEIVED',
      targetType: 'Payment',
      targetId: payment._id,
      req
    });

    res.json({ success: true, message: 'Payment marked as received.', data: { payment } });
  } catch (error) {
    next(error);
  }
};

/**
 * @route POST /api/admin/notifications/:userId
 * @desc  Send a custom notification to a client
 */
const sendNotification = async (req, res, next) => {
  try {
    const { title, message } = req.body;
    if (!title || !message) {
      return res.status(400).json({ success: false, message: 'Title and message are required.' });
    }

    const notification = await Notification.create({
      user: req.params.userId,
      type: 'message',
      title,
      message
    });

    res.status(201).json({ success: true, message: 'Notification sent.', data: { notification } });
  } catch (error) {
    next(error);
  }
};

/**
 * @route GET /api/admin/reports/summary
 * @desc  Generate summary report statistics
 */
const getReportSummary = async (req, res, next) => {
  try {
    const totalApplicants = await User.countDocuments();

    const statusCounts = await Application.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    const paymentStats = await Payment.aggregate([
      { $match: { status: 'Completed' } },
      { $group: { _id: '$paymentMethod', total: { $sum: '$amount' }, count: { $sum: 1 } } }
    ]);

    const totalRevenue = await Payment.aggregate([
      { $match: { status: 'Completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);

    const documentStats = await DocumentRecord.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    const recentRegistrations = await User.find()
      .select('fullName email ucinNumber gcReferenceNumber applicationStatus createdAt')
      .sort({ createdAt: -1 })
      .limit(10);

    res.json({
      success: true,
      data: {
        totalApplicants,
        statusCounts,
        paymentStats,
        totalRevenue: totalRevenue[0]?.total || 0,
        documentStats,
        recentRegistrations,
        generatedAt: new Date()
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route GET /api/admin/audit-logs
 */
const getAuditLogs = async (req, res, next) => {
  try {
    const { page = 1, limit = 50, action } = req.query;
    const query = {};
    if (action) query.action = action;

    const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);

    const [logs, total] = await Promise.all([
      AuditLog.find(query).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)),
      AuditLog.countDocuments(query)
    ]);

    res.json({
      success: true,
      data: {
        logs,
        pagination: { total, page: parseInt(page, 10), limit: parseInt(limit, 10), pages: Math.ceil(total / parseInt(limit, 10)) }
      }
    });
  } catch (error) {
    next(error);
  }
};

/**
 * @route GET /api/admin/officers
 * @desc  List officers/admins for assignment dropdowns
 */
const getOfficers = async (req, res, next) => {
  try {
    const officers = await AdminUser.find({ isActive: true }).select('fullName email role');
    res.json({ success: true, data: { officers } });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getApplicants,
  getApplicantDetail,
  assignOfficer,
  updateApplicationStatus,
  getDocuments,
  reviewDocument,
  requestNewDocument,
  getPayments,
  markPaymentReceived,
  sendNotification,
  getReportSummary,
  getAuditLogs,
  getOfficers
};
