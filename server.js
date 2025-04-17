// require('dotenv').config();

// const PORT = process.env.PORT || 3000;
// const mongoURI = process.env.MONGODB_URI;
// server.js - Main entry point for the Vigilant Citizen backend

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const dotenv = require('dotenv');
const helmet = require('helmet');
const morgan = require('morgan');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet()); // Security headers
app.use(morgan('dev')); // Logging
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON requests

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    // Accept images, videos, and audio files
    if (file.mimetype.startsWith('image/') ||
        file.mimetype.startsWith('video/') ||
        file.mimetype.startsWith('audio/')) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'), false);
    }
  }
});

// Make uploads folder static
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Define Mongoose models
// User model
const userSchema = new mongoose.Schema({
  aadhaarId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: false,
    trim: true
  },
  location: {
    type: {
      type: String,
      default: 'Point'
    },
    coordinates: {
      type: [Number],  // [longitude, latitude]
      required: true
    }
  },
  district: {
    type: String,
    required: true
  },
  state: {
    type: String,
    required: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.index({ location: '2dsphere' });
const User = mongoose.model('User', userSchema);

// Report model
const reportSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['DEFORESTATION', 'CORRUPTION', 'FAKE_FEES', 'POLLUTION', 'INFRASTRUCTURE', 'OTHER']
  },
  location: {
    type: {
      type: String,
      default: 'Point'
    },
    coordinates: {
      type: [Number],  // [longitude, latitude]
      required: true
    }
  },
  address: {
    type: String,
    required: true
  },
  district: {
    type: String,
    required: true
  },
  state: {
    type: String,
    required: true
  },
  media: [{
    type: String,  // URL to uploaded file
    required: false
  }],
  reporter: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['PENDING', 'VERIFIED', 'ESCALATED', 'RESOLVED', 'REJECTED'],
    default: 'PENDING'
  },
  voteCount: {
    type: Number,
    default: 0
  },
  escalatedToJudiciary: {
    type: Boolean,
    default: false
  },
  escalatedAt: {
    type: Date
  },
  resolvedAt: {
    type: Date
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

reportSchema.index({ location: '2dsphere' });
reportSchema.index({ voteCount: -1 });  // Index for sorting by votes
const Report = mongoose.model('Report', reportSchema);

// Vote model
const voteSchema = new mongoose.Schema({
  report: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Report',
    required: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Ensure one vote per user per report
voteSchema.index({ report: 1, user: 1 }, { unique: true });
const Vote = mongoose.model('Vote', voteSchema);

// Notification model
const notificationSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  message: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['NEW_REPORT', 'STATUS_UPDATE', 'ESCALATION', 'RESOLUTION'],
    required: true
  },
  recipients: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  report: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Report'
  },
  read: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Services
// Aadhaar verification service (mock)
const verifyAadhaar = async (aadhaarId, name, phone) => {
  // Mock implementation - always verify if Aadhaar ID is 12 digits
  return aadhaarId && aadhaarId.length === 12 && /^\d+$/.test(aadhaarId);
};

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  try {
    // In a real application, you would use JWT or session-based auth
    // For simplicity, we're using the Aadhaar ID from headers
    const aadhaarId = req.headers['x-aadhaar-id'];

    if (!aadhaarId) {
      return res.status(401).json({ error: true, message: 'Authentication required' });
    }

    // Find user by Aadhaar ID
    const user = await User.findOne({ aadhaarId });
    if (!user) {
      return res.status(404).json({ error: true, message: 'User not found' });
    }

    // Attach user to request
    req.user = {
      id: user._id,
      aadhaarId: user.aadhaarId,
      name: user.name,
      isVerified: user.isVerified
    };

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ error: true, message: 'Authentication failed' });
  }
};

// Routes
// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { aadhaarId, name, phone, email, location, district, state } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ aadhaarId });
    if (existingUser) {
      return res.status(400).json({ error: true, message: 'User with this Aadhaar ID already exists' });
    }

    // Verify Aadhaar (mock service)
    const isVerified = await verifyAadhaar(aadhaarId, name, phone);
    if (!isVerified) {
      return res.status(400).json({ error: true, message: 'Aadhaar verification failed' });
    }

    // Create new user
    const newUser = new User({
      aadhaarId,
      name,
      phone,
      email,
      location: {
        type: 'Point',
        coordinates: location.coordinates
      },
      district,
      state,
      isVerified: true
    });

    await newUser.save();

    res.status(201).json({
      error: false,
      message: 'User registered successfully',
      user: {
        id: newUser._id,
        name: newUser.name,
        aadhaarId: newUser.aadhaarId,
        district: newUser.district,
        state: newUser.state,
        isVerified: newUser.isVerified
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: true, message: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { aadhaarId, phone } = req.body;

    // Find user by Aadhaar ID
    const user = await User.findOne({ aadhaarId });
    if (!user) {
      return res.status(404).json({ error: true, message: 'User not found' });
    }

    // In a real app, you would verify with OTP or biometric
    // Here we're just checking if the phone number matches
    if (user.phone !== phone) {
      return res.status(401).json({ error: true, message: 'Authentication failed' });
    }

    res.status(200).json({
      error: false,
      message: 'Login successful',
      user: {
        id: user._id,
        name: user.name,
        aadhaarId: user.aadhaarId,
        district: user.district,
        state: user.state
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: true, message: 'Login failed' });
  }
});

// Report routes
app.post('/api/reports', authenticateUser, upload.array('media', 5), async (req, res) => {
  try {
    const { title, description, category, location, address, district, state } = req.body;
    const userId = req.user.id;

    // Process uploaded files
    const mediaFiles = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];

    // Create new report
    const newReport = new Report({
      title,
      description,
      category,
      location: {
        type: 'Point',
        coordinates: JSON.parse(location).coordinates
      },
      address,
      district,
      state,
      media: mediaFiles,
      reporter: userId,
      status: 'PENDING'
    });

    await newReport.save();

    // Find nearby users to notify (within 20km)
    const nearbyUsers = await User.find({
      location: {
        $near: {
          $geometry: {
            type: 'Point',
            coordinates: JSON.parse(location).coordinates
          },
          $maxDistance: 20000 // 20km in meters
        }
      }
    }).select('_id');

    // Create notification for nearby users
    if (nearbyUsers.length > 0) {
      const notification = new Notification({
        title: 'New Report in Your Area',
        message: `A new report about ${category} has been filed near you: "${title}"`,
        type: 'NEW_REPORT',
        recipients: nearbyUsers.map(user => user._id),
        report: newReport._id
      });

      await notification.save();
    }

    res.status(201).json({
      error: false,
      message: 'Report created successfully',
      report: {
        id: newReport._id,
        title: newReport.title,
        category: newReport.category,
        status: newReport.status,
        createdAt: newReport.createdAt
      }
    });
  } catch (error) {
    console.error('Report creation error:', error);
    res.status(500).json({ error: true, message: 'Failed to create report' });
  }
});

app.get('/api/reports', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 10,
      category,
      status,
      district,
      state,
      sort = 'latest' // 'latest', 'votes', 'nearby'
    } = req.query;

    // Build query
    const query = {};
    if (category) query.category = category;
    if (status) query.status = status;
    if (district) query.district = district;
    if (state) query.state = state;

    // Build sort options
    let sortOption = {};
    if (sort === 'latest') {
      sortOption = { createdAt: -1 };
    } else if (sort === 'votes') {
      sortOption = { voteCount: -1 };
    }

    // Handle location-based sorting
    if (sort === 'nearby' && req.query.lat && req.query.lng) {
      const reports = await Report.find(query)
        .populate('reporter', 'name')
        .sort(sortOption)
        .skip((page - 1) * limit)
        .limit(parseInt(limit))
        .lean();

      // Add distance field
      reports.forEach(report => {
        // Calculate distance (simplified)
        const userLat = parseFloat(req.query.lat);
        const userLng = parseFloat(req.query.lng);
        const reportLat = report.location.coordinates[1];
        const reportLng = report.location.coordinates[0];

        // Calculate approx. distance in km (Haversine formula would be more accurate)
        const distance = Math.sqrt(
          Math.pow(userLat - reportLat, 2) +
          Math.pow(userLng - reportLng, 2)
        ) * 111; // roughly km per degree

        report.distance = distance.toFixed(1);
      });

      // Sort by distance
      reports.sort((a, b) => a.distance - b.distance);

      const total = await Report.countDocuments(query);

      return res.status(200).json({
        error: false,
        reports,
        total,
        pages: Math.ceil(total / limit),
        currentPage: parseInt(page)
      });
    }

    // Regular pagination with sort
    const reports = await Report.find(query)
      .populate('reporter', 'name')
      .sort(sortOption)
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Report.countDocuments(query);

    res.status(200).json({
      error: false,
      reports,
      total,
      pages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch reports' });
  }
});

app.get('/api/reports/:id', async (req, res) => {
  try {
    const report = await Report.findById(req.params.id)
      .populate('reporter', 'name district state');

    if (!report) {
      return res.status(404).json({ error: true, message: 'Report not found' });
    }

    // Get vote count
    const voteCount = report.voteCount;

    res.status(200).json({
      error: false,
      report: {
        ...report.toObject(),
        voteCount
      }
    });
  } catch (error) {
    console.error('Error fetching report details:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch report details' });
  }
});

app.patch('/api/reports/:id/status', authenticateUser, async (req, res) => {
  try {
    const { status } = req.body;
    const reportId = req.params.id;

    // In a real app, check if user is admin
    // For now, we'll simply update the status

    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ error: true, message: 'Report not found' });
    }

    const oldStatus = report.status;
    report.status = status;

    // If escalating to judiciary
    if (status === 'ESCALATED' && oldStatus !== 'ESCALATED') {
      report.escalatedToJudiciary = true;
      report.escalatedAt = new Date();

      // Create notification for the reporter
      const notification = new Notification({
        title: 'Report Escalated',
        message: `Your report "${report.title}" has been escalated to the judiciary.`,
        type: 'ESCALATION',
        recipients: [report.reporter],
        report: report._id
      });

      await notification.save();
    }

    // If resolving
    if (status === 'RESOLVED' && oldStatus !== 'RESOLVED') {
      report.resolvedAt = new Date();

      // Create notification for the reporter and voters
      const votes = await Vote.find({ report: reportId });
      const voterIds = votes.map(vote => vote.user);

      // Add reporter to notification recipients
      const recipients = [...voterIds];
      if (!recipients.includes(report.reporter)) {
        recipients.push(report.reporter);
      }

      const notification = new Notification({
        title: 'Report Resolved',
        message: `The report "${report.title}" has been resolved.`,
        type: 'RESOLUTION',
        recipients,
        report: report._id
      });

      await notification.save();
    }

    await report.save();

    res.status(200).json({
      error: false,
      message: `Report status updated to ${status}`,
      report: {
        id: report._id,
        title: report.title,
        status: report.status,
        updatedAt: new Date()
      }
    });
  } catch (error) {
    console.error('Error updating report status:', error);
    res.status(500).json({ error: true, message: 'Failed to update report status' });
  }
});

// Vote routes
app.post('/api/votes/:reportId', authenticateUser, async (req, res) => {
  try {
    const reportId = req.params.reportId;
    const userId = req.user.id;

    // Check if report exists
    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ error: true, message: 'Report not found' });
    }

    // Check if user already voted on this report
    const existingVote = await Vote.findOne({ report: reportId, user: userId });
    if (existingVote) {
      return res.status(400).json({ error: true, message: 'You have already voted on this report' });
    }

    // Create new vote
    const newVote = new Vote({
      report: reportId,
      user: userId
    });

    await newVote.save();

    // Update vote count in report
    report.voteCount = await Vote.countDocuments({ report: reportId });
    await report.save();

    // Check if report should be escalated based on votes
    // For example, if it reaches 100 votes
    if (report.voteCount >= 100 && report.status === 'PENDING') {
      report.status = 'ESCALATED';
      report.escalatedToJudiciary = true;
      report.escalatedAt = new Date();
      await report.save();

      // Create notification about escalation
      const notification = new Notification({
        title: 'Report Escalated to Judiciary',
        message: `The report "${report.title}" has reached ${report.voteCount} votes and has been escalated to the judiciary.`,
        type: 'ESCALATION',
        recipients: [report.reporter],
        report: reportId
      });

      await notification.save();
    }

    res.status(200).json({
      error: false,
      message: 'Vote recorded successfully',
      voteCount: report.voteCount
    });
  } catch (error) {
    console.error('Error recording vote:', error);
    res.status(500).json({ error: true, message: 'Failed to record vote' });
  }
});

app.get('/api/votes/:reportId/count', async (req, res) => {
  try {
    const reportId = req.params.reportId;

    // Check if report exists
    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ error: true, message: 'Report not found' });
    }

    const voteCount = await Vote.countDocuments({ report: reportId });

    res.status(200).json({
      error: false,
      reportId,
      voteCount
    });
  } catch (error) {
    console.error('Error fetching vote count:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch vote count' });
  }
});

app.get('/api/votes/:reportId/check', authenticateUser, async (req, res) => {
  try {
    const reportId = req.params.reportId;
    const userId = req.user.id;

    const vote = await Vote.findOne({ report: reportId, user: userId });

    res.status(200).json({
      error: false,
      hasVoted: !!vote
    });
  } catch (error) {
    console.error('Error checking vote status:', error);
    res.status(500).json({ error: true, message: 'Failed to check vote status' });
  }
});

// Notification routes
app.get('/api/notifications', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const { page = 1, limit = 20 } = req.query;

    const notifications = await Notification.find({
      recipients: userId
    })
    .populate('report', 'title category')
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(parseInt(limit));

    const total = await Notification.countDocuments({ recipients: userId });

    // Count unread notifications
    const unreadCount = await Notification.countDocuments({
      recipients: userId,
      read: { $ne: userId }
    });

    res.status(200).json({
      error: false,
      notifications,
      total,
      unreadCount,
      pages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch notifications' });
  }
});

app.patch('/api/notifications/:id/read', authenticateUser, async (req, res) => {
  try {
    const notificationId = req.params.id;
    const userId = req.user.id;

    const notification = await Notification.findById(notificationId);
    if (!notification) {
      return res.status(404).json({ error: true, message: 'Notification not found' });
    }

    // Check if user is a recipient
    if (!notification.recipients.includes(userId)) {
      return res.status(403).json({ error: true, message: 'Not authorized to access this notification' });
    }

    // Mark as read if not already
    if (!notification.read.includes(userId)) {
      notification.read.push(userId);
      await notification.save();
    }

    res.status(200).json({
      error: false,
      message: 'Notification marked as read'
    });
  } catch (error) {
    console.error('Error marking notification as read:', error);
    res.status(500).json({ error: true, message: 'Failed to mark notification as read' });
  }
});

app.post('/api/notifications/read-all', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;

    // Find all unread notifications for this user
    const unreadNotifications = await Notification.find({
      recipients: userId,
      read: { $ne: userId }
    });

    // Mark each as read
    const updatePromises = unreadNotifications.map(notification => {
      notification.read.push(userId);
      return notification.save();
    });

    await Promise.all(updatePromises);

    res.status(200).json({
      error: false,
      message: `Marked ${unreadNotifications.length} notifications as read`
    });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ error: true, message: 'Failed to mark all notifications as read' });
  }
});

// User routes
app.get('/api/users/me', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;

    const user = await User.findById(userId).select('-__v');
    if (!user) {
      return res.status(404).json({ error: true, message: 'User not found' });
    }

    // Get user's reports count
    const reportsCount = await Report.countDocuments({ reporter: userId });

    res.status(200).json({
      error: false,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        district: user.district,
        state: user.state,
        isVerified: user.isVerified,
        reportsCount,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch user profile' });
  }
});

app.patch('/api/users/me', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const { phone, email, location } = req.body;

    // Fields that can be updated
    const updateFields = {};
    if (phone) updateFields.phone = phone;
    if (email) updateFields.email = email;
    if (location) updateFields.location = location;

    const user = await User.findByIdAndUpdate(
      userId,
      { $set: updateFields },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: true, message: 'User not found' });
    }

    res.status(200).json({
      error: false,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        district: user.district,
        state: user.state
      }
    });
  } catch (error) {
    console.error('Error updating user profile:', error);
    res.status(500).json({ error: true, message: 'Failed to update user profile' });
  }
});

app.get('/api/users/me/reports', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const { page = 1, limit = 10, status } = req.query;

    // Build query
    const query = { reporter: userId };
    if (status) query.status = status;

    const reports = await Report.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Report.countDocuments(query);

    res.status(200).json({
      error: false,
      reports,
      total,
      pages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (error) {
    console.error('Error fetching user reports:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch user reports' });
  }
});

app.get('/api/users/me/votes', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const { page = 1, limit = 10 } = req.query;

    // Get user's votes
    const votes = await Vote.find({ user: userId })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Get the associated reports
    const reportIds = votes.map(vote => vote.report);
    const reports = await Report.find({ _id: { $in: reportIds } })
      .populate('reporter', 'name');

    // Map votes to reports with vote date
    const votedReports = reports.map(report => {
      const vote = votes.find(v => v.report.toString() === report._id.toString());
      return {
        ...report.toObject(),
        votedAt: vote.createdAt
      };
    });

    const total = await Vote.countDocuments({ user: userId });

    res.status(200).json({
      error: false,
      reports: votedReports,
      total,
      pages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (error) {
    console.error('Error fetching voted reports:', error);
    res.status(500).json({ error: true, message: 'Failed to fetch voted reports' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', message: 'Vigilant Citizen API is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    error: true,
    message: err.message || 'Internal Server Error'
  });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    // Start server after successful database connection
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });