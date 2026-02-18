const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
const telegram = require('./utils/telegram');

dotenv.config();

const app = express();

// ==================== SECURITY MIDDLEWARE ====================

// 1. Helmet - Secure headers
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://lifafa-backend.onrender.com", "https://muskilxlifafa.vercel.app"]
        }
    }
}));

// 2. CORS - Strict origin control
const allowedOrigins = [
    'https://muskilxlifafa.vercel.app',
    'https://www.muskilxlifafa.vercel.app',
    'http://localhost:3000',
    'http://localhost:5000',
    'https://lifafa-backend.onrender.com'
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, curl)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = '❌ CORS policy violation: This origin is not allowed to access this API.';
            console.log(`Blocked origin: ${origin}`);
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 600 // 10 minutes - cache preflight requests
}));

// Handle preflight requests
app.options('*', cors());

// 3. Rate Limiting - Prevent brute force attacks
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { success: false, msg: 'Too many requests from this IP, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting to all routes
app.use('/api', limiter);

// Stricter rate limit for auth routes
const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 requests per hour
    message: { success: false, msg: 'Too many authentication attempts, please try again later.' }
});

app.use('/api/auth', authLimiter);

// 4. Body parsing with size limits
app.use(express.json({ limit: '10kb' })); // Limit body size to 10kb
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 5. Data sanitization against NoSQL injection
app.use(mongoSanitize());

// 6. Data sanitization against XSS
app.use(xss());

// 7. Prevent parameter pollution
app.use(hpp({
    whitelist: ['page', 'limit', 'sort'] // Allow these parameters to be duplicated
}));

// 8. Compression
app.use(compression());

// 9. Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - IP: ${req.ip}`);
    next();
});

// ==================== ENVIRONMENT CHECKS ====================

// Check required environment variables
const requiredEnvVars = [
    'MONGODB_URI',
    'JWT_SECRET',
    'ADMIN_USERNAME',
    'ADMIN_PASSWORD',
    'TELEGRAM_BOT_TOKEN',
    'FRONTEND_URL'
];

requiredEnvVars.forEach(envVar => {
    if (!process.env[envVar]) {
        console.error(`❌ Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
});

console.log('✅ Environment variables verified');

// Initialize Telegram Bot
const bot = telegram.initBot(process.env.TELEGRAM_BOT_TOKEN);

// MongoDB Connection with secure options
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10, // Maximum number of connections
    minPoolSize: 2,  // Minimum number of connections
    serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
    socketTimeoutMS: 45000, // Close sockets after 45 seconds
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
});

// Handle MongoDB connection errors after initial connection
mongoose.connection.on('error', err => {
    console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('⚠️ MongoDB disconnected');
});

// Graceful shutdown
process.on('SIGINT', async () => {
    await mongoose.connection.close();
    console.log('MongoDB connection closed through app termination');
    process.exit(0);
});

// ==================== MODELS ====================

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, trim: true },
    number: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    telegramUid: { type: String, required: true, unique: true, trim: true },
    balance: { type: Number, default: 0, min: 0 },
    isBlocked: { type: Boolean, default: false },
    lastLogin: Date,
    lastLoginIp: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, enum: ['credit', 'debit', 'withdraw', 'lifafa_created', 'lifafa_claimed'], required: true },
    amount: { type: Number, required: true, min: 0 },
    description: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

const LifafaSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    code: { type: String, required: true, unique: true, index: true },
    amount: { type: Number, required: true, min: 1 },
    numbers: [{ type: String, trim: true }],
    totalUsers: { type: Number, default: 1, min: 1 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    createdByNumber: String,
    isUserCreated: { type: Boolean, default: true },
    claimedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    claimedNumbers: [{ type: String }],
    claimedCount: { type: Number, default: 0, min: 0 },
    totalAmount: { type: Number, default: 0, min: 0 },
    isActive: { type: Boolean, default: true, index: true },
    createdAt: { type: Date, default: Date.now, index: true }
});

const WithdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: true, min: 50 },
    upiId: { type: String, required: true, trim: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'refunded'], default: 'pending', index: true },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    processedAt: Date,
    remarks: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

const CodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true, index: true },
    numbers: [{ type: String }],
    createdBy: String,
    createdAt: { type: Date, default: Date.now, expires: 86400 } // Auto delete after 24 hours
});

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Lifafa = mongoose.model('Lifafa', LifafaSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);
const Code = mongoose.model('Code', CodeSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Create indexes for better performance
UserSchema.index({ number: 1 });
UserSchema.index({ telegramUid: 1 });
LifafaSchema.index({ code: 1 });
LifafaSchema.index({ createdBy: 1, isActive: 1 });
TransactionSchema.index({ userId: 1, createdAt: -1 });
WithdrawalSchema.index({ userId: 1, status: 1 });

// ==================== MIDDLEWARE ====================

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, msg: 'No token provided' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({ success: false, msg: 'User not found' });
        }
        
        if (user.isBlocked) {
            return res.status(403).json({ success: false, msg: 'Account is blocked' });
        }
        
        req.userId = decoded.userId;
        req.user = user;
        next();
    } catch(err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, msg: 'Token expired' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, msg: 'Invalid token' });
        }
        return res.status(401).json({ success: false, msg: 'Authentication failed' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, msg: 'No token provided' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId);
        
        if (!admin) {
            return res.status(403).json({ success: false, msg: 'Not authorized' });
        }
        
        req.adminId = decoded.adminId;
        req.admin = admin;
        next();
    } catch(err) {
        return res.status(401).json({ success: false, msg: 'Invalid token' });
    }
};

// Store OTPs with cleanup
const otpStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (let [key, value] of otpStore.entries()) {
        if (value.expires < now) {
            otpStore.delete(key);
            console.log(`🧹 Cleaned up expired OTP for ${key}`);
        }
    }
}, 5 * 60 * 1000); // Clean up every 5 minutes

// ==================== API ROUTES ====================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Lifafa API is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'development'
    });
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/check-number', async (req, res) => {
    try {
        const { number } = req.body;
        
        if (!number || !/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        const user = await User.findOne({ number });
        res.json({ exists: !!user });
    } catch(err) {
        console.error('Check number error:', err);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/auth/check-telegram', async (req, res) => {
    try {
        const { telegramUid } = req.body;
        
        if (!telegramUid || typeof telegramUid !== 'string') {
            return res.json({ success: false, msg: 'Invalid Telegram UID' });
        }
        
        const existing = await User.findOne({ telegramUid });
        res.json({ available: !existing });
    } catch(err) {
        console.error('Check telegram error:', err);
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { number, telegramUid } = req.body;
        
        if (!number || !telegramUid) {
            return res.json({ success: false, msg: 'Number and Telegram UID required' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ success: false, msg: 'Number already registered' });
        }
        
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) {
            return res.json({ success: false, msg: 'Telegram ID already used' });
        }
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        otpStore.set(number, {
            otp,
            telegramUid,
            expires: Date.now() + 5 * 60 * 1000,
            attempts: 0
        });
        
        const sent = await telegram.sendOTP(telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent to your Telegram' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
    } catch(err) {
        console.error('Send OTP error:', err);
        res.status(500).json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { username, number, password, telegramUid, otp } = req.body;
        
        // Validation
        if (!username || !number || !password || !telegramUid || !otp) {
            return res.json({ success: false, msg: 'All fields required' });
        }
        
        if (username.length < 3 || username.length > 20) {
            return res.json({ success: false, msg: 'Username must be 3-20 characters' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        if (password.length < 6) {
            return res.json({ success: false, msg: 'Password must be at least 6 characters' });
        }
        
        // Check OTP
        const stored = otpStore.get(number);
        if (!stored) {
            return res.json({ success: false, msg: 'OTP expired or not requested' });
        }
        
        if (stored.otp !== otp) {
            stored.attempts = (stored.attempts || 0) + 1;
            if (stored.attempts >= 3) {
                otpStore.delete(number);
                return res.json({ success: false, msg: 'Too many failed attempts. Request new OTP.' });
            }
            otpStore.set(number, stored);
            return res.json({ success: false, msg: 'Invalid OTP' });
        }
        
        if (stored.telegramUid !== telegramUid) {
            return res.json({ success: false, msg: 'Telegram UID mismatch' });
        }
        
        if (Date.now() > stored.expires) {
            otpStore.delete(number);
            return res.json({ success: false, msg: 'OTP expired' });
        }
        
        // Double check if Telegram UID already used
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) {
            return res.json({ success: false, msg: 'Telegram ID already used' });
        }
        
        // Check if number exists
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ success: false, msg: 'Number already registered' });
        }
        
        // Create user
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const user = new User({
            username,
            number,
            password: hashedPassword,
            telegramUid,
            balance: 0
        });
        
        await user.save();
        
        await telegram.sendMessage(telegramUid, 
            `🎉 *Registration Successful!*\n\n👤 *Username:* ${username}\n📱 *Number:* ${number}\n💰 *Balance:* ₹0`,
            { parse_mode: 'Markdown' }
        );
        
        otpStore.delete(number);
        res.json({ success: true, msg: 'Registration successful' });
        
    } catch(err) {
        console.error('Verify OTP error:', err);
        res.status(500).json({ success: false, msg: 'Registration failed' });
    }
});

app.post('/api/auth/send-login-otp', async (req, res) => {
    try {
        const { number } = req.body;
        
        if (!number || !/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        if (user.isBlocked) {
            return res.json({ success: false, msg: 'Account is blocked' });
        }
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        otpStore.set(`login_${number}`, {
            otp,
            telegramUid: user.telegramUid,
            userId: user._id,
            expires: Date.now() + 5 * 60 * 1000,
            attempts: 0
        });
        
        const sent = await telegram.sendOTP(user.telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent to your Telegram' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
    } catch(err) {
        console.error('Send login OTP error:', err);
        res.status(500).json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-login-otp', async (req, res) => {
    try {
        const { number, otp, ip } = req.body;
        
        if (!number || !otp) {
            return res.json({ success: false, msg: 'Number and OTP required' });
        }
        
        const stored = otpStore.get(`login_${number}`);
        if (!stored) {
            return res.json({ success: false, msg: 'OTP expired or not requested' });
        }
        
        if (stored.otp !== otp) {
            stored.attempts = (stored.attempts || 0) + 1;
            if (stored.attempts >= 3) {
                otpStore.delete(`login_${number}`);
                return res.json({ success: false, msg: 'Too many failed attempts. Request new OTP.' });
            }
            otpStore.set(`login_${number}`, stored);
            return res.json({ success: false, msg: 'Invalid OTP' });
        }
        
        if (Date.now() > stored.expires) {
            otpStore.delete(`login_${number}`);
            return res.json({ success: false, msg: 'OTP expired' });
        }
        
        const user = await User.findById(stored.userId);
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        user.lastLoginIp = ip;
        await user.save();
        
        // Send login alert
        await telegram.sendLoginAlert(user.telegramUid, user, ip);
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        otpStore.delete(`login_${number}`);
        
        res.json({ 
            success: true,
            token,
            user: { 
                number: user.number, 
                balance: user.balance, 
                username: user.username 
            }
        });
        
    } catch(err) {
        console.error('Verify login OTP error:', err);
        res.status(500).json({ success: false, msg: 'Login failed' });
    }
});

app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { number, type } = req.body;
        
        if (!number || !type) {
            return res.json({ success: false, msg: 'Number and type required' });
        }
        
        const key = type === 'login' ? `login_${number}` : number;
        const stored = otpStore.get(key);
        
        if (!stored) {
            return res.json({ success: false, msg: 'Request OTP first' });
        }
        
        // Check if too many resend attempts
        stored.resendAttempts = (stored.resendAttempts || 0) + 1;
        if (stored.resendAttempts > 3) {
            otpStore.delete(key);
            return res.json({ success: false, msg: 'Too many resend attempts. Please try again later.' });
        }
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        stored.otp = otp;
        stored.expires = Date.now() + 5 * 60 * 1000;
        otpStore.set(key, stored);
        
        const sent = await telegram.sendOTP(stored.telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP resent' });
        } else {
            res.json({ success: false, msg: 'Failed to resend' });
        }
    } catch(err) {
        console.error('Resend OTP error:', err);
        res.status(500).json({ success: false, msg: 'Failed to resend' });
    }
});

// ==================== NUMBER TOOL ROUTES ====================

app.post('/api/tool/generate-code', async (req, res) => {
    try {
        const { numbers, userId } = req.body;
        
        if (!numbers || !Array.isArray(numbers) || numbers.length === 0) {
            return res.json({ success: false, msg: 'Valid numbers required' });
        }
        
        if (numbers.length > 1000) {
            return res.json({ success: false, msg: 'Maximum 1000 numbers allowed' });
        }
        
        const validNumbers = numbers.filter(n => /^\d{10}$/.test(n));
        
        if (validNumbers.length === 0) {
            return res.json({ success: false, msg: 'No valid 10-digit numbers' });
        }
        
        const code = 'NUM' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const codeDoc = new Code({
            code,
            numbers: validNumbers,
            createdBy: userId || 'anonymous'
        });
        
        await codeDoc.save();
        
        res.json({ 
            success: true, 
            code,
            count: validNumbers.length
        });
        
    } catch(err) {
        console.error('Generate code error:', err);
        res.status(500).json({ success: false, msg: 'Failed to generate code' });
    }
});

app.get('/api/tool/code/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        const codeDoc = await Code.findOne({ code });
        if (!codeDoc) {
            return res.json({ success: false, msg: 'Code not found' });
        }
        
        res.json({ 
            success: true, 
            numbers: codeDoc.numbers,
            count: codeDoc.numbers.length
        });
        
    } catch(err) {
        console.error('Fetch code error:', err);
        res.status(500).json({ success: false, msg: 'Error fetching code' });
    }
});

// ==================== USER ROUTES ====================

app.get('/api/user/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        const recentTransactions = await Transaction.find({ userId: user._id })
            .sort('-createdAt')
            .limit(5);
        
        const unclaimedCount = await Lifafa.countDocuments({
            isActive: true,
            $and: [
                { numbers: user.number },
                { numbers: { $ne: [] } },
                { numbers: { $exists: true } }
            ],
            claimedNumbers: { $ne: user.number }
        });
        
        const createdLifafas = await Lifafa.find({ createdBy: user._id })
            .sort('-createdAt')
            .limit(5);
        
        res.json({ 
            success: true,
            balance: user.balance,
            username: user.username,
            number: user.number,
            telegramUid: user.telegramUid,
            unclaimedLifafas: unclaimedCount,
            recentTransactions,
            createdLifafas
        });
    } catch(err) {
        console.error('Dashboard error:', err);
        res.status(500).json({ success: false, msg: 'Error loading dashboard' });
    }
});

app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        const totalLifafasCreated = await Lifafa.countDocuments({ createdBy: user._id });
        const totalLifafasClaimed = await Lifafa.countDocuments({ claimedBy: user._id });
        const totalTransactions = await Transaction.countDocuments({ userId: user._id });
        
        const recentActivity = await Transaction.find({ userId: user._id })
            .sort('-createdAt')
            .limit(10);
        
        res.json({
            success: true,
            profile: {
                username: user.username,
                number: user.number,
                telegramUid: user.telegramUid,
                balance: user.balance,
                joinedAt: user.createdAt,
                lastLogin: user.lastLogin,
                isBlocked: user.isBlocked,
                stats: {
                    lifafasCreated: totalLifafasCreated,
                    lifafasClaimed: totalLifafasClaimed,
                    transactions: totalTransactions
                },
                recentActivity
            }
        });
    } catch(err) {
        console.error('Profile error:', err);
        res.status(500).json({ success: false, msg: 'Error loading profile' });
    }
});

app.get('/api/user/transactions', authMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        const transactions = await Transaction.find({ userId: req.userId })
            .sort('-createdAt')
            .skip(skip)
            .limit(limit);
        
        const total = await Transaction.countDocuments({ userId: req.userId });
        
        res.json({ 
            success: true, 
            transactions,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch(err) {
        console.error('Transactions error:', err);
        res.status(500).json({ success: false, msg: 'Error loading transactions' });
    }
});

app.post('/api/user/pay', authMiddleware, async (req, res) => {
    try {
        const { receiverNumber, amount } = req.body;
        const sender = req.user;
        
        if (!receiverNumber || !amount) {
            return res.json({ success: false, msg: 'Receiver number and amount required' });
        }
        
        if (!/^\d{10}$/.test(receiverNumber)) {
            return res.json({ success: false, msg: 'Invalid receiver number' });
        }
        
        if (amount <= 0 || amount > 100000) {
            return res.json({ success: false, msg: 'Amount must be between ₹1 and ₹1,00,000' });
        }
        
        if (sender.balance < amount) {
            return res.json({ success: false, msg: 'Insufficient balance' });
        }
        
        const receiver = await User.findOne({ number: receiverNumber });
        if (!receiver) {
            return res.json({ success: false, msg: 'Receiver not found' });
        }
        
        if (receiver.isBlocked) {
            return res.json({ success: false, msg: 'Receiver account is blocked' });
        }
        
        if (sender.number === receiverNumber) {
            return res.json({ success: false, msg: 'Cannot send money to yourself' });
        }
        
        sender.balance -= amount;
        receiver.balance += amount;
        
        await sender.save();
        await receiver.save();
        
        await new Transaction({
            userId: sender._id,
            type: 'debit',
            amount,
            description: `Paid to ${receiverNumber}`
        }).save();
        
        await new Transaction({
            userId: receiver._id,
            type: 'credit',
            amount,
            description: `Received from ${sender.number}`
        }).save();
        
        await telegram.sendTransactionAlert(
            sender.telegramUid, 'debit', amount, sender.balance, `Paid to ${receiverNumber}`
        );
        
        await telegram.sendTransactionAlert(
            receiver.telegramUid, 'credit', amount, receiver.balance, `Received from ${sender.number}`
        );
        
        res.json({ success: true, msg: 'Payment successful', newBalance: sender.balance });
        
    } catch(err) {
        console.error('Pay error:', err);
        res.status(500).json({ success: false, msg: 'Payment failed' });
    }
});

app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        const user = req.user;
        
        if (!amount || amount < 50) {
            return res.json({ success: false, msg: 'Minimum withdrawal amount is ₹50' });
        }
        
        if (amount > 50000) {
            return res.json({ success: false, msg: 'Maximum withdrawal amount is ₹50,000' });
        }
        
        if (!upiId || !/^[\w\.\-]+@[\w\.\-]+$/.test(upiId)) {
            return res.json({ success: false, msg: 'Invalid UPI ID format' });
        }
        
        if (user.balance < amount) {
            return res.json({ success: false, msg: 'Insufficient balance' });
        }
        
        // Check if user has pending withdrawals
        const pendingWithdrawals = await Withdrawal.countDocuments({
            userId: user._id,
            status: 'pending'
        });
        
        if (pendingWithdrawals >= 3) {
            return res.json({ success: false, msg: 'You have too many pending withdrawals' });
        }
        
        const withdrawal = new Withdrawal({
            userId: user._id,
            amount,
            upiId
        });
        
        await withdrawal.save();
        
        user.balance -= amount;
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: 'debit',
            amount,
            description: `Withdrawal request to ${upiId}`
        }).save();
        
        await telegram.sendWithdrawalAlert(user.telegramUid, amount, 'pending');
        
        res.json({ success: true, msg: 'Withdrawal request submitted', newBalance: user.balance });
        
    } catch(err) {
        console.error('Withdraw error:', err);
        res.status(500).json({ success: false, msg: 'Withdrawal failed' });
    }
});

app.get('/api/user/withdrawals', authMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId })
            .sort('-createdAt')
            .limit(20);
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        console.error('Withdrawals error:', err);
        res.status(500).json({ success: false, msg: 'Error loading withdrawals' });
    }
});

app.post('/api/user/create-lifafa', authMiddleware, async (req, res) => {
    try {
        const { title, amount, code, numbers, userCount, channel } = req.body;
        const user = req.user;
        
        if (!title || !amount || amount <= 0) {
            return res.json({ success: false, msg: 'Title and valid amount required' });
        }
        
        if (title.length < 3 || title.length > 50) {
            return res.json({ success: false, msg: 'Title must be 3-50 characters' });
        }
        
        if (amount < 1 || amount > 10000) {
            return res.json({ success: false, msg: 'Amount must be between ₹1 and ₹10,000' });
        }
        
        // Get numbers from code if provided
        let allowedNumbers = [];
        if (code) {
            const codeDoc = await Code.findOne({ code });
            if (codeDoc) {
                allowedNumbers = codeDoc.numbers;
            }
        } else if (numbers && numbers.trim()) {
            allowedNumbers = numbers
                .split(/[\n,]+/)
                .map(n => n.trim())
                .filter(n => /^\d{10}$/.test(n));
            
            if (allowedNumbers.length > 100) {
                return res.json({ success: false, msg: 'Maximum 100 numbers allowed' });
            }
        }
        
        // Calculate total users correctly
        let totalUsers = 1;
        let lifafaType = 'public_unlimited';
        
        if (allowedNumbers.length > 0) {
            totalUsers = allowedNumbers.length;
            lifafaType = 'private';
        } else if (userCount && parseInt(userCount) > 0) {
            totalUsers = parseInt(userCount);
            if (totalUsers > 1000) {
                return res.json({ success: false, msg: 'Maximum 1000 users allowed' });
            }
            lifafaType = 'public_limited';
        } else if (numbers && numbers.trim()) {
            const manualNumbers = numbers.split('\n').filter(n => n.trim());
            allowedNumbers = manualNumbers;
            totalUsers = manualNumbers.length;
            if (totalUsers > 100) {
                return res.json({ success: false, msg: 'Maximum 100 numbers allowed' });
            }
            lifafaType = 'private';
        }
        
        const totalCost = amount * totalUsers;
        
        if (user.balance < totalCost) {
            return res.json({ success: false, msg: `Insufficient balance. Required: ₹${totalCost}` });
        }
        
        const lifafaCode = 'LIF' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const lifafa = new Lifafa({
            title,
            code: lifafaCode,
            amount,
            numbers: allowedNumbers,
            totalUsers: totalUsers,
            createdBy: user._id,
            createdByNumber: user.number,
            isUserCreated: true,
            isActive: true,
            claimedCount: 0,
            claimedNumbers: []
        });
        
        await lifafa.save();
        
        user.balance -= totalCost;
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: 'debit',
            amount: totalCost,
            description: `Created ${lifafaType} Lifafa: ${title} (${totalUsers} users)`
        }).save();
        
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const shareableLink = `${baseUrl}/claimlifafa.html?code=${lifafaCode}`;
        
        let message = `🎁 *Lifafa Created!*\n\n*Title:* ${title}\n*Amount:* ₹${amount}`;
        if (lifafaType === 'private') {
            message += `\n*Type:* Private (${totalUsers} specific users)`;
        } else if (lifafaType === 'public_limited') {
            message += `\n*Type:* Public Limited (${totalUsers} spots)`;
        } else {
            message += `\n*Type:* Public Unlimited`;
        }
        message += `\n*Total Cost:* ₹${totalCost}\n*Code:* \`${lifafaCode}\`\n*Link:* ${shareableLink}`;
        
        await telegram.sendMessage(user.telegramUid, message, { parse_mode: 'Markdown' });
        
        res.json({ 
            success: true, 
            msg: 'Lifafa created successfully',
            code: lifafaCode,
            link: shareableLink,
            totalUsers,
            totalCost,
            newBalance: user.balance,
            type: lifafaType
        });
        
    } catch(err) {
        console.error('Create lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Failed to create lifafa' });
    }
});

app.get('/api/user/my-lifafas', authMiddleware, async (req, res) => {
    try {
        const lifafas = await Lifafa.find({ createdBy: req.userId })
            .sort('-createdAt')
            .limit(50);
        
        res.json({ success: true, lifafas });
    } catch(err) {
        console.error('My lifafas error:', err);
        res.status(500).json({ success: false, msg: 'Error loading lifafas' });
    }
});

app.post('/api/user/unclaimed-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number || number !== user.number) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        const lifafas = await Lifafa.find({
            isActive: true,
            $and: [
                { numbers: number },
                { numbers: { $ne: [] } },
                { numbers: { $exists: true } }
            ],
            claimedNumbers: { $ne: number }
        }).sort('-createdAt');
        
        res.json({ 
            success: true,
            lifafas: lifafas.map(l => ({
                _id: l._id,
                title: l.title,
                amount: l.amount,
                code: l.code,
                channel: l.channel,
                isPublic: false,
                totalUsers: l.totalUsers || 1,
                claimedCount: l.claimedCount || 0
            }))
        });
        
    } catch(err) {
        console.error('Unclaimed lifafas error:', err);
        res.status(500).json({ success: false, msg: 'Failed to fetch lifafas' });
    }
});

app.post('/api/user/claim-lifafa', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const user = req.user;
        
        if (!code || !/^LIF[A-Z0-9]+$/.test(code)) {
            return res.json({ success: false, msg: 'Invalid code format' });
        }
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) {
            return res.json({ success: false, msg: 'Invalid or expired code' });
        }
        
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(user.number)) {
                return res.json({ 
                    success: false, 
                    msg: 'This is a private lifafa and you are not eligible to claim it' 
                });
            }
        }
        
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(user.number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
        if (lifafa.claimedCount >= totalAllowed) {
            return res.json({ success: false, msg: 'This lifafa is fully claimed' });
        }
        
        user.balance += lifafa.amount;
        await user.save();
        
        lifafa.claimedBy.push(user._id);
        lifafa.claimedNumbers.push(user.number);
        lifafa.claimedCount++;
        lifafa.totalAmount += lifafa.amount;
        
        if (lifafa.claimedCount >= totalAllowed) {
            lifafa.isActive = false;
        }
        
        await lifafa.save();
        
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: lifafa.amount,
            description: `Claimed Lifafa: ${lifafa.title}`
        }).save();
        
        await telegram.sendLifafaClaimAlert(user.telegramUid, lifafa, user.balance);
        
        res.json({ success: true, amount: lifafa.amount, newBalance: user.balance });
        
    } catch(err) {
        console.error('Claim lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Claim failed' });
    }
});

app.post('/api/user/claim-all-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number || number !== user.number) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        const lifafas = await Lifafa.find({
            isActive: true,
            $and: [
                { numbers: number },
                { numbers: { $ne: [] } },
                { numbers: { $exists: true } }
            ],
            claimedNumbers: { $ne: number }
        });
        
        if (lifafas.length === 0) {
            return res.json({ success: false, msg: 'No unclaimed private lifafas' });
        }
        
        if (lifafas.length > 10) {
            return res.json({ success: false, msg: 'Cannot claim more than 10 lifafas at once' });
        }
        
        let totalAmount = 0;
        const claimedLifafas = [];
        
        for (const lifafa of lifafas) {
            totalAmount += lifafa.amount;
            claimedLifafas.push(lifafa.title);
            
            lifafa.claimedBy.push(user._id);
            lifafa.claimedNumbers.push(number);
            lifafa.claimedCount++;
            lifafa.totalAmount += lifafa.amount;
            
            const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
            if (lifafa.claimedCount >= totalAllowed) {
                lifafa.isActive = false;
            }
            
            await lifafa.save();
        }
        
        user.balance += totalAmount;
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: totalAmount,
            description: `Bulk claimed ${lifafas.length} private lifafas`
        }).save();
        
        await telegram.sendMessage(user.telegramUid,
            `🎊 *Bulk Claim Successful!*\n\n*Total Private Lifafas:* ${lifafas.length}\n*Total Amount:* +₹${totalAmount}\n*New Balance:* ₹${user.balance}`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ 
            success: true, 
            totalLifafas: lifafas.length, 
            totalAmount, 
            newBalance: user.balance,
            claimed: claimedLifafas
        });
        
    } catch(err) {
        console.error('Claim all error:', err);
        res.status(500).json({ success: false, msg: 'Failed to claim all' });
    }
});

// ==================== PUBLIC LIFAFA ROUTES ====================

app.get('/api/lifafa/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        if (!code || !/^LIF[A-Z0-9]+$/.test(code)) {
            return res.json({ success: false, msg: 'Invalid code format' });
        }
        
        const lifafa = await Lifafa.findOne({ code }).populate('createdBy', 'username number');

        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }

        let type = 'public_unlimited';
        let totalAllowed = 1;
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            type = 'private';
            totalAllowed = lifafa.numbers.length;
        } else if (lifafa.totalUsers > 1) {
            type = 'public_limited';
            totalAllowed = lifafa.totalUsers;
        }

        const claimedCount = lifafa.claimedCount || 0;
        const remaining = Math.max(0, totalAllowed - claimedCount);

        res.json({
            success: true,
            lifafa: {
                title: lifafa.title,
                amount: lifafa.amount,
                code: lifafa.code,
                channel: lifafa.channel,
                numbers: lifafa.numbers,
                totalUsers: lifafa.totalUsers || 1,
                type: type,
                createdBy: lifafa.createdBy ? {
                    username: lifafa.createdBy.username,
                    number: lifafa.createdBy.number
                } : null,
                claimedCount: claimedCount,
                remainingSpots: remaining,
                isActive: lifafa.isActive,
                createdAt: lifafa.createdAt
            }
        });
    } catch(err) {
        console.error('Error in /api/lifafa/:code', err);
        res.status(500).json({ success: false, msg: 'Server error loading lifafa' });
    }
});

app.post('/api/lifafa/claim', async (req, res) => {
    try {
        const { code, number } = req.body;
        
        if (!code || !number) {
            return res.json({ success: false, msg: 'Code and number required' });
        }
        
        if (!/^LIF[A-Z0-9]+$/.test(code)) {
            return res.json({ success: false, msg: 'Invalid code format' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found. Please register first.' });
        }
        
        if (user.isBlocked) {
            return res.json({ success: false, msg: 'Account blocked' });
        }
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) {
            return res.json({ success: false, msg: 'Invalid or expired code' });
        }
        
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(number)) {
                return res.json({ 
                    success: false, 
                    msg: 'This private lifafa is not for you' 
                });
            }
        }
        
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
        if (lifafa.claimedCount >= totalAllowed) {
            lifafa.isActive = false;
            await lifafa.save();
            return res.json({ success: false, msg: 'This lifafa is fully claimed' });
        }
        
        user.balance += lifafa.amount;
        await user.save();
        
        lifafa.claimedBy.push(user._id);
        lifafa.claimedNumbers.push(number);
        lifafa.claimedCount++;
        lifafa.totalAmount += lifafa.amount;
        
        if (lifafa.claimedCount >= totalAllowed) {
            lifafa.isActive = false;
        }
        
        await lifafa.save();
        
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: lifafa.amount,
            description: `Claimed Lifafa: ${lifafa.title}`
        }).save();
        
        res.json({ success: true, amount: lifafa.amount, newBalance: user.balance });
        
    } catch(err) {
        console.error('Claim error:', err);
        res.status(500).json({ success: false, msg: 'Claim failed' });
    }
});

// ==================== ADMIN ROUTES ====================

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.json({ success: false, msg: 'Username and password required' });
        }
        
        let admin = await Admin.findOne({ username });
        
        if (!admin && username === process.env.ADMIN_USERNAME) {
            const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
            admin = new Admin({ username, password: hashedPassword });
            await admin.save();
            console.log('👑 Default admin created');
        }
        
        if (!admin) {
            return res.json({ success: false, msg: 'Admin not found' });
        }
        
        const valid = bcrypt.compareSync(password, admin.password);
        if (!valid) {
            return res.json({ success: false, msg: 'Invalid password' });
        }
        
        const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        res.json({ success: true, token });
    } catch(err) {
        console.error('Admin login error:', err);
        res.status(500).json({ success: false, msg: 'Login failed' });
    }
});

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isBlocked: false });
        const totalLifafas = await Lifafa.countDocuments();
        const activeLifafas = await Lifafa.countDocuments({ isActive: true });
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
        
        res.json({
            success: true,
            stats: {
                users: { total: totalUsers, active: activeUsers },
                lifafas: { total: totalLifafas, active: activeLifafas },
                withdrawals: { pending: pendingWithdrawals },
                totalBalance: totalBalance[0]?.total || 0
            }
        });
    } catch(err) {
        console.error('Admin stats error:', err);
        res.status(500).json({ success: false, msg: 'Error loading stats' });
    }
});

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        const search = req.query.search || '';
        
        let query = {};
        if (search) {
            query = {
                $or: [
                    { number: { $regex: search, $options: 'i' } },
                    { username: { $regex: search, $options: 'i' } },
                    { telegramUid: { $regex: search, $options: 'i' } }
                ]
            };
        }
        
        const users = await User.find(query)
            .select('-password')
            .sort('-createdAt')
            .skip(skip)
            .limit(limit);
        
        const total = await User.countDocuments(query);
        
        res.json({
            success: true,
            users,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            }
        });
    } catch(err) {
        console.error('Get users error:', err);
        res.status(500).json({ success: false, msg: 'Error loading users' });
    }
});

app.get('/api/admin/users/:id', adminMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        const transactions = await Transaction.find({ userId: user._id })
            .sort('-createdAt')
            .limit(20);
        
        const withdrawals = await Withdrawal.find({ userId: user._id })
            .sort('-createdAt');
        
        const createdLifafas = await Lifafa.find({ createdBy: user._id })
            .sort('-createdAt');
        
        res.json({
            success: true,
            user,
            transactions,
            withdrawals,
            createdLifafas
        });
    } catch(err) {
        console.error('Get user error:', err);
        res.status(500).json({ success: false, msg: 'Error loading user' });
    }
});

app.post('/api/admin/user-balance', adminMiddleware, async (req, res) => {
    try {
        const { number, amount, action, reason } = req.body;
        
        if (!number || !amount || !action) {
            return res.json({ success: false, msg: 'Number, amount and action required' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        if (amount <= 0 || amount > 1000000) {
            return res.json({ success: false, msg: 'Amount must be between ₹1 and ₹10,00,000' });
        }
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        let transactionType;
        let description;
        
        if (action === 'add') {
            user.balance += amount;
            transactionType = 'credit';
            description = reason || 'Admin credited';
        } else if (action === 'deduct') {
            if (user.balance < amount) {
                return res.json({ success: false, msg: 'Insufficient balance' });
            }
            user.balance -= amount;
            transactionType = 'debit';
            description = reason || 'Admin debited';
        } else {
            return res.json({ success: false, msg: 'Invalid action' });
        }
        
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: transactionType,
            amount,
            description
        }).save();
        
        await telegram.sendTransactionAlert(
            user.telegramUid, transactionType, amount, user.balance, description
        );
        
        res.json({ 
            success: true, 
            msg: `Balance ${action}ed successfully`,
            newBalance: user.balance
        });
        
    } catch(err) {
        console.error('Balance update error:', err);
        res.status(500).json({ success: false, msg: 'Operation failed' });
    }
});

app.post('/api/admin/block-user', adminMiddleware, async (req, res) => {
    try {
        const { number, block, reason } = req.body;
        
        if (!number) {
            return res.json({ success: false, msg: 'Number required' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        user.isBlocked = block;
        await user.save();
        
        await telegram.sendMessage(user.telegramUid,
            `🚫 *Account ${block ? 'Blocked' : 'Unblocked'}*\n\n${reason ? `Reason: ${reason}` : ''}`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ success: true, msg: `User ${block ? 'blocked' : 'unblocked'}` });
    } catch(err) {
        console.error('Block user error:', err);
        res.status(500).json({ success: false, msg: 'Operation failed' });
    }
});

app.post('/api/admin/create-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { title, amount, numbers } = req.body;
        
        if (!title || !amount) {
            return res.json({ success: false, msg: 'Title and amount required' });
        }
        
        if (title.length < 3 || title.length > 50) {
            return res.json({ success: false, msg: 'Title must be 3-50 characters' });
        }
        
        if (amount <= 0 || amount > 100000) {
            return res.json({ success: false, msg: 'Amount must be between ₹1 and ₹1,00,000' });
        }
        
        const code = 'LIF' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const allowedNumbers = numbers ? numbers.split(/[\n,]+/).map(n => n.trim()).filter(n => /^\d{10}$/.test(n)) : [];
        
        if (allowedNumbers.length > 1000) {
            return res.json({ success: false, msg: 'Maximum 1000 numbers allowed' });
        }
        
        const lifafa = new Lifafa({
            title,
            amount,
            code,
            numbers: allowedNumbers,
            createdBy: req.adminId,
            isUserCreated: false
        });
        
        await lifafa.save();
        
        res.json({ success: true, msg: 'Lifafa created', code });
        
    } catch(err) {
        console.error('Create lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Creation failed' });
    }
});

app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
    try {
        const status = req.query.status;
        let query = {};
        if (status && ['pending', 'approved', 'rejected', 'refunded'].includes(status)) {
            query.status = status;
        }
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'number username')
            .sort('-createdAt')
            .limit(100);
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        console.error('Get withdrawals error:', err);
        res.status(500).json({ success: false, msg: 'Error loading withdrawals' });
    }
});

app.post('/api/admin/update-withdrawal', adminMiddleware, async (req, res) => {
    try {
        const { withdrawalId, status, remarks } = req.body;
        
        if (!withdrawalId || !status) {
            return res.json({ success: false, msg: 'Withdrawal ID and status required' });
        }
        
        if (!['approved', 'rejected', 'refunded'].includes(status)) {
            return res.json({ success: false, msg: 'Invalid status' });
        }
        
        const withdrawal = await Withdrawal.findById(withdrawalId).populate('userId');
        if (!withdrawal) {
            return res.json({ success: false, msg: 'Withdrawal not found' });
        }
        
        const oldStatus = withdrawal.status;
        withdrawal.status = status;
        withdrawal.processedBy = req.adminId;
        withdrawal.processedAt = new Date();
        if (remarks) withdrawal.remarks = remarks;
        
        await withdrawal.save();
        
        if (status === 'refunded' && oldStatus === 'pending') {
            withdrawal.userId.balance += withdrawal.amount;
            await withdrawal.userId.save();
            
            await new Transaction({
                userId: withdrawal.userId._id,
                type: 'credit',
                amount: withdrawal.amount,
                description: 'Withdrawal refunded'
            }).save();
        }
        
        await telegram.sendWithdrawalAlert(withdrawal.userId.telegramUid, withdrawal.amount, status);
        
        res.json({ success: true, msg: `Withdrawal ${status}` });
    } catch(err) {
        console.error('Update withdrawal error:', err);
        res.status(500).json({ success: false, msg: 'Update failed' });
    }
});

app.get('/api/admin/logs', adminMiddleware, async (req, res) => {
    try {
        const logs = await Transaction.find()
            .populate('userId', 'number')
            .sort('-createdAt')
            .limit(100);
            
        res.json({ 
            success: true,
            logs: logs.map(l => ({
                id: l._id,
                type: l.type,
                user: l.userId?.number || 'Unknown',
                amount: l.amount,
                description: l.description,
                time: l.createdAt
            }))
        });
    } catch(err) {
        console.error('Get logs error:', err);
        res.status(500).json({ success: false, msg: 'Error loading logs' });
    }
});

// ==================== ADMIN - LIFAFA OVER & REFUND ====================

app.get('/api/admin/all-lifafas', adminMiddleware, async (req, res) => {
    try {
        const lifafas = await Lifafa.find()
            .populate('createdBy', 'username number')
            .sort('-createdAt')
            .limit(100);
        
        res.json({ success: true, lifafas });
    } catch(err) {
        console.error('Get all lifafas error:', err);
        res.status(500).json({ success: false, msg: 'Error loading lifafas' });
    }
});

app.post('/api/admin/lifafa-over', adminMiddleware, async (req, res) => {
    try {
        const { lifafaId, reason } = req.body;
        
        if (!lifafaId) {
            return res.json({ success: false, msg: 'Lifafa ID required' });
        }
        
        const lifafa = await Lifafa.findById(lifafaId).populate('createdBy');
        
        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }
        
        if (!lifafa.isActive) {
            return res.json({ success: false, msg: 'Lifafa is already over' });
        }
        
        const totalUsers = lifafa.totalUsers || lifafa.numbers?.length || 1;
        const claimedUsers = lifafa.claimedCount || 0;
        const remainingUsers = totalUsers - claimedUsers;
        const remainingAmount = lifafa.amount * remainingUsers;
        
        if (lifafa.createdBy && remainingAmount > 0) {
            lifafa.createdBy.balance += remainingAmount;
            await lifafa.createdBy.save();
            
            await new Transaction({
                userId: lifafa.createdBy._id,
                type: 'credit',
                amount: remainingAmount,
                description: `Refund for lifafa: ${lifafa.title} (${remainingUsers} unclaimed)`
            }).save();
            
            await telegram.sendMessage(lifafa.createdBy.telegramUid,
                `💰 *Lifafa Refund*\n\n` +
                `Your lifafa "${lifafa.title}" has been marked as over.\n` +
                `Remaining amount: ₹${remainingAmount} (${remainingUsers} unclaimed users)\n` +
                `has been refunded to your balance.`,
                { parse_mode: 'Markdown' }
            );
        }
        
        lifafa.isActive = false;
        await lifafa.save();
        
        res.json({ 
            success: true, 
            msg: 'Lifafa marked as over',
            remainingUsers,
            remainingAmount,
            refunded: remainingAmount > 0
        });
        
    } catch(err) {
        console.error('Lifafa over error:', err);
        res.status(500).json({ success: false, msg: 'Operation failed' });
    }
});

app.get('/api/admin/lifafa/:id', adminMiddleware, async (req, res) => {
    try {
        const lifafa = await Lifafa.findById(req.params.id)
            .populate('createdBy', 'username number telegramUid balance')
            .populate('claimedBy', 'username number');
        
        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }
        
        const totalUsers = lifafa.totalUsers || lifafa.numbers?.length || 1;
        const claimedUsers = lifafa.claimedCount || 0;
        const remainingUsers = totalUsers - claimedUsers;
        const remainingAmount = lifafa.amount * remainingUsers;
        
        res.json({
            success: true,
            lifafa: {
                ...lifafa.toObject(),
                stats: {
                    totalUsers,
                    claimedUsers,
                    remainingUsers,
                    totalAmount: lifafa.amount * totalUsers,
                    claimedAmount: lifafa.amount * claimedUsers,
                    remainingAmount
                }
            }
        });
    } catch(err) {
        console.error('Get lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Error loading lifafa' });
    }
});

// ==================== ADMIN - DELETE USER ====================
app.post('/api/admin/delete-user', adminMiddleware, async (req, res) => {
    try {
        const { userId, number, reason } = req.body;
        
        if (!userId || !number || !reason) {
            return res.json({ success: false, msg: 'User ID, number and reason required' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        if (user.balance > 0) {
            return res.json({ success: false, msg: 'Cannot delete user with balance > 0. Refund first.' });
        }
        
        // Start a session for transaction
        const session = await mongoose.startSession();
        session.startTransaction();
        
        try {
            await Transaction.deleteMany({ userId: user._id }).session(session);
            await Withdrawal.deleteMany({ userId: user._id }).session(session);
            await Lifafa.deleteMany({ createdBy: user._id }).session(session);
            
            await Lifafa.updateMany(
                { claimedBy: user._id },
                { $pull: { claimedBy: user._id } }
            ).session(session);
            
            await User.findByIdAndDelete(userId).session(session);
            
            await session.commitTransaction();
            session.endSession();
            
            res.json({ success: true, msg: 'User deleted successfully' });
        } catch(err) {
            await session.abortTransaction();
            session.endSession();
            throw err;
        }
        
    } catch(err) {
        console.error('Delete user error:', err);
        res.status(500).json({ success: false, msg: 'Failed to delete user' });
    }
});

// ==================== ADMIN - DELETE LIFAFA ====================
app.post('/api/admin/delete-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { lifafaId, reason } = req.body;
        
        if (!lifafaId || !reason) {
            return res.json({ success: false, msg: 'Lifafa ID and reason required' });
        }
        
        const lifafa = await Lifafa.findById(lifafaId).populate('createdBy');
        
        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }
        
        if (lifafa.isActive && lifafa.createdBy) {
            const totalUsers = lifafa.totalUsers || lifafa.numbers?.length || 1;
            const claimedUsers = lifafa.claimedCount || 0;
            const remainingUsers = totalUsers - claimedUsers;
            const remainingAmount = lifafa.amount * remainingUsers;
            
            if (remainingAmount > 0) {
                lifafa.createdBy.balance += remainingAmount;
                await lifafa.createdBy.save();
                
                await new Transaction({
                    userId: lifafa.createdBy._id,
                    type: 'credit',
                    amount: remainingAmount,
                    description: `Refund for deleted lifafa: ${lifafa.title}`
                }).save();
            }
        }
        
        await Lifafa.findByIdAndDelete(lifafaId);
        
        res.json({ success: true, msg: 'Lifafa deleted successfully' });
        
    } catch(err) {
        console.error('Delete lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Failed to delete lifafa' });
    }
});

// ==================== 404 HANDLER ====================
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        msg: 'Route not found',
        path: req.originalUrl
    });
});

// ==================== ERROR HANDLING MIDDLEWARE ====================
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err);
    
    // Check if error is a known type
    if (err.name === 'ValidationError') {
        return res.status(400).json({ 
            success: false, 
            msg: 'Validation error', 
            errors: err.errors 
        });
    }
    
    if (err.name === 'CastError') {
        return res.status(400).json({ 
            success: false, 
            msg: 'Invalid ID format' 
        });
    }
    
    if (err.code === 11000) {
        return res.status(400).json({ 
            success: false, 
            msg: 'Duplicate key error' 
        });
    }
    
    // Default error
    res.status(500).json({ 
        success: false, 
        msg: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Test endpoint: http://localhost:${PORT}/api/test`);
    console.log(`🛡️ Security middleware enabled`);
    
    // Create default admin if not exists
    setTimeout(async () => {
        try {
            const adminExists = await Admin.findOne({ username: process.env.ADMIN_USERNAME });
            if (!adminExists) {
                const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
                await new Admin({
                    username: process.env.ADMIN_USERNAME,
                    password: hashedPassword
                }).save();
                console.log('👑 Default admin created');
            }
        } catch(err) {
            console.log('❌ Error creating default admin:', err.message);
        }
    }, 2000);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('❌ UNHANDLED REJECTION:', err);
    // Close server & exit process
    server.close(() => process.exit(1));
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('❌ UNCAUGHT EXCEPTION:', err);
    // Close server & exit process
    server.close(() => process.exit(1));
});

module.exports = app;
