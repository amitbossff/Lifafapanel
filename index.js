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

app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
}));

const allowedOrigins = [
    'https://muskilxlifafa.vercel.app',
    'https://www.muskilxlifafa.vercel.app',
    'http://localhost:3000',
    'http://localhost:5000',
    'https://lifafa-backend.onrender.com'
];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            return callback(new Error('CORS policy violation'), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.options('*', cors());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, msg: 'Too many requests' }
});

app.use('/api', (req, res, next) => {
    if (req.path.startsWith('/auth')) return next();
    limiter(req, res, next);
});

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());

app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
    next();
});

// ==================== ENVIRONMENT CHECKS ====================

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
telegram.initBot(process.env.TELEGRAM_BOT_TOKEN);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    minPoolSize: 2,
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => {
    console.error('❌ MongoDB Error:', err);
    process.exit(1);
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
    channels: [{ type: String }],
    verificationToken: { type: String },
    verificationExpiry: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['credit', 'debit', 'withdraw', 'lifafa_created', 'lifafa_claimed'] },
    amount: { type: Number, required: true },
    description: String,
    createdAt: { type: Date, default: Date.now }
});

const LifafaSchema = new mongoose.Schema({
    title: { type: String, required: true },
    code: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    numbers: [{ type: String }],
    totalUsers: { type: Number, default: 1 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdByNumber: String,
    isUserCreated: { type: Boolean, default: true },
    claimedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    claimedNumbers: [{ type: String }],
    claimedCount: { type: Number, default: 0 },
    totalAmount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    channels: [{ type: String }],
    channelRequired: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const WithdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true, min: 50 },
    upiId: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'refunded'], default: 'pending' },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    processedAt: Date,
    remarks: String,
    createdAt: { type: Date, default: Date.now }
});

const CodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    numbers: [{ type: String }],
    createdBy: String,
    createdAt: { type: Date, default: Date.now, expires: 86400 }
});

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const VerificationSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    chatId: { type: String },
    lifafaCode: { type: String },
    channels: [{ type: String }],
    verifiedChannels: [{ type: String }],
    createdAt: { type: Date, default: Date.now, expires: 172800 } // 48 hours in seconds
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Lifafa = mongoose.model('Lifafa', LifafaSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);
const Code = mongoose.model('Code', CodeSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Verification = mongoose.model('Verification', VerificationSchema);

// ==================== MIDDLEWARE ====================

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, msg: 'No token' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(401).json({ success: false, msg: 'User not found' });
        if (user.isBlocked) return res.status(403).json({ success: false, msg: 'Account blocked' });
        
        req.userId = decoded.userId;
        req.user = user;
        next();
    } catch(err) {
        return res.status(401).json({ success: false, msg: 'Invalid token' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, msg: 'No token' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId);
        if (!admin) return res.status(403).json({ success: false, msg: 'Not authorized' });
        
        req.adminId = decoded.adminId;
        next();
    } catch(err) {
        return res.status(401).json({ success: false, msg: 'Invalid token' });
    }
};

// Store OTPs
const otpStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (let [key, value] of otpStore.entries()) {
        if (value.expires < now) otpStore.delete(key);
    }
}, 5 * 60 * 1000);

// ==================== TEST ROUTES ====================

app.get('/api/health', (req, res) => {
    res.json({ success: true, status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/api/test', (req, res) => {
    res.json({ success: true, message: 'Lifafa API is running' });
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/check-number', async (req, res) => {
    try {
        const { number } = req.body;
        if (!/^\d{10}$/.test(number)) return res.json({ success: false, msg: 'Invalid number' });
        const user = await User.findOne({ number });
        res.json({ exists: !!user });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/auth/check-telegram', async (req, res) => {
    try {
        const { telegramUid } = req.body;
        const existing = await User.findOne({ telegramUid });
        res.json({ available: !existing });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { number, telegramUid } = req.body;
        
        if (!/^\d{10}$/.test(number)) return res.json({ success: false, msg: 'Invalid number' });
        
        const existingUser = await User.findOne({ number });
        if (existingUser) return res.json({ success: false, msg: 'Number already registered' });
        
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) return res.json({ success: false, msg: 'Telegram ID already used' });
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        otpStore.set(number, {
            otp,
            telegramUid,
            expires: Date.now() + 5 * 60 * 1000
        });
        
        const sent = await telegram.sendOTP(telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { username, number, password, telegramUid, otp } = req.body;
        
        const stored = otpStore.get(number);
        if (!stored) return res.json({ success: false, msg: 'OTP expired' });
        if (stored.otp !== otp) return res.json({ success: false, msg: 'Invalid OTP' });
        if (stored.telegramUid !== telegramUid) return res.json({ success: false, msg: 'Telegram mismatch' });
        if (Date.now() > stored.expires) {
            otpStore.delete(number);
            return res.json({ success: false, msg: 'OTP expired' });
        }
        
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) return res.json({ success: false, msg: 'Telegram ID already used' });
        
        const existingUser = await User.findOne({ number });
        if (existingUser) return res.json({ success: false, msg: 'Number already registered' });
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const user = new User({
            username,
            number,
            password: hashedPassword,
            telegramUid,
            balance: 0,
            channels: []
        });
        
        await user.save();
        
        await telegram.sendMessage(telegramUid, 
            `🎉 *Registration Successful!*\n\n👤 *Username:* ${username}\n📱 *Number:* ${number}\n💰 *Balance:* ₹0`,
            { parse_mode: 'Markdown' }
        );
        
        otpStore.delete(number);
        res.json({ success: true, msg: 'Registration successful' });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Registration failed' });
    }
});

app.post('/api/auth/send-login-otp', async (req, res) => {
    try {
        const { number } = req.body;
        
        if (!/^\d{10}$/.test(number)) return res.json({ success: false, msg: 'Invalid number' });
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ success: false, msg: 'User not found' });
        if (user.isBlocked) return res.json({ success: false, msg: 'Account blocked' });
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        otpStore.set(`login_${number}`, {
            otp,
            telegramUid: user.telegramUid,
            userId: user._id,
            expires: Date.now() + 5 * 60 * 1000
        });
        
        const sent = await telegram.sendOTP(user.telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-login-otp', async (req, res) => {
    try {
        const { number, otp, ip } = req.body;
        
        const stored = otpStore.get(`login_${number}`);
        if (!stored) return res.json({ success: false, msg: 'OTP expired' });
        if (stored.otp !== otp) return res.json({ success: false, msg: 'Invalid OTP' });
        if (Date.now() > stored.expires) {
            otpStore.delete(`login_${number}`);
            return res.json({ success: false, msg: 'OTP expired' });
        }
        
        const user = await User.findById(stored.userId);
        if (!user) return res.json({ success: false, msg: 'User not found' });
        
        user.lastLogin = new Date();
        user.lastLoginIp = ip;
        await user.save();
        
        await telegram.sendLoginAlert(user.telegramUid, user, ip);
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        otpStore.delete(`login_${number}`);
        
        res.json({ 
            success: true,
            token,
            user: { 
                number: user.number, 
                balance: user.balance, 
                username: user.username,
                channels: user.channels || []
            }
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Login failed' });
    }
});

app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { number, type } = req.body;
        const key = type === 'login' ? `login_${number}` : number;
        const stored = otpStore.get(key);
        
        if (!stored) return res.json({ success: false, msg: 'Request OTP first' });
        
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
        res.status(500).json({ success: false, msg: 'Failed to resend' });
    }
});

// ==================== VERIFICATION ROUTES ====================

// Generate verification token (PUBLIC - no auth required)
app.post('/api/verification/generate', async (req, res) => {
    try {
        const { channels, lifafaCode } = req.body;
        let userId = null;
        
        // Check if user is logged in (optional)
        const token = req.headers.authorization?.split(' ')[1];
        if (token) {
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET);
                userId = decoded.userId;
            } catch(err) {
                // Ignore token errors for non-logged in users
            }
        }
        
        if (!channels || !Array.isArray(channels) || channels.length === 0) {
            return res.json({ success: false, msg: 'Channels required' });
        }
        
        // Check if user already has valid verification
        if (userId) {
            const existingVerification = await Verification.findOne({
                userId,
                channels: { $all: channels },
                createdAt: { $gt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
            });
            
            if (existingVerification) {
                const allVerified = existingVerification.verifiedChannels.length === channels.length;
                if (allVerified) {
                    return res.json({
                        success: true,
                        token: existingVerification.token,
                        alreadyVerified: true,
                        channels: channels.map(name => ({
                            name,
                            verified: existingVerification.verifiedChannels.includes(name)
                        }))
                    });
                }
            }
        }
        
        // Generate new token
        const verificationToken = 'VERIFY_' + Math.random().toString(36).substring(2, 15) + 
                     Math.random().toString(36).substring(2, 15);
        
        const verification = new Verification({
            token: verificationToken,
            userId,
            lifafaCode,
            channels,
            verifiedChannels: []
        });
        
        await verification.save();
        
        res.json({
            success: true,
            token: verificationToken,
            channels: channels.map(name => ({ name, verified: false }))
        });
        
    } catch(err) {
        console.error('Generate verification error:', err);
        res.status(500).json({ success: false, msg: 'Failed to generate verification' });
    }
});

// Check verification token
app.get('/api/verification/check/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        const verification = await Verification.findOne({ token });
        if (!verification) {
            return res.json({ success: false, msg: 'Invalid token' });
        }
        
        // Check if expired (48 hours)
        const now = Date.now();
        const createdAt = verification.createdAt.getTime();
        const expiryTime = createdAt + (48 * 60 * 60 * 1000); // 48 hours
        
        if (now > expiryTime) {
            return res.json({ success: false, msg: 'Token expired' });
        }
        
        // Get channels with verification status
        const channels = verification.channels.map(name => ({
            name,
            verified: verification.verifiedChannels.includes(name)
        }));
        
        const allVerified = channels.every(c => c.verified);
        
        res.json({
            success: true,
            channels,
            allVerified,
            expiresAt: new Date(expiryTime)
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

// Get verification status
app.get('/api/verification/status/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        const verification = await Verification.findOne({ token });
        if (!verification) {
            return res.json({ success: false, msg: 'Not found' });
        }
        
        const channels = verification.channels.map(name => ({
            name,
            verified: verification.verifiedChannels.includes(name)
        }));
        
        res.json({
            success: true,
            channels,
            allVerified: channels.every(c => c.verified)
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to get status' });
    }
});

// Verify a single channel
app.post('/api/verification/verify', async (req, res) => {
    try {
        const { token, channel, chatId } = req.body;
        
        const verification = await Verification.findOne({ token });
        if (!verification) {
            return res.json({ success: false, msg: 'Invalid token' });
        }
        
        // Check if channel is in the list
        if (!verification.channels.includes(channel)) {
            return res.json({ success: false, msg: 'Invalid channel' });
        }
        
        // Check if already verified
        if (verification.verifiedChannels.includes(channel)) {
            return res.json({ 
                success: true, 
                verified: true,
                channel,
                allVerified: verification.verifiedChannels.length === verification.channels.length
            });
        }
        
        // Here you would call Telegram API to check if user is member
        // For production, implement actual Telegram API call:
        // const isMember = await telegram.checkChannelMembership(chatId, channel);
        
        // For demo, we'll simulate successful verification
        // In production, replace with actual Telegram API check
        const isMember = true; // Simulate for demo
        
        if (!isMember) {
            return res.json({ success: false, msg: 'Not a member. Please join first.' });
        }
        
        // Mark as verified
        verification.verifiedChannels.push(channel);
        
        // Save chatId if provided
        if (chatId) {
            verification.chatId = chatId;
        }
        
        await verification.save();
        
        // If user is logged in, update their channels
        if (verification.userId) {
            const user = await User.findById(verification.userId);
            if (user && !user.channels.includes(channel)) {
                user.channels.push(channel);
                await user.save();
            }
        }
        
        res.json({ 
            success: true, 
            verified: true,
            channel,
            allVerified: verification.verifiedChannels.length === verification.channels.length
        });
        
    } catch(err) {
        console.error('Verification error:', err);
        res.status(500).json({ success: false, msg: 'Verification failed' });
    }
});

// Save chatId for verification
app.post('/api/verification/save-chatid', async (req, res) => {
    try {
        const { token, chatId } = req.body;
        
        const verification = await Verification.findOne({ token });
        if (!verification) {
            return res.json({ success: false, msg: 'Invalid token' });
        }
        
        verification.chatId = chatId;
        await verification.save();
        
        res.json({ success: true });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to save chat ID' });
    }
});

// Check user verification for lifafa
app.post('/api/verification/check-user', async (req, res) => {
    try {
        const { userId, lifafaCode } = req.body;
        
        const lifafa = await Lifafa.findOne({ code: lifafaCode });
        if (!lifafa || !lifafa.channelRequired || !lifafa.channels?.length) {
            return res.json({ success: true, verified: true }); // No channels required
        }
        
        // Check if user has valid verification
        const verification = await Verification.findOne({
            userId,
            channels: { $all: lifafa.channels },
            createdAt: { $gt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
        });
        
        if (verification) {
            const allVerified = verification.verifiedChannels.length === lifafa.channels.length;
            return res.json({
                success: true,
                verified: allVerified,
                verification
            });
        }
        
        res.json({ success: true, verified: false });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to check verification' });
    }
});

// ==================== CHANNEL ROUTES ====================

app.post('/api/channel/check-admin', async (req, res) => {
    try {
        const { channel } = req.body;
        if (!channel) return res.json({ success: false, msg: 'Channel required' });
        
        // In production, call Telegram API to check if bot is admin
        // For demo, we'll simulate
        const isAdmin = !channel.includes('invalid');
        
        res.json({
            success: true,
            channel,
            isAdmin,
            botUsername: process.env.BOT_USERNAME || 'LIFAFAXAMITBOT'
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to check admin' });
    }
});

app.post('/api/channel/generate-verification', authMiddleware, async (req, res) => {
    try {
        const { channels, lifafaCode } = req.body;
        const userId = req.userId;
        
        if (!channels || !Array.isArray(channels) || !lifafaCode) {
            return res.json({ success: false, msg: 'Missing required fields' });
        }
        
        const token = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        
        const verification = new Verification({
            token,
            userId,
            lifafaCode,
            channels,
            verifiedChannels: []
        });
        
        await verification.save();
        
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const verificationLink = `${baseUrl}/verification.html?token=${token}`;
        const botLink = `https://t.me/${process.env.BOT_USERNAME || 'LIFAFAXAMITBOT'}?start=verify_${token}`;
        
        res.json({
            success: true,
            token,
            verificationLink,
            botLink,
            botUsername: process.env.BOT_USERNAME || 'LIFAFAXAMITBOT'
        });
        
    } catch(err) {
        console.error('Generate verification error:', err);
        res.status(500).json({ success: false, msg: 'Failed to generate verification' });
    }
});

app.get('/api/channel/verification-status/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        const verification = await Verification.findOne({ token });
        if (!verification) {
            return res.json({ success: false, msg: 'Verification not found' });
        }
        
        const channels = verification.channels.map(name => ({
            name,
            verified: verification.verifiedChannels.includes(name)
        }));
        
        const allVerified = channels.every(c => c.verified);
        
        res.json({
            success: true,
            token,
            channels,
            allVerified
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to get status' });
    }
});

app.post('/api/channel/mark-verified', async (req, res) => {
    try {
        const { token, channel } = req.body;
        
        const verification = await Verification.findOne({ token });
        if (!verification) {
            return res.json({ success: false, msg: 'Verification not found' });
        }
        
        if (!verification.verifiedChannels.includes(channel)) {
            verification.verifiedChannels.push(channel);
            await verification.save();
            
            // Update user's channels if userId exists
            if (verification.userId) {
                const user = await User.findById(verification.userId);
                if (user && !user.channels.includes(channel)) {
                    user.channels.push(channel);
                    await user.save();
                }
            }
        }
        
        res.json({
            success: true,
            token,
            channel,
            verified: true,
            allVerified: verification.verifiedChannels.length === verification.channels.length
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to mark verified' });
    }
});

// ==================== NUMBER TOOL ROUTES ====================

app.post('/api/tool/generate-code', async (req, res) => {
    try {
        const { numbers, userId } = req.body;
        
        if (!numbers || !Array.isArray(numbers) || numbers.length === 0) {
            return res.json({ success: false, msg: 'Valid numbers required' });
        }
        
        const validNumbers = numbers.filter(n => /^\d{10}$/.test(n));
        if (validNumbers.length === 0) {
            return res.json({ success: false, msg: 'No valid numbers' });
        }
        
        const code = 'NUM' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const codeDoc = new Code({
            code,
            numbers: validNumbers,
            createdBy: userId || 'anonymous'
        });
        
        await codeDoc.save();
        
        res.json({ success: true, code, count: validNumbers.length });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to generate code' });
    }
});

app.get('/api/tool/code/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const codeDoc = await Code.findOne({ code });
        if (!codeDoc) return res.json({ success: false, msg: 'Code not found' });
        
        res.json({ success: true, numbers: codeDoc.numbers, count: codeDoc.numbers.length });
    } catch(err) {
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
        
        // Check active verification
        const activeVerification = await Verification.findOne({
            userId: user._id,
            createdAt: { $gt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
        }).sort('-createdAt');
        
        res.json({ 
            success: true,
            balance: user.balance,
            username: user.username,
            number: user.number,
            telegramUid: user.telegramUid,
            channels: user.channels || [],
            unclaimedLifafas: unclaimedCount,
            recentTransactions,
            createdLifafas,
            verification: activeVerification ? {
                token: activeVerification.token,
                channels: activeVerification.channels,
                verifiedChannels: activeVerification.verifiedChannels,
                allVerified: activeVerification.verifiedChannels.length === activeVerification.channels.length
            } : null
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading dashboard' });
    }
});

app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        const totalLifafasCreated = await Lifafa.countDocuments({ createdBy: user._id });
        const totalLifafasClaimed = await Lifafa.countDocuments({ claimedBy: user._id });
        const totalTransactions = await Transaction.countDocuments({ userId: user._id });
        
        // Get all verifications
        const verifications = await Verification.find({ 
            userId: user._id,
            createdAt: { $gt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
        }).sort('-createdAt');
        
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
                channels: user.channels || [],
                stats: {
                    lifafasCreated: totalLifafasCreated,
                    lifafasClaimed: totalLifafasClaimed,
                    transactions: totalTransactions,
                    verifications: verifications.length
                }
            }
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading profile' });
    }
});

app.post('/api/user/pay', authMiddleware, async (req, res) => {
    try {
        const { receiverNumber, amount } = req.body;
        const sender = req.user;
        
        if (!/^\d{10}$/.test(receiverNumber)) return res.json({ success: false, msg: 'Invalid number' });
        if (amount <= 0 || amount > 100000) return res.json({ success: false, msg: 'Invalid amount' });
        if (sender.balance < amount) return res.json({ success: false, msg: 'Insufficient balance' });
        
        const receiver = await User.findOne({ number: receiverNumber });
        if (!receiver) return res.json({ success: false, msg: 'Receiver not found' });
        if (receiver.isBlocked) return res.json({ success: false, msg: 'Receiver blocked' });
        if (sender.number === receiverNumber) return res.json({ success: false, msg: 'Cannot send to self' });
        
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
        res.status(500).json({ success: false, msg: 'Payment failed' });
    }
});

app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        const user = req.user;
        
        if (amount < 50) return res.json({ success: false, msg: 'Minimum ₹50' });
        if (amount > 50000) return res.json({ success: false, msg: 'Maximum ₹50,000' });
        if (!/^[\w\.\-]+@[\w\.\-]+$/.test(upiId)) return res.json({ success: false, msg: 'Invalid UPI' });
        if (user.balance < amount) return res.json({ success: false, msg: 'Insufficient balance' });
        
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
            description: `Withdrawal to ${upiId}`
        }).save();
        
        await telegram.sendWithdrawalAlert(user.telegramUid, amount, 'pending');
        
        res.json({ success: true, msg: 'Withdrawal requested', newBalance: user.balance });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Withdrawal failed' });
    }
});

app.get('/api/user/withdrawals', authMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId }).sort('-createdAt');
        res.json({ success: true, withdrawals });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading withdrawals' });
    }
});

app.post('/api/user/create-lifafa', authMiddleware, async (req, res) => {
    try {
        const { title, amount, code, numbers, userCount, channels, channelRequired } = req.body;
        const user = req.user;
        
        if (!title || !amount || amount <= 0) {
            return res.json({ success: false, msg: 'Title and amount required' });
        }
        
        let allowedNumbers = [];
        if (code) {
            const codeDoc = await Code.findOne({ code });
            if (codeDoc) allowedNumbers = codeDoc.numbers;
        } else if (numbers && numbers.trim()) {
            allowedNumbers = numbers
                .split(/[\n,]+/)
                .map(n => n.trim())
                .filter(n => /^\d{10}$/.test(n));
        }
        
        let totalUsers = 1;
        let lifafaType = 'public_unlimited';
        
        if (allowedNumbers.length > 0) {
            totalUsers = allowedNumbers.length;
            lifafaType = 'private';
        } else if (userCount && parseInt(userCount) > 0) {
            totalUsers = parseInt(userCount);
            lifafaType = 'public_limited';
        } else if (numbers && numbers.trim()) {
            const manualNumbers = numbers.split('\n').filter(n => n.trim());
            allowedNumbers = manualNumbers;
            totalUsers = manualNumbers.length;
            lifafaType = 'private';
        }
        
        const totalCost = amount * totalUsers;
        
        if (user.balance < totalCost) {
            return res.json({ success: false, msg: `Required: ₹${totalCost}` });
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
            claimedNumbers: [],
            channels: channels || [],
            channelRequired: channelRequired || false
        });
        
        await lifafa.save();
        
        user.balance -= totalCost;
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: 'debit',
            amount: totalCost,
            description: `Created ${lifafaType} Lifafa: ${title}`
        }).save();
        
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const shareableLink = `${baseUrl}/claimlifafa.html?code=${lifafaCode}`;
        
        let message = `🎁 *Lifafa Created!*\n\n*Title:* ${title}\n*Amount:* ₹${amount}`;
        if (lifafaType === 'private') {
            message += `\n*Type:* Private (${totalUsers} users)`;
        } else if (lifafaType === 'public_limited') {
            message += `\n*Type:* Public Limited (${totalUsers} spots)`;
        } else {
            message += `\n*Type:* Public Unlimited`;
        }
        if (channels && channels.length > 0) {
            message += `\n*Channels:* ${channels.join(', ')}`;
        }
        message += `\n*Code:* \`${lifafaCode}\`\n*Link:* ${shareableLink}`;
        
        await telegram.sendMessage(user.telegramUid, message, { parse_mode: 'Markdown' });
        
        res.json({ 
            success: true, 
            msg: 'Lifafa created',
            code: lifafaCode,
            link: shareableLink,
            totalUsers,
            totalCost,
            newBalance: user.balance,
            type: lifafaType,
            channels,
            channelRequired
        });
        
    } catch(err) {
        console.error('Create lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Failed to create' });
    }
});

app.get('/api/user/my-lifafas', authMiddleware, async (req, res) => {
    try {
        const lifafas = await Lifafa.find({ createdBy: req.userId }).sort('-createdAt');
        res.json({ success: true, lifafas });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading lifafas' });
    }
});

app.post('/api/user/unclaimed-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number || number !== user.number) return res.json({ success: false, msg: 'Invalid number' });
        
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
                channels: l.channels,
                channelRequired: l.channelRequired,
                isPublic: false,
                totalUsers: l.totalUsers || 1,
                claimedCount: l.claimedCount || 0
            }))
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to fetch' });
    }
});

app.post('/api/user/claim-lifafa', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const user = req.user;
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) return res.json({ success: false, msg: 'Invalid code' });
        
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(user.number)) {
                return res.json({ success: false, msg: 'Not eligible' });
            }
        }
        
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(user.number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        // Check channel verification if required
        if (lifafa.channelRequired && lifafa.channels && lifafa.channels.length > 0) {
            // First check if user has channels in their profile
            const userChannels = user.channels || [];
            const missingFromProfile = lifafa.channels.filter(c => !userChannels.includes(c));
            
            if (missingFromProfile.length > 0) {
                // Check if there's an active verification
                const verification = await Verification.findOne({
                    userId: user._id,
                    channels: { $all: lifafa.channels },
                    createdAt: { $gt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
                });
                
                if (!verification) {
                    return res.json({ 
                        success: false, 
                        msg: 'Channels not verified',
                        missingChannels: lifafa.channels
                    });
                }
                
                const missingFromVerification = lifafa.channels.filter(c => !verification.verifiedChannels.includes(c));
                if (missingFromVerification.length > 0) {
                    return res.json({ 
                        success: false, 
                        msg: 'Channels not verified',
                        missingChannels: missingFromVerification
                    });
                }
                
                // Update user's channels
                lifafa.channels.forEach(c => {
                    if (!user.channels.includes(c)) {
                        user.channels.push(c);
                    }
                });
                await user.save();
            }
        }
        
        const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
        if (lifafa.claimedCount >= totalAllowed) {
            return res.json({ success: false, msg: 'Fully claimed' });
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
            description: `Claimed: ${lifafa.title}`
        }).save();
        
        await telegram.sendLifafaClaimAlert(user.telegramUid, lifafa, user.balance);
        
        res.json({ success: true, amount: lifafa.amount, newBalance: user.balance });
        
    } catch(err) {
        console.error('Claim error:', err);
        res.status(500).json({ success: false, msg: 'Claim failed' });
    }
});

// ==================== PUBLIC LIFAFA ROUTES ====================

app.get('/api/lifafa/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        const lifafa = await Lifafa.findOne({ code }).populate('createdBy', 'username number');
        if (!lifafa) return res.json({ success: false, msg: 'Lifafa not found' });

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
                channels: lifafa.channels || [],
                channelRequired: lifafa.channelRequired || false,
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
        res.status(500).json({ success: false, msg: 'Server error' });
    }
});

app.post('/api/lifafa/claim', async (req, res) => {
    try {
        const { code, number } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ success: false, msg: 'User not found' });
        if (user.isBlocked) return res.json({ success: false, msg: 'Account blocked' });
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) return res.json({ success: false, msg: 'Invalid code' });
        
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(number)) {
                return res.json({ success: false, msg: 'Not eligible' });
            }
        }
        
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        // Check channel verification if required
        if (lifafa.channelRequired && lifafa.channels && lifafa.channels.length > 0) {
            // First check if user has channels in their profile
            const userChannels = user.channels || [];
            const missingFromProfile = lifafa.channels.filter(c => !userChannels.includes(c));
            
            if (missingFromProfile.length > 0) {
                // Check if there's an active verification
                const verification = await Verification.findOne({
                    userId: user._id,
                    channels: { $all: lifafa.channels },
                    createdAt: { $gt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
                });
                
                if (!verification) {
                    return res.json({ 
                        success: false, 
                        msg: 'Channels not verified',
                        missingChannels: lifafa.channels
                    });
                }
                
                const missingFromVerification = lifafa.channels.filter(c => !verification.verifiedChannels.includes(c));
                if (missingFromVerification.length > 0) {
                    return res.json({ 
                        success: false, 
                        msg: 'Channels not verified',
                        missingChannels: missingFromVerification
                    });
                }
                
                // Update user's channels
                lifafa.channels.forEach(c => {
                    if (!user.channels.includes(c)) {
                        user.channels.push(c);
                    }
                });
                await user.save();
            }
        }
        
        const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
        if (lifafa.claimedCount >= totalAllowed) {
            lifafa.isActive = false;
            await lifafa.save();
            return res.json({ success: false, msg: 'Fully claimed' });
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
            description: `Claimed: ${lifafa.title}`
        }).save();
        
        res.json({ success: true, amount: lifafa.amount, newBalance: user.balance });
        
    } catch(err) {
        console.error('Claim error:', err);
        res.status(500).json({ success: false, msg: 'Claim failed' });
    }
});

// ==================== TELEGRAM WEBHOOK (Optional) ====================
app.post('/webhook/telegram', (req, res) => {
    // Handle Telegram webhook updates
    // This is where you'd process updates if using webhook instead of polling
    res.sendStatus(200);
});

// ==================== 404 HANDLER ====================
app.use('*', (req, res) => {
    res.status(404).json({ success: false, msg: 'Route not found' });
});

// ==================== ERROR HANDLER ====================
app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    res.status(500).json({ success: false, msg: 'Internal server error' });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    
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
            console.log('❌ Error creating admin:', err.message);
        }
    }, 2000);
});

process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled rejection:', err);
    server.close(() => process.exit(1));
});

module.exports = app;
