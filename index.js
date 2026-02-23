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
const crypto = require('crypto');

dotenv.config();

const app = express();

// ==================== SECURITY MIDDLEWARE ====================

app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://lifafa-backend.onrender.com", "https://muskilxlifafa.vercel.app", "http://localhost:5000"]
        }
    }
}));

// CORS
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
            console.log(`Blocked origin: ${origin}`);
            return callback(new Error('CORS not allowed'), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    maxAge: 600
}));

app.options('*', cors());

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, msg: 'Too many requests from this IP' }
});

app.use('/api', (req, res, next) => {
    if (req.path.startsWith('/auth')) {
        return next();
    }
    limiter(req, res, next);
});

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());
app.use(compression());

// Logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - IP: ${req.ip}`);
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

// ==================== TELEGRAM BOT SETUP ====================
let bot = null;
try {
    const TelegramBot = require('node-telegram-bot-api');
    if (process.env.TELEGRAM_BOT_TOKEN) {
        bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });
        console.log('✅ Telegram Bot Connected');
        
        bot.onText(/\/start/, (msg) => {
            bot.sendMessage(msg.chat.id, 
                `👋 Welcome to MuskilxLifafa Bot!\n\n` +
                `Commands:\n` +
                `/id - Get your Telegram ID\n` +
                `/check @channel - Check channel membership\n` +
                `/balance - Check your balance\n` +
                `/help - Show help`
            );
        });
        
        bot.onText(/\/id/, (msg) => {
            bot.sendMessage(msg.chat.id, `📱 Your Telegram ID: ${msg.chat.id}`);
        });
        
        bot.onText(/\/check (.+)/, async (msg, match) => {
            const chatId = msg.chat.id;
            const channel = match[1].replace('@', '');
            try {
                const chatMember = await bot.getChatMember(`@${channel}`, chatId);
                const isMember = ['member', 'administrator', 'creator'].includes(chatMember.status);
                bot.sendMessage(chatId, 
                    isMember ? `✅ You are a member of @${channel}` : `❌ You are NOT a member of @${channel}`
                );
            } catch(err) {
                bot.sendMessage(chatId, `❌ Error checking channel: ${err.message}`);
            }
        });
        
        bot.onText(/\/balance/, async (msg) => {
            const chatId = msg.chat.id;
            const user = await User.findOne({ telegramUid: chatId.toString() });
            if (user) {
                bot.sendMessage(chatId, `💰 Your Balance: ₹${user.balance}`);
            } else {
                bot.sendMessage(chatId, `❌ You are not registered. Please register on the website first.`);
            }
        });
    }
} catch(err) {
    console.log('⚠️ Telegram Bot Error:', err.message);
}

// Helper: Check channel membership
async function checkChannelMembership(telegramUid, channels) {
    if (!bot || !telegramUid || !channels || channels.length === 0) {
        return { success: false, missingChannels: channels || [] };
    }
    
    const missingChannels = [];
    
    for (const channel of channels) {
        try {
            const cleanChannel = channel.replace('@', '');
            const chatMember = await bot.getChatMember(`@${cleanChannel}`, telegramUid);
            const isMember = ['member', 'administrator', 'creator'].includes(chatMember.status);
            
            if (!isMember) missingChannels.push(channel);
        } catch(err) {
            missingChannels.push(channel);
        }
    }
    
    return {
        success: missingChannels.length === 0,
        missingChannels
    };
}

// ==================== DATABASE CONNECTION ====================

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    maxPoolSize: 10,
    minPoolSize: 2,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => console.log('✅ MongoDB Connected Successfully'))
.catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
});

mongoose.connection.on('error', err => {
    console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('⚠️ MongoDB disconnected');
});

process.on('SIGINT', async () => {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
    process.exit(0);
});

// ==================== MODELS ====================

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, trim: true },
    number: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
    telegramUid: { type: String, required: true, index: true },
    balance: { type: Number, default: 0, min: 0 },
    isBlocked: { type: Boolean, default: false },
    blockedNumbers: [{ type: String }], // Numbers blocked from claiming
    lastLogin: Date,
    lastLoginIp: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

// Transaction Model with TXN ID
const TransactionSchema = new mongoose.Schema({
    txnId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { 
        type: String, 
        enum: ['credit', 'debit', 'withdraw', 'lifafa_created', 'lifafa_claimed', 'admin_add', 'admin_deduct', 'pay_sent', 'pay_received'], 
        required: true 
    },
    amount: { type: Number, required: true },
    description: String,
    senderInfo: { type: String }, // For pay_received, store sender username
    receiverInfo: { type: String }, // For pay_sent, store receiver username
    createdAt: { type: Date, default: Date.now, index: true }
});

// Withdrawal Model with TXN ID
const WithdrawalSchema = new mongoose.Schema({
    txnId: { type: String, unique: true, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: true, min: 50 },
    upiId: { type: String, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'refunded'], default: 'pending' },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    processedAt: Date,
    remarks: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

// Lifafa Model
const LifafaSchema = new mongoose.Schema({
    title: { type: String, required: true },
    code: { type: String, required: true, unique: true },
    amount: { type: Number, required: true, min: 1 },
    type: { type: String, enum: ['normal', 'special'], required: true },
    numbers: [{ type: String }], // Max 3000 numbers
    totalUsers: { type: Number, default: 1 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdByAdmin: { type: Boolean, default: false },
    claimedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    claimedNumbers: [{ type: String }],
    claimedCount: { type: Number, default: 0 },
    totalAmount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    channels: [{ type: String }],
    channelRequired: { type: Boolean, default: false },
    codeUsed: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

// Code Model (60 days expiry)
const CodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    numbers: [{ type: String }],
    createdBy: String,
    createdAt: { type: Date, default: Date.now, index: true },
    expiresAt: { type: Date, default: () => new Date(+new Date() + 60*24*60*60*1000) } // 60 days
});

// Admin Model
const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

// Session Model (for tracking user logins)
const SessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    token: { type: String, required: true, unique: true },
    deviceInfo: { type: String },
    ip: String,
    createdAt: { type: Date, default: Date.now, expires: 7*24*60*60 } // Auto delete after 7 days
});

// Log Model
const LogSchema = new mongoose.Schema({
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    action: { type: String, required: true },
    details: mongoose.Schema.Types.Mixed,
    ip: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);
const Lifafa = mongoose.model('Lifafa', LifafaSchema);
const Code = mongoose.model('Code', CodeSchema);
const Admin = mongoose.model('Admin', AdminSchema);
const Session = mongoose.model('Session', SessionSchema);
const Log = mongoose.model('Log', LogSchema);

// Create indexes
UserSchema.index({ number: 1 });
UserSchema.index({ telegramUid: 1 });
LifafaSchema.index({ code: 1 });
LifafaSchema.index({ createdBy: 1, isActive: 1 });
TransactionSchema.index({ userId: 1, createdAt: -1 });
WithdrawalSchema.index({ userId: 1, status: 1 });
SessionSchema.index({ userId: 1 });
SessionSchema.index({ token: 1 });

// Create default admin
async function createDefaultAdmin() {
    try {
        const adminExists = await Admin.findOne({ username: process.env.ADMIN_USERNAME });
        if (!adminExists) {
            const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
            await new Admin({
                username: process.env.ADMIN_USERNAME,
                password: hashedPassword
            }).save();
            console.log('✅ Default admin created');
        }
    } catch(err) {
        console.log('❌ Error creating admin:', err.message);
    }
}
createDefaultAdmin();

// ==================== MIDDLEWARE ====================

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, msg: 'No token provided' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user) return res.status(401).json({ success: false, msg: 'User not found' });
        if (user.isBlocked) return res.status(403).json({ success: false, msg: 'Account is blocked' });
        
        // Update session last seen
        await Session.findOneAndUpdate(
            { token },
            { $set: { lastSeen: new Date() } }
        );
        
        req.userId = decoded.userId;
        req.user = user;
        req.token = token;
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
        if (!token) return res.status(401).json({ success: false, msg: 'No token provided' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId);
        
        if (!admin) return res.status(403).json({ success: false, msg: 'Not authorized' });
        
        req.adminId = decoded.adminId;
        req.admin = admin;
        next();
    } catch(err) {
        return res.status(401).json({ success: false, msg: 'Invalid token' });
    }
};

// Generate TXN ID
function generateTxnId(prefix = 'TXN') {
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = crypto.randomBytes(4).toString('hex').toUpperCase();
    return prefix + timestamp + random;
}

// Generate session token
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// OTP Store
const otpStore = new Map();
setInterval(() => {
    const now = Date.now();
    for (let [key, value] of otpStore.entries()) {
        if (value.expires < now) {
            otpStore.delete(key);
        }
    }
}, 5 * 60 * 1000);

// Create admin log
async function createAdminLog(adminId, action, details = {}, req) {
    try {
        await new Log({
            adminId,
            action,
            details,
            ip: req.ip || req.headers['x-forwarded-for'] || 'unknown'
        }).save();
    } catch(err) {}
}

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
            expires: Date.now() + 5 * 60 * 1000
        });
        
        if (bot) {
            await bot.sendMessage(telegramUid, `🔐 *Your Registration OTP*\n\nOTP: \`${otp}\`\nValid for 5 minutes`, { parse_mode: 'Markdown' });
        }
        
        res.json({ success: true, msg: 'OTP sent' });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { username, number, password, telegramUid, otp } = req.body;
        
        if (!username || !number || !password || !telegramUid || !otp) {
            return res.json({ success: false, msg: 'All fields required' });
        }
        
        if (username.length < 3) {
            return res.json({ success: false, msg: 'Username too short' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        if (password.length < 6) {
            return res.json({ success: false, msg: 'Password must be 6+ chars' });
        }
        
        const stored = otpStore.get(number);
        if (!stored || stored.otp !== otp || stored.telegramUid !== telegramUid) {
            return res.json({ success: false, msg: 'Invalid OTP' });
        }
        
        if (Date.now() > stored.expires) {
            otpStore.delete(number);
            return res.json({ success: false, msg: 'OTP expired' });
        }
        
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) {
            return res.json({ success: false, msg: 'Telegram ID already used' });
        }
        
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ success: false, msg: 'Number already registered' });
        }
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const user = new User({
            username,
            number,
            password: hashedPassword,
            telegramUid,
            balance: 0
        });
        
        await user.save();
        
        if (bot) {
            await bot.sendMessage(telegramUid, 
                `✅ *Registration Successful!*\n\nUsername: ${username}\nNumber: ${number}\nBalance: ₹0`,
                { parse_mode: 'Markdown' }
            );
        }
        
        otpStore.delete(number);
        res.json({ success: true, msg: 'Registration successful' });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Registration failed' });
    }
});

app.post('/api/auth/send-login-otp', async (req, res) => {
    try {
        const { number } = req.body;
        
        if (!number || !/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        if (user.isBlocked) {
            return res.json({ success: false, msg: 'Account blocked' });
        }
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        otpStore.set(`login_${number}`, {
            otp,
            userId: user._id,
            expires: Date.now() + 5 * 60 * 1000
        });
        
        if (bot) {
            await bot.sendMessage(user.telegramUid, `🔐 *Login OTP*\n\nOTP: \`${otp}\`\nValid for 5 minutes`, { parse_mode: 'Markdown' });
        }
        
        res.json({ success: true, msg: 'OTP sent' });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-login-otp', async (req, res) => {
    try {
        const { number, otp, ip, deviceInfo } = req.body;
        
        if (!number || !otp) {
            return res.json({ success: false, msg: 'Number and OTP required' });
        }
        
        const stored = otpStore.get(`login_${number}`);
        if (!stored || stored.otp !== otp) {
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
        
        // Create session token
        const sessionToken = generateSessionToken();
        const jwtToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        // Save session
        await new Session({
            userId: user._id,
            token: sessionToken,
            deviceInfo: deviceInfo || 'Unknown device',
            ip
        }).save();
        
        // Send login alert
        await sendLoginAlert(user.telegramUid, user, ip);
        
        otpStore.delete(`login_${number}`);
        
        res.json({ 
            success: true,
            token: jwtToken,
            sessionToken,
            user: { 
                number: user.number, 
                balance: user.balance, 
                username: user.username 
            }
        });
        
    } catch(err) {
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
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        stored.otp = otp;
        stored.expires = Date.now() + 5 * 60 * 1000;
        otpStore.set(key, stored);
        
        if (bot) {
            await bot.sendMessage(stored.telegramUid || stored.userId, `🔐 *New OTP*\n\nOTP: \`${otp}\`\nValid for 5 minutes`, { parse_mode: 'Markdown' });
        }
        
        res.json({ success: true, msg: 'OTP resent' });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to resend' });
    }
});

// ==================== LOGOUT ROUTES ====================

// Logout from current device
app.post('/api/user/logout-current', authMiddleware, async (req, res) => {
    try {
        // Delete current session
        await Session.findOneAndDelete({ token: req.token });
        
        res.json({ success: true, msg: 'Logged out from current device' });
    } catch(err) {
        console.error('Logout error:', err);
        res.status(500).json({ success: false, msg: 'Logout failed' });
    }
});

// Logout from all devices
app.post('/api/user/logout-all', authMiddleware, async (req, res) => {
    try {
        // Delete all sessions for this user
        await Session.deleteMany({ userId: req.userId });
        
        res.json({ success: true, msg: 'Logged out from all devices' });
    } catch(err) {
        console.error('Logout all error:', err);
        res.status(500).json({ success: false, msg: 'Failed to logout from all devices' });
    }
});

// ==================== NUMBER TOOL ROUTES ====================

app.post('/api/tool/generate-code', async (req, res) => {
    try {
        const { numbers } = req.body;
        
        if (!numbers || !Array.isArray(numbers) || numbers.length === 0) {
            return res.json({ success: false, msg: 'Valid numbers required' });
        }
        
        if (numbers.length > 3000) {
            return res.json({ success: false, msg: 'Maximum 3000 numbers allowed' });
        }
        
        const validNumbers = numbers.filter(n => /^\d{10}$/.test(n));
        
        if (validNumbers.length === 0) {
            return res.json({ success: false, msg: 'No valid 10-digit numbers' });
        }
        
        const code = 'NUM' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
        
        const codeDoc = new Code({
            code,
            numbers: validNumbers
        });
        
        await codeDoc.save();
        
        res.json({ 
            success: true, 
            code,
            count: validNumbers.length,
            expiresAt: codeDoc.expiresAt
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to generate code' });
    }
});

app.get('/api/tool/code/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        const codeDoc = await Code.findOne({ code, expiresAt: { $gt: new Date() } });
        if (!codeDoc) {
            return res.json({ success: false, msg: 'Code not found or expired' });
        }
        
        res.json({ 
            success: true, 
            numbers: codeDoc.numbers,
            count: codeDoc.numbers.length,
            expiresAt: codeDoc.expiresAt
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error fetching code' });
    }
});

// ==================== USER ROUTES ====================

app.get('/api/user/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        const unclaimedCount = await Lifafa.countDocuments({
            isActive: true,
            numbers: user.number,
            claimedNumbers: { $ne: user.number }
        });
        
        // Get active sessions count
        const activeSessions = await Session.countDocuments({ userId: user._id });
        
        res.json({ 
            success: true,
            balance: user.balance,
            username: user.username,
            number: user.number,
            telegramUid: user.telegramUid,
            unclaimedLifafas: unclaimedCount,
            activeSessions
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
        const activeSessions = await Session.countDocuments({ userId: user._id });
        
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
                blockedNumbers: user.blockedNumbers || [],
                activeSessions,
                stats: {
                    lifafasCreated: totalLifafasCreated,
                    lifafasClaimed: totalLifafasClaimed,
                    transactions: totalTransactions
                }
            }
        });
    } catch(err) {
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
            hasMore: skip + transactions.length < total
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading transactions' });
    }
});

// Pay to user with sender username instead of number
app.post('/api/user/pay', authMiddleware, async (req, res) => {
    try {
        const { receiverNumber, amount } = req.body;
        const sender = req.user;
        
        if (!receiverNumber || !/^\d{10}$/.test(receiverNumber)) {
            return res.json({ success: false, msg: 'Invalid receiver number' });
        }
        
        if (!amount || amount < 1 || amount > 100000) {
            return res.json({ success: false, msg: 'Invalid amount' });
        }
        
        if (sender.balance < amount) {
            return res.json({ success: false, msg: 'Insufficient balance' });
        }
        
        if (sender.number === receiverNumber) {
            return res.json({ success: false, msg: 'Cannot send to yourself' });
        }
        
        const receiver = await User.findOne({ number: receiverNumber });
        if (!receiver) {
            return res.json({ success: false, msg: 'Receiver not found' });
        }
        
        if (receiver.isBlocked) {
            return res.json({ success: false, msg: 'Receiver account blocked' });
        }
        
        // Generate TXN IDs
        const txnIdSent = generateTxnId('PAY');
        const txnIdReceived = generateTxnId('REC');
        
        // Update balances
        sender.balance -= amount;
        receiver.balance += amount;
        
        await sender.save();
        await receiver.save();
        
        // Create transactions with sender username instead of number
        await new Transaction({
            txnId: txnIdSent,
            userId: sender._id,
            type: 'pay_sent',
            amount,
            description: `Paid to ${receiver.username}`,
            receiverInfo: receiver.username
        }).save();
        
        await new Transaction({
            txnId: txnIdReceived,
            userId: receiver._id,
            type: 'pay_received',
            amount,
            description: `Received from ${sender.username}`,
            senderInfo: sender.username
        }).save();
        
        // Send notifications with usernames
        if (bot) {
            await bot.sendMessage(sender.telegramUid, 
                `💸 *Payment Sent*\n\nTXN ID: \`${txnIdSent}\`\nAmount: ₹${amount}\nTo: ${receiver.username}\nBalance: ₹${sender.balance}`,
                { parse_mode: 'Markdown' }
            );
            await bot.sendMessage(receiver.telegramUid,
                `💰 *Payment Received*\n\nTXN ID: \`${txnIdReceived}\`\nAmount: ₹${amount}\nFrom: ${sender.username}\nBalance: ₹${receiver.balance}`,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ 
            success: true, 
            msg: 'Payment successful',
            txnId: txnIdSent,
            newBalance: sender.balance,
            receiverName: receiver.username
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Payment failed' });
    }
});

app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        const user = req.user;
        
        if (!amount || amount < 50) {
            return res.json({ success: false, msg: 'Minimum withdrawal ₹50' });
        }
        
        if (amount > 50000) {
            return res.json({ success: false, msg: 'Maximum withdrawal ₹50,000' });
        }
        
        if (!upiId || !/^[\w\.\-]+@[\w\.\-]+$/.test(upiId)) {
            return res.json({ success: false, msg: 'Invalid UPI ID' });
        }
        
        if (user.balance < amount) {
            return res.json({ success: false, msg: 'Insufficient balance' });
        }
        
        // Check pending withdrawals
        const pendingCount = await Withdrawal.countDocuments({ 
            userId: user._id, 
            status: 'pending' 
        });
        
        if (pendingCount >= 3) {
            return res.json({ success: false, msg: 'Too many pending withdrawals' });
        }
        
        const txnId = generateTxnId('WDR');
        
        const withdrawal = new Withdrawal({
            txnId,
            userId: user._id,
            amount,
            upiId
        });
        
        await withdrawal.save();
        
        user.balance -= amount;
        await user.save();
        
        const transactionTxnId = generateTxnId('TRX');
        
        await new Transaction({
            txnId: transactionTxnId,
            userId: user._id,
            type: 'withdraw',
            amount,
            description: `Withdrawal request to ${upiId}`
        }).save();
        
        if (bot) {
            await bot.sendMessage(user.telegramUid,
                `⏳ *Withdrawal Request Submitted*\n\nTXN ID: \`${txnId}\`\nAmount: ₹${amount}\nUPI: ${upiId}\nStatus: Pending`,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ 
            success: true, 
            msg: 'Withdrawal request submitted',
            txnId,
            newBalance: user.balance
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Withdrawal failed' });
    }
});

app.get('/api/user/withdrawals', authMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId })
            .sort('-createdAt')
            .limit(50);
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading withdrawals' });
    }
});

app.post('/api/user/ban-number', authMiddleware, async (req, res) => {
    try {
        const { numberToBan } = req.body;
        const user = req.user;
        
        if (!numberToBan || !/^\d{10}$/.test(numberToBan)) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        if (!user.blockedNumbers) {
            user.blockedNumbers = [];
        }
        
        if (!user.blockedNumbers.includes(numberToBan)) {
            user.blockedNumbers.push(numberToBan);
            await user.save();
        }
        
        res.json({ success: true, msg: 'Number blocked', blockedNumbers: user.blockedNumbers });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to block number' });
    }
});

app.post('/api/user/unban-number', authMiddleware, async (req, res) => {
    try {
        const { numberToUnban } = req.body;
        const user = req.user;
        
        if (user.blockedNumbers) {
            user.blockedNumbers = user.blockedNumbers.filter(n => n !== numberToUnban);
            await user.save();
        }
        
        res.json({ success: true, msg: 'Number unblocked', blockedNumbers: user.blockedNumbers });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to unblock number' });
    }
});

// ==================== UNCLAIMED LIFAFAS WITH CHANNEL STATUS ====================

app.post('/api/user/unclaimed-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number || number !== user.number) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        const lifafas = await Lifafa.find({
            isActive: true,
            numbers: number,
            claimedNumbers: { $ne: number }
        }).sort('-createdAt');
        
        // Filter out blocked numbers
        const filteredLifafas = lifafas.filter(l => {
            if (!user.blockedNumbers || user.blockedNumbers.length === 0) return true;
            return !user.blockedNumbers.includes(l.createdBy?.toString());
        });
        
        // For each lifafa, check if user has already joined channels
        const lifafasWithStatus = await Promise.all(filteredLifafas.map(async (l) => {
            let channelStatus = 'unknown';
            let missingChannels = [];
            
            // Check channel membership if lifafa has channels
            if (l.channelRequired && l.channels && l.channels.length > 0) {
                const verification = await checkChannelMembership(user.telegramUid, l.channels);
                channelStatus = verification.success ? 'verified' : 'pending';
                missingChannels = verification.missingChannels || [];
            } else {
                channelStatus = 'not_required';
            }
            
            return {
                _id: l._id,
                title: l.title,
                amount: l.amount,
                code: l.code,
                channels: l.channels || [],
                channelRequired: l.channelRequired || false,
                channelStatus: channelStatus,
                missingChannels: missingChannels,
                totalUsers: l.totalUsers || 1,
                claimedCount: l.claimedCount || 0
            };
        }));
        
        res.json({ 
            success: true,
            lifafas: lifafasWithStatus
        });
        
    } catch(err) {
        console.error('Unclaimed lifafas error:', err);
        res.status(500).json({ success: false, msg: 'Failed to fetch lifafas' });
    }
});

// ==================== CLAIM LIFAFAS WITH CHANNEL VERIFICATION ====================

app.post('/api/user/claim-lifafa', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const user = req.user;
        
        console.log(`📝 Claim attempt - User: ${user.number}, Code: ${code}`);
        
        if (!code) {
            console.log('❌ No code provided');
            return res.json({ success: false, msg: 'Code required' });
        }
        
        // More flexible code validation
        if (!code.startsWith('LIF')) {
            console.log('❌ Invalid code format - does not start with LIF');
            return res.json({ success: false, msg: 'Invalid code format' });
        }
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) {
            console.log(`❌ Lifafa not found or inactive: ${code}`);
            return res.json({ success: false, msg: 'Invalid or expired code' });
        }
        
        console.log(`✅ Lifafa found: ${lifafa.title}, Amount: ${lifafa.amount}`);
        
        // Check if user is blocked from this creator
        if (user.blockedNumbers && user.blockedNumbers.includes(lifafa.createdBy?.toString())) {
            console.log(`❌ User blocked from this creator`);
            return res.json({ success: false, msg: 'You are blocked from claiming this lifafa' });
        }
        
        // Check if lifafa is for this number
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(user.number)) {
                console.log(`❌ User not eligible for this private lifafa`);
                return res.json({ success: false, msg: 'Not eligible for this lifafa' });
            }
        }
        
        // Check if already claimed
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(user.number)) {
            console.log(`❌ Already claimed by this user`);
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        // Check channel verification if required
        if (lifafa.channelRequired && lifafa.channels && lifafa.channels.length > 0) {
            console.log(`🔍 Checking channel membership for ${lifafa.channels.length} channels`);
            
            // Verify channel membership via Telegram
            const verification = await checkChannelMembership(user.telegramUid, lifafa.channels);
            
            if (!verification.success) {
                console.log(`❌ Channel verification failed:`, verification.missingChannels);
                return res.json({ 
                    success: false, 
                    msg: 'Channels not verified',
                    missingChannels: verification.missingChannels
                });
            }
            console.log(`✅ All channels verified`);
        }
        
        // Check if fully claimed
        const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
        if (lifafa.claimedCount >= totalAllowed) {
            console.log(`❌ Lifafa fully claimed`);
            lifafa.isActive = false;
            await lifafa.save();
            return res.json({ success: false, msg: 'This lifafa is fully claimed' });
        }
        
        // Process claim
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
        
        const txnId = generateTxnId('CLM');
        
        await new Transaction({
            txnId,
            userId: user._id,
            type: 'lifafa_claimed',
            amount: lifafa.amount,
            description: `Claimed Lifafa: ${lifafa.title}`
        }).save();
        
        console.log(`✅ Claim successful! Amount: ${lifafa.amount}, TXN: ${txnId}`);
        
        if (bot) {
            await bot.sendMessage(user.telegramUid,
                `🎉 *Lifafa Claimed!*\n\nTXN ID: \`${txnId}\`\nTitle: ${lifafa.title}\nAmount: +₹${lifafa.amount}\nBalance: ₹${user.balance}`,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ 
            success: true, 
            amount: lifafa.amount, 
            newBalance: user.balance, 
            txnId,
            channelStatus: 'verified'
        });
        
    } catch(err) {
        console.error('❌ Claim lifafa error:', err);
        res.status(500).json({ success: false, msg: 'Claim failed: ' + err.message });
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
            numbers: number,
            claimedNumbers: { $ne: number }
        });
        
        if (lifafas.length === 0) {
            return res.json({ success: false, msg: 'No unclaimed lifafas' });
        }
        
        if (lifafas.length > 10) {
            return res.json({ success: false, msg: 'Cannot claim more than 10 at once' });
        }
        
        // CHECK ALL CHANNELS FIRST
        let allChannelsVerified = true;
        let allMissingChannels = [];
        
        for (const lifafa of lifafas) {
            if (lifafa.channelRequired && lifafa.channels && lifafa.channels.length > 0) {
                const verification = await checkChannelMembership(user.telegramUid, lifafa.channels);
                
                if (!verification.success) {
                    allChannelsVerified = false;
                    allMissingChannels = [...allMissingChannels, ...verification.missingChannels];
                }
            }
        }
        
        // If any channel verification failed, return the missing channels
        if (!allChannelsVerified) {
            // Remove duplicates from missing channels
            const uniqueMissingChannels = [...new Set(allMissingChannels)];
            
            return res.json({ 
                success: false, 
                msg: 'Channel verification failed for some lifafas',
                missingChannels: uniqueMissingChannels
            });
        }
        
        // ALL CHANNELS VERIFIED - Proceed with claiming
        let totalAmount = 0;
        const claimedLifafas = [];
        const txnIds = [];
        
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
            
            const txnId = generateTxnId('CLM');
            txnIds.push(txnId);
            
            await new Transaction({
                txnId,
                userId: user._id,
                type: 'lifafa_claimed',
                amount: lifafa.amount,
                description: `Claimed lifafa: ${lifafa.title}`
            }).save();
        }
        
        user.balance += totalAmount;
        await user.save();
        
        const bulkTxnId = generateTxnId('BLK');
        
        await new Transaction({
            txnId: bulkTxnId,
            userId: user._id,
            type: 'lifafa_claimed',
            amount: totalAmount,
            description: `Bulk claimed ${lifafas.length} lifafas`
        }).save();
        
        if (bot) {
            await bot.sendMessage(user.telegramUid,
                `🎊 *Bulk Claim Successful!*\n\n` +
                `Total Lifafas: ${lifafas.length}\n` +
                `Total Amount: +₹${totalAmount}\n` +
                `New Balance: ₹${user.balance}\n` +
                `Bulk TXN: \`${bulkTxnId}\``,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ 
            success: true, 
            totalLifafas: lifafas.length, 
            totalAmount, 
            newBalance: user.balance,
            txnId: bulkTxnId,
            channelStatus: 'all_verified'
        });
        
    } catch(err) {
        console.error('Claim all error:', err);
        res.status(500).json({ success: false, msg: 'Failed to claim all' });
    }
});

// ==================== CREATE LIFAFA ====================

app.post('/api/user/create-lifafa', authMiddleware, async (req, res) => {
    try {
        const { title, amount, type, numbers, userCount, channels, channelRequired, codeUsed } = req.body;
        const user = req.user;
        
        if (!title || title.length < 3) {
            return res.json({ success: false, msg: 'Valid title required' });
        }
        
        if (!amount || amount < 1 || amount > 10000) {
            return res.json({ success: false, msg: 'Amount must be ₹1-10000' });
        }
        
        let totalUsers = 1;
        let finalNumbers = [];
        
        if (type === 'special') {
            // Get numbers from code
            if (codeUsed) {
                const codeDoc = await Code.findOne({ code: codeUsed });
                if (codeDoc) {
                    finalNumbers = codeDoc.numbers;
                }
            }
            
            // Add manual numbers
            if (numbers && numbers.trim()) {
                const manualNumbers = numbers.split(/[\n,]+/).map(n => n.trim()).filter(n => /^\d{10}$/.test(n));
                finalNumbers = [...new Set([...finalNumbers, ...manualNumbers])];
            }
            
            if (finalNumbers.length === 0) {
                return res.json({ success: false, msg: 'No valid numbers' });
            }
            
            if (finalNumbers.length > 3000) {
                return res.json({ success: false, msg: 'Maximum 3000 numbers allowed' });
            }
            
            totalUsers = finalNumbers.length;
        } else {
            // Normal lifafa
            if (userCount && parseInt(userCount) > 0) {
                totalUsers = parseInt(userCount);
                if (totalUsers > 3000) {
                    return res.json({ success: false, msg: 'Maximum 3000 users' });
                }
            }
        }
        
        const totalCost = amount * totalUsers;
        
        if (user.balance < totalCost) {
            return res.json({ success: false, msg: `Insufficient balance: Need ₹${totalCost}` });
        }
        
        const lifafaCode = 'LIF' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
        
        const lifafa = new Lifafa({
            title,
            code: lifafaCode,
            amount,
            type,
            numbers: finalNumbers,
            totalUsers,
            createdBy: user._id,
            createdByAdmin: false,
            channels: channels || [],
            channelRequired: channelRequired || false,
            codeUsed
        });
        
        await lifafa.save();
        
        user.balance -= totalCost;
        await user.save();
        
        const txnId = generateTxnId('CRT');
        
        await new Transaction({
            txnId,
            userId: user._id,
            type: 'lifafa_created',
            amount: totalCost,
            description: `Created ${type} lifafa: ${title} (${totalUsers} users)`
        }).save();
        
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const claimLink = `${baseUrl}/claimlifafa.html?code=${lifafaCode}`;
        
        if (bot) {
            let message = `🎁 *Lifafa Created!*\n\n` +
                `*Title:* ${title}\n` +
                `*Amount:* ₹${amount} per user\n` +
                `*Type:* ${type}\n` +
                `*Total Users:* ${totalUsers}\n` +
                `*Total Cost:* ₹${totalCost}\n` +
                `*TXN ID:* \`${txnId}\`\n` +
                `*Code:* \`${lifafaCode}\`\n` +
                `*Link:* ${claimLink}`;
            
            if (channels && channels.length > 0) {
                message += `\n*Channels:* ${channels.join(', ')}`;
            }
            
            await bot.sendMessage(user.telegramUid, message, { parse_mode: 'Markdown' });
        }
        
        res.json({ 
            success: true, 
            msg: 'Lifafa created successfully',
            code: lifafaCode,
            link: claimLink,
            totalUsers,
            totalCost,
            newBalance: user.balance,
            txnId
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
            .limit(100);
        
        res.json({ success: true, lifafas });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading lifafas' });
    }
});

// ==================== PUBLIC LIFAFA ROUTES ====================

app.get('/api/lifafa/:code', async (req, res) => {
    try {
        const { code } = req.params;
        
        const lifafa = await Lifafa.findOne({ code }).populate('createdBy', 'username number');
        
        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }
        
        let type = 'normal';
        let totalAllowed = 1;
        
        if (lifafa.type === 'special') {
            type = 'special';
            totalAllowed = lifafa.numbers?.length || 1;
        } else if (lifafa.totalUsers > 1) {
            type = 'public_limited';
            totalAllowed = lifafa.totalUsers;
        }
        
        res.json({
            success: true,
            lifafa: {
                title: lifafa.title,
                amount: lifafa.amount,
                code: lifafa.code,
                channels: lifafa.channels || [],
                channelRequired: lifafa.channelRequired || false,
                type: type,
                totalUsers: totalAllowed,
                claimedCount: lifafa.claimedCount || 0,
                remainingSpots: Math.max(0, totalAllowed - (lifafa.claimedCount || 0)),
                isActive: lifafa.isActive,
                createdAt: lifafa.createdAt
            }
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading lifafa' });
    }
});

app.post('/api/lifafa/claim', async (req, res) => {
    try {
        const { code, number } = req.body;
        
        if (!code || !number || !/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Valid code and number required' });
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
        
        // Check if user is blocked from this creator
        if (user.blockedNumbers && user.blockedNumbers.includes(lifafa.createdBy?.toString())) {
            return res.json({ success: false, msg: 'You are blocked from claiming this lifafa' });
        }
        
        // Check eligibility for special lifafa
        if (lifafa.type === 'special' && lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(number)) {
                return res.json({ success: false, msg: 'Not eligible for this lifafa' });
            }
        }
        
        // Check if already claimed
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        // Check channel verification if required
        if (lifafa.channelRequired && lifafa.channels && lifafa.channels.length > 0) {
            const verification = await checkChannelMembership(user.telegramUid, lifafa.channels);
            if (!verification.success) {
                return res.json({ 
                    success: false, 
                    msg: 'Channels not verified',
                    missingChannels: verification.missingChannels
                });
            }
        }
        
        // Check if fully claimed
        const totalAllowed = lifafa.type === 'special' ? lifafa.numbers?.length : lifafa.totalUsers;
        if (lifafa.claimedCount >= totalAllowed) {
            lifafa.isActive = false;
            await lifafa.save();
            return res.json({ success: false, msg: 'Fully claimed' });
        }
        
        // Process claim
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
        
        const txnId = generateTxnId('CLM');
        
        await new Transaction({
            txnId,
            userId: user._id,
            type: 'lifafa_claimed',
            amount: lifafa.amount,
            description: `Claimed lifafa: ${lifafa.title}`
        }).save();
        
        if (bot) {
            await bot.sendMessage(user.telegramUid,
                `🎉 *Lifafa Claimed!*\n\n` +
                `TXN ID: \`${txnId}\`\n` +
                `Title: ${lifafa.title}\n` +
                `Amount: +₹${lifafa.amount}\n` +
                `Balance: ₹${user.balance}`,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ 
            success: true, 
            amount: lifafa.amount, 
            newBalance: user.balance,
            txnId
        });
        
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

// Get all active sessions count
app.get('/api/admin/active-sessions', adminMiddleware, async (req, res) => {
    try {
        const totalSessions = await Session.countDocuments();
        const uniqueUsers = await Session.distinct('userId');
        
        res.json({
            success: true,
            totalSessions,
            uniqueUsers: uniqueUsers.length
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error fetching sessions' });
    }
});

// Logout all users from all devices
app.post('/api/admin/logout-all-users', adminMiddleware, async (req, res) => {
    try {
        // Delete all sessions
        const deletedCount = (await Session.deleteMany({})).deletedCount;
        
        await createAdminLog(req.adminId, 'logout_all_users', { sessionsCleared: deletedCount }, req);
        
        res.json({ 
            success: true, 
            msg: `All users logged out from all devices`,
            sessionsCleared: deletedCount
        });
    } catch(err) {
        console.error('Logout all users error:', err);
        res.status(500).json({ success: false, msg: 'Failed to logout all users' });
    }
});

// Get single user details
app.get('/api/admin/user/:userId', adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const user = await User.findById(userId).select('-password');
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        // Get user stats
        const totalLifafasCreated = await Lifafa.countDocuments({ createdBy: userId });
        const totalLifafasClaimed = await Lifafa.countDocuments({ claimedBy: userId });
        const totalTransactions = await Transaction.countDocuments({ userId });
        const recentTransactions = await Transaction.find({ userId })
            .sort('-createdAt')
            .limit(10);
        const withdrawals = await Withdrawal.find({ userId })
            .sort('-createdAt')
            .limit(10);
        const activeSessions = await Session.countDocuments({ userId });
        
        res.json({
            success: true,
            user,
            stats: {
                lifafasCreated: totalLifafasCreated,
                lifafasClaimed: totalLifafasClaimed,
                transactions: totalTransactions
            },
            recentTransactions,
            withdrawals,
            activeSessions
        });
    } catch(err) {
        console.error('Get user details error:', err);
        res.status(500).json({ success: false, msg: 'Error loading user details' });
    }
});

// Logout user from all devices (admin)
app.post('/api/admin/logout-user-all', adminMiddleware, async (req, res) => {
    try {
        const { userId } = req.body;
        
        if (!userId) {
            return res.json({ success: false, msg: 'User ID required' });
        }
        
        // Delete all sessions for this user
        const deletedCount = (await Session.deleteMany({ userId })).deletedCount;
        
        await createAdminLog(req.adminId, 'logout_user_all', { userId, sessionsCleared: deletedCount }, req);
        
        res.json({ success: true, msg: `User logged out from all devices`, sessionsCleared: deletedCount });
    } catch(err) {
        console.error('Logout user all error:', err);
        res.status(500).json({ success: false, msg: 'Failed to logout user from all devices' });
    }
});

// Create account without OTP - Allow multiple accounts with same Telegram ID
app.post('/api/admin/create-account', adminMiddleware, async (req, res) => {
    try {
        const { username, number, telegramUid, password } = req.body;
        
        if (!username || !number || !telegramUid || !password) {
            return res.json({ success: false, msg: 'All fields required' });
        }
        
        if (!/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Invalid number format' });
        }
        
        if (username.length < 3) {
            return res.json({ success: false, msg: 'Username must be at least 3 characters' });
        }
        
        if (password.length < 6) {
            return res.json({ success: false, msg: 'Password must be at least 6 characters' });
        }
        
        // Check if number exists
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ success: false, msg: 'Number already registered' });
        }
        
        // Allow multiple accounts with same Telegram ID - removed the check
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const user = new User({
            username,
            number,
            password: hashedPassword,
            telegramUid,
            balance: 0
        });
        
        await user.save();
        
        await createAdminLog(req.adminId, 'create_account', { username, number, telegramUid }, req);
        
        res.json({ success: true, msg: 'Account created', user: { username, number, telegramUid } });
    } catch(err) {
        console.error('Create account error:', err);
        res.status(500).json({ success: false, msg: 'Failed to create account: ' + err.message });
    }
});

app.post('/api/admin/login-as-user', adminMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        // Create JWT for user
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        await createAdminLog(req.adminId, 'login_as_user', { number: user.number, username: user.username }, req);
        
        res.json({ 
            success: true, 
            token,
            user: {
                number: user.number,
                username: user.username,
                balance: user.balance
            }
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to login as user' });
    }
});

app.post('/api/admin/user-balance', adminMiddleware, async (req, res) => {
    try {
        const { number, amount, action, reason } = req.body;
        
        if (!number || !amount || amount <= 0) {
            return res.json({ success: false, msg: 'Valid number and amount required' });
        }
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        const oldBalance = user.balance;
        
        if (action === 'add') {
            user.balance += amount;
        } else if (action === 'deduct') {
            if (user.balance < amount) {
                return res.json({ success: false, msg: 'Insufficient balance' });
            }
            user.balance -= amount;
        } else {
            return res.json({ success: false, msg: 'Invalid action' });
        }
        
        await user.save();
        
        const txnId = generateTxnId(action === 'add' ? 'ADD' : 'DED');
        
        await new Transaction({
            txnId,
            userId: user._id,
            type: action === 'add' ? 'admin_add' : 'admin_deduct',
            amount,
            description: reason || (action === 'add' ? 'Admin added balance' : 'Admin deducted balance')
        }).save();
        
        await createAdminLog(req.adminId, `${action}_balance`, { number, amount, reason, oldBalance, newBalance: user.balance }, req);
        
        if (bot) {
            await bot.sendMessage(user.telegramUid,
                action === 'add' 
                    ? `💰 *Balance Added*\n\nTXN ID: \`${txnId}\`\nAmount: +₹${amount}\nReason: ${reason || 'Admin credit'}\nNew Balance: ₹${user.balance}`
                    : `💸 *Balance Deducted*\n\nTXN ID: \`${txnId}\`\nAmount: -₹${amount}\nReason: ${reason || 'Admin debit'}\nNew Balance: ₹${user.balance}`,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ 
            success: true, 
            msg: `Balance ${action}ed`,
            newBalance: user.balance,
            txnId
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to update balance' });
    }
});

app.post('/api/admin/block-user', adminMiddleware, async (req, res) => {
    try {
        const { number, block, reason } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        user.isBlocked = block;
        await user.save();
        
        await createAdminLog(req.adminId, block ? 'block_user' : 'unblock_user', { number, reason }, req);
        
        if (bot && block) {
            await bot.sendMessage(user.telegramUid,
                `🔒 *Account Blocked*\n\nYour account has been blocked.\nReason: ${reason || 'No reason provided'}\nContact admin for more information.`,
                { parse_mode: 'Markdown' }
            );
        }
        
        res.json({ success: true, msg: block ? 'User blocked' : 'User unblocked' });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to update user' });
    }
});

// ✅ FIXED: Delete user with proper error handling
app.post('/api/admin/delete-user', adminMiddleware, async (req, res) => {
    try {
        const { userId, reason } = req.body;
        
        if (!userId) {
            return res.json({ success: false, msg: 'User ID required' });
        }
        
        // Find user first
        const user = await User.findById(userId);
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        console.log(`🗑️ Deleting user: ${user.username} (${user.number})`);
        
        // Delete user's sessions
        await Session.deleteMany({ userId: user._id });
        
        // Delete user's transactions
        await Transaction.deleteMany({ userId: user._id });
        
        // Delete user's withdrawals
        await Withdrawal.deleteMany({ userId: user._id });
        
        // Delete user's lifafas (optional - you might want to keep them)
        // await Lifafa.deleteMany({ createdBy: user._id });
        
        // Create log before deletion
        await createAdminLog(req.adminId, 'delete_user', { 
            number: user.number, 
            username: user.username, 
            reason 
        }, req);
        
        // Delete the user
        await User.findByIdAndDelete(userId);
        
        console.log(`✅ User deleted successfully: ${user.username}`);
        
        res.json({ success: true, msg: 'User deleted successfully' });
    } catch(err) {
        console.error('❌ Delete user error:', err);
        res.status(500).json({ success: false, msg: 'Failed to delete user: ' + err.message });
    }
});

app.post('/api/admin/ban-numbers', adminMiddleware, async (req, res) => {
    try {
        const { userId, numbers, action } = req.body;
        
        const user = await User.findById(userId);
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        if (!user.blockedNumbers) {
            user.blockedNumbers = [];
        }
        
        if (action === 'add') {
            const newNumbers = numbers.filter(n => !user.blockedNumbers.includes(n));
            user.blockedNumbers.push(...newNumbers);
        } else if (action === 'remove') {
            user.blockedNumbers = user.blockedNumbers.filter(n => !numbers.includes(n));
        }
        
        await user.save();
        
        await createAdminLog(req.adminId, 'update_blocked_numbers', { 
            userId: user._id, 
            number: user.number,
            action,
            numbers 
        }, req);
        
        res.json({ 
            success: true, 
            msg: 'Blocked numbers updated',
            blockedNumbers: user.blockedNumbers
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to update blocked numbers' });
    }
});

app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
    try {
        const status = req.query.status || 'all';
        
        let query = {};
        if (status !== 'all') {
            query.status = status;
        }
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'username number telegramUid')
            .sort('-createdAt')
            .limit(100);
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading withdrawals' });
    }
});

app.post('/api/admin/update-withdrawal', adminMiddleware, async (req, res) => {
    try {
        const { withdrawalId, status, remarks } = req.body;
        
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
        
        await createAdminLog(req.adminId, 'update_withdrawal', { 
            withdrawalId, 
            oldStatus, 
            newStatus: status,
            amount: withdrawal.amount,
            user: withdrawal.userId?.number 
        }, req);
        
        // Handle refund
        if (status === 'refunded' && withdrawal.userId) {
            withdrawal.userId.balance += withdrawal.amount;
            await withdrawal.userId.save();
            
            const txnId = generateTxnId('REF');
            
            await new Transaction({
                txnId,
                userId: withdrawal.userId._id,
                type: 'credit',
                amount: withdrawal.amount,
                description: `Withdrawal refunded: ${withdrawal.txnId}`
            }).save();
        }
        
        if (bot && withdrawal.userId) {
            let message = '';
            if (status === 'approved') {
                message = `✅ *Withdrawal Approved*\n\nTXN ID: \`${withdrawal.txnId}\`\nAmount: ₹${withdrawal.amount}\nUPI: ${withdrawal.upiId}`;
            } else if (status === 'rejected') {
                message = `❌ *Withdrawal Rejected*\n\nTXN ID: \`${withdrawal.txnId}\`\nAmount: ₹${withdrawal.amount}\nReason: ${remarks || 'No reason provided'}`;
            } else if (status === 'refunded') {
                message = `↩️ *Withdrawal Refunded*\n\nTXN ID: \`${withdrawal.txnId}\`\nAmount: ₹${withdrawal.amount} has been refunded to your balance.`;
            }
            
            if (message) {
                await bot.sendMessage(withdrawal.userId.telegramUid, message, { parse_mode: 'Markdown' });
            }
        }
        
        res.json({ success: true, msg: `Withdrawal ${status}` });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to update withdrawal' });
    }
});

app.get('/api/admin/logs', adminMiddleware, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;
        
        const logs = await Log.find()
            .populate('adminId', 'username')
            .sort('-createdAt')
            .skip(skip)
            .limit(limit);
        
        const total = await Log.countDocuments();
        
        res.json({
            success: true,
            logs,
            hasMore: skip + logs.length < total
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading logs' });
    }
});

app.get('/api/admin/all-lifafas', adminMiddleware, async (req, res) => {
    try {
        const lifafas = await Lifafa.find()
            .populate('createdBy', 'username number')
            .sort('-createdAt')
            .limit(200);
        
        res.json({ success: true, lifafas });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error loading lifafas' });
    }
});

app.post('/api/admin/delete-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { lifafaId, reason } = req.body;
        
        const lifafa = await Lifafa.findById(lifafaId).populate('createdBy');
        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }
        
        // Refund remaining amount to creator
        if (lifafa.createdBy && lifafa.isActive) {
            const remainingUsers = (lifafa.totalUsers || lifafa.numbers?.length || 1) - (lifafa.claimedCount || 0);
            const refundAmount = remainingUsers * lifafa.amount;
            
            if (refundAmount > 0) {
                lifafa.createdBy.balance += refundAmount;
                await lifafa.createdBy.save();
                
                const txnId = generateTxnId('REF');
                
                await new Transaction({
                    txnId,
                    userId: lifafa.createdBy._id,
                    type: 'credit',
                    amount: refundAmount,
                    description: `Refund for deleted lifafa: ${lifafa.title}`
                }).save();
            }
        }
        
        await createAdminLog(req.adminId, 'delete_lifafa', { 
            code: lifafa.code, 
            title: lifafa.title,
            reason 
        }, req);
        
        await Lifafa.findByIdAndDelete(lifafaId);
        
        res.json({ success: true, msg: 'Lifafa deleted' });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to delete lifafa' });
    }
});

app.post('/api/admin/lifafa-over', adminMiddleware, async (req, res) => {
    try {
        const { lifafaId, reason } = req.body;
        
        const lifafa = await Lifafa.findById(lifafaId).populate('createdBy');
        if (!lifafa) {
            return res.json({ success: false, msg: 'Lifafa not found' });
        }
        
        if (!lifafa.isActive) {
            return res.json({ success: false, msg: 'Lifafa already over' });
        }
        
        // Refund remaining amount to creator
        let refundAmount = 0;
        if (lifafa.createdBy) {
            const remainingUsers = (lifafa.totalUsers || lifafa.numbers?.length || 1) - (lifafa.claimedCount || 0);
            refundAmount = remainingUsers * lifafa.amount;
            
            if (refundAmount > 0) {
                lifafa.createdBy.balance += refundAmount;
                await lifafa.createdBy.save();
                
                const txnId = generateTxnId('REF');
                
                await new Transaction({
                    txnId,
                    userId: lifafa.createdBy._id,
                    type: 'credit',
                    amount: refundAmount,
                    description: `Refund for lifafa marked over: ${lifafa.title}`
                }).save();
            }
        }
        
        lifafa.isActive = false;
        await lifafa.save();
        
        await createAdminLog(req.adminId, 'mark_lifafa_over', { 
            code: lifafa.code, 
            title: lifafa.title,
            refundAmount,
            reason 
        }, req);
        
        res.json({ success: true, msg: 'Lifafa marked over', refundAmount });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to mark lifafa over' });
    }
});

app.post('/api/admin/unclaimed-checker', adminMiddleware, async (req, res) => {
    try {
        const { number, startDate, endDate } = req.body;
        
        if (!number || !/^\d{10}$/.test(number)) {
            return res.json({ success: false, msg: 'Valid number required' });
        }
        
        let dateQuery = {};
        if (startDate && endDate) {
            dateQuery = {
                createdAt: {
                    $gte: new Date(startDate),
                    $lte: new Date(endDate)
                }
            };
        }
        
        // Find all lifafas where this number is in numbers array
        const lifafas = await Lifafa.find({
            numbers: number,
            ...dateQuery
        }).populate('createdBy', 'username number');
        
        // Calculate totals
        const totalReceived = lifafas.length;
        const totalAmount = lifafas.reduce((sum, l) => sum + l.amount, 0);
        const claimedLifafas = lifafas.filter(l => l.claimedNumbers && l.claimedNumbers.includes(number));
        const claimedAmount = claimedLifafas.reduce((sum, l) => sum + l.amount, 0);
        const unclaimedLifafas = lifafas.filter(l => !l.claimedNumbers || !l.claimedNumbers.includes(number));
        const unclaimedAmount = unclaimedLifafas.reduce((sum, l) => sum + l.amount, 0);
        
        res.json({
            success: true,
            stats: {
                totalReceived,
                totalAmount,
                claimed: {
                    count: claimedLifafas.length,
                    amount: claimedAmount
                },
                unclaimed: {
                    count: unclaimedLifafas.length,
                    amount: unclaimedAmount
                }
            },
            lifafas: lifafas.map(l => ({
                title: l.title,
                amount: l.amount,
                code: l.code,
                createdAt: l.createdAt,
                createdBy: l.createdBy?.username || 'Admin',
                claimed: l.claimedNumbers?.includes(number) || false
            }))
        });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Error checking unclaimed' });
    }
});

app.post('/api/admin/create-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { title, amount, type, numbers, userCount, channels, channelRequired, codeUsed } = req.body;
        
        if (!title || title.length < 3) {
            return res.json({ success: false, msg: 'Valid title required' });
        }
        
        if (!amount || amount < 1 || amount > 10000) {
            return res.json({ success: false, msg: 'Amount must be ₹1-10000' });
        }
        
        let totalUsers = 1;
        let finalNumbers = [];
        
        if (type === 'special') {
            if (codeUsed) {
                const codeDoc = await Code.findOne({ code: codeUsed });
                if (codeDoc) {
                    finalNumbers = codeDoc.numbers;
                }
            }
            
            if (numbers && numbers.trim()) {
                const manualNumbers = numbers.split(/[\n,]+/).map(n => n.trim()).filter(n => /^\d{10}$/.test(n));
                finalNumbers = [...new Set([...finalNumbers, ...manualNumbers])];
            }
            
            if (finalNumbers.length === 0) {
                return res.json({ success: false, msg: 'No valid numbers' });
            }
            
            if (finalNumbers.length > 3000) {
                return res.json({ success: false, msg: 'Maximum 3000 numbers allowed' });
            }
            
            totalUsers = finalNumbers.length;
        } else {
            if (userCount && parseInt(userCount) > 0) {
                totalUsers = parseInt(userCount);
                if (totalUsers > 3000) {
                    return res.json({ success: false, msg: 'Maximum 3000 users' });
                }
            }
        }
        
        const lifafaCode = 'LIF' + Date.now().toString(36).toUpperCase() + crypto.randomBytes(3).toString('hex').toUpperCase();
        
        const lifafa = new Lifafa({
            title,
            code: lifafaCode,
            amount,
            type,
            numbers: finalNumbers,
            totalUsers,
            createdByAdmin: true,
            channels: channels || [],
            channelRequired: channelRequired || false,
            codeUsed
        });
        
        await lifafa.save();
        
        await createAdminLog(req.adminId, 'create_lifafa', { 
            code: lifafaCode, 
            title, 
            type, 
            totalUsers,
            amount 
        }, req);
        
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const claimLink = `${baseUrl}/claimlifafa.html?code=${lifafaCode}`;
        
        res.json({ 
            success: true, 
            msg: 'Lifafa created',
            code: lifafaCode,
            link: claimLink,
            totalUsers
        });
        
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Failed to create lifafa' });
    }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
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
    console.log(`✅ Channel verification system active`);
    console.log(`✅ TXN ID generation enabled`);
    console.log(`✅ Session tracking enabled`);
    console.log(`✅ Admin create account fixed (multiple accounts allowed)`);
    console.log(`✅ Delete user error fixed`);
    console.log(`✅ Pay to user shows username instead of number`);
    
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

process.on('unhandledRejection', (err) => {
    console.error('❌ UNHANDLED REJECTION:', err);
    server.close(() => process.exit(1));
});

process.on('uncaughtException', (err) => {
    console.error('❌ UNCAUGHT EXCEPTION:', err);
    server.close(() => process.exit(1));
});

module.exports = app;
