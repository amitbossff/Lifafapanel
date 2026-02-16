const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const telegram = require('./utils/telegram');

dotenv.config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json());

// Initialize Telegram Bot
const bot = telegram.initBot(process.env.TELEGRAM_BOT_TOKEN);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.log('❌ MongoDB Error:', err));

// ==================== MODELS ====================

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    number: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    telegramUid: { type: String, required: true, unique: true },
    telegramChatId: String,
    isTelegramVerified: { type: Boolean, default: false },
    balance: { type: Number, default: 0 }, // ₹0 STARTING BALANCE
    isBlocked: { type: Boolean, default: false },
    lastLogin: Date,
    lastLoginIp: String,
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['credit', 'debit', 'withdraw', 'lifafa'], required: true },
    amount: { type: Number, required: true },
    description: String,
    createdAt: { type: Date, default: Date.now }
});

const LifafaSchema = new mongoose.Schema({
    title: { type: String, required: true },
    code: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    channel: String,
    numbers: [{ type: String }],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    claimedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    claimedNumbers: [{ type: String }],
    claimedCount: { type: Number, default: 0 },
    totalAmount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const WithdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    processedAt: Date,
    remarks: String,
    createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Transaction = mongoose.model('Transaction', TransactionSchema);
const Lifafa = mongoose.model('Lifafa', LifafaSchema);
const Withdrawal = mongoose.model('Withdrawal', WithdrawalSchema);
const Admin = mongoose.model('Admin', AdminSchema);

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
        return res.status(401).json({ success: false, msg: 'Invalid token' });
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

// Store OTPs
const otpStore = new Map();

// Cleanup old OTPs every hour
setInterval(() => {
    const now = Date.now();
    for (let [key, value] of otpStore.entries()) {
        if (value.expires < now) {
            otpStore.delete(key);
        }
    }
}, 60 * 60 * 1000);

// ==================== AUTH ROUTES ====================

// Check if number exists
app.post('/api/auth/check-number', async (req, res) => {
    try {
        const { number } = req.body;
        const user = await User.findOne({ number });
        res.json({ exists: !!user });
    } catch(err) {
        res.json({ exists: false });
    }
});

// Check if Telegram UID is available
app.post('/api/auth/check-telegram', async (req, res) => {
    try {
        const { telegramUid } = req.body;
        
        const existing = await User.findOne({ telegramUid });
        
        res.json({ 
            available: !existing,
            exists: !!existing
        });
    } catch(err) {
        res.json({ available: false });
    }
});

// Send OTP for registration
app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { number, telegramUid } = req.body;
        
        if (!number || !telegramUid) {
            return res.json({ success: false, msg: 'Number and Telegram UID required' });
        }
        
        // Check if number exists
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ success: false, msg: 'Number already registered' });
        }
        
        // Check if Telegram UID already used
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) {
            return res.json({ success: false, msg: 'This Telegram account is already linked to another user' });
        }
        
        // Check if Telegram UID is valid
        const isValid = await telegram.checkTelegramUID(telegramUid);
        if (!isValid) {
            return res.json({ success: false, msg: 'Invalid Telegram UID. Please send /start to bot first' });
        }
        
        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store OTP
        otpStore.set(number, {
            otp,
            telegramUid,
            expires: Date.now() + 5 * 60 * 1000
        });
        
        // Send OTP via Telegram
        const sent = await telegram.sendOTP(telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent to your Telegram' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP. Check Telegram UID' });
        }
        
    } catch(err) {
        console.error('Send OTP error:', err);
        res.json({ success: false, msg: 'Failed to send OTP' });
    }
});

// Verify OTP and Register
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { username, number, password, telegramUid, otp } = req.body;
        
        // Check OTP
        const stored = otpStore.get(number);
        
        if (!stored) {
            return res.json({ success: false, msg: 'OTP expired or not requested' });
        }
        
        if (stored.otp !== otp) {
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
            return res.json({ success: false, msg: 'This Telegram account is already linked to another user' });
        }
        
        // Check if number exists
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ success: false, msg: 'Number already registered' });
        }
        
        // Create user with ₹0 balance
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const user = new User({
            username,
            number,
            password: hashedPassword,
            telegramUid,
            telegramChatId: telegramUid,
            isTelegramVerified: true,
            balance: 0 // ₹0 STARTING BALANCE - NO BONUS
        });
        
        await user.save();
        
        // NO WELCOME TRANSACTION - NO BONUS
        
        // Send welcome message
        await telegram.sendMessage(telegramUid, 
            `🎉 *Registration Successful!*\n\n` +
            `👤 *Username:* ${username}\n` +
            `📱 *Number:* ${number}\n` +
            `💰 *Balance:* ₹0\n\n` +
            `Start using the app now!`,
            { parse_mode: 'Markdown' }
        );
        
        // Clear OTP
        otpStore.delete(number);
        
        res.json({ success: true, msg: 'Registration successful' });
        
    } catch(err) {
        console.error('Verify OTP error:', err);
        res.json({ success: false, msg: 'Registration failed' });
    }
});

// Send Login OTP
app.post('/api/auth/send-login-otp', async (req, res) => {
    try {
        const { number } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        if (user.isBlocked) {
            return res.json({ success: false, msg: 'Account is blocked' });
        }
        
        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store OTP
        otpStore.set(`login_${number}`, {
            otp,
            telegramUid: user.telegramUid,
            userId: user._id,
            expires: Date.now() + 5 * 60 * 1000
        });
        
        // Send OTP via Telegram
        const sent = await telegram.sendOTP(user.telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent to your Telegram' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
        
    } catch(err) {
        console.error('Send login OTP error:', err);
        res.json({ success: false, msg: 'Failed to send OTP' });
    }
});

// Verify Login OTP
app.post('/api/auth/verify-login-otp', async (req, res) => {
    try {
        const { number, otp, ip } = req.body;
        
        const stored = otpStore.get(`login_${number}`);
        
        if (!stored) {
            return res.json({ success: false, msg: 'OTP expired or not requested' });
        }
        
        if (stored.otp !== otp) {
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
        
        // Generate token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        // Clear OTP
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
        res.json({ success: false, msg: 'Login failed' });
    }
});

// Resend OTP
app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { number, type } = req.body;
        
        const key = type === 'login' ? `login_${number}` : number;
        const stored = otpStore.get(key);
        
        if (!stored) {
            return res.json({ success: false, msg: 'Request OTP first' });
        }
        
        // Generate new OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        stored.otp = otp;
        stored.expires = Date.now() + 5 * 60 * 1000;
        otpStore.set(key, stored);
        
        // Send OTP
        const sent = await telegram.sendOTP(stored.telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP resent' });
        } else {
            res.json({ success: false, msg: 'Failed to resend' });
        }
        
    } catch(err) {
        console.error('Resend OTP error:', err);
        res.json({ success: false, msg: 'Failed to resend' });
    }
});

// ==================== USER ROUTES ====================

// Dashboard
app.get('/api/user/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        // Get recent transactions
        const recentTransactions = await Transaction.find({ userId: user._id })
            .sort('-createdAt')
            .limit(5);
        
        // Get unclaimed lifafa count
        const unclaimedCount = await Lifafa.countDocuments({
            isActive: true,
            numbers: user.number,
            claimedNumbers: { $ne: user.number }
        });
        
        res.json({ 
            success: true,
            balance: user.balance,
            username: user.username,
            number: user.number,
            telegramUid: user.telegramUid,
            unclaimedLifafas: unclaimedCount,
            recentTransactions
        });
    } catch(err) {
        console.error('Dashboard error:', err);
        res.json({ success: false, msg: 'Error loading dashboard' });
    }
});

// Transactions
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
        res.json({ success: false, msg: 'Error loading transactions' });
    }
});

// Pay to user
app.post('/api/user/pay', authMiddleware, async (req, res) => {
    try {
        const { receiverNumber, amount } = req.body;
        
        if (!receiverNumber || !amount) {
            return res.json({ success: false, msg: 'Receiver number and amount required' });
        }
        
        if (amount <= 0) {
            return res.json({ success: false, msg: 'Invalid amount' });
        }
        
        const sender = req.user;
        
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
        
        // Update balances
        sender.balance -= amount;
        receiver.balance += amount;
        
        await sender.save();
        await receiver.save();
        
        // Create transactions
        const senderTransaction = new Transaction({
            userId: sender._id,
            type: 'debit',
            amount,
            description: `Paid to ${receiverNumber}`
        });
        
        const receiverTransaction = new Transaction({
            userId: receiver._id,
            type: 'credit',
            amount,
            description: `Received from ${sender.number}`
        });
        
        await senderTransaction.save();
        await receiverTransaction.save();
        
        // Send Telegram notifications
        await telegram.sendTransactionAlert(
            sender.telegramUid, 
            'debit', 
            amount, 
            sender.balance, 
            `Paid to ${receiverNumber}`
        );
        
        await telegram.sendTransactionAlert(
            receiver.telegramUid, 
            'credit', 
            amount, 
            receiver.balance, 
            `Received from ${sender.number}`
        );
        
        res.json({ success: true, msg: 'Payment successful', newBalance: sender.balance });
        
    } catch(err) {
        console.error('Pay error:', err);
        res.json({ success: false, msg: 'Payment failed' });
    }
});

// Withdraw request
app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = req.user;
        
        if (!amount || amount <= 0) {
            return res.json({ success: false, msg: 'Invalid amount' });
        }
        
        if (user.balance < amount) {
            return res.json({ success: false, msg: 'Insufficient balance' });
        }
        
        // Minimum withdrawal
        if (amount < 50) {
            return res.json({ success: false, msg: 'Minimum withdrawal amount is ₹50' });
        }
        
        // Create withdrawal request
        const withdrawal = new Withdrawal({
            userId: user._id,
            amount
        });
        
        await withdrawal.save();
        
        // Freeze amount
        user.balance -= amount;
        await user.save();
        
        // Create transaction
        await new Transaction({
            userId: user._id,
            type: 'debit',
            amount,
            description: 'Withdrawal request',
            referenceId: withdrawal._id
        }).save();
        
        // Notify user
        await telegram.sendWithdrawalAlert(user.telegramUid, amount, 'pending');
        
        res.json({ 
            success: true, 
            msg: 'Withdrawal request submitted', 
            newBalance: user.balance,
            withdrawalId: withdrawal._id
        });
        
    } catch(err) {
        console.error('Withdraw error:', err);
        res.json({ success: false, msg: 'Withdrawal request failed' });
    }
});

// Get withdrawal status
app.get('/api/user/withdrawals', authMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId })
            .sort('-createdAt');
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        res.json({ success: false, msg: 'Error loading withdrawals' });
    }
});

// Get unclaimed lifafas for user
app.post('/api/user/unclaimed-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number) {
            return res.json({ success: false, msg: 'Number required' });
        }
        
        if (number !== user.number) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        // Find all active lifafas where number is in allowed numbers and not claimed by this user/number
        const lifafas = await Lifafa.find({
            isActive: true,
            numbers: number,
            claimedNumbers: { $ne: number },
            claimedBy: { $ne: user._id }
        }).sort('-createdAt');
        
        res.json({ 
            success: true,
            lifafas: lifafas.map(l => ({
                _id: l._id,
                title: l.title,
                amount: l.amount,
                code: l.code,
                channel: l.channel
            }))
        });
        
    } catch(err) {
        console.error('Unclaimed lifafas error:', err);
        res.json({ success: false, msg: 'Failed to fetch lifafas' });
    }
});

// Claim single lifafa
app.post('/api/user/claim-lifafa', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const user = req.user;
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) {
            return res.json({ success: false, msg: 'Invalid or expired code' });
        }
        
        // Check if number is allowed
        if (!lifafa.numbers.includes(user.number)) {
            return res.json({ success: false, msg: 'You are not eligible for this lifafa' });
        }
        
        // Check if already claimed by number
        if (lifafa.claimedNumbers.includes(user.number)) {
            return res.json({ success: false, msg: 'You have already claimed this lifafa' });
        }
        
        // Check if already claimed by user
        if (lifafa.claimedBy.includes(user._id)) {
            return res.json({ success: false, msg: 'You have already claimed this lifafa' });
        }
        
        // Add to user balance
        user.balance += lifafa.amount;
        await user.save();
        
        // Mark as claimed
        lifafa.claimedBy.push(user._id);
        lifafa.claimedNumbers.push(user.number);
        lifafa.claimedCount += 1;
        lifafa.totalAmount += lifafa.amount;
        await lifafa.save();
        
        // Create transaction
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: lifafa.amount,
            description: `Lifafa: ${lifafa.title}`
        }).save();
        
        // Telegram notification
        await telegram.sendLifafaClaimAlert(user.telegramUid, lifafa, user.balance);
        
        res.json({ 
            success: true,
            amount: lifafa.amount,
            newBalance: user.balance,
            msg: 'Claimed successfully'
        });
        
    } catch(err) {
        console.error('Claim lifafa error:', err);
        res.json({ success: false, msg: 'Claim failed' });
    }
});

// Claim all unclaimed lifafas
app.post('/api/user/claim-all-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number || number !== user.number) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        // Find all unclaimed lifafas
        const lifafas = await Lifafa.find({
            isActive: true,
            numbers: number,
            claimedNumbers: { $ne: number },
            claimedBy: { $ne: user._id }
        });
        
        if (lifafas.length === 0) {
            return res.json({ success: false, msg: 'No unclaimed lifafas' });
        }
        
        let totalAmount = 0;
        const claimedLifafas = [];
        
        // Claim each lifafa
        for (const lifafa of lifafas) {
            totalAmount += lifafa.amount;
            claimedLifafas.push({
                title: lifafa.title,
                amount: lifafa.amount,
                code: lifafa.code
            });
            
            lifafa.claimedBy.push(user._id);
            lifafa.claimedNumbers.push(number);
            lifafa.claimedCount += 1;
            lifafa.totalAmount += lifafa.amount;
            await lifafa.save();
        }
        
        // Add total amount to balance
        user.balance += totalAmount;
        await user.save();
        
        // Create single transaction for all
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: totalAmount,
            description: `Bulk claimed ${lifafas.length} lifafas`
        }).save();
        
        // Telegram notification
        await telegram.sendBulkLifafaClaimAlert(
            user.telegramUid, 
            lifafas.length, 
            totalAmount, 
            user.balance
        );
        
        res.json({ 
            success: true,
            totalLifafas: lifafas.length,
            totalAmount,
            newBalance: user.balance,
            claimed: claimedLifafas,
            msg: `Successfully claimed ${lifafas.length} lifafas worth ₹${totalAmount}`
        });
        
    } catch(err) {
        console.error('Claim all lifafas error:', err);
        res.json({ success: false, msg: 'Failed to claim lifafas' });
    }
});

// Get user profile
app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const user = req.user;
        
        res.json({
            success: true,
            profile: {
                username: user.username,
                number: user.number,
                telegramUid: user.telegramUid,
                balance: user.balance,
                joinedAt: user.createdAt,
                lastLogin: user.lastLogin
            }
        });
    } catch(err) {
        res.json({ success: false, msg: 'Error loading profile' });
    }
});

// ==================== ADMIN ROUTES ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if admin exists
        let admin = await Admin.findOne({ username });
        
        // Create default admin if not exists and credentials match .env
        if (!admin && username === process.env.ADMIN_USERNAME) {
            const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
            admin = new Admin({
                username: process.env.ADMIN_USERNAME,
                password: hashedPassword
            });
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
        
        const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ 
            success: true, 
            token,
            admin: {
                username: admin.username,
                role: admin.role
            }
        });
    } catch(err) {
        console.error('Admin login error:', err);
        res.json({ success: false, msg: 'Login failed' });
    }
});

// Admin Dashboard Stats
app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isBlocked: false });
        const blockedUsers = await User.countDocuments({ isBlocked: true });
        
        const totalLifafas = await Lifafa.countDocuments();
        const activeLifafas = await Lifafa.countDocuments({ isActive: true });
        
        const totalWithdrawals = await Withdrawal.countDocuments();
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        
        const totalBalance = await User.aggregate([
            { $group: { _id: null, total: { $sum: '$balance' } } }
        ]);
        
        res.json({
            success: true,
            stats: {
                users: { total: totalUsers, active: activeUsers, blocked: blockedUsers },
                lifafas: { total: totalLifafas, active: activeLifafas },
                withdrawals: { total: totalWithdrawals, pending: pendingWithdrawals },
                totalBalance: totalBalance[0]?.total || 0
            }
        });
    } catch(err) {
        console.error('Admin stats error:', err);
        res.json({ success: false, msg: 'Error loading stats' });
    }
});

// Get all users
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
        res.json({ success: false, msg: 'Error loading users' });
    }
});

// Update user balance
app.post('/api/admin/user-balance', adminMiddleware, async (req, res) => {
    try {
        const { number, amount, action, reason } = req.body;
        
        if (!number || !amount || !action) {
            return res.json({ success: false, msg: 'Number, amount and action required' });
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
        
        // Create transaction
        await new Transaction({
            userId: user._id,
            type: transactionType,
            amount,
            description
        }).save();
        
        // Send Telegram notification
        await telegram.sendTransactionAlert(
            user.telegramUid, 
            transactionType, 
            amount, 
            user.balance, 
            description
        );
        
        res.json({ 
            success: true, 
            msg: `Balance ${action}ed successfully`,
            newBalance: user.balance
        });
        
    } catch(err) {
        console.error('Balance update error:', err);
        res.json({ success: false, msg: 'Operation failed' });
    }
});

// Block/Unblock user
app.post('/api/admin/block-user', adminMiddleware, async (req, res) => {
    try {
        const { number, block, reason } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ success: false, msg: 'User not found' });
        }
        
        user.isBlocked = block;
        await user.save();
        
        // Send Telegram notification
        await telegram.sendMessage(user.telegramUid,
            `🚫 *Account ${block ? 'Blocked' : 'Unblocked'}*\n\n` +
            `Your account has been ${block ? 'blocked' : 'unblocked'} by admin.\n` +
            (reason ? `Reason: ${reason}\n` : '') +
            `Time: ${new Date().toLocaleString()}`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ success: true, msg: `User ${block ? 'blocked' : 'unblocked'}` });
    } catch(err) {
        console.error('Block user error:', err);
        res.json({ success: false, msg: 'Operation failed' });
    }
});

// Create Lifafa
app.post('/api/admin/create-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { title, amount, code, channel, numbers } = req.body;
        
        if (!title || !amount) {
            return res.json({ success: false, msg: 'Title and amount required' });
        }
        
        if (!numbers || numbers.length === 0) {
            return res.json({ success: false, msg: 'At least one number required' });
        }
        
        const finalCode = code || 'LIF' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        // Check if code already exists
        const existing = await Lifafa.findOne({ code: finalCode });
        if (existing) {
            return res.json({ success: false, msg: 'Code already exists' });
        }
        
        const lifafa = new Lifafa({
            title,
            amount,
            code: finalCode,
            channel,
            numbers,
            createdBy: req.adminId
        });
        
        await lifafa.save();
        
        // Broadcast to eligible users (max 50 for performance)
        const users = await User.find({ 
            number: { $in: numbers },
            isTelegramVerified: true 
        }).limit(50);
        
        users.forEach(user => {
            telegram.sendLifafaAlert(user.telegramUid, lifafa);
        });
        
        res.json({ 
            success: true,
            msg: 'Lifafa created successfully', 
            code: finalCode,
            totalNumbers: numbers.length
        });
    } catch(err) {
        console.error('Create lifafa error:', err);
        res.json({ success: false, msg: 'Creation failed' });
    }
});

// Get withdrawals
app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
    try {
        const status = req.query.status;
        let query = {};
        if (status) {
            query.status = status;
        }
        
        const withdrawals = await Withdrawal.find(query)
            .populate('userId', 'number username telegramUid balance')
            .sort('-createdAt');
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        console.error('Get withdrawals error:', err);
        res.json({ success: false, msg: 'Error loading withdrawals' });
    }
});

// Update withdrawal status
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
        
        // If rejected, return money to user
        if (status === 'rejected' && oldStatus === 'pending') {
            withdrawal.userId.balance += withdrawal.amount;
            await withdrawal.userId.save();
            
            await new Transaction({
                userId: withdrawal.userId._id,
                type: 'credit',
                amount: withdrawal.amount,
                description: 'Withdrawal rejected - amount returned'
            }).save();
        }
        
        // Notify user
        await telegram.sendWithdrawalAlert(
            withdrawal.userId.telegramUid, 
            withdrawal.amount, 
            status
        );
        
        res.json({ success: true, msg: `Withdrawal ${status}` });
    } catch(err) {
        console.error('Update withdrawal error:', err);
        res.json({ success: false, msg: 'Update failed' });
    }
});

// Get logs
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
        res.json({ success: false, msg: 'Error loading logs' });
    }
});

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Lifafa API is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📝 Test endpoint: http://localhost:${PORT}/api/test`);
    
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

// For Vercel
module.exports = app;