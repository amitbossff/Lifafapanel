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
app.use(cors());
app.use(express.json());

// Initialize Telegram Bot
const bot = telegram.initBot(process.env.TELEGRAM_BOT_TOKEN);

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.log('❌ MongoDB Error:', err));

// ==================== MODELS ====================
const UserSchema = new mongoose.Schema({
    username: String,
    number: { type: String, unique: true },
    password: String,
    telegramUid: { type: String, unique: true, sparse: true },
    telegramChatId: String,
    isTelegramVerified: { type: Boolean, default: false },
    balance: { type: Number, default: 0 },
    isBlocked: { type: Boolean, default: false },
    lastLogin: Date,
    lastLoginIp: String,
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    type: String, // 'credit', 'debit', 'withdraw', 'lifafa'
    amount: Number,
    description: String,
    createdAt: { type: Date, default: Date.now }
});

const LifafaSchema = new mongoose.Schema({
    title: String,
    code: { type: String, unique: true },
    amount: Number,
    channel: String,
    numbers: [{ type: String }], // Allowed numbers
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    claimedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    claimedNumbers: [{ type: String }],
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const WithdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    amount: Number,
    status: { type: String, default: 'pending' }, // pending, approved, rejected
    createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
    username: String,
    password: String,
    role: { type: String, default: 'admin' }
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
        if (!token) return res.status(401).json({ msg: 'No token' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch(err) {
        res.status(401).json({ msg: 'Invalid token' });
    }
};

const adminMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ msg: 'No token' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId);
        if (!admin) return res.status(403).json({ msg: 'Not authorized' });
        
        req.adminId = decoded.adminId;
        next();
    } catch(err) {
        res.status(401).json({ msg: 'Invalid token' });
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
            return res.json({ msg: 'Number and Telegram UID required' });
        }
        
        // Check if number exists
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ msg: 'Number already registered' });
        }
        
        // Check if Telegram UID already used
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) {
            return res.json({ msg: 'This Telegram account is already linked to another user' });
        }
        
        // Check if Telegram UID is valid
        const isValid = await telegram.checkTelegramUID(telegramUid);
        if (!isValid) {
            return res.json({ msg: 'Invalid Telegram UID. Please send /start to bot first' });
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
            res.json({ msg: 'Failed to send OTP. Check Telegram UID' });
        }
        
    } catch(err) {
        res.json({ msg: 'Failed to send OTP' });
    }
});

// Verify OTP and Register
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { username, number, password, telegramUid, otp } = req.body;
        
        // Check OTP
        const stored = otpStore.get(number);
        
        if (!stored) {
            return res.json({ msg: 'OTP expired or not requested' });
        }
        
        if (stored.otp !== otp) {
            return res.json({ msg: 'Invalid OTP' });
        }
        
        if (stored.telegramUid !== telegramUid) {
            return res.json({ msg: 'Telegram UID mismatch' });
        }
        
        if (Date.now() > stored.expires) {
            otpStore.delete(number);
            return res.json({ msg: 'OTP expired' });
        }
        
        // Double check if Telegram UID already used
        const existingTelegram = await User.findOne({ telegramUid });
        if (existingTelegram) {
            return res.json({ msg: 'This Telegram account is already linked to another user' });
        }
        
        // Check if number exists
        const existingUser = await User.findOne({ number });
        if (existingUser) {
            return res.json({ msg: 'Number already registered' });
        }
        
        // Create user
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const user = new User({
            username,
            number,
            password: hashedPassword,
            telegramUid,
            telegramChatId: telegramUid,
            isTelegramVerified: true,
            balance: 100 // Welcome bonus
        });
        
        await user.save();
        
        // Welcome transaction
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: 100,
            description: 'Welcome bonus'
        }).save();
        
        // Send welcome message
        await telegram.sendTransactionAlert(telegramUid, 'credit', 100, 100, 'Welcome bonus');
        
        // Clear OTP
        otpStore.delete(number);
        
        res.json({ success: true, msg: 'Registration successful' });
        
    } catch(err) {
        res.json({ msg: 'Registration failed' });
    }
});

// Login with OTP
app.post('/api/auth/send-login-otp', async (req, res) => {
    try {
        const { number } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) {
            return res.json({ msg: 'User not found' });
        }
        
        if (user.isBlocked) {
            return res.json({ msg: 'Account blocked' });
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
            res.json({ msg: 'Failed to send OTP' });
        }
        
    } catch(err) {
        res.json({ msg: 'Login failed' });
    }
});

// Verify Login OTP
app.post('/api/auth/verify-login-otp', async (req, res) => {
    try {
        const { number, otp, ip } = req.body;
        
        const stored = otpStore.get(`login_${number}`);
        
        if (!stored) {
            return res.json({ msg: 'OTP expired or not requested' });
        }
        
        if (stored.otp !== otp) {
            return res.json({ msg: 'Invalid OTP' });
        }
        
        if (Date.now() > stored.expires) {
            otpStore.delete(`login_${number}`);
            return res.json({ msg: 'OTP expired' });
        }
        
        const user = await User.findById(stored.userId);
        if (!user) {
            return res.json({ msg: 'User not found' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        user.lastLoginIp = ip;
        await user.save();
        
        // Send login alert
        await telegram.sendLoginAlert(user.telegramUid, user, ip);
        
        // Generate token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        
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
        res.json({ msg: 'Login failed' });
    }
});

// Resend OTP
app.post('/api/auth/resend-otp', async (req, res) => {
    try {
        const { number, type } = req.body; // type: 'register' or 'login'
        
        const key = type === 'login' ? `login_${number}` : number;
        const stored = otpStore.get(key);
        
        if (!stored) {
            return res.json({ msg: 'Request OTP first' });
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
            res.json({ msg: 'Failed to resend' });
        }
        
    } catch(err) {
        res.json({ msg: 'Failed to resend' });
    }
});

// ==================== USER ROUTES ====================

// Dashboard
app.get('/api/user/dashboard', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.json({ msg: 'User not found' });
        if (user.isBlocked) return res.json({ msg: 'Account blocked' });
        
        res.json({ 
            balance: user.balance,
            username: user.username,
            number: user.number
        });
    } catch(err) {
        res.json({ msg: 'Error' });
    }
});

// Transactions
app.get('/api/user/transactions', authMiddleware, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.userId })
            .sort('-createdAt')
            .limit(50);
        res.json(transactions);
    } catch(err) {
        res.json([]);
    }
});

// Pay to user
app.post('/api/user/pay', authMiddleware, async (req, res) => {
    try {
        const { receiverNumber, amount } = req.body;
        
        if (amount <= 0) return res.json({ msg: 'Invalid amount' });
        
        const sender = await User.findById(req.userId);
        if (sender.balance < amount) return res.json({ msg: 'Insufficient balance' });
        
        const receiver = await User.findOne({ number: receiverNumber });
        if (!receiver) return res.json({ msg: 'Receiver not found' });
        
        if (receiver.isBlocked) return res.json({ msg: 'Receiver is blocked' });
        
        // Update balances
        sender.balance -= amount;
        receiver.balance += amount;
        
        await sender.save();
        await receiver.save();
        
        // Transactions
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
        
        res.json({ msg: 'Payment successful' });
    } catch(err) {
        res.json({ msg: 'Payment failed' });
    }
});

// Withdraw request
app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.userId);
        
        if (amount <= 0) return res.json({ msg: 'Invalid amount' });
        if (user.balance < amount) return res.json({ msg: 'Insufficient balance' });
        
        // Create withdrawal request
        const withdrawal = new Withdrawal({
            userId: user._id,
            amount
        });
        
        await withdrawal.save();
        
        // Freeze amount
        user.balance -= amount;
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: 'debit',
            amount,
            description: 'Withdrawal request'
        }).save();
        
        // Notify user
        await telegram.sendWithdrawalAlert(user.telegramUid, amount, 'pending');
        
        res.json({ msg: 'Withdrawal request submitted' });
    } catch(err) {
        res.json({ msg: 'Request failed' });
    }
});

// Create referral code
app.post('/api/user/create-code', authMiddleware, async (req, res) => {
    try {
        const { numbers } = req.body;
        const user = await User.findById(req.userId);
        
        // Generate random code
        const code = 'LIF' + Math.random().toString(36).substring(2, 8).toUpperCase();
        
        res.json({ 
            code,
            total: numbers.length,
            msg: 'Code created'
        });
    } catch(err) {
        res.json({ msg: 'Failed to create code' });
    }
});

// Get unclaimed lifafas for user
app.post('/api/user/unclaimed-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = await User.findById(req.userId);
        
        if (!number) {
            return res.json({ msg: 'Number required' });
        }
        
        // Find all active lifafas where number is in allowed numbers and not claimed by this user
        const lifafas = await Lifafa.find({
            isActive: true,
            numbers: number,
            claimedNumbers: { $ne: number },
            claimedBy: { $ne: user._id }
        });
        
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
        res.json({ msg: 'Failed to fetch lifafas' });
    }
});

// Claim single lifafa
app.post('/api/user/claim-lifafa', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const user = await User.findById(req.userId);
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) return res.json({ msg: 'Invalid code' });
        
        // Check if number is allowed
        if (!lifafa.numbers.includes(user.number)) {
            return res.json({ msg: 'You are not eligible for this lifafa' });
        }
        
        // Check if already claimed by number
        if (lifafa.claimedNumbers.includes(user.number)) {
            return res.json({ msg: 'You have already claimed this lifafa' });
        }
        
        // Check if already claimed by user
        if (lifafa.claimedBy.includes(user._id)) {
            return res.json({ msg: 'You have already claimed this lifafa' });
        }
        
        // Add to user balance
        user.balance += lifafa.amount;
        await user.save();
        
        // Mark as claimed
        lifafa.claimedBy.push(user._id);
        lifafa.claimedNumbers.push(user.number);
        await lifafa.save();
        
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
            msg: 'Claimed successfully'
        });
    } catch(err) {
        res.json({ msg: 'Claim failed' });
    }
});

// Claim all unclaimed lifafas
app.post('/api/user/claim-all-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = await User.findById(req.userId);
        
        if (!number || number !== user.number) {
            return res.json({ msg: 'Invalid number' });
        }
        
        // Find all unclaimed lifafas
        const lifafas = await Lifafa.find({
            isActive: true,
            numbers: number,
            claimedNumbers: { $ne: number },
            claimedBy: { $ne: user._id }
        });
        
        if (lifafas.length === 0) {
            return res.json({ msg: 'No unclaimed lifafas' });
        }
        
        let totalAmount = 0;
        const claimedLifafas = [];
        
        // Claim each lifafa
        for (const lifafa of lifafas) {
            totalAmount += lifafa.amount;
            claimedLifafas.push({
                title: lifafa.title,
                amount: lifafa.amount
            });
            
            lifafa.claimedBy.push(user._id);
            lifafa.claimedNumbers.push(number);
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
            claimed: claimedLifafas,
            msg: `Successfully claimed ${lifafas.length} lifafas worth ₹${totalAmount}`
        });
        
    } catch(err) {
        res.json({ msg: 'Failed to claim lifafas' });
    }
});

// ==================== ADMIN ROUTES ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if admin exists
        let admin = await Admin.findOne({ username });
        
        if (!admin && username === process.env.ADMIN_USERNAME) {
            const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
            admin = new Admin({
                username: process.env.ADMIN_USERNAME,
                password: hashedPassword
            });
            await admin.save();
        }
        
        if (!admin) return res.json({ msg: 'Admin not found' });
        
        const valid = bcrypt.compareSync(password, admin.password);
        if (!valid) return res.json({ msg: 'Wrong password' });
        
        const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET);
        res.json({ token });
    } catch(err) {
        res.json({ msg: 'Login failed' });
    }
});

// Create Lifafa (with numbers)
app.post('/api/admin/create-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { title, amount, code, channel, numbers } = req.body;
        
        const finalCode = code || 'LIF' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const lifafa = new Lifafa({
            title,
            amount,
            code: finalCode,
            channel,
            numbers: numbers || [],
            createdBy: req.adminId
        });
        
        await lifafa.save();
        
        // Broadcast to eligible users (max 100 for performance)
        if (numbers && numbers.length > 0) {
            const users = await User.find({ 
                number: { $in: numbers },
                isTelegramVerified: true 
            }).limit(100);
            
            users.forEach(user => {
                telegram.sendLifafaAlert(user.telegramUid, lifafa);
            });
        }
        
        res.json({ 
            success: true,
            msg: 'Lifafa created successfully', 
            code: finalCode,
            totalNumbers: numbers?.length || 0
        });
    } catch(err) {
        res.json({ msg: 'Creation failed' });
    }
});

// Get withdrawals
app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find()
            .populate('userId', 'number username telegramUid')
            .sort('-createdAt');
        res.json(withdrawals);
    } catch(err) {
        res.json([]);
    }
});

// Update withdrawal status
app.post('/api/admin/update-withdrawal', adminMiddleware, async (req, res) => {
    try {
        const { withdrawalId, status } = req.body;
        
        const withdrawal = await Withdrawal.findById(withdrawalId).populate('userId');
        if (!withdrawal) return res.json({ msg: 'Not found' });
        
        withdrawal.status = status;
        await withdrawal.save();
        
        // If rejected, return money
        if (status === 'rejected') {
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
        
        res.json({ msg: `Withdrawal ${status}` });
    } catch(err) {
        res.json({ msg: 'Update failed' });
    }
});

// User balance management
app.post('/api/admin/user-balance', adminMiddleware, async (req, res) => {
    try {
        const { number, amount, action } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ msg: 'User not found' });
        
        if (action === 'add') {
            user.balance += amount;
            await new Transaction({
                userId: user._id,
                type: 'credit',
                amount,
                description: 'Admin credited'
            }).save();
            
            await telegram.sendTransactionAlert(
                user.telegramUid, 
                'credit', 
                amount, 
                user.balance, 
                'Admin credited'
            );
            
        } else if (action === 'deduct') {
            if (user.balance < amount) return res.json({ msg: 'Insufficient balance' });
            user.balance -= amount;
            await new Transaction({
                userId: user._id,
                type: 'debit',
                amount,
                description: 'Admin debited'
            }).save();
            
            await telegram.sendTransactionAlert(
                user.telegramUid, 
                'debit', 
                amount, 
                user.balance, 
                'Admin debited'
            );
        }
        
        await user.save();
        res.json({ msg: `Balance ${action}ed successfully` });
    } catch(err) {
        res.json({ msg: 'Operation failed' });
    }
});

// Block/Unblock user
app.post('/api/admin/block-user', adminMiddleware, async (req, res) => {
    try {
        const { number, block } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ msg: 'User not found' });
        
        user.isBlocked = block;
        await user.save();
        
        await telegram.sendMessage(user.telegramUid,
            `🚫 *Account ${block ? 'Blocked' : 'Unblocked'}*\n\n` +
            `Your account has been ${block ? 'blocked' : 'unblocked'} by admin.`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ msg: `User ${block ? 'blocked' : 'unblocked'}` });
    } catch(err) {
        res.json({ msg: 'Operation failed' });
    }
});

// Get logs
app.get('/api/admin/logs', adminMiddleware, async (req, res) => {
    try {
        const logs = await Transaction.find()
            .populate('userId', 'number')
            .sort('-createdAt')
            .limit(50);
            
        res.json(logs.map(l => ({
            action: l.type,
            target: l.userId?.number || 'Unknown',
            description: l.description,
            amount: l.amount,
            time: l.createdAt
        })));
    } catch(err) {
        res.json([]);
    }
});

// Get all users
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
    try {
        const users = await User.find()
            .select('-password')
            .sort('-createdAt');
        res.json(users);
    } catch(err) {
        res.json([]);
    }
});

// Get lifafa stats
app.get('/api/admin/lifafa-stats', adminMiddleware, async (req, res) => {
    try {
        const stats = await Lifafa.aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    active: { $sum: { $cond: ['$isActive', 1, 0] } },
                    totalAmount: { $sum: '$amount' },
                    totalClaims: { $sum: { $size: '$claimedBy' } }
                }
            }
        ]);
        
        res.json(stats[0] || { total: 0, active: 0, totalAmount: 0, totalClaims: 0 });
    } catch(err) {
        res.json({ total: 0 });
    }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    
    // Create default admin
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
        } catch(err) {}
    }, 2000);
});

// For Vercel
module.exports = app;
