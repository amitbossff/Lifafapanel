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
app.use(cors({ origin: '*', credentials: true }));
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
    balance: { type: Number, default: 0 },
    isBlocked: { type: Boolean, default: false },
    lastLogin: Date,
    lastLoginIp: String,
    createdAt: { type: Date, default: Date.now }
});

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['credit', 'debit', 'withdraw', 'lifafa_created', 'lifafa_claimed'], required: true },
    amount: { type: Number, required: true },
    description: String,
    createdAt: { type: Date, default: Date.now }
});

const LifafaSchema = new mongoose.Schema({
    title: { type: String, required: true },
    code: { type: String, required: true, unique: true },
    amount: { type: Number, required: true },
    numbers: [{ type: String }],
    totalUsers: { type: Number, default: 0 }, // For limited public lifafas
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdByNumber: String,
    isUserCreated: { type: Boolean, default: true },
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

// ==================== MIDDLEWARE ====================

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ success: false, msg: 'No token provided' });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        if (!user) return res.status(401).json({ success: false, msg: 'User not found' });
        if (user.isBlocked) return res.status(403).json({ success: false, msg: 'Account is blocked' });
        
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
        if (!token) return res.status(401).json({ success: false, msg: 'No token provided' });
        
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
}, 60 * 60 * 1000);

// ==================== AUTH ROUTES ====================

app.post('/api/auth/check-number', async (req, res) => {
    try {
        const { number } = req.body;
        const user = await User.findOne({ number });
        res.json({ exists: !!user });
    } catch(err) {
        res.json({ exists: false });
    }
});

app.post('/api/auth/check-telegram', async (req, res) => {
    try {
        const { telegramUid } = req.body;
        const existing = await User.findOne({ telegramUid });
        res.json({ available: !existing });
    } catch(err) {
        res.json({ available: false });
    }
});

app.post('/api/auth/send-otp', async (req, res) => {
    try {
        const { number, telegramUid } = req.body;
        
        if (!number || !telegramUid) {
            return res.json({ success: false, msg: 'Number and Telegram UID required' });
        }
        
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
            res.json({ success: true, msg: 'OTP sent to your Telegram' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
    } catch(err) {
        res.json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { username, number, password, telegramUid, otp } = req.body;
        
        const stored = otpStore.get(number);
        if (!stored) return res.json({ success: false, msg: 'OTP expired or not requested' });
        if (stored.otp !== otp) return res.json({ success: false, msg: 'Invalid OTP' });
        if (stored.telegramUid !== telegramUid) return res.json({ success: false, msg: 'Telegram UID mismatch' });
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
        res.json({ success: false, msg: 'Registration failed' });
    }
});

app.post('/api/auth/send-login-otp', async (req, res) => {
    try {
        const { number } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ success: false, msg: 'User not found' });
        if (user.isBlocked) return res.json({ success: false, msg: 'Account is blocked' });
        
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        otpStore.set(`login_${number}`, {
            otp,
            telegramUid: user.telegramUid,
            userId: user._id,
            expires: Date.now() + 5 * 60 * 1000
        });
        
        const sent = await telegram.sendOTP(user.telegramUid, otp);
        
        if (sent) {
            res.json({ success: true, msg: 'OTP sent to your Telegram' });
        } else {
            res.json({ success: false, msg: 'Failed to send OTP' });
        }
    } catch(err) {
        res.json({ success: false, msg: 'Failed to send OTP' });
    }
});

app.post('/api/auth/verify-login-otp', async (req, res) => {
    try {
        const { number, otp, ip } = req.body;
        
        const stored = otpStore.get(`login_${number}`);
        if (!stored) return res.json({ success: false, msg: 'OTP expired or not requested' });
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
            user: { number: user.number, balance: user.balance, username: user.username }
        });
        
    } catch(err) {
        res.json({ success: false, msg: 'Login failed' });
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
        res.json({ success: false, msg: 'Failed to resend' });
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
        res.json({ success: false, msg: 'Failed to generate code' });
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
        res.json({ success: false, msg: 'Error fetching code' });
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
            $or: [
                { numbers: user.number },
                { numbers: { $size: 0 }, $or: [{ totalUsers: { $exists: false } }, { totalUsers: 1 }] }
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
        res.json({ success: false, msg: 'Error loading dashboard' });
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
        res.json({ success: false, msg: 'Error loading profile' });
    }
});

app.get('/api/user/transactions', authMiddleware, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.userId })
            .sort('-createdAt')
            .limit(50);
        
        res.json({ success: true, transactions });
    } catch(err) {
        res.json({ success: false, msg: 'Error loading transactions' });
    }
});

app.post('/api/user/pay', authMiddleware, async (req, res) => {
    try {
        const { receiverNumber, amount } = req.body;
        const sender = req.user;
        
        if (!receiverNumber || !amount || amount <= 0) {
            return res.json({ success: false, msg: 'Invalid request' });
        }
        
        if (sender.balance < amount) {
            return res.json({ success: false, msg: 'Insufficient balance' });
        }
        
        const receiver = await User.findOne({ number: receiverNumber });
        if (!receiver) return res.json({ success: false, msg: 'Receiver not found' });
        if (receiver.isBlocked) return res.json({ success: false, msg: 'Receiver is blocked' });
        
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
        res.json({ success: false, msg: 'Payment failed' });
    }
});

app.post('/api/user/withdraw', authMiddleware, async (req, res) => {
    try {
        const { amount, upiId } = req.body;
        const user = req.user;
        
        if (!amount || amount < 50) return res.json({ success: false, msg: 'Minimum withdrawal ₹50' });
        if (!upiId) return res.json({ success: false, msg: 'UPI ID required' });
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
            description: `Withdrawal request to ${upiId}`
        }).save();
        
        await telegram.sendWithdrawalAlert(user.telegramUid, amount, 'pending');
        
        res.json({ success: true, msg: 'Withdrawal request submitted', newBalance: user.balance });
        
    } catch(err) {
        res.json({ success: false, msg: 'Withdrawal failed' });
    }
});

app.get('/api/user/withdrawals', authMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId }).sort('-createdAt');
        res.json({ success: true, withdrawals });
    } catch(err) {
        res.json({ success: false, msg: 'Error loading withdrawals' });
    }
});

// ==================== CREATE LIFAFA (USER) - FIXED ====================
app.post('/api/user/create-lifafa', authMiddleware, async (req, res) => {
    try {
        const { title, amount, code, numbers, userCount, channel } = req.body;
        const user = req.user;
        
        if (!title || !amount || amount <= 0) {
            return res.json({ success: false, msg: 'Title and valid amount required' });
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
        }
        
        // Calculate total users correctly
        let totalUsers = 1; // Default for public unlimited
        
        if (allowedNumbers.length > 0) {
            // Option 1: Code from Number Tool (specific numbers)
            totalUsers = allowedNumbers.length;
        } else if (userCount && parseInt(userCount) > 0) {
            // Option 2: Manual user count (limited public lifafa)
            totalUsers = parseInt(userCount);
        } else if (numbers && numbers.trim()) {
            // Option 3: Manual numbers entered
            const manualNumbers = numbers.split('\n').filter(n => n.trim());
            totalUsers = manualNumbers.length;
        }
        // else: totalUsers = 1 (public unlimited - anyone can claim once)
        
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
            description: `Created Lifafa: ${title} (${totalUsers} users)`
        }).save();
        
        const baseUrl = process.env.FRONTEND_URL || 'https://muskilxlifafa.vercel.app';
        const shareableLink = `${baseUrl}/claimlifafa.html?code=${lifafaCode}`;
        
        await telegram.sendMessage(user.telegramUid,
            `🎁 *Lifafa Created!*\n\n*Title:* ${title}\n*Amount:* ₹${amount} × ${totalUsers} users\n*Total Cost:* ₹${totalCost}\n*Code:* \`${lifafaCode}\`\n*Link:* ${shareableLink}`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ 
            success: true, 
            msg: 'Lifafa created successfully',
            code: lifafaCode,
            link: shareableLink,
            totalUsers,
            totalCost,
            newBalance: user.balance
        });
        
    } catch(err) {
        console.error('Create lifafa error:', err);
        res.json({ success: false, msg: 'Failed to create lifafa' });
    }
});

app.get('/api/user/my-lifafas', authMiddleware, async (req, res) => {
    try {
        const lifafas = await Lifafa.find({ createdBy: req.userId }).sort('-createdAt');
        res.json({ success: true, lifafas });
    } catch(err) {
        res.json({ success: false, msg: 'Error loading lifafas' });
    }
});

// ==================== GET UNCLAIMED LIFAFAS FOR USER - FIXED ====================
app.post('/api/user/unclaimed-lifafas', authMiddleware, async (req, res) => {
    try {
        const { number } = req.body;
        const user = req.user;
        
        if (!number || number !== user.number) {
            return res.json({ success: false, msg: 'Invalid number' });
        }
        
        // Sirf wahi lifafas dikhao jo:
        // 1. Active hain
        // 2. User ne claim nahi kiya
        // 3. Ya to user ka number specific list mein ho (private), YA
        // 4. Public unlimited ho (numbers empty, totalUsers = 1)
        // 5. Public limited wale (totalUsers > 1) NAHI DIKHANE
        
        const lifafas = await Lifafa.find({
            isActive: true,
            claimedNumbers: { $ne: number },
            $or: [
                // Private lifafas - jinka number specifically add kiya gaya hai
                { numbers: number, numbers: { $ne: [] } },
                
                // Public unlimited lifafas - jisme koi bhi claim kar sakta hai, unlimited
                { 
                    numbers: { $size: 0 }, 
                    $or: [
                        { totalUsers: { $exists: false } },
                        { totalUsers: 1 }
                    ]
                }
                // Public limited (totalUsers > 1) - NAHI DIKHAENGE
            ]
        }).sort('-createdAt');
        
        res.json({ 
            success: true,
            lifafas: lifafas.map(l => ({
                _id: l._id,
                title: l.title,
                amount: l.amount,
                code: l.code,
                channel: l.channel,
                isPublic: l.numbers.length === 0,
                totalUsers: l.totalUsers || 1,
                claimedCount: l.claimedCount || 0
            }))
        });
        
    } catch(err) {
        console.error('Unclaimed lifafas error:', err);
        res.json({ success: false, msg: 'Failed to fetch lifafas' });
    }
});

app.post('/api/user/claim-lifafa', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const user = req.user;
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) return res.json({ success: false, msg: 'Invalid code' });
        
        // Check eligibility
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(user.number)) {
                return res.json({ success: false, msg: 'Not eligible' });
            }
        }
        
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(user.number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        // Check if limit reached
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
        
        // Mark as inactive if limit reached
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
        res.json({ success: false, msg: 'Claim failed' });
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
            $or: [
                { numbers: number },
                { numbers: { $size: 0 }, $or: [{ totalUsers: { $exists: false } }, { totalUsers: 1 }] }
            ],
            claimedNumbers: { $ne: number }
        });
        
        if (lifafas.length === 0) {
            return res.json({ success: false, msg: 'No unclaimed lifafas' });
        }
        
        let totalAmount = 0;
        for (const lifafa of lifafas) {
            totalAmount += lifafa.amount;
            
            lifafa.claimedBy.push(user._id);
            lifafa.claimedNumbers.push(number);
            lifafa.claimedCount++;
            lifafa.totalAmount += lifafa.amount;
            await lifafa.save();
        }
        
        user.balance += totalAmount;
        await user.save();
        
        await new Transaction({
            userId: user._id,
            type: 'credit',
            amount: totalAmount,
            description: `Bulk claimed ${lifafas.length} lifafas`
        }).save();
        
        await telegram.sendMessage(user.telegramUid,
            `🎊 *Bulk Claim Successful!*\n\n*Total Lifafas:* ${lifafas.length}\n*Total Amount:* +₹${totalAmount}\n*New Balance:* ₹${user.balance}`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ success: true, totalLifafas: lifafas.length, totalAmount, newBalance: user.balance });
        
    } catch(err) {
        res.json({ success: false, msg: 'Failed to claim' });
    }
});

// ==================== PUBLIC LIFAFA ROUTES ====================

app.get('/api/lifafa/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const lifafa = await Lifafa.findOne({ code, isActive: true })
            .populate('createdBy', 'username number');
        
        if (!lifafa) return res.json({ success: false, msg: 'Lifafa not found' });
        
        res.json({
            success: true,
            lifafa: {
                title: lifafa.title,
                amount: lifafa.amount,
                code: lifafa.code,
                channel: lifafa.channel,
                numbers: lifafa.numbers,
                totalUsers: lifafa.totalUsers || 1,
                isPublic: lifafa.numbers.length === 0,
                createdBy: lifafa.createdBy ? {
                    username: lifafa.createdBy.username,
                    number: lifafa.createdBy.number
                } : null,
                claimedCount: lifafa.claimedCount || 0,
                isActive: lifafa.isActive,
                createdAt: lifafa.createdAt
            }
        });
    } catch(err) {
        console.error('Error in /api/lifafa/:code', err);
        res.json({ success: false, msg: 'Error loading lifafa' });
    }
});

app.post('/api/lifafa/claim', async (req, res) => {
    try {
        const { code, number } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ success: false, msg: 'User not found. Please register first.' });
        if (user.isBlocked) return res.json({ success: false, msg: 'Account blocked' });
        
        const lifafa = await Lifafa.findOne({ code, isActive: true });
        if (!lifafa) return res.json({ success: false, msg: 'Invalid code' });
        
        // Check eligibility
        if (lifafa.numbers && lifafa.numbers.length > 0) {
            if (!lifafa.numbers.includes(number)) {
                return res.json({ success: false, msg: 'Not eligible' });
            }
        }
        
        if (lifafa.claimedNumbers && lifafa.claimedNumbers.includes(number)) {
            return res.json({ success: false, msg: 'Already claimed' });
        }
        
        // Check if limit reached
        const totalAllowed = lifafa.totalUsers || lifafa.numbers?.length || 999999;
        if (lifafa.claimedCount >= totalAllowed) {
            return res.json({ success: false, msg: 'This lifafa is fully claimed' });
        }
        
        user.balance += lifafa.amount;
        await user.save();
        
        lifafa.claimedBy.push(user._id);
        lifafa.claimedNumbers.push(number);
        lifafa.claimedCount++;
        lifafa.totalAmount += lifafa.amount;
        
        // Mark as inactive if limit reached
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
        console.error('Error in /api/lifafa/claim', err);
        res.json({ success: false, msg: 'Claim failed' });
    }
});

// ==================== ADMIN ROUTES ====================

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        let admin = await Admin.findOne({ username });
        
        if (!admin && username === process.env.ADMIN_USERNAME) {
            const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
            admin = new Admin({ username, password: hashedPassword });
            await admin.save();
        }
        
        if (!admin) return res.json({ success: false, msg: 'Admin not found' });
        
        const valid = bcrypt.compareSync(password, admin.password);
        if (!valid) return res.json({ success: false, msg: 'Invalid password' });
        
        const token = jwt.sign({ adminId: admin._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        res.json({ success: true, token });
    } catch(err) {
        res.json({ success: false, msg: 'Login failed' });
    }
});

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const activeUsers = await User.countDocuments({ isBlocked: false });
        const totalLifafas = await Lifafa.countDocuments();
        const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
        const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$balance' } } }]);
        
        res.json({
            success: true,
            stats: {
                users: { total: totalUsers, active: activeUsers },
                lifafas: { total: totalLifafas },
                withdrawals: { pending: pendingWithdrawals },
                totalBalance: totalBalance[0]?.total || 0
            }
        });
    } catch(err) {
        res.json({ success: false, msg: 'Error' });
    }
});

app.get('/api/admin/users', adminMiddleware, async (req, res) => {
    try {
        const users = await User.find().select('-password').sort('-createdAt');
        res.json({ success: true, users });
    } catch(err) {
        res.json({ success: false, msg: 'Error' });
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
        res.json({ success: false, msg: 'Error loading user' });
    }
});

app.post('/api/admin/user-balance', adminMiddleware, async (req, res) => {
    try {
        const { number, amount, action, reason } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ success: false, msg: 'User not found' });
        
        if (action === 'add') {
            user.balance += amount;
            await new Transaction({
                userId: user._id,
                type: 'credit',
                amount,
                description: reason || 'Admin credited'
            }).save();
        } else if (action === 'deduct') {
            if (user.balance < amount) return res.json({ success: false, msg: 'Insufficient balance' });
            user.balance -= amount;
            await new Transaction({
                userId: user._id,
                type: 'debit',
                amount,
                description: reason || 'Admin debited'
            }).save();
        }
        
        await user.save();
        
        await telegram.sendTransactionAlert(
            user.telegramUid, action === 'add' ? 'credit' : 'debit', amount, user.balance, reason || `Admin ${action}`
        );
        
        res.json({ success: true, msg: `Balance ${action}ed`, newBalance: user.balance });
        
    } catch(err) {
        res.json({ success: false, msg: 'Operation failed' });
    }
});

app.post('/api/admin/block-user', adminMiddleware, async (req, res) => {
    try {
        const { number, block, reason } = req.body;
        
        const user = await User.findOne({ number });
        if (!user) return res.json({ success: false, msg: 'User not found' });
        
        user.isBlocked = block;
        await user.save();
        
        await telegram.sendMessage(user.telegramUid,
            `🚫 *Account ${block ? 'Blocked' : 'Unblocked'}*\n\n${reason ? `Reason: ${reason}` : ''}`,
            { parse_mode: 'Markdown' }
        );
        
        res.json({ success: true, msg: `User ${block ? 'blocked' : 'unblocked'}` });
    } catch(err) {
        res.json({ success: false, msg: 'Operation failed' });
    }
});

app.post('/api/admin/create-lifafa', adminMiddleware, async (req, res) => {
    try {
        const { title, amount, numbers } = req.body;
        
        const code = 'LIF' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        const allowedNumbers = numbers ? numbers.split(/[\n,]+/).map(n => n.trim()).filter(n => /^\d{10}$/.test(n)) : [];
        
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
        res.json({ success: false, msg: 'Creation failed' });
    }
});

app.get('/api/admin/withdrawals', adminMiddleware, async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find().populate('userId', 'number username').sort('-createdAt');
        res.json({ success: true, withdrawals });
    } catch(err) {
        res.json({ success: false, msg: 'Error' });
    }
});

app.post('/api/admin/update-withdrawal', adminMiddleware, async (req, res) => {
    try {
        const { withdrawalId, status, remarks } = req.body;
        
        const withdrawal = await Withdrawal.findById(withdrawalId).populate('userId');
        if (!withdrawal) return res.json({ success: false, msg: 'Not found' });
        
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
        res.json({ success: false, msg: 'Update failed' });
    }
});

app.get('/api/admin/logs', adminMiddleware, async (req, res) => {
    try {
        const logs = await Transaction.find().populate('userId', 'number').sort('-createdAt').limit(100);
        res.json({ success: true, logs });
    } catch(err) {
        res.json({ success: false, msg: 'Error' });
    }
});

// ==================== ADMIN - LIFAFA OVER & REFUND ====================

app.get('/api/admin/all-lifafas', adminMiddleware, async (req, res) => {
    try {
        const lifafas = await Lifafa.find()
            .populate('createdBy', 'username number')
            .sort('-createdAt');
        
        res.json({ success: true, lifafas });
    } catch(err) {
        res.json({ success: false, msg: 'Error loading lifafas' });
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
        res.json({ success: false, msg: 'Operation failed' });
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
        res.json({ success: false, msg: 'Error loading lifafa' });
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
        
        await Transaction.deleteMany({ userId: user._id });
        await Withdrawal.deleteMany({ userId: user._id });
        await Lifafa.deleteMany({ createdBy: user._id });
        
        await Lifafa.updateMany(
            { claimedBy: user._id },
            { $pull: { claimedBy: user._id } }
        );
        
        await User.findByIdAndDelete(userId);
        
        res.json({ success: true, msg: 'User deleted successfully' });
        
    } catch(err) {
        console.error('Delete user error:', err);
        res.json({ success: false, msg: 'Failed to delete user' });
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
        res.json({ success: false, msg: 'Failed to delete lifafa' });
    }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📝 Test: http://localhost:${PORT}/api/test`);
});

module.exports = app;
