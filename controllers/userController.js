const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Lifafa = require('../models/Lifafa');
const Withdrawal = require('../models/Withdrawal');
const Code = require('../models/Code');
const telegram = require('../utils/telegram');

// Dashboard
exports.getDashboard = async (req, res) => {
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
};

// Profile
exports.getProfile = async (req, res) => {
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
};

// Transactions
exports.getTransactions = async (req, res) => {
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
};

// Pay to user
exports.payUser = async (req, res) => {
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
};

// Withdraw request
exports.requestWithdraw = async (req, res) => {
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
};

// Get withdrawals
exports.getWithdrawals = async (req, res) => {
    try {
        const withdrawals = await Withdrawal.find({ userId: req.userId })
            .sort('-createdAt')
            .limit(20);
        
        res.json({ success: true, withdrawals });
    } catch(err) {
        console.error('Withdrawals error:', err);
        res.status(500).json({ success: false, msg: 'Error loading withdrawals' });
    }
};

// Create lifafa
exports.createLifafa = async (req, res) => {
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
        
        let totalUsers = 1;
        let lifafaType = 'public_unlimited';
        
        if (allowedNumbers.length > 0) {
            totalUsers = allowedNumbers.length;
            lifafaType = 'private';
        }
