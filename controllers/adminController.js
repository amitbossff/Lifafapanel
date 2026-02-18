const User = require('../models/User');
const Transaction = require('../models/Transaction');
const Lifafa = require('../models/Lifafa');
const Withdrawal = require('../models/Withdrawal');
const Admin = require('../models/Admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const telegram = require('../utils/telegram');
const mongoose = require('mongoose');

// Admin login
exports.login = async (req, res) => {
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
};

// Get stats
exports.getStats = async (req, res) => {
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
};

// Get all users
exports.getUsers = async (req, res) => {
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
};

// Get user by ID
exports.getUserById = async (req, res) => {
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
};

// Update user balance
exports.updateBalance = async (req, res) => {
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
};

// Block/unblock user
exports.toggleBlockUser = async (req, res) => {
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
};

// Create lifafa (admin)
exports.createLifafa = async (req, res) => {
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
};

// Get all withdrawals
exports.getWithdrawals = async (req, res) => {
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
};

// Update withdrawal status
exports.updateWithdrawal = async (req, res) => {
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
};

// Get logs
exports.getLogs = async (req, res) => {
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
};

// Get all lifafas
exports.getAllLifafas = async (req, res) => {
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
};

// Mark lifafa as over
exports.markLifafaOver = async (req, res) => {
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
                `💰 *Lifafa Refund*\n\nYour lifafa "${lifafa.title}" has been marked as over.\nRemaining amount: ₹${remainingAmount} has been refunded.`,
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
};

// Get lifafa by ID
exports.getLifafaById = async (req, res) => {
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
};

// Delete user
exports.deleteUser = async (req, res) => {
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
};

// Delete lifafa
exports.deleteLifafa = async (req, res) => {
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
};
