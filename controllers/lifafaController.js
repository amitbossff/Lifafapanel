const Lifafa = require('../models/Lifafa');
const User = require('../models/User');
const Transaction = require('../models/Transaction');

// Get lifafa details by code
exports.getLifafaByCode = async (req, res) => {
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
        console.error('Error in getLifafaByCode:', err);
        res.status(500).json({ success: false, msg: 'Server error loading lifafa' });
    }
};

// Claim lifafa (public)
exports.claimLifafaPublic = async (req, res) => {
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
};
