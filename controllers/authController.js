const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const telegram = require('../utils/telegram');

// Store OTPs
const otpStore = new Map();

// Cleanup OTPs every hour
setInterval(() => {
    const now = Date.now();
    for (let [key, value] of otpStore.entries()) {
        if (value.expires < now) otpStore.delete(key);
    }
}, 60 * 60 * 1000);

// Check if number exists
exports.checkNumber = async (req, res) => {
    try {
        const { number } = req.body;
        const user = await User.findOne({ number });
        res.json({ exists: !!user });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
};

// Check if Telegram UID is available
exports.checkTelegram = async (req, res) => {
    try {
        const { telegramUid } = req.body;
        const existing = await User.findOne({ telegramUid });
        res.json({ available: !existing });
    } catch(err) {
        res.status(500).json({ success: false, msg: 'Server error' });
    }
};

// Send OTP for registration
exports.sendOTP = async (req, res) => {
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
};

// Verify OTP and Register
exports.verifyOTP = async (req, res) => {
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
};

// Send Login OTP
exports.sendLoginOTP = async (req, res) => {
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
            expires: Date.now() + 5 * 60 * 1000
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
};

// Verify Login OTP
exports.verifyLoginOTP = async (req, res) => {
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
};

// Resend OTP
exports.resendOTP = async (req, res) => {
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
};
