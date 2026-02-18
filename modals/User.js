const mongoose = require('mongoose');

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

UserSchema.index({ number: 1 });
UserSchema.index({ telegramUid: 1 });

module.exports = mongoose.model('User', UserSchema);
