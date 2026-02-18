const mongoose = require('mongoose');

const LifafaSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    code: { type: String, required: true, unique: true, index: true },
    amount: { type: Number, required: true, min: 1 },
    numbers: [{ type: String, trim: true }],
    totalUsers: { type: Number, default: 1, min: 1 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
    createdByNumber: String,
    isUserCreated: { type: Boolean, default: true },
    claimedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    claimedNumbers: [{ type: String }],
    claimedCount: { type: Number, default: 0, min: 0 },
    totalAmount: { type: Number, default: 0, min: 0 },
    isActive: { type: Boolean, default: true, index: true },
    createdAt: { type: Date, default: Date.now, index: true }
});

LifafaSchema.index({ createdBy: 1, isActive: 1 });

module.exports = mongoose.model('Lifafa', LifafaSchema);
