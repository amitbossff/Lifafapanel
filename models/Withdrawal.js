const mongoose = require('mongoose');

const WithdrawalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    amount: { type: Number, required: true, min: 50 },
    upiId: { type: String, required: true, trim: true },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'refunded'], default: 'pending', index: true },
    processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    processedAt: Date,
    remarks: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

WithdrawalSchema.index({ userId: 1, status: 1 });

module.exports = mongoose.model('Withdrawal', WithdrawalSchema);
