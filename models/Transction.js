const mongoose = require('mongoose');

const TransactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, enum: ['credit', 'debit', 'withdraw', 'lifafa_created', 'lifafa_claimed'], required: true },
    amount: { type: Number, required: true, min: 0 },
    description: String,
    createdAt: { type: Date, default: Date.now, index: true }
});

TransactionSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Transaction', TransactionSchema);
