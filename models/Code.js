const mongoose = require('mongoose');

const CodeSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true, index: true },
    numbers: [{ type: String }],
    createdBy: String,
    createdAt: { type: Date, default: Date.now, expires: 86400 } // Auto delete after 24 hours
});

module.exports = mongoose.model('Code', CodeSchema);
