const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');

const adminMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ success: false, msg: 'No token provided' });
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.adminId);
        
        if (!admin) {
            return res.status(403).json({ success: false, msg: 'Not authorized' });
        }
        
        req.adminId = decoded.adminId;
        req.admin = admin;
        next();
    } catch(err) {
        return res.status(401).json({ success: false, msg: 'Invalid token' });
    }
};

module.exports = adminMiddleware;
