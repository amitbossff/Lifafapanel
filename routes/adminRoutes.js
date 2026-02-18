const express = require('express');
const router = express.Router();
const adminMiddleware = require('../middleware/admin');
const adminController = require('../controllers/adminController');

// Public admin route
router.post('/login', adminController.login);

// Protected admin routes
router.get('/stats', adminMiddleware, adminController.getStats);
router.get('/users', adminMiddleware, adminController.getUsers);
router.get('/users/:id', adminMiddleware, adminController.getUserById);
router.post('/user-balance', adminMiddleware, adminController.updateBalance);
router.post('/block-user', adminMiddleware, adminController.toggleBlockUser);
router.post('/create-lifafa', adminMiddleware, adminController.createLifafa);
router.get('/withdrawals', adminMiddleware, adminController.getWithdrawals);
router.post('/update-withdrawal', adminMiddleware, adminController.updateWithdrawal);
router.get('/logs', adminMiddleware, adminController.getLogs);
router.get('/all-lifafas', adminMiddleware, adminController.getAllLifafas);
router.post('/lifafa-over', adminMiddleware, adminController.markLifafaOver);
router.get('/lifafa/:id', adminMiddleware, adminController.getLifafaById);
router.post('/delete-user', adminMiddleware, adminController.deleteUser);
router.post('/delete-lifafa', adminMiddleware, adminController.deleteLifafa);

module.exports = router;
