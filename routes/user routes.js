const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const userController = require('../controllers/userController');

router.get('/dashboard', authMiddleware, userController.getDashboard);
router.get('/profile', authMiddleware, userController.getProfile);
router.get('/transactions', authMiddleware, userController.getTransactions);
router.post('/pay', authMiddleware, userController.payUser);
router.post('/withdraw', authMiddleware, userController.requestWithdraw);
router.get('/withdrawals', authMiddleware, userController.getWithdrawals);
router.post('/create-lifafa', authMiddleware, userController.createLifafa);
router.get('/my-lifafas', authMiddleware, userController.getMyLifafas);
router.post('/unclaimed-lifafas', authMiddleware, userController.getUnclaimedLifafas);
router.post('/claim-lifafa', authMiddleware, userController.claimLifafa);
router.post('/claim-all-lifafas', authMiddleware, userController.claimAllLifafas);

module.exports = router;
