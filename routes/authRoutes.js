const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

router.post('/check-number', authController.checkNumber);
router.post('/check-telegram', authController.checkTelegram);
router.post('/send-otp', authController.sendOTP);
router.post('/verify-otp', authController.verifyOTP);
router.post('/send-login-otp', authController.sendLoginOTP);
router.post('/verify-login-otp', authController.verifyLoginOTP);
router.post('/resend-otp', authController.resendOTP);

module.exports = router;
