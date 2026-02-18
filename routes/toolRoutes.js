const express = require('express');
const router = express.Router();
const toolController = require('../controllers/toolController');

router.post('/generate-code', toolController.generateCode);
router.get('/code/:code', toolController.getCode);

module.exports = router;
