const express = require('express');
const router = express.Router();
const lifafaController = require('../controllers/lifafaController');

router.get('/:code', lifafaController.getLifafaByCode);
router.post('/claim', lifafaController.claimLifafaPublic);

module.exports = router;
