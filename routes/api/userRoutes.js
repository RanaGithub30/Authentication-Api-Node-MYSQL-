const express = require('express');
const router = express.Router();
const userController = require('../../controllers/api/AuthManageController');

const cors = require('cors');
router.use(cors());

// Import the authentication middleware
const authenticateToken = require('../../middleware/authMiddleware');

router.post('/register', userController.registerUser);
router.post('/email/verify', userController.verifyEmail);
router.post('/login', userController.login);
router.post('/resend/otp', userController.resendOtp);
router.post('/user/forget/pass', userController.resendOtp);
router.post('/user/forget/pass/email/verify', userController.verifyEmail);
router.post('/user/forget/pass/change', userController.forgotPassChange);

// Auth Routes
router.get('/user/profile/details', authenticateToken, userController.userProfileDetails);
router.post('/edit/profile', authenticateToken, userController.userProfileEdit);
router.post('/change/password', authenticateToken, userController.userPassChange);

module.exports = router;