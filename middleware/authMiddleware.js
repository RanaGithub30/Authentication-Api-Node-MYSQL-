const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(403).json({ success: false, message: 'Forbidden: No token provided' });
    }

    jwt.verify(token, 'test', (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ success: false, message: 'Forbidden: Token expired' });
            }
            return res.status(403).json({ success: false, message: 'Forbidden: Invalid token' });
        }
        req.user = user;
        next();
    });
};

module.exports = authenticateToken;