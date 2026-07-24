const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_123";

module.exports = function (req, res, next) {
    // Get token from header
    const authHeader = req.header("Authorization");
    if (!authHeader) {
        return res.status(401).json({ success: false, message: "No token, authorization denied" });
    }

    try {
        // Format is usually "Bearer <TOKEN>"
        const token = authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : authHeader;
        const decoded = jwt.verify(token, JWT_SECRET);
        
        req.user = decoded; // Adds user payload (id, email) to request
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: "Token is not valid" });
    }
};