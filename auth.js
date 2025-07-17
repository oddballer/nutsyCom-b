const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d'; // 7 days

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

// Verify JWT token
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
};

// Hash password
const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Compare password
const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = verifyToken(token);
    if (!decoded) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Check if session exists and is valid
    const sessionResult = await db.query(
      'SELECT * FROM user_sessions WHERE user_id = $1 AND token_hash = $2 AND expires_at > CURRENT_TIMESTAMP',
      [decoded.userId, token]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(403).json({ error: 'Session expired or invalid' });
    }

    // Update last_used_at
    await db.query(
      'UPDATE user_sessions SET last_used_at = CURRENT_TIMESTAMP WHERE id = $1',
      [sessionResult.rows[0].id]
    );

    req.user = { id: decoded.userId };
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Optional authentication middleware (doesn't fail if no token)
const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const decoded = verifyToken(token);
    if (decoded) {
      req.user = { id: decoded.userId };
    } else {
      req.user = null;
    }
  } catch (error) {
    req.user = null;
  }
  next();
};

// Clean up expired sessions
const cleanupExpiredSessions = async () => {
  try {
    await db.query('SELECT cleanup_expired_sessions()');
  } catch (error) {
    console.error('Error cleaning up expired sessions:', error);
  }
};

module.exports = {
  generateToken,
  verifyToken,
  hashPassword,
  comparePassword,
  authenticateToken,
  optionalAuth,
  cleanupExpiredSessions
}; 