const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const auth = require('./auth');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// CORS configuration for different environments
const allowedOrigins = [
  'http://localhost:5173', // Vite dev server
  'http://localhost:3000', // Alternative dev port
  'https://www.nutsy.dev', // Your production frontend domain
  'https://nutsy.dev', // Alternative domain
  'https://nutsycom.vercel.app', // Vercel frontend domain
  'https://nutsycom-f.vercel.app', // Alternative Vercel domain
  'https://nutsy-backend-197d2c7f6689.herokuapp.com', // Your Heroku backend domain
  process.env.FRONTEND_URL, // Environment variable for frontend URL
].filter(Boolean); // Remove undefined values

console.log('Allowed origins:', allowedOrigins);
console.log('NODE_ENV:', process.env.NODE_ENV);

const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? allowedOrigins
      : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Apply rate limiting to all routes
app.use(limiter);

// Add CSP headers to allow necessary resources
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.socket.io; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' ws: wss:; frame-src 'self';"
  );
  next();
});

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? allowedOrigins
    : '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Serve favicon
app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // No content response
});

// Root route
app.get('/', (req, res) => {
  res.json({
    message: 'NutsyCom Backend API',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /api/auth/register',
        login: 'POST /api/auth/login',
        logout: 'POST /api/auth/logout',
        profile: 'GET /api/auth/profile'
      },
      chat: {
        rooms: 'GET /api/rooms',
        messages: 'GET /api/rooms/:roomId/messages',
        websocket: 'Socket.IO connection available'
      }
    },
    status: 'running'
  });
});

// Database initialization endpoint
app.get('/api/init-db', async (req, res) => {
  try {
    const fs = require('fs');
    const path = require('path');
    const schema = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
    
    // Split schema into individual statements
    const statements = schema.split(';').filter(stmt => stmt.trim());
    
    for (const statement of statements) {
      if (statement.trim()) {
        await db.query(statement);
      }
    }
    
    res.json({ message: 'Database initialized successfully' });
  } catch (error) {
    console.error('Database initialization error:', error);
    res.status(500).json({ error: 'Failed to initialize database' });
  }
});

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, display_name } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    // Check if user already exists
    const existingUser = await db.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const passwordHash = await auth.hashPassword(password);

    // Create user
    const userResult = await db.query(
      `INSERT INTO users (username, email, password_hash, display_name) 
       VALUES ($1, $2, $3, $4) RETURNING id, username, email, display_name, created_at`,
      [username, email, passwordHash, display_name || username]
    );

    const user = userResult.rows[0];

    // Generate token
    const token = auth.generateToken(user.id);

    // Create session
    await db.query(
      `INSERT INTO user_sessions (user_id, token_hash, expires_at, ip_address, user_agent) 
       VALUES ($1, $2, $3, $4, $5)`,
      [
        user.id, 
        token, 
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        req.ip,
        req.get('User-Agent')
      ]
    );

    // Add user to general room
    await db.query(
      'INSERT INTO room_memberships (user_id, room_id, role) VALUES ($1, 1, $2) ON CONFLICT DO NOTHING',
      [user.id, 'member']
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name
      },
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const userResult = await db.query(
      'SELECT id, username, email, password_hash, display_name FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    // Check password
    const isValidPassword = await auth.comparePassword(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await db.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Generate token
    const token = auth.generateToken(user.id);

    // Create session
    await db.query(
      `INSERT INTO user_sessions (user_id, token_hash, expires_at, ip_address, user_agent) 
       VALUES ($1, $2, $3, $4, $5)`,
      [
        user.id, 
        token, 
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        req.ip,
        req.get('User-Agent')
      ]
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name
      },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Failed to login' });
  }
});

app.post('/api/auth/logout', auth.authenticateToken, async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Remove session
    await db.query(
      'DELETE FROM user_sessions WHERE user_id = $1 AND token_hash = $2',
      [req.user.id, token]
    );

    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Failed to logout' });
  }
});

app.get('/api/auth/profile', auth.authenticateToken, async (req, res) => {
  try {
    const userResult = await db.query(
      'SELECT id, username, email, display_name, created_at, last_login FROM users WHERE id = $1',
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: userResult.rows[0] });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Chat routes
app.get('/api/rooms', auth.optionalAuth, async (req, res) => {
  try {
    let query = `
      SELECT cr.*, 
             COUNT(rm.user_id) as member_count,
             CASE WHEN $1 IS NOT NULL THEN 
               (SELECT role FROM room_memberships WHERE user_id = $1 AND room_id = cr.id)
             ELSE NULL END as user_role
      FROM chat_rooms cr
      LEFT JOIN room_memberships rm ON cr.id = rm.room_id
      WHERE cr.is_private = FALSE OR $1 IS NOT NULL
      GROUP BY cr.id
      ORDER BY cr.updated_at DESC
    `;

    const result = await db.query(query, [req.user?.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching rooms:', error);
    res.status(500).json({ error: 'Failed to fetch rooms' });
  }
});

app.get('/api/rooms/:roomId/messages', auth.optionalAuth, async (req, res) => {
  try {
    const { roomId } = req.params;
    const { limit = 50, offset = 0 } = req.query;

    // Check if user has access to the room
    if (req.user) {
      const accessResult = await db.query(
        'SELECT * FROM room_memberships WHERE user_id = $1 AND room_id = $2',
        [req.user.id, roomId]
      );

      if (accessResult.rows.length === 0) {
        // Check if room is public
        const roomResult = await db.query(
          'SELECT is_private FROM chat_rooms WHERE id = $1',
          [roomId]
        );

        if (roomResult.rows.length === 0 || roomResult.rows[0].is_private) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }
    }

    const result = await db.query(
      `SELECT m.*, u.username, u.display_name
       FROM messages m
       JOIN users u ON m.user_id = u.id
       WHERE m.room_id = $1 AND m.is_deleted = FALSE
       ORDER BY m.sent_at DESC
       LIMIT $2 OFFSET $3`,
      [roomId, parseInt(limit), parseInt(offset)]
    );

    res.json(result.rows.reverse()); // Return in chronological order
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// WebSocket events
const onlineUsers = new Map(); // userId -> socket.id
const socketUsers = new Map(); // socket.id -> userId

// Helper to emit all online user objects
async function emitOnlineUsers() {
  if (onlineUsers.size === 0) {
    io.emit('onlineUsers', []);
    return;
  }
  const userIds = Array.from(onlineUsers.keys());
  // Fetch all user objects in a single query
  const result = await db.query(
    `SELECT id, username, display_name FROM users WHERE id = ANY($1)`,
    [userIds]
  );
  io.emit('onlineUsers', result.rows);
}

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Authenticate socket connection
  socket.on('authenticate', async (token) => {
    try {
      const decoded = auth.verifyToken(token);
      if (!decoded) {
        socket.emit('authError', { message: 'Invalid token' });
        return;
      }

      // Verify session exists
      const sessionResult = await db.query(
        'SELECT * FROM user_sessions WHERE user_id = $1 AND token_hash = $2 AND expires_at > CURRENT_TIMESTAMP',
        [decoded.userId, token]
      );

      if (sessionResult.rows.length === 0) {
        socket.emit('authError', { message: 'Session expired' });
        return;
      }

      // Store user info
      socketUsers.set(socket.id, decoded.userId);
      onlineUsers.set(decoded.userId, socket.id);

      // Get user info
      const userResult = await db.query(
        'SELECT id, username, display_name FROM users WHERE id = $1',
        [decoded.userId]
      );

      socket.user = userResult.rows[0];
      socket.emit('authenticated', { user: socket.user });
      await emitOnlineUsers();

      console.log('User authenticated:', socket.user.username);
    } catch (error) {
      console.error('Socket authentication error:', error);
      socket.emit('authError', { message: 'Authentication failed' });
    }
  });

  // Join a room
  socket.on('joinRoom', async (roomId) => {
    try {
      if (!socket.user) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      // Check if user has access to the room
      const accessResult = await db.query(
        'SELECT * FROM room_memberships WHERE user_id = $1 AND room_id = $2',
        [socket.user.id, roomId]
      );

      if (accessResult.rows.length === 0) {
        // Check if room is public
        const roomResult = await db.query(
          'SELECT is_private FROM chat_rooms WHERE id = $1',
          [roomId]
        );

        if (roomResult.rows.length === 0 || roomResult.rows[0].is_private) {
          socket.emit('error', { message: 'Access denied to room' });
          return;
        }
      }

      socket.join(roomId);
      socket.emit('roomJoined', { roomId });
      console.log(`User ${socket.user.username} joined room ${roomId}`);
    } catch (error) {
      console.error('Error joining room:', error);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });

  // Handle new message
  socket.on('chatMessage', async ({ roomId, content }) => {
    try {
      if (!socket.user) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      console.log('Received message:', { roomId, userId: socket.user.id, content });
      
      // Save message to DB
      const result = await db.query(
        `INSERT INTO messages (room_id, user_id, content) VALUES ($1, $2, $3) RETURNING *`,
        [roomId, socket.user.id, content]
      );
      const message = result.rows[0];
      
      // Get user info for the message
      const messageWithUser = {
        ...message,
        username: socket.user.username,
        display_name: socket.user.display_name
      };
      
      console.log('Message saved:', messageWithUser);

      // Broadcast to room
      io.to(roomId).emit('chatMessage', messageWithUser);
      
    } catch (error) {
      console.error('Error handling chat message:', error);
      socket.emit('chatError', { 
        message: 'Failed to send message',
        error: error.message 
      });
    }
  });

  // --- WebRTC Signaling Events ---

  // User joins the WebRTC call in a room
  socket.on('webrtc-join', (roomId) => {
    if (!socket.user) {
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }
    // Notify others in the room that a user joined the call
    socket.to(roomId).emit('webrtc-user-joined', { userId: socket.user.id });
  });

  // Relay WebRTC signaling data (offer/answer/ICE)
  socket.on('webrtc-signal', ({ roomId, targetUserId, signalData }) => {
    if (!socket.user) {
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }
    // Send signaling data to a specific user in the room
    // Find the socket ID for the target user
    const targetSocketId = Array.from(io.sockets.sockets.values()).find(s => s.user && s.user.id === targetUserId)?.id;
    if (targetSocketId) {
      io.to(targetSocketId).emit('webrtc-signal', {
        fromUserId: socket.user.id,
        signalData
      });
    }
  });

  // User leaves the WebRTC call in a room
  socket.on('webrtc-leave', (roomId) => {
    if (!socket.user) {
      socket.emit('error', { message: 'Not authenticated' });
      return;
    }
    // Notify others in the room that a user left the call
    socket.to(roomId).emit('webrtc-user-left', { userId: socket.user.id });
  });

  socket.on('disconnect', async () => {
    const userId = socketUsers.get(socket.id);
    if (userId) {
      onlineUsers.delete(userId);
      socketUsers.delete(socket.id);
      await emitOnlineUsers();
      console.log('User disconnected:', socket.id);
    }
  });
});

// Clean up expired sessions periodically
setInterval(auth.cleanupExpiredSessions, 60 * 60 * 1000); // Every hour

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('JWT Secret:', process.env.JWT_SECRET ? 'Set' : 'Using default (change in production)');
});