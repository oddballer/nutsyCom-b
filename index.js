const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const db = require('./db');
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
    version: '0.1.0',
    endpoints: {
      messages: '/api/rooms/:roomId/messages',
      websocket: 'Socket.IO connection available'
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

// REST endpoint to fetch messages for a room
app.get('/api/rooms/:roomId/messages', async (req, res) => {
  try {
    console.log('Received request for room:', req.params.roomId);
    const { roomId } = req.params;
    const result = await db.query(
      `SELECT messages.*, users.username
       FROM messages
       JOIN users ON messages.user_id = users.id
       WHERE room_id = $1
       ORDER BY sent_at ASC`,
      [roomId]
    );
    console.log('Found messages:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// WebSocket events
const onlineUsers = new Map(); // userId -> socket.id

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  // Track user online status
  socket.on('userOnline', (userId) => {
    onlineUsers.set(userId, socket.id);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  });

  // Join a room
  socket.on('joinRoom', (roomId) => {
    socket.join(roomId);
  });

  // Handle new message
  socket.on('chatMessage', async ({ roomId, userId, content }) => {
    try {
      console.log('Received message:', { roomId, userId, content });
      
      // First, ensure the user exists in the database
      let userResult = await db.query('SELECT id FROM users WHERE id = $1', [userId]);
      
      if (userResult.rows.length === 0) {
        // Create the user if they don't exist
        console.log('Creating new user:', userId);
        userResult = await db.query(
          'INSERT INTO users (id, username) VALUES ($1, $2) RETURNING id',
          [userId, `User ${userId}`]
        );
      }
      
      // Ensure the room exists
      let roomResult = await db.query('SELECT id FROM chat_rooms WHERE id = $1', [roomId]);
      
      if (roomResult.rows.length === 0) {
        // Create the room if it doesn't exist
        console.log('Creating new room:', roomId);
        roomResult = await db.query(
          'INSERT INTO chat_rooms (id, name) VALUES ($1, $2) RETURNING id',
          [roomId, `Room ${roomId}`]
        );
      }
      
      // Save message to DB
      const result = await db.query(
        `INSERT INTO messages (room_id, user_id, content) VALUES ($1, $2, $3) RETURNING *`,
        [roomId, userId, content]
      );
      const message = result.rows[0];
      
      console.log('Message saved:', message);

      // Broadcast to room
      io.to(roomId).emit('chatMessage', message);
      
    } catch (error) {
      console.error('Error handling chat message:', error);
      // Send error back to the client
      socket.emit('chatError', { 
        message: 'Failed to send message',
        error: error.message 
      });
    }
  });

  socket.on('disconnect', () => {
    // Remove user from onlineUsers
    for (const [userId, id] of onlineUsers.entries()) {
      if (id === socket.id) {
        onlineUsers.delete(userId);
        break;
      }
    }
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});