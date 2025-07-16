const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const db = require('./db');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*', // Adjust for production
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

// REST endpoint to fetch messages for a room
app.get('/api/rooms/:roomId/messages', async (req, res) => {
  const { roomId } = req.params;
  const result = await db.query(
    `SELECT messages.*, users.username
     FROM messages
     JOIN users ON messages.user_id = users.id
     WHERE room_id = $1
     ORDER BY sent_at ASC`,
    [roomId]
  );
  res.json(result.rows);
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
    // Save to DB
    const result = await db.query(
      `INSERT INTO messages (room_id, user_id, content) VALUES ($1, $2, $3) RETURNING *`,
      [roomId, userId, content]
    );
    const message = result.rows[0];

    // Broadcast to room
    io.to(roomId).emit('chatMessage', message);
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