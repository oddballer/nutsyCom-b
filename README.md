# NutsyCom Backend

A Node.js backend for the NutsyCom chat application with authentication and real-time messaging.

## Features

- **User Authentication**: JWT-based authentication with password hashing
- **Session Management**: Persistent user sessions with automatic cleanup
- **Real-time Chat**: WebSocket-based messaging with Socket.IO
- **Room Management**: Public and private chat rooms with membership control
- **Rate Limiting**: Protection against abuse
- **PostgreSQL**: Persistent data storage with proper relationships

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set up environment variables:
   ```bash
   # Database Configuration
   DATABASE_URL=postgresql://username:password@localhost:5432/nutsycom
   
   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
   
   # Environment
   NODE_ENV=development
   
   # Frontend URL (for CORS)
   FRONTEND_URL=http://localhost:5173
   
   # Server Port
   PORT=4000
   ```

3. Initialize the database:
   ```bash
   # Visit http://localhost:4000/api/init-db in your browser
   # Or make a GET request to the endpoint
   ```

4. Start the server:
   ```bash
   npm start
   ```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user (requires auth)
- `GET /api/auth/profile` - Get user profile (requires auth)

### Chat
- `GET /api/rooms` - Get available chat rooms
- `GET /api/rooms/:roomId/messages` - Get messages for a room

### WebSocket Events

#### Client to Server
- `authenticate(token)` - Authenticate socket connection
- `joinRoom(roomId)` - Join a chat room
- `chatMessage({ roomId, content })` - Send a message

#### Server to Client
- `authenticated({ user })` - Authentication successful
- `authError({ message })` - Authentication failed
- `roomJoined({ roomId })` - Successfully joined room
- `chatMessage(message)` - New message received
- `onlineUsers([userId, ...])` - List of online users
- `error({ message })` - Error occurred

## Database Schema

The backend uses PostgreSQL with the following main tables:
- `users` - User accounts and authentication
- `chat_rooms` - Chat rooms (public/private)
- `messages` - Chat messages
- `room_memberships` - User membership in rooms
- `user_sessions` - JWT session management
- `user_relationships` - User relationships (friends, blocks)

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Session management with expiration
- Rate limiting
- CORS protection
- Input validation
- SQL injection protection with parameterized queries
