const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// ── Database setup ──
const db = new Database(path.join(__dirname, 'chess.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS friends (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id),
    UNIQUE(from_user_id, to_user_id)
  );
`);

// Prepared statements
const stmts = {
  findUser: db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?'),
  findUserById: db.prepare('SELECT id, username FROM users WHERE id = ?'),
  createUser: db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)'),
  searchUsers: db.prepare('SELECT id, username FROM users WHERE username LIKE ? AND id != ? LIMIT 20'),

  sendRequest: db.prepare('INSERT OR IGNORE INTO friends (from_user_id, to_user_id, status) VALUES (?, ?, \'pending\')'),
  acceptRequest: db.prepare('UPDATE friends SET status = \'accepted\' WHERE from_user_id = ? AND to_user_id = ? AND status = \'pending\''),
  removeFriend: db.prepare('DELETE FROM friends WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)'),

  getFriends: db.prepare(`
    SELECT u.id, u.username, f.status,
      CASE WHEN f.from_user_id = ? THEN 'sent' ELSE 'received' END as direction
    FROM friends f
    JOIN users u ON u.id = CASE WHEN f.from_user_id = ? THEN f.to_user_id ELSE f.from_user_id END
    WHERE (f.from_user_id = ? OR f.to_user_id = ?)
    ORDER BY f.status ASC, u.username ASC
  `),

  checkExistingFriendship: db.prepare(`
    SELECT id FROM friends
    WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)
  `),
};

// ── Middleware ──
app.use(express.json());
app.use(express.static(__dirname));

// ── Auth token store (in-memory, simple approach) ──
const sessions = new Map(); // token -> { userId, username }

function authenticate(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  req.user = sessions.get(token);
  next();
}

// ── Auth Routes ──
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const existing = stmts.findUser.get(username);
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const result = stmts.createUser.run(username, hash);
  const token = uuidv4();
  sessions.set(token, { userId: result.lastInsertRowid, username });

  res.json({ token, userId: result.lastInsertRowid, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = stmts.findUser.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = uuidv4();
  sessions.set(token, { userId: user.id, username: user.username });
  res.json({ token, userId: user.id, username: user.username });
});

app.post('/api/logout', authenticate, (req, res) => {
  const token = req.headers['x-auth-token'];
  sessions.delete(token);
  res.json({ ok: true });
});

// ── Friends Routes ──
app.get('/api/friends', authenticate, (req, res) => {
  const friends = stmts.getFriends.all(req.user.userId, req.user.userId, req.user.userId, req.user.userId);
  res.json({ friends });
});

app.get('/api/users/search', authenticate, (req, res) => {
  const q = req.query.q;
  if (!q || q.length < 1) return res.json({ users: [] });
  const users = stmts.searchUsers.all('%' + q + '%', req.user.userId);
  res.json({ users });
});

app.post('/api/friends/request', authenticate, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  if (userId === req.user.userId) return res.status(400).json({ error: 'Cannot add yourself' });

  const target = stmts.findUserById.get(userId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  const existing = stmts.checkExistingFriendship.get(req.user.userId, userId, userId, req.user.userId);
  if (existing) return res.status(409).json({ error: 'Friend request already exists' });

  stmts.sendRequest.run(req.user.userId, userId);

  // Notify target user via socket
  const targetSocket = onlineUsers.get(userId);
  if (targetSocket) {
    io.to(targetSocket).emit('friend-request', { fromId: req.user.userId, fromUsername: req.user.username });
  }

  res.json({ ok: true });
});

app.post('/api/friends/accept', authenticate, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  stmts.acceptRequest.run(userId, req.user.userId);

  // Notify the other user
  const targetSocket = onlineUsers.get(userId);
  if (targetSocket) {
    io.to(targetSocket).emit('friend-accepted', { userId: req.user.userId, username: req.user.username });
  }

  res.json({ ok: true });
});

app.post('/api/friends/remove', authenticate, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  stmts.removeFriend.run(req.user.userId, userId, userId, req.user.userId);
  res.json({ ok: true });
});

// ── Socket.IO for online games ──
const onlineUsers = new Map();  // userId -> socketId
const activeGames = new Map();  // gameId -> { white: {userId, socketId}, black: {userId, socketId}, moves: [], timerPreset, ... }
const pendingChallenges = new Map(); // challengeId -> { from, to, color, timerPreset }

io.on('connection', (socket) => {
  let currentUserId = null;
  let currentUsername = null;

  socket.on('auth', (token) => {
    const session = sessions.get(token);
    if (!session) { socket.emit('auth-fail'); return; }
    currentUserId = session.userId;
    currentUsername = session.username;
    onlineUsers.set(currentUserId, socket.id);
    socket.emit('auth-ok', { userId: currentUserId, username: currentUsername });

    // Broadcast online status to friends
    broadcastOnlineStatus(currentUserId, true);
  });

  socket.on('get-online-friends', () => {
    if (!currentUserId) return;
    const friends = stmts.getFriends.all(currentUserId, currentUserId, currentUserId, currentUserId);
    const onlineFriends = friends
      .filter(f => f.status === 'accepted' && onlineUsers.has(f.id))
      .map(f => f.id);
    socket.emit('online-friends', onlineFriends);
  });

  // Challenge a friend
  socket.on('challenge', ({ targetUserId, color, timerPreset }) => {
    if (!currentUserId) return;
    const targetSocket = onlineUsers.get(targetUserId);
    if (!targetSocket) { socket.emit('challenge-error', 'Player is offline'); return; }

    const challengeId = uuidv4();
    pendingChallenges.set(challengeId, {
      from: { userId: currentUserId, username: currentUsername, socketId: socket.id },
      to: { userId: targetUserId },
      color: color || 'w', // challenger plays as this color
      timerPreset: timerPreset || 0,
    });

    io.to(targetSocket).emit('challenge-received', {
      challengeId,
      fromId: currentUserId,
      fromUsername: currentUsername,
      color: color === 'w' ? 'b' : 'w', // opponent gets the other color
      timerPreset: timerPreset || 0,
    });

    socket.emit('challenge-sent', { challengeId });

    // Auto-expire challenge after 60s
    setTimeout(() => {
      if (pendingChallenges.has(challengeId)) {
        pendingChallenges.delete(challengeId);
        socket.emit('challenge-expired', { challengeId });
        const ts = onlineUsers.get(targetUserId);
        if (ts) io.to(ts).emit('challenge-expired', { challengeId });
      }
    }, 60000);
  });

  socket.on('challenge-accept', ({ challengeId }) => {
    const challenge = pendingChallenges.get(challengeId);
    if (!challenge || challenge.to.userId !== currentUserId) return;
    pendingChallenges.delete(challengeId);

    const gameId = uuidv4();
    const game = {
      id: gameId,
      white: challenge.color === 'w'
        ? { userId: challenge.from.userId, socketId: challenge.from.socketId }
        : { userId: currentUserId, socketId: socket.id },
      black: challenge.color === 'b'
        ? { userId: challenge.from.userId, socketId: challenge.from.socketId }
        : { userId: currentUserId, socketId: socket.id },
      moves: [],
      timerPreset: challenge.timerPreset,
    };
    activeGames.set(gameId, game);

    // Join both to a room
    const whiteSocket = io.sockets.sockets.get(game.white.socketId);
    const blackSocket = io.sockets.sockets.get(game.black.socketId);
    if (whiteSocket) whiteSocket.join(gameId);
    if (blackSocket) blackSocket.join(gameId);

    // Notify both players
    if (whiteSocket) whiteSocket.emit('game-start', { gameId, color: 'w', timerPreset: game.timerPreset, opponentName: currentUsername });
    if (blackSocket) blackSocket.emit('game-start', { gameId, color: 'b', timerPreset: game.timerPreset, opponentName: challenge.from.username });
  });

  socket.on('challenge-decline', ({ challengeId }) => {
    const challenge = pendingChallenges.get(challengeId);
    if (!challenge) return;
    pendingChallenges.delete(challengeId);
    const fromSocket = onlineUsers.get(challenge.from.userId);
    if (fromSocket) io.to(fromSocket).emit('challenge-declined', { challengeId });
  });

  // Game moves
  socket.on('game-move', ({ gameId, uci, fen }) => {
    const game = activeGames.get(gameId);
    if (!game) return;
    game.moves.push(uci);
    // Relay to opponent
    socket.to(gameId).emit('opponent-move', { uci, fen });
  });

  socket.on('game-over', ({ gameId, result }) => {
    const game = activeGames.get(gameId);
    if (!game) return;
    socket.to(gameId).emit('game-ended', { result });
    activeGames.delete(gameId);
  });

  socket.on('game-resign', ({ gameId }) => {
    const game = activeGames.get(gameId);
    if (!game) return;
    const resignerColor = game.white.socketId === socket.id ? 'White' : 'Black';
    const winnerColor = resignerColor === 'White' ? 'Black' : 'White';
    io.to(gameId).emit('game-ended', { result: `${winnerColor} wins by resignation` });
    activeGames.delete(gameId);
  });

  socket.on('disconnect', () => {
    if (currentUserId) {
      onlineUsers.delete(currentUserId);
      broadcastOnlineStatus(currentUserId, false);

      // Handle disconnection from active games
      for (const [gameId, game] of activeGames) {
        if (game.white.socketId === socket.id || game.black.socketId === socket.id) {
          const disconnectedColor = game.white.socketId === socket.id ? 'White' : 'Black';
          const winnerColor = disconnectedColor === 'White' ? 'Black' : 'White';
          socket.to(gameId).emit('game-ended', { result: `${winnerColor} wins (opponent disconnected)` });
          activeGames.delete(gameId);
        }
      }
    }
  });

  function broadcastOnlineStatus(userId, isOnline) {
    const friends = stmts.getFriends.all(userId, userId, userId, userId);
    for (const f of friends) {
      if (f.status === 'accepted') {
        const fSocket = onlineUsers.get(f.id);
        if (fSocket) io.to(fSocket).emit('friend-status', { userId, online: isOnline });
      }
    }
  }
});

// ── Start server ──
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Chess server running at http://localhost:${PORT}`);
  console.log(`Other devices on your network can connect via http://<your-ip>:${PORT}`);
});
