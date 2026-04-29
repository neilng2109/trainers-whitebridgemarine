require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);

const FRONTEND_URL = process.env.FRONTEND_URL || '*';

const io = new Server(server, {
  cors: { origin: FRONTEND_URL, methods: ['GET', 'POST'] }
});

app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-prod';
const INSTRUCTOR_EMAIL = process.env.INSTRUCTOR_EMAIL || 'instructor@whitebridgemarine.com';
const INSTRUCTOR_PASS = process.env.INSTRUCTOR_PASS || 'csmart2026';

// In-memory store
const sessions = new Map(); // sessionId -> session
const pinIndex = new Map(); // pin -> sessionId

function genPIN() {
  let pin;
  do { pin = Math.floor(1000 + Math.random() * 9000).toString(); } while (pinIndex.has(pin));
  return pin;
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email === INSTRUCTOR_EMAIL && password === INSTRUCTOR_PASS) {
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '12h' });
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

// POST /api/sessions — create session
app.post('/api/sessions', requireAuth, (req, res) => {
  const { name, duration, trainers, expected } = req.body || {};
  if (!Array.isArray(trainers) || trainers.length === 0) {
    return res.status(400).json({ error: 'Select at least one trainer' });
  }
  const id = uuidv4();
  const pin = genPIN();
  sessions.set(id, { id, pin, name, duration, trainers, expected, participants: [], createdAt: Date.now() });
  pinIndex.set(pin, id);
  res.json({ id, pin });
});

// GET /api/sessions/:id — dashboard poll
app.get('/api/sessions/:id', requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
});

// POST /api/sessions/join — participant joins by PIN
app.post('/api/sessions/join', (req, res) => {
  const { pin, name } = req.body || {};
  const sessionId = pinIndex.get(pin);
  if (!sessionId) return res.status(404).json({ error: 'Invalid PIN' });
  const session = sessions.get(sessionId);
  const participant = { name: name || 'Participant', joinedAt: Date.now() };
  session.participants.push(participant);
  io.to(sessionId).emit('participant:joined', { count: session.participants.length, participant });
  res.json({ sessionId, sessionName: session.name, trainers: session.trainers });
});

// DELETE /api/sessions/:id — end session
app.delete('/api/sessions/:id', requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  pinIndex.delete(session.pin);
  sessions.delete(req.params.id);
  io.to(req.params.id).emit('session:ended');
  res.json({ ok: true });
});

// Socket.io — instructor joins session room
io.on('connection', socket => {
  socket.on('join:session', sessionId => {
    socket.join(sessionId);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`WBM backend running on port ${PORT}`));
