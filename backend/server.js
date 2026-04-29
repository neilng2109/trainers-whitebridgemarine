require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
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
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@whitebridgemarine.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin-change-me';

// In-memory stores
const instructors = new Map(); // id -> { id, name, email, passwordHash }
const sessions = new Map();    // sessionId -> session
const pinIndex = new Map();    // pin -> sessionId

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

function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

// POST /api/auth/login — instructor login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const instructor = [...instructors.values()].find(i => i.email === email);
  if (!instructor) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, instructor.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: instructor.id, email: instructor.email, role: 'instructor' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, name: instructor.name });
});

// POST /api/admin/login — admin login
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ email, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// ── Admin — Instructor management ─────────────────────────────────────────────

// GET /api/admin/instructors
app.get('/api/admin/instructors', requireAdmin, (req, res) => {
  const list = [...instructors.values()].map(({ id, name, email }) => ({ id, name, email }));
  res.json(list);
});

// POST /api/admin/instructors
app.post('/api/admin/instructors', requireAdmin, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const exists = [...instructors.values()].find(i => i.email === email);
  if (exists) return res.status(409).json({ error: 'An instructor with that email already exists' });
  const id = uuidv4();
  const passwordHash = await bcrypt.hash(password, 10);
  instructors.set(id, { id, name, email, passwordHash });
  res.status(201).json({ id, name, email });
});

// PUT /api/admin/instructors/:id
app.put('/api/admin/instructors/:id', requireAdmin, (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  const instructor = instructors.get(req.params.id);
  if (!instructor) return res.status(404).json({ error: 'Instructor not found' });
  const duplicate = [...instructors.values()].find(i => i.email === email && i.id !== req.params.id);
  if (duplicate) return res.status(409).json({ error: 'That email is already in use' });
  instructor.name = name;
  instructor.email = email;
  res.json({ id: instructor.id, name, email });
});

// DELETE /api/admin/instructors/:id
app.delete('/api/admin/instructors/:id', requireAdmin, (req, res) => {
  if (!instructors.has(req.params.id)) return res.status(404).json({ error: 'Instructor not found' });
  instructors.delete(req.params.id);
  res.json({ ok: true });
});

// POST /api/admin/instructors/:id/reset-password
app.post('/api/admin/instructors/:id/reset-password', requireAdmin, async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const instructor = instructors.get(req.params.id);
  if (!instructor) return res.status(404).json({ error: 'Instructor not found' });
  instructor.passwordHash = await bcrypt.hash(password, 10);
  res.json({ ok: true });
});

// ── Sessions ──────────────────────────────────────────────────────────────────

// POST /api/sessions
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

// GET /api/sessions/:id
app.get('/api/sessions/:id', requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
});

// POST /api/sessions/join
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

// DELETE /api/sessions/:id
app.delete('/api/sessions/:id', requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  pinIndex.delete(session.pin);
  sessions.delete(req.params.id);
  io.to(req.params.id).emit('session:ended');
  res.json({ ok: true });
});

// ── Socket.io ─────────────────────────────────────────────────────────────────

io.on('connection', socket => {
  socket.on('join:session', sessionId => socket.join(sessionId));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`WBM backend running on port ${PORT}`));
