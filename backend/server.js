require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS instructors (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);
}

// Sessions remain in-memory (transient)
const sessions = new Map();
const pinIndex = new Map();

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

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const { rows } = await pool.query('SELECT * FROM instructors WHERE email = $1', [email]);
  const instructor = rows[0];
  if (!instructor) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, instructor.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: instructor.id, email: instructor.email, role: 'instructor' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, name: instructor.name });
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  const { rows } = await pool.query('SELECT * FROM instructors WHERE id = $1', [req.user.id]);
  const instructor = rows[0];
  if (!instructor) return res.status(404).json({ error: 'Instructor not found' });
  const match = await bcrypt.compare(currentPassword, instructor.password_hash);
  if (!match) return res.status(401).json({ error: 'Current password is incorrect' });
  const passwordHash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE instructors SET password_hash = $1 WHERE id = $2', [passwordHash, req.user.id]);
  res.json({ ok: true });
});

app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ email, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// ── Admin — Instructor management ─────────────────────────────────────────────

app.get('/api/admin/instructors', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, email FROM instructors ORDER BY name');
  res.json(rows);
});

app.post('/api/admin/instructors', requireAdmin, async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const id = uuidv4();
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    await pool.query(
      'INSERT INTO instructors (id, name, email, password_hash) VALUES ($1, $2, $3, $4)',
      [id, name, email, passwordHash]
    );
    res.status(201).json({ id, name, email });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'An instructor with that email already exists' });
    throw err;
  }
});

app.put('/api/admin/instructors/:id', requireAdmin, async (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
  try {
    const { rowCount } = await pool.query(
      'UPDATE instructors SET name = $1, email = $2 WHERE id = $3',
      [name, email, req.params.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Instructor not found' });
    res.json({ id: req.params.id, name, email });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That email is already in use' });
    throw err;
  }
});

app.delete('/api/admin/instructors/:id', requireAdmin, async (req, res) => {
  const { rowCount } = await pool.query('DELETE FROM instructors WHERE id = $1', [req.params.id]);
  if (rowCount === 0) return res.status(404).json({ error: 'Instructor not found' });
  res.json({ ok: true });
});

app.post('/api/admin/instructors/:id/reset-password', requireAdmin, async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const passwordHash = await bcrypt.hash(password, 10);
  const { rowCount } = await pool.query(
    'UPDATE instructors SET password_hash = $1 WHERE id = $2',
    [passwordHash, req.params.id]
  );
  if (rowCount === 0) return res.status(404).json({ error: 'Instructor not found' });
  res.json({ ok: true });
});

// ── Sessions ──────────────────────────────────────────────────────────────────

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

app.get('/api/sessions/:id', requireAuth, (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
});

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
initDB()
  .then(() => server.listen(PORT, () => console.log(`WBM backend running on port ${PORT}`)))
  .catch(err => { console.error('DB init failed:', err); process.exit(1); });
