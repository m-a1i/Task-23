const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Admin, Message } = require('./models');

const app = express();
const JWT_SECRET = 'your_super_secret_jwt_key';

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied. Token missing.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// POST /api/login - Authenticate admin
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(400).json({ error: 'Invalid username or password.' });

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) return res.status(400).json({ error: 'Invalid username or password.' });

    const token = jwt.sign({ id: admin._id, username: admin.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/messages - Fetch all messages (Protected)
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find().sort({ created_at: -1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch messages.' });
  }
});

// PATCH /api/messages/:id/read - Toggle read status (Protected)
app.patch('/api/messages/:id/read', authenticateToken, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    msg.isRead = !msg.isRead;
    await msg.save();
    res.json(msg);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update status.' });
  }
});

// DELETE /api/messages/:id - Delete message (Protected)
app.delete('/api/messages/:id', authenticateToken, async (req, res) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Message deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete message.' });
  }
});

mongoose.connect('mongodb://localhost:27017/adminPanel')
  .then(() => app.listen(3000, () => console.log('Server running on port 3000')))
  .catch(err => console.error(err));
