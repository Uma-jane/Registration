const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

// In-memory store when database is unavailable
const inMemoryUsers = new Map();
let inMemoryId = 1;

const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ message: 'Method not allowed' });
  }

  try {
    const { username, email, phone, password, confirmPassword } = req.body;

    if (!username || !email || !phone || !password || !confirmPassword) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const [existingUsers] = await pool.query(
        'SELECT * FROM users WHERE username = ? OR email = ?',
        [username, email]
      );

      if (existingUsers.length > 0) {
        return res.status(409).json({ message: 'Username or email already exists' });
      }

      await pool.query(
        'INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)',
        [username, email, phone, hashedPassword]
      );
    } catch (dbErr) {
      if (inMemoryUsers.has(username) || [...inMemoryUsers.values()].some(u => u.email === email)) {
        return res.status(409).json({ message: 'Username or email already exists' });
      }
      inMemoryUsers.set(username, {
        id: inMemoryId++,
        username,
        email,
        phone,
        password: hashedPassword
      });
    }

    res.status(201).json({ message: 'Registration successful!' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: err.message || 'Internal server error' });
  }
};
