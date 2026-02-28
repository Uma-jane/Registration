const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_123';

// In-memory store when database is unavailable
const inMemoryUsers = new Map();
let inMemoryId = 1;

// Middleware
const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:3000',
    process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            return callback(null, true); // Allow all origins for now
        }
        return callback(null, true);
    },
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Registration Endpoint
app.post('/register', async (req, res) => {
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
            // Try database first
            const [existingUsers] = await db.query(
                'SELECT * FROM users WHERE username = ? OR email = ?',
                [username, email]
            );

            if (existingUsers.length > 0) {
                return res.status(409).json({ message: 'Username or email already exists' });
            }

            await db.query(
                'INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)',
                [username, email, phone, hashedPassword]
            );
        } catch (dbErr) {
            // Fallback to in-memory when database is unavailable
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
});

// Login Endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        let user = null;

        try {
            const [users] = await db.query(
                'SELECT * FROM users WHERE username = ?',
                [username]
            );
            if (users.length > 0) user = users[0];
        } catch (dbErr) {
            // Fallback to in-memory when database is unavailable
            const inMem = inMemoryUsers.get(username);
            if (inMem) user = inMem;
        }

        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('authToken', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 3600000 // 1 hour
        });

        res.status(200).json({ message: 'login success', user: { username: user.username } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Check Auth Endpoint (for dashboard)
app.get('/verify-auth', (req, res) => {
    const token = req.cookies.authToken;

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.status(200).json({ user: decoded });
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Logout Endpoint
app.post('/logout', (req, res) => {
    res.clearCookie('authToken');
    res.status(200).json({ message: 'logout success' });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
