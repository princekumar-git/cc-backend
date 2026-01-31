const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// --- Middleware ---
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 1000 * 60 * 60 * 24 // Session lasts 24 hours
    } 
}));

// --- Database Setup ---
const db = new sqlite3.Database('./college.db', (err) => {
    if (err) console.error(err.message);
    console.log('Connected to the SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT CHECK(role IN ('admin', 'faculty'))
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS academic_structure (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT, 
        name TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS content (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        faculty_id INTEGER,
        type TEXT CHECK(type IN ('problem', 'contest')),
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(faculty_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    const adminHash = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, [adminHash]);
});

// --- Routes ---

// 1. Session Persistence (NEW)
app.get('/api/session', (req, res) => {
    if (req.session.userId) {
        // Return current user info if session exists
        res.json({ 
            loggedIn: true, 
            role: req.session.role, 
            userId: req.session.userId 
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// 2. Authentication
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({ error: 'Missing fields'});
    const hashedPassword = await bcrypt.hash(password, 10);
    
    db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'faculty')`, [username, hashedPassword], function(err) {
        if (err) return res.status(400).json({ error: 'Username already exists' });
        res.json({ message: 'Faculty registered successfully' });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        req.session.userId = user.id;
        req.session.role = user.role;
        res.json({ role: user.role });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out' });
});

// 3. Admin: Academic Structure (CRUD)
app.post('/api/academic', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const { type, name } = req.body;
    db.run(`INSERT INTO academic_structure (type, name) VALUES (?, ?)`, [type, name], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, type, name });
    });
});

app.get('/api/academic', (req, res) => {
    db.all(`SELECT * FROM academic_structure`, [], (err, rows) => {
        res.json(rows);
    });
});

// DELETE Academic Structure (Fixing "Can't delete" issue)
app.delete('/api/academic/:id', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    db.run(`DELETE FROM academic_structure WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted successfully' });
    });
});

// 4. Content Operations
app.post('/api/content', (req, res) => {
    if (req.session.role !== 'faculty') return res.status(403).json({ error: 'Unauthorized' });
    const { type, title, description } = req.body;
    db.run(`INSERT INTO content (faculty_id, type, title, description) VALUES (?, ?, ?, ?)`, 
        [req.session.userId, type, title, description], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Submitted for verification' });
    });
});

app.get('/api/content/pending', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    db.all(`SELECT c.*, u.username as faculty_name FROM content c JOIN users u ON c.faculty_id = u.id WHERE status = 'pending'`, [], (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/content/my', (req, res) => {
    if (req.session.role !== 'faculty') return res.status(403).json({ error: 'Unauthorized' });
    db.all(`SELECT * FROM content WHERE faculty_id = ?`, [req.session.userId], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/content/verify', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const { id, status } = req.body;
    db.run(`UPDATE content SET status = ? WHERE id = ?`, [status || 'verified', id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Content status updated' });
    });
});

app.put('/api/content/:id', (req, res) => {
    if (req.session.role !== 'faculty') return res.status(403).json({ error: 'Unauthorized' });
    const { title, description } = req.body;
    db.run(`UPDATE content SET title = ?, description = ? WHERE id = ? AND faculty_id = ? AND status != 'verified'`, 
        [title, description, req.params.id, req.session.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Content updated' });
    });
});

app.delete('/api/content/:id', (req, res) => {
    const userId = req.session.userId;
    const role = req.session.role;
    let sql = `DELETE FROM content WHERE id = ?`;
    let params = [req.params.id];

    if (role === 'faculty') {
        sql += ` AND faculty_id = ?`;
        params.push(userId);
    } else if (role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    db.run(sql, params, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted successfully' });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});