const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// ==========================
// 1. MIDDLEWARE SETUP
// ==========================
app.use(bodyParser.json());
// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, 'public'))); 

app.use(session({
    secret: 'campus-code-secure-key-2024', // Change this in production
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    } 
}));

// ==========================
// 2. DATABASE SCHEMA
// ==========================
const db = new sqlite3.Database('./college.db', (err) => {
    if (err) console.error('DB Connection Error:', err.message);
    else console.log('Connected to the SQLite database.');
});

db.serialize(() => {
    // --- Users Table ---
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT CHECK(role IN ('admin', 'faculty'))
    )`);

    // --- Academic Entities (Enriched Fields) ---
    
    // 1. Programs (e.g., B.Tech, M.Tech)
    db.run(`CREATE TABLE IF NOT EXISTS programs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        code TEXT UNIQUE,   -- e.g., BTECH
        duration INTEGER,   -- e.g., 4 (years)
        degree_type TEXT    -- e.g., Undergraduate
    )`);

    // 2. Departments (e.g., Computer Science)
    db.run(`CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        code TEXT UNIQUE,   -- e.g., CSE
        hod_name TEXT,
        contact_email TEXT
    )`);

    // 3. Sections (e.g., Section A, 2024 Batch)
    db.run(`CREATE TABLE IF NOT EXISTS sections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,          -- e.g., 'A'
        semester INTEGER,
        capacity INTEGER
    )`);

    // 4. Subjects (e.g., Data Structures)
    db.run(`CREATE TABLE IF NOT EXISTS subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        code TEXT UNIQUE,   -- e.g., CS101
        credits INTEGER,
        type TEXT           -- e.g., Core / Elective
    )`);

    // --- Academic Mapping (The "Glue") ---
    // This links a Subject to a specific Program, Dept, and Section
    db.run(`CREATE TABLE IF NOT EXISTS academic_mappings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        program_id INTEGER,
        department_id INTEGER,
        section_id INTEGER,
        subject_id INTEGER,
        FOREIGN KEY(program_id) REFERENCES programs(id) ON DELETE CASCADE,
        FOREIGN KEY(department_id) REFERENCES departments(id) ON DELETE CASCADE,
        FOREIGN KEY(section_id) REFERENCES sections(id) ON DELETE CASCADE,
        FOREIGN KEY(subject_id) REFERENCES subjects(id) ON DELETE CASCADE
    )`);

    // --- Content: Problems ---
    db.run(`CREATE TABLE IF NOT EXISTS problems (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        faculty_id INTEGER,
        title TEXT,
        description TEXT,
        difficulty TEXT CHECK(difficulty IN ('Easy', 'Medium', 'Hard')),
        tags TEXT,
        constraints TEXT,
        input_format TEXT,
        output_format TEXT,
        sample_input TEXT,
        sample_output TEXT,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(faculty_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // --- Content: Contests ---
    db.run(`CREATE TABLE IF NOT EXISTS contests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        faculty_id INTEGER,
        title TEXT,
        description TEXT,
        start_time DATETIME,
        end_time DATETIME,
        duration_minutes INTEGER,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(faculty_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // --- Create Default Admin ---
    const adminUser = 'admin@campus.com'; 
    db.get("SELECT * FROM users WHERE username = ?", [adminUser], (err, row) => {
        if (!row) {
            bcrypt.hash('admin123', 10, (err, hash) => {
                db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [adminUser, hash, 'admin']);
                console.log("System Initialized. Admin: admin@campus.com / admin123");
            });
        }
    });
});

// ==========================
// 3. AUTHENTICATION ROUTES
// ==========================

// Check Session
app.get('/api/session', (req, res) => {
    if (req.session.userId) {
        res.json({ loggedIn: true, role: req.session.role });
    } else {
        res.json({ loggedIn: false });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        req.session.userId = user.id;
        req.session.role = user.role;
        
        const redirectUrl = user.role === 'admin' ? '/admin.html' : '/faculty.html';
        res.json({ message: 'Success', role: user.role, redirect: redirectUrl });
    });
});

// Register (Faculty)
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if(!username || !password) return res.status(400).json({error: 'Missing fields'});
    
    try {
        const h = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'faculty')`, [username, h], (err) => {
            if(err) return res.status(400).json({error: 'Username exists'});
            res.json({message: 'Registered successfully'});
        });
    } catch (e) { res.status(500).json({error: 'Server error'}); }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out' });
});

// ==========================
// 4. ACADEMIC ROUTES (Admin)
// ==========================

// Create Academic Entities
app.post('/api/academic', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    
    const { type, data } = req.body;
    let sql, params;

    switch(type) {
        case 'program':
            sql = `INSERT INTO programs (name, code, duration, degree_type) VALUES (?, ?, ?, ?)`;
            params = [data.name, data.code, data.duration, data.degree_type];
            break;
        case 'department':
            sql = `INSERT INTO departments (name, code, hod_name, contact_email) VALUES (?, ?, ?, ?)`;
            params = [data.name, data.code, data.hod_name, data.contact_email];
            break;
        case 'section':
            sql = `INSERT INTO sections (name, semester, capacity) VALUES (?, ?, ?)`;
            params = [data.name, data.semester, data.capacity];
            break;
        case 'subject':
            sql = `INSERT INTO subjects (name, code, credits, type) VALUES (?, ?, ?, ?)`;
            params = [data.name, data.code, data.credits, data.type];
            break;
        default: return res.status(400).json({ error: 'Invalid Entity Type' });
    }

    db.run(sql, params, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, message: 'Created successfully' });
    });
});

// Get All Data (For Dropdowns)
app.get('/api/academic/all', (req, res) => {
    const data = {};
    db.serialize(() => {
        db.all("SELECT * FROM programs", (err, rows) => data.programs = rows);
        db.all("SELECT * FROM departments", (err, rows) => data.departments = rows);
        db.all("SELECT * FROM sections", (err, rows) => data.sections = rows);
        db.all("SELECT * FROM subjects", (err, rows) => {
            data.subjects = rows;
            res.json(data);
        });
    });
});

// Create Mapping (Link entities)
app.post('/api/academic/map', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const { program_id, department_id, section_id, subject_id } = req.body;
    
    db.run(`INSERT INTO academic_mappings (program_id, department_id, section_id, subject_id) VALUES (?, ?, ?, ?)`,
        [program_id, department_id, section_id, subject_id], function(err) {
            if(err) return res.status(500).json({error: err.message});
            res.json({message: 'Mapped successfully'});
        });
});

// Get Mappings (For Table View)
app.get('/api/academic/map', (req, res) => {
    const sql = `
        SELECT m.id, 
               p.name as program, p.code as prog_code,
               d.name as department, d.code as dept_code,
               s.name as section, s.semester,
               sub.name as subject, sub.code as sub_code
        FROM academic_mappings m
        JOIN programs p ON m.program_id = p.id
        JOIN departments d ON m.department_id = d.id
        JOIN sections s ON m.section_id = s.id
        JOIN subjects sub ON m.subject_id = sub.id
    `;
    db.all(sql, [], (err, rows) => {
        if(err) return res.status(500).json({error: err.message});
        res.json(rows);
    });
});

// Delete Mapping
app.delete('/api/academic/map/:id', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    db.run(`DELETE FROM academic_mappings WHERE id = ?`, [req.params.id], (err) => {
        if(err) return res.status(500).json({error: err.message});
        res.json({message: 'Deleted'});
    });
});

// ==========================
// 5. CONTENT ROUTES (Problems/Contests)
// ==========================

// Create Content
app.post('/api/content', (req, res) => {
    if (req.session.role !== 'faculty') return res.status(403).json({ error: 'Unauthorized' });
    
    const { type, ...d } = req.body;
    const uid = req.session.userId;
    
    if (type === 'problem') {
        const sql = `INSERT INTO problems (faculty_id, title, description, difficulty, tags, constraints, input_format, output_format, sample_input, sample_output) VALUES (?,?,?,?,?,?,?,?,?,?)`;
        const params = [uid, d.title, d.description, d.difficulty, d.tags, d.constraints, d.input_format, d.output_format, d.sample_input, d.sample_output];
        db.run(sql, params, (err) => {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Problem Created' });
        });
    } else if (type === 'contest') {
        const sql = `INSERT INTO contests (faculty_id, title, description, start_time, end_time, duration_minutes) VALUES (?,?,?,?,?,?)`;
        const params = [uid, d.title, d.description, d.start_time, d.end_time, d.duration];
        db.run(sql, params, (err) => {
            if(err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Contest Scheduled' });
        });
    } else {
        res.status(400).json({ error: 'Invalid Type' });
    }
});

// Get My Content (Faculty)
app.get('/api/content/my', (req, res) => {
    if (req.session.role !== 'faculty') return res.status(403).json({ error: 'Unauthorized' });
    const uid = req.session.userId;
    const sql = `
        SELECT id, title, description, difficulty as extra_info, 'problem' as type, status FROM problems WHERE faculty_id = ?
        UNION ALL
        SELECT id, title, description, start_time as extra_info, 'contest' as type, status FROM contests WHERE faculty_id = ?
    `;
    db.all(sql, [uid, uid], (err, rows) => res.json(rows || []));
});

// Get Pending Content (Admin)
app.get('/api/content/pending', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const sql = `
        SELECT id, title, description, 'problem' as type, status, (SELECT username FROM users WHERE id=problems.faculty_id) as faculty_name FROM problems WHERE status='pending'
        UNION ALL
        SELECT id, title, description, 'contest' as type, status, (SELECT username FROM users WHERE id=contests.faculty_id) as faculty_name FROM contests WHERE status='pending'
    `;
    db.all(sql, [], (err, rows) => res.json(rows || []));
});

// Verify Content
app.post('/api/content/verify', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const { id, type } = req.body;
    const table = type === 'contest' ? 'contests' : 'problems';
    db.run(`UPDATE ${table} SET status = 'verified' WHERE id = ?`, [id], (err) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Verified' });
    });
});

// Delete Content
app.delete('/api/content/:type/:id', (req, res) => {
    const { type, id } = req.params;
    const table = type === 'contest' ? 'contests' : 'problems';
    // (Optional: Add check for faculty ownership here)
    db.run(`DELETE FROM ${table} WHERE id = ?`, [id], (err) => {
        if(err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Deleted' });
    });
});

// ==========================
// 6. SERVER START
// ==========================
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});