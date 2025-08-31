const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
// The port has been changed to 8080 to avoid the EADDRINUSE error.
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'frontend'))); // Serve frontend files

// Session management
app.use(session({
  secret: 'pathstarter-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Database initialization
const db = new sqlite3.Database('./database.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create tables if they don't exist
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);

  // Jobs table
  db.run(`CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    company TEXT NOT NULL,
    location TEXT NOT NULL,
    description TEXT NOT NULL,
    requirements TEXT,
    salary TEXT,
    posted_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Applications table
  db.run(`CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    job_id INTEGER,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(job_id) REFERENCES jobs(id)
  )`);
});

// Helper function to check for authentication
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Routes

// User registration
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if email already exists
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (row) {
      return res.status(409).json({ error: 'Email already in use' });
    }

    // Hash password
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        return res.status(500).json({ error: 'Password hashing failed' });
      }

      // Insert new user
      db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [name, email, hash],
        function (err) {
          if (err) {
            return res.status(500).json({ error: 'User registration failed' });
          }
          res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
        }
      );
    });
  });
});

// User login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Find user by email
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare passwords
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Password comparison failed' });
      }
      if (!result) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Set session
      req.session.userId = user.id;
      req.session.userName = user.name;
      res.json({ message: 'Login successful', user: { id: user.id, name: user.name, email: user.email } });
    });
  });
});

// User logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logout successful' });
  });
});

// Get user profile
app.get('/api/profile', requireAuth, (req, res) => {
  const userId = req.session.userId;
  db.get('SELECT id, name, email FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  });
});

// Get all jobs
app.get('/api/jobs', (req, res) => {
  db.all('SELECT * FROM jobs ORDER BY posted_at DESC', (err, jobs) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(jobs);
  });
});

// Get a single job by ID
app.get('/api/jobs/:id', (req, res) => {
  const jobId = req.params.id;
  db.get('SELECT * FROM jobs WHERE id = ?', [jobId], (err, job) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }
    res.json(job);
  });
});

// Post a new job (protected route)
app.post('/api/jobs', requireAuth, (req, res) => {
  const { title, company, location, description, requirements, salary } = req.body;
  
  if (!title || !company || !location || !description) {
    return res.status(400).json({ error: 'Title, company, location, and description are required' });
  }

  db.run(
    'INSERT INTO jobs (title, company, location, description, requirements, salary) VALUES (?, ?, ?, ?, ?, ?)',
    [title, company, location, description, requirements, salary],
    function (err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to post job' });
      }
      res.status(201).json({ message: 'Job posted successfully', jobId: this.lastID });
    }
  );
});

// Apply to a job (protected route)
app.post('/api/jobs/:id/apply', requireAuth, (req, res) => {
  const jobId = req.params.id;
  const userId = req.session.userId;
  
  // Check if user has already applied
  db.get(
    'SELECT * FROM applications WHERE user_id = ? AND job_id = ?',
    [userId, jobId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (row) {
        return res.status(409).json({ error: 'You have already applied to this job' });
      }
      
      // Create application
      db.run(
        'INSERT INTO applications (user_id, job_id) VALUES (?, ?)',
        [userId, jobId],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to apply to job' });
          }
          
          res.json({ 
            message: 'Application submitted successfully',
            applicationId: this.lastID
          });
        }
      );
    });
});

// Get user's applications
app.get('/api/applications', requireAuth, (req, res) => {
  const userId = req.session.userId;
  
  db.all(`
    SELECT a.*, j.title, j.company, j.location 
    FROM applications a 
    JOIN jobs j ON a.job_id = j.id 
    WHERE a.user_id = ? 
    ORDER BY a.applied_at DESC
  `, [userId], (err, applications) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json(applications);
  });
});

// Serve frontend files for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
