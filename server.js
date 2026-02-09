// Solo Earn — Production Backend Server
// Node.js + Express + PostgreSQL

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // 100 requests per window
});
app.use('/api/', limiter);

// PostgreSQL Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Check database connection
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

// Initialize database tables
async function initializeDatabase() {
  try {
    const client = await pool.connect();

    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        passwordHash VARCHAR(255) NOT NULL,
        displayName VARCHAR(100),
        coins INTEGER DEFAULT 0,
        emailVerified BOOLEAN DEFAULT FALSE,
        phone VARCHAR(20),
        profile JSONB DEFAULT '{}',
        referralCode VARCHAR(50) UNIQUE,
        lastDailyClaim BIGINT DEFAULT 0,
        lastSpin BIGINT DEFAULT 0,
        achievements TEXT[],
        createdAt BIGINT DEFAULT 0,
        updatedAt BIGINT DEFAULT 0
      )
    `);

    // Payouts table
    await client.query(`
      CREATE TABLE IF NOT EXISTS payouts (
        id SERIAL PRIMARY KEY,
        ref VARCHAR(50) UNIQUE NOT NULL,
        userId INTEGER REFERENCES users(id) ON DELETE CASCADE,
        bank VARCHAR(100),
        account VARCHAR(20),
        accountName VARCHAR(100),
        amountNGN DECIMAL(10,2),
        coins INTEGER,
        status VARCHAR(20) DEFAULT 'requested',
        createdAt BIGINT DEFAULT 0,
        completedAt BIGINT
      )
    `);

    // Verification codes table
    await client.query(`
      CREATE TABLE IF NOT EXISTS verifications (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        code VARCHAR(10),
        expiresAt BIGINT,
        tries INTEGER DEFAULT 0,
        createdAt BIGINT DEFAULT 0
      )
    `);

    // Games table
    await client.query(`
      CREATE TABLE IF NOT EXISTS games (
        id SERIAL PRIMARY KEY,
        slug VARCHAR(100) UNIQUE NOT NULL,
        title VARCHAR(100),
        description TEXT,
        reward INTEGER DEFAULT 50,
        plays INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'active',
        createdAt BIGINT DEFAULT 0
      )
    `);

    // Game plays table
    await client.query(`
      CREATE TABLE IF NOT EXISTS game_plays (
        id SERIAL PRIMARY KEY,
        userId INTEGER REFERENCES users(id) ON DELETE CASCADE,
        gameId INTEGER REFERENCES games(id) ON DELETE CASCADE,
        coinsEarned INTEGER,
        createdAt BIGINT DEFAULT 0
      )
    `);

    // Complaints table
    await client.query(`
      CREATE TABLE IF NOT EXISTS complaints (
        id SERIAL PRIMARY KEY,
        userId INTEGER REFERENCES users(id) ON DELETE CASCADE,
        subject VARCHAR(200),
        details TEXT,
        status VARCHAR(20) DEFAULT 'open',
        replies JSONB DEFAULT '[]',
        createdAt BIGINT DEFAULT 0
      )
    `);

    // Activity logs table
    await client.query(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        userId INTEGER,
        action VARCHAR(100),
        details TEXT,
        ipAddress VARCHAR(50),
        createdAt BIGINT DEFAULT 0
      )
    `);

    // Admin users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        passwordHash VARCHAR(255) NOT NULL,
        displayName VARCHAR(100),
        role VARCHAR(50) DEFAULT 'admin',
        permissions TEXT[],
        createdAt BIGINT DEFAULT 0
      )
    `);

    client.release();
    console.log('✅ Database tables initialized');
  } catch (err) {
    console.error('❌ Database initialization error:', err);
  }
}

// JWT Authentication
function generateToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return null;
  }
}

// Middleware: authenticate user
async function authenticateUser(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Invalid token' });

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });

    req.user = result.rows[0];
    next();
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
}

// Log activity
async function logActivity(userId, action, details, ipAddress) {
  try {
    await pool.query(
      'INSERT INTO activity_logs (userId, action, details, ipAddress, createdAt) VALUES ($1, $2, $3, $4, $5)',
      [userId, action, details, ipAddress, Date.now()]
    );
  } catch (err) {
    console.error('Error logging activity:', err);
  }
}

// ==================== AUTH ROUTES ====================

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, displayName } = req.body;

    if (!email || !password || !displayName) {
      return res.status(400).json({ error: 'All fields required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if email exists
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows[0]) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    const referralCode = 'REF' + Math.random().toString(36).slice(2, 8).toUpperCase();

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (email, passwordHash, displayName, referralCode, createdAt)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, displayName`,
      [email.toLowerCase(), passwordHash, displayName, referralCode, Date.now()]
    );

    const user = result.rows[0];
    const token = generateToken(user.id);

    logActivity(user.id, 'SIGNUP', 'User account created', req.ip);

    res.json({
      ok: true,
      user: { id: user.id, email: user.email, displayName: user.displayName },
      token
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Sign In
app.post('/api/auth/signin', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    const user = result.rows[0];

    if (!user) return res.status(404).json({ error: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = generateToken(user.id);

    logActivity(user.id, 'SIGNIN', 'User signed in', req.ip);

    res.json({
      ok: true,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        coins: user.coins,
        emailVerified: user.emailverified
      },
      token
    });
  } catch (err) {
    console.error('Signin error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== USER ROUTES ====================

// Get user profile
app.get('/api/user/profile', authenticateUser, async (req, res) => {
  try {
    res.json({
      ok: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        displayName: req.user.displayname,
        coins: req.user.coins,
        phone: req.user.phone,
        emailVerified: req.user.emailverified,
        referralCode: req.user.referralcode,
        achievements: req.user.achievements || [],
        lastDailyClaim: req.user.lastdailyclaim,
        lastSpin: req.user.lastspin
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
app.post('/api/user/update-profile', authenticateUser, async (req, res) => {
  try {
    const { displayName, phone } = req.body;
    const userId = req.user.id;

    await pool.query(
      'UPDATE users SET displayName = $1, phone = $2, updatedAt = $3 WHERE id = $4',
      [displayName, phone, Date.now(), userId]
    );

    logActivity(userId, 'UPDATE_PROFILE', 'User updated profile', req.ip);

    res.json({ ok: true, message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Change password
app.post('/api/user/change-password', authenticateUser, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const validPassword = await bcrypt.compare(currentPassword, req.user.passwordhash);
    if (!validPassword) return res.status(401).json({ error: 'Current password is incorrect' });

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET passwordHash = $1, updatedAt = $2 WHERE id = $3', [newHash, Date.now(), userId]);

    logActivity(userId, 'CHANGE_PASSWORD', 'User changed password', req.ip);

    res.json({ ok: true, message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== COINS & REWARDS ====================

// Claim daily bonus
app.post('/api/rewards/claim-daily', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const now = Date.now();
    const dailyMS = 24 * 60 * 60 * 1000;
    const lastClaim = req.user.lastdailyclaim || 0;

    if (now - lastClaim < dailyMS) {
      const remaining = Math.ceil((dailyMS - (now - lastClaim)) / 3600000);
      return res.status(400).json({ error: `Try again in ${remaining} hours` });
    }

    const dailyCoins = parseInt(process.env.DAILY_COINS || 100);
    await pool.query(
      'UPDATE users SET coins = coins + $1, lastDailyClaim = $2 WHERE id = $3',
      [dailyCoins, now, userId]
    );

    logActivity(userId, 'CLAIM_DAILY', `Claimed ${dailyCoins} coins`, req.ip);

    res.json({ ok: true, coinsEarned: dailyCoins });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Spin wheel
app.post('/api/rewards/spin-wheel', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const now = Date.now();
    const spinMS = 48 * 60 * 60 * 1000;
    const lastSpin = req.user.lastspin || 0;

    if (now - lastSpin < spinMS) {
      const remaining = Math.ceil((spinMS - (now - lastSpin)) / 3600000);
      return res.status(400).json({ error: `Try again in ${remaining} hours` });
    }

    const prizes = [50, 100, 150, 200, 300, 500];
    const prize = prizes[Math.floor(Math.random() * prizes.length)];

    await pool.query(
      'UPDATE users SET coins = coins + $1, lastSpin = $2 WHERE id = $3',
      [prize, now, userId]
    );

    logActivity(userId, 'SPIN_WHEEL', `Won ${prize} coins`, req.ip);

    res.json({ ok: true, coinsEarned: prize });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== GAMES ====================

// Get all games
app.get('/api/games', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, slug, title, description, reward, plays FROM games WHERE status = $1 ORDER BY plays DESC',
      ['active']
    );
    res.json({ ok: true, games: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Record game play
app.post('/api/games/:gameId/play', authenticateUser, async (req, res) => {
  try {
    const { gameId } = req.params;
    const userId = req.user.id;
    const { coinsEarned } = req.body;

    if (!coinsEarned || coinsEarned < 0) {
      return res.status(400).json({ error: 'Invalid coins earned' });
    }

    // Update user coins
    await pool.query(
      'UPDATE users SET coins = coins + $1 WHERE id = $2',
      [coinsEarned, userId]
    );

    // Record game play
    await pool.query(
      'INSERT INTO game_plays (userId, gameId, coinsEarned, createdAt) VALUES ($1, $2, $3, $4)',
      [userId, gameId, coinsEarned, Date.now()]
    );

    // Increment game plays count
    await pool.query('UPDATE games SET plays = plays + 1 WHERE id = $1', [gameId]);

    logActivity(userId, 'PLAY_GAME', `Earned ${coinsEarned} coins`, req.ip);

    res.json({ ok: true, coinsEarned });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== EMAIL VERIFICATION ====================

// Send verification code
app.post('/api/email/send-verification', authenticateUser, async (req, res) => {
  try {
    const email = req.user.email;
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Save code to database
    await pool.query(
      'INSERT INTO verifications (email, code, expiresAt, createdAt) VALUES ($1, $2, $3, $4)',
      [email, code, expiresAt, Date.now()]
    );

    // Send email (using SendGrid or similar)
    if (process.env.SENDGRID_API_KEY) {
      const sgMail = require('@sendgrid/mail');
      sgMail.setApiKey(process.env.SENDGRID_API_KEY);

      await sgMail.send({
        to: email,
        from: process.env.SENDGRID_FROM_EMAIL || 'noreply@soloearn.app',
        subject: 'Verify your email - Solo Earn',
        html: `
          <h2>Email Verification</h2>
          <p>Your verification code is: <strong>${code}</strong></p>
          <p>This code expires in 10 minutes.</p>
        `
      });
    }

    logActivity(req.user.id, 'SEND_VERIFICATION', 'Verification email sent', req.ip);

    res.json({ ok: true, message: 'Verification code sent to your email' });
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
});

// Verify email code
app.post('/api/email/verify-code', authenticateUser, async (req, res) => {
  try {
    const { code } = req.body;
    const email = req.user.email;
    const userId = req.user.id;

    if (!code) return res.status(400).json({ error: 'Code required' });

    const result = await pool.query(
      'SELECT * FROM verifications WHERE email = $1 ORDER BY createdAt DESC LIMIT 1',
      [email]
    );

    const verification = result.rows[0];
    if (!verification) return res.status(404).json({ error: 'No verification request found' });

    if (Date.now() > verification.expiresat) {
      return res.status(400).json({ error: 'Code expired' });
    }

    if (code !== verification.code) {
      // Increment tries
      await pool.query('UPDATE verifications SET tries = tries + 1 WHERE id = $1', [verification.id]);
      return res.status(400).json({ error: 'Incorrect code' });
    }

    // Mark email as verified
    await pool.query('UPDATE users SET emailVerified = true WHERE id = $1', [userId]);

    logActivity(userId, 'VERIFY_EMAIL', 'Email verified', req.ip);

    res.json({ ok: true, message: 'Email verified successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== PAYOUTS ====================

// Request payout
app.post('/api/payouts/request', authenticateUser, async (req, res) => {
  try {
    const { bank, account, accountName, amountNGN } = req.body;
    const userId = req.user.id;

    if (!bank || !account || !accountName || !amountNGN) {
      return res.status(400).json({ error: 'All fields required' });
    }

    // Check email verified
    if (!req.user.emailverified) {
      return res.status(400).json({ error: 'Please verify your email first' });
    }

    // Check minimum withdrawal
    const minWithdraw = parseInt(process.env.MIN_WITHDRAW_NGN || 1000);
    if (amountNGN < minWithdraw) {
      return res.status(400).json({ error: `Minimum withdrawal is ₦${minWithdraw}` });
    }

    // Check coin balance (100 coins = 1 NGN)
    const coinsNeeded = amountNGN * 100;
    if (req.user.coins < coinsNeeded) {
      return res.status(400).json({ error: 'Insufficient coin balance' });
    }

    const ref = 'WD-' + Math.random().toString(36).slice(2, 9).toUpperCase();

    // Create payout record
    await pool.query(
      `INSERT INTO payouts (ref, userId, bank, account, accountName, amountNGN, coins, status, createdAt)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [ref, userId, bank, account, accountName, amountNGN, coinsNeeded, 'requested', Date.now()]
    );

    // Deduct coins
    await pool.query('UPDATE users SET coins = coins - $1 WHERE id = $2', [coinsNeeded, userId]);

    logActivity(userId, 'REQUEST_PAYOUT', `₦${amountNGN} withdrawal requested`, req.ip);

    res.json({ ok: true, ref, message: 'Payout request submitted' });
  } catch (err) {
    console.error('Payout error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get payout history
app.get('/api/payouts/history', authenticateUser, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT ref, amountNGN, status, createdAt, completedAt FROM payouts WHERE userId = $1 ORDER BY createdAt DESC',
      [req.user.id]
    );
    res.json({ ok: true, payouts: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== ADMIN ROUTES ====================

// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await pool.query('SELECT * FROM admin_users WHERE email = $1', [email.toLowerCase()]);
    const admin = result.rows[0];

    if (!admin) {
      // Create first admin
      if (email === 'admin@soloearn.app' && password === 'admin123') {
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
          'INSERT INTO admin_users (email, passwordHash, displayName, role, createdAt) VALUES ($1, $2, $3, $4, $5)',
          [email.toLowerCase(), hash, 'Administrator', 'super_admin', Date.now()]
        );
        const token = generateToken(email);
        return res.json({ ok: true, admin: { email, role: 'super_admin' }, token });
      }
      return res.status(404).json({ error: 'Admin not found' });
    }

    const validPassword = await bcrypt.compare(password, admin.passwordhash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid password' });

    const token = generateToken(admin.id);
    res.json({ ok: true, admin: { email: admin.email, role: admin.role }, token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateUser, async (req, res) => {
  try {
    // Check if user is admin (in real setup, add admin verification)
    const result = await pool.query(
      'SELECT id, email, displayName, coins, emailVerified, createdAt FROM users ORDER BY createdAt DESC'
    );
    res.json({ ok: true, users: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get payouts (admin only)
app.get('/api/admin/payouts', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.ref, p.amountNGN, p.status, p.createdAt, u.email
      FROM payouts p
      JOIN users u ON p.userId = u.id
      ORDER BY p.createdAt DESC
    `);
    res.json({ ok: true, payouts: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Complete payout (admin only)
app.post('/api/admin/payouts/:ref/complete', async (req, res) => {
  try {
    const { ref } = req.params;
    await pool.query('UPDATE payouts SET status = $1, completedAt = $2 WHERE ref = $3', ['completed', Date.now(), ref]);
    res.json({ ok: true, message: 'Payout completed' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/health', (req, res) => {
  res.json({ ok: true, message: 'Server is running' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
async function start() {
  await initializeDatabase();
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║      Solo Earn Server Running 🚀       ║
╠════════════════════════════════════════╣
║  Port: ${PORT}                          
║  Database: PostgreSQL Connected ✅     
║  Environment: ${process.env.NODE_ENV || 'development'}           
╚════════════════════════════════════════╝
    `);
  });
}

start().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

module.exports = app;