import express from "express";
import http from "http";
import { Server as IOServer } from "socket.io";
import jwt from "jsonwebtoken";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import path from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import cors from "cors";
import crypto from "crypto";
import multer from "multer";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || "+laiJJBzxKqfsTNDNIN0NFBuICH2T1FOeLqzwBJkGAVRndhZ5aL5NW83gF6Agg03iYA8XlPHDJJcw1QJfgGQHA==";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "adminpass";
let PORT = process.env.PORT || 3001;

console.log(`Starting server with admin secret: ${ADMIN_SECRET}`);

const app = express();
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: "*" } });

let db;

// Database initialization
async function initDB() {
  try {
    // Create db directory if it doesn't exist
    const dbDir = path.join(__dirname, "db");
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
      console.log('Created database directory');
    }

    db = await open({
      filename: path.join(__dirname, "db", "game.db"),
      driver: sqlite3.Database,
    });

    console.log('Database connection established');

    // Create tables
    await db.exec(`
      CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
      );
      CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER,
        device_id TEXT UNIQUE,
        device_secret TEXT,
        role TEXT,
        FOREIGN KEY(game_id) REFERENCES games(id)
      );
      CREATE TABLE IF NOT EXISTS prizes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER,
        title TEXT,
        description TEXT,
        media TEXT,
        FOREIGN KEY(game_id) REFERENCES games(id)
      );
      CREATE TABLE IF NOT EXISTS rounds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER,
        prize_id INTEGER,
        started_at TEXT,
        announced_at TEXT,
        finished_at TEXT,
        operator_device TEXT,
        screen_device TEXT,
        FOREIGN KEY(game_id) REFERENCES games(id),
        FOREIGN KEY(prize_id) REFERENCES prizes(id)
      );
      CREATE TABLE IF NOT EXISTS media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        media_url TEXT NOT NULL,
        type TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS game_media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER,
        media_id INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(game_id, media_id),
        FOREIGN KEY(game_id) REFERENCES games(id),
        FOREIGN KEY(media_id) REFERENCES media(id)
      );
    `);

    console.log('Database tables created/verified');

    // Insert default games if none exist
    const gameCount = await db.get('SELECT COUNT(*) as count FROM games');
    if (gameCount.count === 0) {
      console.log('Creating default games...');
      await db.run('INSERT INTO games (name) VALUES (?)', 'Default Game');
      await db.run('INSERT INTO games (name) VALUES (?)', 'Prize Wheel');
      await db.run('INSERT INTO games (name) VALUES (?)', 'Lucky Draw');
      console.log('Default games created');
    }

    console.log('Database initialization completed successfully');
    return true;
  } catch (error) {
    console.error('Database initialization failed:', error);
    throw error;
  }
}

// File upload configuration
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
  console.log('Created uploads directory');
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) { 
    cb(null, uploadDir); 
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_');
    cb(null, unique + '-' + safe);
  }
});
const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Middleware setup
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, "public")));

// Debug middleware
app.use((req, res, next) => {
  console.log(`\n=== ${new Date().toISOString()} ===`);
  console.log(`${req.method} ${req.path}`);
  console.log(`Headers:`, {
    'x-admin-secret': req.headers['x-admin-secret'] ? '[PROVIDED]' : '[MISSING]',
    'content-type': req.headers['content-type'],
    'authorization': req.headers['authorization'] ? '[PROVIDED]' : '[MISSING]'
  });
  next();
});

// Utility functions
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}

async function verifyDevice(deviceId, deviceSecret) {
  try {
    const row = await db.get(
      `SELECT d.*, g.name as game_name FROM devices d JOIN games g ON d.game_id = g.id WHERE d.device_id = ?`,
      deviceId
    );
    if (!row) return null;
    if (row.device_secret !== deviceSecret) return null;
    return row;
  } catch (error) {
    console.error('Device verification error:', error);
    return null;
  }
}

// Admin middleware
function requireAdmin(req, res, next) {
  const secret = req.headers['x-admin-secret'];
  
  console.log(`Admin auth check - provided: "${secret}", expected: "${ADMIN_SECRET}"`);
  
  if (!secret) {
    console.log('❌ No admin secret provided');
    return res.status(403).json({ error: 'Admin secret required in X-Admin-Secret header' });
  }
  
  if (secret !== ADMIN_SECRET) {
    console.log('❌ Invalid admin secret');
    return res.status(403).json({ error: 'Invalid admin secret' });
  }
  
  console.log('✅ Admin auth successful');
  next();
}

// Error handling middleware
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Static file routes
app.get('/shared.js', (req, res) => {
  console.log('Serving shared.js');
  res.sendFile(path.join(__dirname, 'shared.js'));
});

// Test routes
app.get('/api/test', (req, res) => {
  console.log('✅ Test route hit');
  res.json({ 
    message: 'Server is working', 
    timestamp: new Date().toISOString(),
    path: req.path 
  });
});

app.get('/api/admin/test', requireAdmin, (req, res) => {
  console.log('✅ Admin test route hit');
  res.json({ 
    message: 'Admin authentication working', 
    timestamp: new Date().toISOString(),
    adminSecret: ADMIN_SECRET
  });
});

// Authentication endpoints
app.post("/api/auth/device", asyncHandler(async (req, res) => {
  const { deviceId, deviceSecret } = req.body;
  
  if (!deviceId || !deviceSecret) {
    return res.status(400).json({ error: "deviceId and deviceSecret required" });
  }

  const device = await verifyDevice(deviceId, deviceSecret);
  if (!device) {
    return res.status(401).json({ error: "Invalid device credentials" });
  }

  const token = signToken({
    deviceId: device.device_id,
    role: device.role,
    game_id: device.game_id,
    device_db_id: device.id,
  });

  res.json({
    token,
    device: {
      deviceId: device.device_id,
      role: device.role,
      gameId: device.game_id,
      gameName: device.game_name,
    },
  });
}));

// Game API endpoints
app.get("/api/games/:gameId/prizes", asyncHandler(async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Authorization header required" });
  
  const token = auth.split(" ")[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  
  if (parseInt(req.params.gameId) !== decoded.game_id) {
    return res.status(403).json({ error: "Access denied for this game" });
  }
  
  const prizes = await db.all("SELECT * FROM prizes WHERE game_id = ?", req.params.gameId);
  res.json(prizes);
}));

app.get("/api/games/:gameId/media", asyncHandler(async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Authorization header required" });
  
  const token = auth.split(" ")[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  
  if (parseInt(req.params.gameId) !== decoded.game_id) {
    return res.status(403).json({ error: "Access denied for this game" });
  }
  
  const media = await db.all(`
    SELECT m.* FROM media m
    JOIN game_media gm ON m.id = gm.media_id
    WHERE gm.game_id = ?
    ORDER BY m.type, m.created_at
  `, req.params.gameId);
  
  res.json(media);
}));

// ===== GAME MANAGEMENT ADMIN ENDPOINTS =====

// Get all games
app.get('/api/admin/games', requireAdmin, asyncHandler(async (req, res) => {
  console.log('📋 Fetching all games');
  const games = await db.all('SELECT * FROM games ORDER BY name');
  console.log(`Found ${games.length} games`);
  res.json(games);
}));

// Create new game
app.post('/api/admin/games', requireAdmin, asyncHandler(async (req, res) => {
  const { name } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ error: 'Game name is required' });
  }
  
  console.log(`Creating new game: ${name}`);
  
  const result = await db.run('INSERT INTO games (name) VALUES (?)', name.trim());
  const newGame = { id: result.lastID, name: name.trim() };
  
  console.log(`✅ Game created:`, newGame);
  res.json(newGame);
}));

// Update game
app.put('/api/admin/games/:id', requireAdmin, asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ error: 'Game name is required' });
  }
  
  console.log(`Updating game ${id} to: ${name}`);
  
  const result = await db.run('UPDATE games SET name = ? WHERE id = ?', name.trim(), id);
  
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Game not found' });
  }
  
  const updatedGame = { id: parseInt(id), name: name.trim() };
  console.log(`✅ Game updated:`, updatedGame);
  res.json(updatedGame);
}));

// Delete game and all related data
app.delete('/api/admin/games/:id', requireAdmin, asyncHandler(async (req, res) => {
  const { id } = req.params;
  
  // Check if game exists
  const game = await db.get('SELECT * FROM games WHERE id = ?', id);
  if (!game) {
    return res.status(404).json({ error: 'Game not found' });
  }
  
  console.log(`Deleting game "${game.name}" and all related data...`);
  
  // Start transaction
  await db.exec('BEGIN TRANSACTION');
  
  try {
    // Delete all related data in correct order
    await db.run('DELETE FROM game_media WHERE game_id = ?', id);
    await db.run('DELETE FROM rounds WHERE game_id = ?', id);
    await db.run('DELETE FROM prizes WHERE game_id = ?', id);
    await db.run('DELETE FROM devices WHERE game_id = ?', id);
    await db.run('DELETE FROM games WHERE id = ?', id);
    
    await db.exec('COMMIT');
    
    console.log(`✅ Successfully deleted game "${game.name}"`);
    res.json({ ok: true, message: `Game "${game.name}" deleted successfully` });
  } catch (err) {
    await db.exec('ROLLBACK');
    throw err;
  }
}));

// ===== PRIZE MANAGEMENT =====

// Get all prizes
app.get('/api/admin/prizes', requireAdmin, asyncHandler(async (req, res) => {
  console.log('📋 Fetching all prizes');
  const prizes = await db.all(
    'SELECT p.*, g.name as game_name FROM prizes p LEFT JOIN games g ON p.game_id = g.id ORDER BY g.name, p.title'
  );
  console.log(`Found ${prizes.length} prizes`);
  res.json(prizes);
}));

// Create prize
app.post('/api/admin/prizes', requireAdmin, upload.single('media'), asyncHandler(async (req, res) => {
  const { game_id, title, description } = req.body;
  let mediaPath = req.body.media || null;
  
  if (req.file) {
    mediaPath = '/uploads/' + req.file.filename;
  }
  
  console.log(`Creating prize: ${title} for game ${game_id}`);
  
  const result = await db.run(
    'INSERT INTO prizes (game_id, title, description, media) VALUES (?, ?, ?, ?)',
    game_id, title, description, mediaPath
  );
  
  const newPrize = { id: result.lastID, game_id, title, description, media: mediaPath };
  console.log(`✅ Prize created:`, newPrize);
  res.json(newPrize);
}));

// Update prize
app.put('/api/admin/prizes/:id', requireAdmin, upload.single('media'), asyncHandler(async (req, res) => {
  const id = req.params.id;
  const { title, description } = req.body;
  
  if (req.file) {
    const mediaPath = '/uploads/' + req.file.filename;
    await db.run('UPDATE prizes SET title = ?, description = ?, media = ? WHERE id = ?', 
                 title, description, mediaPath, id);
  } else {
    await db.run('UPDATE prizes SET title = ?, description = ? WHERE id = ?', 
                 title, description, id);
  }
  
  console.log(`✅ Prize ${id} updated`);
  res.json({ ok: true, id: parseInt(id) });
}));

// Delete prize
app.delete('/api/admin/prizes/:id', requireAdmin, asyncHandler(async (req, res) => {
  const id = req.params.id;
  
  const result = await db.run('DELETE FROM prizes WHERE id = ?', id);
  
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Prize not found' });
  }
  
  console.log(`✅ Prize ${id} deleted`);
  res.json({ ok: true });
}));

// ===== DEVICE MANAGEMENT =====

// Get all devices
app.get('/api/admin/devices', requireAdmin, asyncHandler(async (req, res) => {
  console.log('📋 Fetching all devices');
  const devices = await db.all(
    'SELECT d.*, g.name as game_name FROM devices d LEFT JOIN games g ON d.game_id = g.id ORDER BY g.name, d.device_id'
  );
  console.log(`Found ${devices.length} devices`);
  res.json(devices);
}));

// Create device
app.post('/api/admin/devices', requireAdmin, asyncHandler(async (req, res) => {
  const { game_id, device_id, role } = req.body;
  const device_secret = crypto.randomBytes(6).toString('hex');
  
  console.log(`Creating device: ${device_id} (${role}) for game ${game_id}`);
  
  const result = await db.run(
    'INSERT INTO devices (game_id, device_id, device_secret, role) VALUES (?, ?, ?, ?)',
    game_id, device_id, device_secret, role
  );
  
  const newDevice = { 
    id: result.lastID, 
    game_id: parseInt(game_id),
    device_id, 
    device_secret, 
    role 
  };
  
  console.log(`✅ Device created:`, { ...newDevice, device_secret: '[HIDDEN]' });
  res.json(newDevice);
}));

// ===== MEDIA MANAGEMENT =====

// Get all media
app.get('/api/admin/media', requireAdmin, asyncHandler(async (req, res) => {
  console.log('📋 Fetching all media');
  const media = await db.all('SELECT * FROM media ORDER BY created_at DESC');
  console.log(`Found ${media.length} media items`);
  res.json(media);
}));

// Upload media
app.post('/api/admin/media', requireAdmin, upload.single('media'), asyncHandler(async (req, res) => {
  const { title, type } = req.body;
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const filename = req.file.filename;
  const media_url = '/uploads/' + filename;
  
  console.log(`Uploading media: ${title} (${type})`);
  
  const result = await db.run(
    'INSERT INTO media (title, filename, media_url, type) VALUES (?, ?, ?, ?)',
    title, filename, media_url, type
  );
  
  const newMedia = { 
    id: result.lastID, 
    title, 
    filename, 
    media_url, 
    type 
  };
  
  console.log(`✅ Media uploaded:`, newMedia);
  res.json(newMedia);
}));

// Delete media
app.delete('/api/admin/media/:id', requireAdmin, asyncHandler(async (req, res) => {
  const id = req.params.id;
  
  // Get media info before deleting
  const media = await db.get('SELECT * FROM media WHERE id = ?', id);
  
  if (!media) {
    return res.status(404).json({ error: 'Media not found' });
  }
  
  console.log(`Deleting media: ${media.title}`);
  
  // Delete physical file
  const filePath = path.join(__dirname, 'public', 'uploads', media.filename);
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    console.log(`Deleted file: ${media.filename}`);
  }
  
  // Delete from database
  await db.run('DELETE FROM game_media WHERE media_id = ?', id);
  await db.run('DELETE FROM media WHERE id = ?', id);
  
  console.log(`✅ Media ${id} deleted`);
  res.json({ ok: true });
}));

// ===== GAME-MEDIA ASSIGNMENTS =====

// Get all game-media assignments
app.get('/api/admin/game-media', requireAdmin, asyncHandler(async (req, res) => {
  console.log('📋 Fetching game-media assignments');
  const assignments = await db.all(`
    SELECT gm.*, g.name as game_name, m.title as media_title, m.type as media_type
    FROM game_media gm
    JOIN games g ON gm.game_id = g.id
    JOIN media m ON gm.media_id = m.id
    ORDER BY g.name, m.type
  `);
  console.log(`Found ${assignments.length} assignments`);
  res.json(assignments);
}));

// Create game-media assignment
app.post('/api/admin/game-media', requireAdmin, asyncHandler(async (req, res) => {
  const { game_id, media_id } = req.body;
  
  console.log(`Assigning media ${media_id} to game ${game_id}`);
  
  await db.run(
    'INSERT OR REPLACE INTO game_media (game_id, media_id) VALUES (?, ?)',
    game_id, media_id
  );
  
  console.log(`✅ Media assigned to game`);
  res.json({ ok: true });
}));

// Delete game-media assignment
app.delete('/api/admin/game-media/:gameId/:mediaId', requireAdmin, asyncHandler(async (req, res) => {
  const { gameId, mediaId } = req.params;
  
  console.log(`Removing media ${mediaId} from game ${gameId}`);
  
  await db.run(
    'DELETE FROM game_media WHERE game_id = ? AND media_id = ?',
    gameId, mediaId
  );
  
  console.log(`✅ Media assignment removed`);
  res.json({ ok: true });
}));


// Socket.io authentication and connection handling will be set up by setupSocketHandlers()
// This is now handled in the setupSocketHandlers function above

// Global error handler
app.use((error, req, res, next) => {
  console.error('❌ Global error handler:', error);
  
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
    return res.status(400).json({ error: 'Duplicate entry' });
  }
  
  res.status(500).json({ 
    error: 'Internal server error', 
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// 404 handler - must be last
app.use('*', (req, res) => {
  console.log(`❌ Route not found: ${req.method} ${req.path}`);
  res.status(404).json({ 
    error: 'Route not found', 
    path: req.path,
    method: req.method,
    availableEndpoints: [
      'GET /api/test',
      'GET /api/admin/test',
      'GET /api/admin/games',
      'POST /api/admin/games',
      'GET /api/admin/prizes',
      'GET /api/admin/devices',
      'GET /api/admin/media'
    ]
  });
});

// Server startup with port conflict handling
async function startServer() {
  try {
    console.log('🚀 Starting server initialization...');
    
    // Initialize database
    await initDB();
    
    // Setup initial socket handlers
    setupSocketHandlers(io);
    
    // Start server with error handling
    server.listen(PORT)
      .on('listening', () => {
        console.log('\n' + '='.repeat(50));
        console.log('✅ SERVER STARTED SUCCESSFULLY');
        console.log('='.repeat(50));
        console.log(`🌐 Server URL: http://localhost:${PORT}`);
        console.log(`⚙️  Admin Panel: http://localhost:${PORT}/admin.html`);
        console.log(`🔑 Admin Secret: ${ADMIN_SECRET}`);
        console.log(`📊 Test Endpoint: http://localhost:${PORT}/api/test`);
        console.log(`🔐 Admin Test: http://localhost:${PORT}/api/admin/test`);
        console.log('='.repeat(50));
        console.log('\n📝 Available Admin Endpoints:');
        console.log('   GET  /api/admin/games');
        console.log('   POST /api/admin/games');
        console.log('   GET  /api/admin/prizes');
        console.log('   GET  /api/admin/devices');
        console.log('   GET  /api/admin/media');
        console.log('\n✨ Server is ready to accept connections!\n');
      })
      .on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
          console.error(`❌ Port ${PORT} is already in use!`);
          console.log('\n🔧 Windows Solutions:');
          console.log('   1. Kill existing Node processes:');
          console.log('      taskkill /IM node.exe /F');
          console.log('   2. Find what\'s using the port:');
          console.log(`      netstat -ano | findstr :${PORT}`);
          console.log('   3. Use PowerShell to set different port:');
          console.log('      $env:PORT=3001; node server.js');
          console.log('   4. Use Command Prompt to set different port:');
          console.log('      set PORT=3001 && node server.js\n');
          
          // Try alternative ports
          console.log('🔄 Trying alternative ports...');
          tryAlternativePorts();
        } else {
          console.error('❌ Failed to start server:', error);
          process.exit(1);
        }
      });
    
  } catch (error) {
    console.error('❌ Failed to initialize server:', error);
    process.exit(1);
  }
}

// Try alternative ports if main port is busy
async function tryAlternativePorts() {
  const alternativePorts = [3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010];
  
  for (const port of alternativePorts) {
    try {
      await new Promise((resolve, reject) => {
        const testServer = http.createServer(app);
        const testIO = new IOServer(testServer, { cors: { origin: "*" } });
        
        // Copy socket handlers to new server
        setupSocketHandlers(testIO);
        
        testServer.listen(port)
          .on('listening', () => {
            console.log(`\n✅ Started on alternative port ${port}`);
            console.log(`🌐 Server URL: http://localhost:${port}`);
            console.log(`⚙️  Admin Panel: http://localhost:${port}/admin.html`);
            console.log(`🔑 Admin Secret: ${ADMIN_SECRET}`);
            
            // Update global references
            global.server = testServer;
            global.io = testIO;
            PORT = port;
            
            resolve();
          })
          .on('error', (err) => {
            testServer.close();
            if (err.code === 'EADDRINUSE') {
              console.log(`   Port ${port} also busy, trying next...`);
              reject(err);
            } else {
              reject(err);
            }
          });
      });
      return; // Success, exit function
    } catch (err) {
      continue; // Try next port
    }
  }
  
  console.error('❌ All alternative ports are busy. Please free up a port or specify one:');
  console.log('\n🔧 Windows PowerShell:');
  console.log('   $env:PORT=8000; node server.js');
  console.log('\n🔧 Windows Command Prompt:');
  console.log('   set PORT=8000 && node server.js');
  console.log('\n🔧 Or kill existing Node processes:');
  console.log('   taskkill /IM node.exe /F');
  process.exit(1);
}

// Setup socket handlers (extracted to reuse)
function setupSocketHandlers(ioInstance) {
  // Socket.io authentication middleware
  ioInstance.use(async (socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) {
      console.log('❌ Socket connection rejected: no token');
      return next(new Error("no_token"));
    }
    
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = decoded;
      console.log(`✅ Socket authenticated: ${decoded.deviceId}`);
      return next();
    } catch (e) {
      console.log('❌ Socket connection rejected: invalid token');
      return next(new Error("invalid_token"));
    }
  });

  // Socket.io connection handling
  ioInstance.on("connection", (socket) => {
    const user = socket.user;
    const gameRoom = `game_${user.game_id}`;

    socket.join(gameRoom);
    console.log(`🔌 Socket connected: device=${user.deviceId} role=${user.role} joined ${gameRoom}`);

    socket.emit("connected", { serverTime: new Date().toISOString() });

    socket.on("start_round", asyncHandler(async () => {
      if (user.role !== "operator") {
        console.log(`❌ Non-operator tried to start round: ${user.deviceId}`);
        return;
      }
      
      const startedAt = new Date().toISOString();
      const result = await db.run(
        `INSERT INTO rounds (game_id, started_at, operator_device) VALUES (?, ?, ?)`,
        user.game_id,
        startedAt,
        user.deviceId
      );
      
      const roundId = result.lastID;
      console.log(`🎮 Round ${roundId} started by ${user.deviceId}`);
      
      ioInstance.to(gameRoom).emit("game_started", {
        roundId,
        startedAt,
        operatorDevice: user.deviceId,
      });
    }));

    socket.on("announce_prize", asyncHandler(async (payload) => {
      if (user.role !== "operator") {
        console.log(`❌ Non-operator tried to announce prize: ${user.deviceId}`);
        return;
      }
      
      const { roundId, prizeId } = payload;
      const announcedAt = new Date().toISOString();

      await db.run(`UPDATE rounds SET prize_id = ?, announced_at = ? WHERE id = ?`, 
                   prizeId, announcedAt, roundId);
      const prize = await db.get("SELECT * FROM prizes WHERE id = ?", prizeId);

      console.log(`🏆 Prize announced for round ${roundId}: ${prize?.title}`);
      
      ioInstance.to(gameRoom).emit("prize_announced", {
        roundId,
        prize,
        announcedAt,
        operatorDevice: user.deviceId,
      });
    }));

    socket.on("finish_round", asyncHandler(async (payload) => {
      if (user.role !== "operator") {
        console.log(`❌ Non-operator tried to finish round: ${user.deviceId}`);
        return;
      }
      
      const { roundId } = payload;
      const finishedAt = new Date().toISOString();
      
      await db.run(`UPDATE rounds SET finished_at = ? WHERE id = ?`, finishedAt, roundId);
      
      console.log(`✅ Round ${roundId} finished by ${user.deviceId}`);
      
      ioInstance.to(gameRoom).emit("round_finished", {
        roundId,
        finishedAt,
        operatorDevice: user.deviceId,
      });
    }));

    // Media control events
    socket.on("show_pricing_sheet", () => {
      if (user.role !== "operator") return;
      console.log(`📄 Showing pricing sheet - ${user.deviceId}`);
      ioInstance.to(gameRoom).emit("show_pricing_sheet");
    });

    socket.on("hide_pricing_sheet", () => {
      if (user.role !== "operator") return;
      console.log(`📄 Hiding pricing sheet - ${user.deviceId}`);
      ioInstance.to(gameRoom).emit("hide_pricing_sheet");
    });

    socket.on("disconnect", (reason) => {
      console.log(`🔌 Socket disconnected: ${user.deviceId} - ${reason}`);
    });
  });
}

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  console.log('🛑 SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    if (db) {
      db.close();
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  console.log('\n🛑 SIGINT received, shutting down gracefully...');
  server.close(() => {
    console.log('✅ Server closed');
    if (db) {
      db.close();
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});

// Start the server
startServer();