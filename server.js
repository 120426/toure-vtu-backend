require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_super_secret_key';
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ==========================================
// 1. AUTHENTICATION ROUTES (SIGNUP & LOGIN)
// ==========================================

// SIGNUP ROUTE
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Insert user into Supabase
    const { data: user, error } = await supabase
      .from('users')
      .insert({
        username,
        email,
        password_hash: passwordHash,
        wallet_balance: 1000.00 // Optional welcome demo balance
      })
      .select('id, username, email, wallet_balance, role')
      .single();

    if (error) {
      if (error.code === '23505') { // Postgres duplicate key error
        return res.status(400).json({ success: false, message: 'Username or Email already exists' });
      }
      return res.status(400).json({ success: false, message: error.message });
    }

    // Generate JWT Token
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    return res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token,
      user
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// LOGIN ROUTE
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  try {
    // Fetch user record
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate JWT Token
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

    return res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        wallet_balance: user.wallet_balance,
        role: user.role
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// 2. SOCKET AUTHENTICATION MIDDLEWARE
// ==========================================

// Middleware to verify JWT before letting a client connect to WebSockets
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization;

  if (!token) {
    return next(new Error('Authentication token required'));
  }

  try {
    const cleanToken = token.replace('Bearer ', '');
    const decoded = jwt.verify(cleanToken, JWT_SECRET);
    socket.userId = decoded.id; // Attach user ID directly to the socket
    next();
  } catch (err) {
    next(new Error('Invalid or expired authentication token'));
  }
});

// ==========================================
// 3. GAME ENGINE & SOCKET EVENTS
// ==========================================

let currentRound = {
  id: null,
  serverSeed: null,
  seedHash: null,
  crashMultiplier: 1.00,
  currentMultiplier: 1.00,
  status: 'PREPARING',
  startTime: null
};

function generateGameRound() {
  const serverSeed = crypto.randomBytes(32).toString('hex');
  const seedHash = crypto.createHash('sha256').update(serverSeed).digest('hex');
  const h = crypto.createHmac('sha256', serverSeed).update('aviator-game').digest('hex');
  const intVal = parseInt(h.substring(0, 13), 16);
  const e = Math.pow(2, 52);

  let crashPoint = 1.00;
  if (intVal % 33 !== 0) {
    crashPoint = Math.max(1.00, parseFloat(((e * 100 - intVal) / (e - intVal) / 100).toFixed(2)));
  }

  return { serverSeed, seedHash, crashPoint };
}

async function startGameEngine() {
  while (true) {
    const { serverSeed, seedHash, crashPoint } = generateGameRound();

    const { data: dbRound, error } = await supabase
      .from('game_rounds')
      .insert({
        server_seed: serverSeed,
        seed_hash: seedHash,
        crash_multiplier: crashPoint,
        status: 'PREPARING'
      })
      .select()
      .single();

    if (error || !dbRound) {
      await new Promise(res => setTimeout(res, 3000));
      continue;
    }

    currentRound = {
      id: dbRound.id,
      serverSeed,
      seedHash,
      crashMultiplier: crashPoint,
      currentMultiplier: 1.00,
      status: 'PREPARING',
      startTime: null
    };

    io.emit('round_preparing', {
      roundId: currentRound.id,
      seedHash: currentRound.seedHash,
      bettingTimeRemaining: 5000
    });

    await new Promise(res => setTimeout(res, 5000));

    currentRound.status = 'RUNNING';
    currentRound.startTime = Date.now();

    await supabase.from('game_rounds').update({ status: 'RUNNING', started_at: new Date() }).eq('id', currentRound.id);
    io.emit('round_started', { roundId: currentRound.id });

    await new Promise((resolve) => {
      const interval = setInterval(async () => {
        const elapsedTime = (Date.now() - currentRound.startTime) / 1000;
        const nextMultiplier = parseFloat((1.00 * Math.pow(Math.E, 0.06 * elapsedTime)).toFixed(2));

        if (nextMultiplier >= currentRound.crashMultiplier) {
          clearInterval(interval);
          currentRound.currentMultiplier = currentRound.crashMultiplier;
          resolve();
        } else {
          currentRound.currentMultiplier = nextMultiplier;
          io.emit('multiplier_update', { multiplier: currentRound.currentMultiplier });
        }
      }, 100);
    });

    currentRound.status = 'CRASHED';
    await supabase.from('game_rounds').update({ status: 'CRASHED', ended_at: new Date() }).eq('id', currentRound.id);
    await supabase.from('bets').update({ status: 'LOST' }).eq('round_id', currentRound.id).eq('status', 'ACTIVE');

    io.emit('round_crashed', {
      roundId: currentRound.id,
      crashMultiplier: currentRound.crashMultiplier,
      serverSeed: currentRound.serverSeed
    });

    await new Promise(res => setTimeout(res, 3000));
  }
}

io.on('connection', (socket) => {
  const userId = socket.userId; // Retrieved securely from socket authentication middleware

  socket.emit('game_state', {
    roundId: currentRound.id,
    status: currentRound.status,
    seedHash: currentRound.seedHash,
    currentMultiplier: currentRound.currentMultiplier
  });

  socket.on('place_bet', async (data) => {
    const { amount } = data;

    if (currentRound.status !== 'PREPARING') {
      return socket.emit('bet_error', { message: 'Betting phase closed for this round' });
    }

    const { data: response, error } = await supabase.rpc('place_aviator_bet', {
      p_user_id: userId,
      p_round_id: currentRound.id,
      p_amount: amount
    });

    if (error || !response?.success) {
      return socket.emit('bet_error', { message: error?.message || 'Failed to place bet' });
    }

    socket.emit('bet_success', { betId: response.bet_id, newBalance: response.new_balance });
    io.emit('player_bet_placed', { userId, amount });
  });

  socket.on('cashout', async (data) => {
    const { betId } = data;

    if (currentRound.status !== 'RUNNING') {
      return socket.emit('cashout_error', { message: 'Game is not actively running' });
    }

    const { data: response, error } = await supabase.rpc('cashout_aviator_bet', {
      p_user_id: userId,
      p_bet_id: betId,
      p_current_multiplier: currentRound.currentMultiplier
    });

    if (error || !response?.success) {
      return socket.emit('cashout_error', { message: error?.message || 'Cashout failed' });
    }

    socket.emit('cashout_success', {
      payout: response.payout,
      multiplier: response.multiplier,
      newBalance: response.new_balance
    });

    io.emit('player_cashed_out', { userId, multiplier: response.multiplier, payout: response.payout });
  });
});

// Install required packages: npm install bcryptjs jsonwebtoken
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  startGameEngine();
});
