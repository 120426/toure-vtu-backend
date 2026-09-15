require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const Pusher = require('pusher');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ==========================================
// 0. HEALTH CHECK & SAFE INITIALIZATION
// ==========================================

// Base Route (Prevents "Cannot GET /" error in browser)
app.get('/', (req, res) => {
  return res.json({
    success: true,
    message: "Toure Tech Aviator Backend API is live",
    timestamp: new Date().toISOString()
  });
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://placeholder.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder_key';

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Safely initialize Pusher
let pusher;
if (process.env.PUSHER_APP_ID && process.env.PUSHER_KEY) {
  pusher = new Pusher({
    appId: process.env.PUSHER_APP_ID,
    key: process.env.PUSHER_KEY,
    secret: process.env.PUSHER_SECRET,
    cluster: process.env.PUSHER_CLUSTER,
    useTLS: true
  });
} else {
  // Mock pusher fallback to prevent server crash if variables are unassigned
  pusher = { trigger: () => {} };
}

// Auth Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, message: 'No token provided' });

  try {
    const token = authHeader.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

// ==========================================
// 1. AUTHENTICATION & ACCOUNT ENDPOINTS
// ==========================================

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const { data: user, error } = await supabase
      .from('users')
      .insert({ username, email, password_hash: passwordHash, wallet_balance: 0.00 })
      .select('id, username, email, wallet_balance, role')
      .single();

    if (error) return res.status(400).json({ success: false, message: error.message });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ success: true, token, user });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error || !user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({
      success: true,
      token,
      user: { id: user.id, username: user.username, email: user.email, wallet_balance: user.wallet_balance }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// USER PROFILE / ACCOUNT DETAILS
app.get('/api/account/profile', authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, email, wallet_balance, role, created_at')
      .eq('id', req.userId)
      .single();

    if (error) return res.status(400).json({ success: false, message: error.message });
    return res.json({ success: true, user });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// 2. DEPOSIT & WITHDRAWAL ENDPOINTS
// ==========================================

// INITIATE FLUTTERWAVE DEPOSIT
app.post('/api/wallet/deposit/initialize', authenticate, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ success: false, message: 'Invalid amount' });

  try {
    const { data: user } = await supabase.from('users').select('email').eq('id', req.userId).single();
    const reference = `DEP-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    await supabase.from('transactions').insert({
      user_id: req.userId,
      type: 'DEPOSIT',
      amount,
      status: 'PENDING',
      reference
    });

    const response = await axios.post(
      'https://api.flutterwave.com/v3/payments',
      {
        tx_ref: reference,
        amount,
        currency: 'NGN',
        redirect_url: 'https://your-frontend-domain.com/payment-callback',
        customer: { email: user.email },
        customizations: { title: 'Wallet Top-up' }
      },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    return res.json({ success: true, payment_link: response.data.data.link, reference });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// FLUTTERWAVE DEPOSIT WEBHOOK
app.post('/api/wallet/webhook/flutterwave', async (req, res) => {
  const signature = req.headers['verif-hash'];
  if (!signature || signature !== process.env.FLW_SECRET_HASH) {
    return res.status(401).send('Unauthorized request');
  }

  const { event, data } = req.body;

  if (event === 'charge.completed' && data.status === 'successful') {
    const reference = data.tx_ref;
    const amountPaid = data.amount;

    const { data: tx } = await supabase
      .from('transactions')
      .select('*')
      .eq('reference', reference)
      .eq('status', 'PENDING')
      .single();

    if (tx) {
      await supabase.from('transactions').update({ status: 'COMPLETED' }).eq('id', tx.id);

      const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', tx.user_id).single();
      await supabase
        .from('users')
        .update({ wallet_balance: parseFloat(user.wallet_balance) + parseFloat(amountPaid) })
        .eq('id', tx.user_id);
    }
  }

  return res.status(200).send('Webhook Processed');
});

// REQUEST WITHDRAWAL
app.post('/api/wallet/withdraw', authenticate, async (req, res) => {
  const { amount, bankCode, accountNumber } = req.body;

  if (!amount || amount <= 0 || !bankCode || !accountNumber) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }

  try {
    const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.userId).single();

    if (user.wallet_balance < amount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    await supabase.from('users').update({ wallet_balance: user.wallet_balance - amount }).eq('id', req.userId);

    const reference = `WITH-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    await supabase.from('transactions').insert({
      user_id: req.userId,
      type: 'WITHDRAWAL',
      amount,
      status: 'PENDING',
      reference
    });

    return res.json({ success: true, message: 'Withdrawal request submitted for processing', reference });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// 3. TRANSACTION HISTORY ENDPOINT
// ==========================================

app.get('/api/wallet/history', authenticate, async (req, res) => {
  try {
    const { data: history, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('user_id', req.userId)
      .order('created_at', { ascending: false });

    if (error) return res.status(400).json({ success: false, message: error.message });
    return res.json({ success: true, history });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// 4. AVIATOR GAME PLAY ENDPOINTS
// ==========================================

app.post('/api/game/bet', authenticate, async (req, res) => {
  const { roundId, amount } = req.body;

  const { data: response, error } = await supabase.rpc('place_aviator_bet', {
    p_user_id: req.userId,
    p_round_id: roundId,
    p_amount: amount
  });

  if (error || !response?.success) {
    return res.status(400).json({ success: false, message: error?.message || 'Failed to place bet' });
  }

  pusher.trigger('aviator-channel', 'player_bet', { userId: req.userId, amount });
  return res.json({ success: true, betId: response.bet_id, newBalance: response.new_balance });
});

app.post('/api/game/cashout', authenticate, async (req, res) => {
  const { betId, currentMultiplier } = req.body;

  const { data: response, error } = await supabase.rpc('cashout_aviator_bet', {
    p_user_id: req.userId,
    p_bet_id: betId,
    p_current_multiplier: currentMultiplier
  });

  if (error || !response?.success) {
    return res.status(400).json({ success: false, message: error?.message || 'Cashout failed' });
  }

  pusher.trigger('aviator-channel', 'player_cashed_out', {
    userId: req.userId,
    multiplier: response.multiplier,
    payout: response.payout
  });

  return res.json({ success: true, payout: response.payout, newBalance: response.new_balance });
});

module.exports = app;
