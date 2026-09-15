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

// Admin Credentials from Environment Variables (with fallbacks)
const ADMIN_GMAIL = process.env.ADMIN_GMAIL || "touretechadmin@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ToureAdmin123!";

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

// Admin Auth Middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, message: 'No admin token provided' });

  try {
    const token = authHeader.replace('Bearer ', '');
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) {
      return res.status(403).json({ success: false, message: 'Admin privileges required' });
    }
    req.adminEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid admin session' });
  }
};

// ==========================================
// 1. AUTHENTICATION & ACCOUNT ENDPOINTS
// ==========================================

// ADMIN LOGIN (Hardcoded Credentials Check)
app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body;

  if (email === ADMIN_GMAIL && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ email, isAdmin: true }, JWT_SECRET, { expiresIn: '1d' });
    return res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: { email: ADMIN_GMAIL, name: 'Toure Bet Superadmin' }
    });
  }

  return res.status(401).json({ success: false, message: 'Invalid Admin Gmail or Password' });
});

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
// 2. ADMIN CONTROL PANEL ENDPOINTS
// ==========================================

// GET ALL PENDING WITHDRAWAL REQUESTS
app.get('/api/admin/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const { data: requests, error } = await supabase
      .from('transactions')
      .select('id, amount, status, reference, created_at, users(email, username)')
      .eq('type', 'WITHDRAWAL')
      .order('created_at', { ascending: false });

    if (error) return res.status(400).json({ success: false, message: error.message });

    const formattedRequests = requests.map(r => ({
      id: r.id,
      amount: r.amount,
      status: r.status,
      email: r.users?.email || 'N/A',
      user_name: r.users?.username || 'N/A',
      bank_name: 'Bank Transfer',
      account_number: r.reference
    }));

    return res.json({ success: true, requests: formattedRequests });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// APPROVE / REJECT WITHDRAWAL
app.post('/api/admin/withdrawals/process', authenticateAdmin, async (req, res) => {
  const { requestId, action } = req.body;

  if (!requestId || !['APPROVED', 'REJECTED'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Invalid request data' });
  }

  try {
    const { data: tx, error: fetchErr } = await supabase
      .from('transactions')
      .select('*')
      .eq('id', requestId)
      .single();

    if (fetchErr || !tx) return res.status(404).json({ success: false, message: 'Transaction not found' });

    // Update Transaction status
    await supabase.from('transactions').update({ status: action }).eq('id', requestId);

    // If REJECTED, refund the user's balance
    if (action === 'REJECTED') {
      const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', tx.user_id).single();
      if (user) {
        const refundedBalance = parseFloat(user.wallet_balance) + parseFloat(tx.amount);
        await supabase.from('users').update({ wallet_balance: refundedBalance }).eq('id', tx.user_id);
      }
    }

    return res.json({ success: true, message: `Withdrawal request ${action.toLowerCase()} successfully` });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// MANUAL USER WALLET CREDIT / DEBIT
app.post('/api/admin/wallet/adjust', authenticateAdmin, async (req, res) => {
  const { email, amount, action } = req.body;

  if (!email || !amount || amount <= 0 || !['CREDIT', 'DEBIT'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Invalid parameters provided' });
  }

  try {
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, wallet_balance')
      .eq('email', email)
      .single();

    if (userErr || !user) return res.status(404).json({ success: false, message: 'User account not found' });

    let currentBal = parseFloat(user.wallet_balance || 0);
    let newBal = action === 'CREDIT' ? currentBal + parseFloat(amount) : currentBal - parseFloat(amount);

    if (newBal < 0) newBal = 0;

    await supabase.from('users').update({ wallet_balance: newBal }).eq('id', user.id);

    // Record system adjustment transaction
    await supabase.from('transactions').insert({
      user_id: user.id,
      type: action === 'CREDIT' ? 'DEPOSIT' : 'WITHDRAWAL',
      amount,
      status: 'COMPLETED',
      reference: `ADMIN-${action}-${Date.now()}`
    });

    return res.json({ success: true, message: `Wallet updated. New Balance: ₦${newBal.toFixed(2)}` });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// UPDATE BROADCAST NOTICE TICKER
app.post('/api/admin/ticker/update', authenticateAdmin, async (req, res) => {
  const { notice } = req.body;

  if (!notice) return res.status(400).json({ success: false, message: 'Notice message is required' });

  try {
    pusher.trigger('aviator-channel', 'ticker_update', { notice });
    return res.json({ success: true, message: 'Notice broadcasted live across player screens' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// 3. DEPOSIT & WITHDRAWAL ENDPOINTS
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
        redirect_url: 'https://toure-bet-backend.vercel.app/',
        customer: { email: user.email },
        customizations: { title: 'Wallet Top-up' }
      },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    return res.json({ success: true, payment_link: response.data.data.link, reference });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.response?.data?.message || err.message });
  }
});

// FLUTTERWAVE DEPOSIT WEBHOOK
app.post('/api/wallet/webhook/flutterwave', async (req, res) => {
  try {
    const secretHash = process.env.FLW_SECRET_HASH;
    const signature = req.headers['verif-hash'] || req.headers['flutterwave-signature'];

    if (!signature || (secretHash && signature !== secretHash)) {
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
        await supabase
          .from('transactions')
          .update({ status: 'COMPLETED' })
          .eq('id', tx.id);

        const { data: user } = await supabase
          .from('users')
          .select('wallet_balance')
          .eq('id', tx.user_id)
          .single();

        if (user) {
          const updatedBalance = parseFloat(user.wallet_balance) + parseFloat(amountPaid);
          await supabase
            .from('users')
            .update({ wallet_balance: updatedBalance })
            .eq('id', tx.user_id);
        }
      }
    }

    return res.status(200).send('Webhook Processed');
  } catch (err) {
    console.error('Webhook Error:', err);
    return res.status(200).send('Webhook Received With Warning');
  }
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
// 4. TRANSACTION HISTORY ENDPOINT
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
// 5. AVIATOR GAME PLAY ENDPOINTS
// ==========================================

app.post('/api/game/bet', authenticate, async (req, res) => {
  try {
    const rawRoundId = req.body.roundId || req.body.round_id;
    const rawAmount = req.body.amount;

    if (!rawRoundId || rawAmount === undefined || rawAmount === null) {
      return res.status(400).json({ success: false, message: 'roundId and amount are required' });
    }

    const roundId = String(rawRoundId);
    const amount = parseFloat(rawAmount);

    if (isNaN(amount) || amount <= 0) {
      return res.status(400).json({ success: false, message: 'Invalid amount format' });
    }

    const { data: response, error } = await supabase.rpc('place_aviator_bet', {
      p_user_id: req.userId,
      p_round_id: roundId,
      p_amount: amount
    });

    if (error) {
      console.error("RPC Error (place_aviator_bet):", error);
      return res.status(400).json({ success: false, message: error.message || 'Failed to place bet' });
    }

    if (!response || !response.success) {
      return res.status(400).json({ success: false, message: response?.message || 'Failed to place bet' });
    }

    pusher.trigger('aviator-channel', 'player_bet', { userId: req.userId, amount });

    return res.json({
      success: true,
      betId: response.bet_id || response.betId,
      newBalance: response.new_balance || response.newBalance
    });
  } catch (err) {
    console.error("Bet Endpoint Server Error:", err);
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/game/cashout', authenticate, async (req, res) => {
  try {
    const rawBetId = req.body.betId || req.body.bet_id;
    const rawMultiplier = req.body.currentMultiplier || req.body.multiplier;

    if (!rawBetId || !rawMultiplier) {
      return res.status(400).json({ success: false, message: 'betId and currentMultiplier are required' });
    }

    const betId = isNaN(rawBetId) ? String(rawBetId) : parseInt(rawBetId, 10);
    const currentMultiplier = parseFloat(rawMultiplier);

    const { data: response, error } = await supabase.rpc('cashout_aviator_bet', {
      p_user_id: req.userId,
      p_bet_id: betId,
      p_current_multiplier: currentMultiplier
    });

    if (error) {
      console.error("RPC Error (cashout_aviator_bet):", error);
      return res.status(400).json({ success: false, message: error.message || 'Cashout failed' });
    }

    if (!response || !response.success) {
      return res.status(400).json({ success: false, message: response?.message || 'Cashout failed' });
    }

    pusher.trigger('aviator-channel', 'player_cashed_out', {
      userId: req.userId,
      multiplier: response.multiplier,
      payout: response.payout
    });

    return res.json({
      success: true,
      payout: response.payout,
      newBalance: response.new_balance || response.newBalance
    });
  } catch (err) {
    console.error("Cashout Endpoint Server Error:", err);
    return res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = app;
