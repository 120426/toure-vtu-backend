require('dotenv').config();
const express = require('express');
const cors = express.cors || require('cors');
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

// SUPPORT LINK ENDPOINT
app.get('/api/support', async (req, res) => {
  return res.json({
    success: true,
    support_link: process.env.SUPPORT_LINK || 'https://wa.me/234XXXXXXXXX'
  });
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://placeholder.supabase.co';
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'placeholder_key';

const ADMIN_GMAIL = process.env.ADMIN_GMAIL || "mahadiengineer556@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Almahadi1204@";

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

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
    req.username = decoded.username;
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
      .select('*') // Updated to select all fields to inspect available schema columns
      .single();

    if (error) return res.status(400).json({ success: false, message: error.message });

    console.log("SIGNUP USER FIELDS:", user ? Object.keys(user) : 'No user data');

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ success: true, token, user });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();
    if (error || !user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    console.log("LOGIN USER FIELDS:", Object.keys(user));

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({
      success: true,
      token,
      user
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/account/profile', authenticate, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.userId)
      .single();

    if (error) return res.status(400).json({ success: false, message: error.message });
    
    console.log("PROFILE FIELDS:", user ? Object.keys(user) : 'None');
    return res.json({ success: true, user });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ==========================================
// 2. ADMIN CONTROL PANEL ENDPOINTS
// ==========================================

app.get('/api/admin/stats', authenticateAdmin, async (req, res) => {
  try {
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    const { count: pendingWithdrawals } = await supabase.from('transactions').select('*', { count: 'exact', head: true }).eq('type', 'WITHDRAWAL').eq('status', 'PENDING');
    
    const { data: usersData } = await supabase.from('users').select('wallet_balance');
    const totalWalletsBalance = usersData ? usersData.reduce((acc, u) => acc + parseFloat(u.wallet_balance || 0), 0) : 0;

    return res.json({
      success: true,
      stats: {
        totalUsers: totalUsers || 0,
        pendingWithdrawals: pendingWithdrawals || 0,
        totalWalletsBalance,
        systemStatus: 'Active'
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) return res.status(400).json({ success: false, message: error.message });
    if (users && users.length > 0) {
      console.log("ADMIN USERS TABLE FIELDS:", Object.keys(users[0]));
    }
    return res.json({ success: true, users });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const { data: transactions, error } = await supabase
      .from('transactions')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) return res.status(400).json({ success: false, message: error.message });
    if (transactions && transactions.length > 0) {
      console.log("ADMIN TRANSACTIONS FIELDS:", Object.keys(transactions[0]));
    }
    return res.json({ success: true, transactions });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.get('/api/admin/withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const { data: requests, error } = await supabase
      .from('transactions')
      .select(`
        *,
        users (*)
      `)
      .eq('type', 'WITHDRAWAL')
      .order('created_at', { ascending: false });

    if (error) {
      console.error("Supabase withdrawal fetch error:", error);
      return res.status(400).json({ success: false, message: error.message });
    }

    if (!requests || requests.length === 0) {
      return res.json({ success: true, requests: [] });
    }

    console.log("WITHDRAWAL JOIN FIELDS:", Object.keys(requests[0]));

    return res.json({ success: true, requests });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

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
      .eq('type', 'WITHDRAWAL')
      .single();

    if (fetchErr || !tx) return res.status(404).json({ success: false, message: 'Withdrawal transaction not found' });

    await supabase.from('transactions').update({ status: action }).eq('id', requestId);

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

app.get('/api/admin/deposits', authenticateAdmin, async (req, res) => {
  try {
    const { data: requests, error } = await supabase
      .from('transactions')
      .select(`
        *,
        users (*)
      `)
      .eq('type', 'DEPOSIT')
      .order('created_at', { ascending: false });

    if (error) {
      console.error("Supabase deposit fetch error:", error);
      return res.status(400).json({ success: false, message: error.message });
    }

    return res.json({ success: true, requests: requests || [] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/admin/deposits/process', authenticateAdmin, async (req, res) => {
  const { requestId, action } = req.body;

  if (!requestId || !['APPROVED', 'REJECTED'].includes(action)) {
    return res.status(400).json({ success: false, message: 'Invalid request data' });
  }

  try {
    const { data: tx, error: fetchErr } = await supabase
      .from('transactions')
      .select('*')
      .eq('id', requestId)
      .eq('type', 'DEPOSIT')
      .single();

    if (fetchErr || !tx) {
      return res.status(404).json({ success: false, message: 'Deposit transaction not found' });
    }

    if (tx.status === 'COMPLETED' || tx.status === 'APPROVED') {
      return res.status(400).json({ success: false, message: 'Deposit has already been processed' });
    }

    const newStatus = action === 'APPROVED' ? 'COMPLETED' : 'REJECTED';

    await supabase.from('transactions').update({ status: newStatus }).eq('id', requestId);

    if (action === 'APPROVED') {
      const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', tx.user_id).single();
      if (user) {
        const newBalance = parseFloat(user.wallet_balance || 0) + parseFloat(tx.amount);
        await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', tx.user_id);
      }
    }

    return res.json({ success: true, message: `Deposit request ${action.toLowerCase()} successfully` });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

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

// ==========================================
// 3. DEPOSIT & WITHDRAWAL ENDPOINTS
// ==========================================

app.post('/api/wallet/deposit/initialize', authenticate, async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ success: false, message: 'Invalid amount' });

  try {
    const { data: user } = await supabase.from('users').select('email, username').eq('id', req.userId).single();
    const reference = `DEP-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    await supabase.from('transactions').insert({
      user_id: req.userId,
      type: 'DEPOSIT',
      amount,
      status: 'PENDING',
      reference
    });

    const backendUrl = process.env.BACKEND_URL || 'https://toure-bet-backend.vercel.app';

    const response = await axios.post(
      'https://api.flutterwave.com/v3/payments',
      {
        tx_ref: reference,
        amount,
        currency: 'NGN',
        redirect_url: `${backendUrl}/api/wallet/deposit/verify`,
        payment_options: 'card,banktransfer,ussd',
        customer: { 
          email: user?.email || 'user@tourebet.com',
          name: user?.username || 'Toure Bet User'
        },
        customizations: { 
          title: 'Toure Bet Wallet Top-up', 
          description: 'Fund your game account balance' 
        }
      },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    return res.json({ success: true, payment_link: response.data.data.link, reference });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.response?.data?.message || err.message });
  }
});

app.get('/api/wallet/deposit/verify', async (req, res) => {
  const { transaction_id, status, tx_ref } = req.query;

  if (status !== 'successful' && status !== 'completed') {
    return res.redirect('https://toure-bet-frontend.vercel.app/wallet?status=failed');
  }

  try {
    const flwResponse = await axios.get(
      `https://api.flutterwave.com/v3/transactions/${transaction_id}/verify`,
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    const txData = flwResponse.data.data;

    if (txData.status === 'successful' && txData.tx_ref === tx_ref) {
      const { data: tx } = await supabase
        .from('transactions')
        .select('*')
        .eq('reference', tx_ref)
        .single();

      if (tx && tx.status === 'PENDING') {
        await supabase.from('transactions').update({ status: 'COMPLETED' }).eq('id', tx.id);

        const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', tx.user_id).single();
        if (user) {
          const newBalance = parseFloat(user.wallet_balance || 0) + parseFloat(tx.amount);
          await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', tx.user_id);
        }
      }
    }

    return res.redirect('https://toure-bet-frontend.vercel.app/wallet?status=success');
  } catch (err) {
    console.error("Flutterwave verification error:", err.message);
    return res.redirect('https://toure-bet-frontend.vercel.app/wallet?status=error');
  }
});

const handleWithdrawalRequest = async (req, res) => {
  const { amount, bank_name, bankName, account_number, accountNumber, account_name, accountName } = req.body;
  
  const finalAmount = parseFloat(amount);
  const finalBank = bank_name || bankName;
  const finalAccNo = account_number || accountNumber;
  const finalAccName = account_name || accountName;

  if (!finalAmount || finalAmount <= 0 || !finalAccNo) {
    return res.status(400).json({ success: false, message: 'Valid amount and account number are required' });
  }

  try {
    const { data: user } = await supabase.from('users').select('wallet_balance').eq('id', req.userId).single();

    if (!user || user.wallet_balance < finalAmount) {
      return res.status(400).json({ success: false, message: 'Insufficient balance' });
    }

    const newBalance = parseFloat(user.wallet_balance) - finalAmount;
    await supabase.from('users').update({ wallet_balance: newBalance }).eq('id', req.userId);

    const { error: insertErr } = await supabase.from('transactions').insert({
      user_id: req.userId,
      type: 'WITHDRAWAL',
      amount: finalAmount,
      status: 'PENDING',
      reference: `WDR-${Date.now()}`,
      bank_name: finalBank || 'Bank Transfer',
      account_number: finalAccNo,
      account_name: finalAccName || 'Account Holder'
    });

    if (insertErr) {
      await supabase.from('users').update({ wallet_balance: user.wallet_balance }).eq('id', req.userId);
      return res.status(400).json({ success: false, message: insertErr.message || 'Failed to save withdrawal' });
    }

    return res.json({ success: true, message: 'Withdrawal request submitted successfully' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
};

app.post('/api/wallet/withdraw', authenticate, handleWithdrawalRequest);
app.post('/api/wallet/withdraw/request', authenticate, handleWithdrawalRequest);

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
      return res.status(400).json({ success: false, message: error.message || 'Failed to place bet' });
    }

    console.log("AVIATOR BET RPC RESPONSE:", response);

    if (!response || !response.success) {
      return res.status(400).json({ success: false, message: response?.message || 'Failed to place bet' });
    }

    const betId = response.bet_id || response.betId;

    pusher.trigger('aviator-channel', 'player_bet', { 
      userId: req.userId, 
      username: req.username || 'Player',
      amount,
      betId,
      roundId 
    });

    return res.json({
      success: true,
      betId,
      newBalance: response.new_balance || response.newBalance
    });
  } catch (err) {
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

    const betId = String(rawBetId);
    const currentMultiplier = parseFloat(rawMultiplier);

    const { data: response, error } = await supabase.rpc('cashout_aviator_bet', {
      p_user_id: req.userId,
      p_bet_id: betId,
      p_current_multiplier: currentMultiplier
    });

    if (error) {
      return res.status(400).json({ success: false, message: error.message || 'Cashout failed' });
    }

    console.log("AVIATOR CASHOUT RPC RESPONSE:", response);

    if (!response || !response.success) {
      return res.status(400).json({ success: false, message: response?.message || 'Cashout failed' });
    }

    const payout = response.payout;
    const multiplier = response.multiplier || currentMultiplier;

    pusher.trigger('aviator-channel', 'player_cashed_out', {
      userId: req.userId,
      username: req.username || 'Player',
      betId,
      multiplier,
      payout
    });

    return res.json({
      success: true,
      payout,
      newBalance: response.new_balance || response.newBalance
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = app;
