require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// 1. Middleware Setup
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static HTML files (e.g. admin.html)
app.use(express.static(__dirname));

// 2. Supabase Setup
const supabaseUrl = process.env.SUPABASE_URL || "https://placeholder.supabase.co";
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || "placeholder-key";
const supabase = createClient(supabaseUrl, supabaseKey);

const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_123";

// Service Mappings
const NETWORK_CODES = { 'MTN': '01', 'GLO': '02', '9MOBILE': '03', 'ETISALAT': '03', 'AIRTEL': '04' };

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Access token missing' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Helper to sanitize Nigerian Phone Numbers
function sanitizePhoneNumber(phone) {
  if (!phone) return '';
  let str = phone.toString().replace(/[^0-9]/g, '');
  if (str.startsWith('234') && str.length === 13) {
    str = '0' + str.substring(3);
  }
  return str;
}

// Helper: Virtual Account Generator
async function generateVirtualAccount(user) {
    const nameParts = (user.fullname || "User").trim().split(" ");
    const firstName = nameParts[0] || "User";
    const lastName = nameParts.slice(1).join(" ") || "Toure";

    const response = await axios.post(
        'https://api.flutterwave.com/v3/virtual-account-numbers',
        {
            email: user.email,
            is_permanent: true,
            currency: "NGN",
            firstname: firstName,
            lastname: lastName,
            phonenumber: user.phone || "08000000000",
            narration: `${user.fullname || 'User'} - Toure Data Wallet`,
            bvn: user.bvn
        },
        {
            headers: {
                Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                'Content-Type': 'application/json'
            }
        }
    );

    if (response.data.status === 'success' && response.data.data) {
        return {
            account_number: response.data.data.account_number,
            bank_name: response.data.data.bank_name
        };
    } else {
        throw new Error(response.data.message || "Flutterwave rejected virtual account creation.");
    }
}

// Root Health Route
app.get("/", (req, res) => {
    res.send("Welcome to TOURE VTU Backend API");
});

// Admin Panel Route
app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "admin.html"));
});

// ------------------------------------------
// AUTHENTICATION ROUTES
// ------------------------------------------
app.post("/api/auth/register", async (req, res) => {
    const fullname = req.body.fullname || req.body.fullName;
    const email = req.body.email;
    const password = req.body.password;
    const phone = req.body.phone || req.body.phoneNumber;
    const bvn = req.body.bvn;

    if (!fullname || !email || !password || !bvn) {
        return res.status(400).json({ success: false, message: "Fullname, email, password, and BVN are required" });
    }

    if (bvn.length !== 11 || isNaN(bvn)) {
        return res.status(400).json({ success: false, message: "Please enter a valid 11-digit BVN" });
    }

    try {
        const { data: existingUser } = await supabase.from('users').select('id').eq('email', email).maybeSingle();
        if (existingUser) return res.status(400).json({ success: false, message: "Email is already registered" });

        let vaDetails;
        try {
            vaDetails = await generateVirtualAccount({ fullname, email, phone, bvn });
        } catch (flwErr) {
            const errorMsg = flwErr.response?.data?.message || flwErr.message;
            return res.status(400).json({ success: false, message: `Virtual Account Generation Failed: ${errorMsg}` });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{
                fullname, email, password: hashedPassword, phone: phone || null, bvn,
                va_account_number: vaDetails.account_number, va_bank_name: vaDetails.bank_name, balance: 0, wallet_balance: 0
            }])
            .select('id, fullname, email, phone, balance, wallet_balance, va_account_number, va_bank_name, created_at')
            .single();

        if (error) throw error;
        res.status(201).json({ success: true, message: "User registered successfully!", user: newUser });

    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const { data: user } = await supabase.from('users').select('*').eq('email', email).maybeSingle();
        if (!user) return res.status(400).json({ success: false, message: "Invalid email or password" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ success: false, message: "Invalid email or password" });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });

        const userBal = parseFloat(user.wallet_balance ?? user.balance ?? 0);

        res.json({
            success: true,
            message: "Login successful!",
            token,
            user: {
                id: user.id, fullname: user.fullname, email: user.email, phone: user.phone,
                balance: userBal, wallet_balance: userBal, va_account_number: user.va_account_number, va_bank_name: user.va_bank_name
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

const getProfileHandler = async (req, res) => {
    try {
        const { data: user } = await supabase
            .from('users')
            .select('id, fullname, email, phone, balance, wallet_balance, va_account_number, va_bank_name, created_at')
            .eq('id', req.user.id)
            .single();

        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        const userBal = parseFloat(user.wallet_balance ?? user.balance ?? 0);
        res.json({ success: true, user: { ...user, balance: userBal, wallet_balance: userBal } });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
};

app.get("/profile", authMiddleware, getProfileHandler);
app.get("/api/user/profile", authMiddleware, getProfileHandler);

// ------------------------------------------
// WALLET ENDPOINT
// ------------------------------------------
app.get('/api/wallet', authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, balance, wallet_balance, va_account_number, va_bank_name')
      .eq('id', req.user.id)
      .single();

    if (error) return res.status(400).json({ success: false, message: error.message });

    const rawBal = user.wallet_balance !== null && user.wallet_balance !== undefined && parseFloat(user.wallet_balance) > 0 
      ? user.wallet_balance 
      : (user.balance ?? 0);

    const currentBal = parseFloat(rawBal || 0);

    return res.status(200).json({
      success: true,
      balance: currentBal,
      wallet_balance: currentBal,
      wallet: { 
        balance: currentBal, 
        wallet_balance: currentBal,
        email: user.email, 
        va_account_number: user.va_account_number, 
        va_bank_name: user.va_bank_name 
      },
      virtual_account: { account_number: user.va_account_number, bank_name: user.va_bank_name }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
});

// ------------------------------------------
// CLUBKONNECT DYNAMIC PLANS FETCH
// ------------------------------------------
app.get(['/api/services/plans/airtime', '/api/plans/airtime'], async (req, res) => {
  try {
    const userId = process.env.CLUBKONNECT_USER_ID || 'CK101285317';
    const response = await axios.get(`https://www.nellobytesystems.com/APIAirtimeNetworkV2.asp?UserID=${userId}`, { timeout: 15000 });
    return res.status(200).json({ success: true, data: response.data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch airtime networks', error: err.message });
  }
});

app.get(['/api/services/plans/data', '/api/plans/data'], async (req, res) => {
  try {
    const userId = process.env.CLUBKONNECT_USER_ID || 'CK101285317';
    const response = await axios.get(`https://www.nellobytesystems.com/APIDatabundlePlansV2.asp?UserID=${userId}`, { timeout: 15000 });
    return res.status(200).json({ success: true, data: response.data });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch data plans', error: err.message });
  }
});

// ==========================================
// ADMIN AUTHENTICATION MIDDLEWARE
// ==========================================
const adminAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ status: 'error', message: 'Admin authentication token missing' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('id', decoded.id)
      .single();

    if (error || !user) {
      return res.status(403).json({ status: 'error', message: 'Unauthorized admin access' });
    }

    req.admin = user;
    next();
  } catch (err) {
    return res.status(403).json({ status: 'error', message: 'Invalid or expired admin token' });
  }
};

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

const adminAuth = (req, res, next) => {
  // 1. Allow CORS preflight requests
  if (req.method === 'OPTIONS') {
    return next();
  }

  // 2. Extract authorization header or custom key header
  const authHeader = req.headers.authorization || req.headers['x-admin-key'];

  if (!authHeader) {
    return res.status(401).json({ 
      status: 'error', 
      message: 'Unauthorized: Missing authorization header.' 
    });
  }

  // 3. Parse token (handles "Bearer <token>" or direct string)
  const token = authHeader.startsWith('Bearer ') 
    ? authHeader.split(' ')[1] 
    : authHeader;

  // 4. Validate against environment variable (or fallback key)
  const EXPECTED_SECRET = process.env.ADMIN_SECRET_KEY || 'your_admin_secret_key';

  if (token !== EXPECTED_SECRET) {
    return res.status(401).json({ 
      status: 'error', 
      message: 'Unauthorized: Invalid or expired admin token.' 
    });
  }

  // Token valid, proceed to endpoint handler
  next();
};

// ==========================================
// ADMIN & APP CONFIGURATION ENDPOINTS
// ==========================================

// 1. Get all users with wallet balances (Protected)
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, fullname, email, phone, wallet_balance, balance, created_at')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const users = (data || []).map(u => ({
      ...u,
      wallet_balance: parseFloat(u.wallet_balance ?? u.balance ?? 0)
    }));

    res.json({ status: 'success', users });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 2. Adjust User Wallet Balance (Protected)
app.post('/api/admin/adjust-wallet', adminAuth, async (req, res) => {
  const { userId, amount, action, reason } = req.body; 

  if (!userId || !amount || !action) {
    return res.status(400).json({ 
      status: 'error', 
      message: 'Missing required parameters (userId, amount, action)' 
    });
  }

  const numAmount = parseFloat(amount);
  if (isNaN(numAmount) || numAmount <= 0) {
    return res.status(400).json({ status: 'error', message: 'Invalid adjustment amount' });
  }

  try {
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('wallet_balance, balance')
      .eq('id', userId)
      .single();

    if (userErr || !user) throw new Error('User not found');

    const currentBalance = parseFloat(user.wallet_balance ?? user.balance ?? 0);
    const newBalance = action === 'credit' 
      ? currentBalance + numAmount 
      : currentBalance - numAmount;

    if (newBalance < 0) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'Insufficient funds for debit operation' 
      });
    }

    const { error: updateErr } = await supabase
      .from('users')
      .update({ wallet_balance: newBalance, balance: newBalance })
      .eq('id', userId);

    if (updateErr) throw updateErr;

    await supabase.from('transactions').insert([{
      user_id: userId,
      type: action.toUpperCase(),
      amount: numAmount,
      status: 'SUCCESS',
      description: reason || `Admin manual ${action}`
    }]);

    res.json({ 
      status: 'success', 
      message: `Successfully ${action}ed ₦${numAmount}`, 
      newBalance 
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 3. Get All Plans / Pricing Rules (Public Endpoint for App)
app.get('/api/plans', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('plans')
      .select('*')
      .order('network', { ascending: true });

    if (error) throw error;
    res.json({ status: 'success', plans: data || [] });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 4. Update Plan Price (Protected)
app.post('/api/admin/update-price', adminAuth, async (req, res) => {
  const { plan_id, id, user_price } = req.body;

  const targetId = plan_id || id;

  if (!targetId || user_price === undefined) {
    return res.status(400).json({ 
      status: 'error', 
      message: 'plan_id (or id) and user_price are required' 
    });
  }

  try {
    const { error } = await supabase
      .from('plans')
      .update({ 
        user_price: parseFloat(user_price), 
        updated_at: new Date().toISOString() 
      })
      .eq('plan_id', targetId);

    if (error) throw error;
    res.json({ status: 'success', message: 'Price updated successfully' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 5. Get App Settings (Public Endpoint for App)
app.get('/api/settings', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('app_settings')
      .select('*');

    if (error) throw error;

    const settings = {};
    (data || []).forEach(item => {
      settings[item.key] = item.value;
    });

    res.json({ status: 'success', settings });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// 6. Update App Settings (Protected)
app.post('/api/admin/update-settings', adminAuth, async (req, res) => {
  const { settings } = req.body;

  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ status: 'error', message: 'Invalid payload format' });
  }

  try {
    const updates = Object.keys(settings).map(key => {
      return supabase
        .from('app_settings')
        .upsert({ key, value: String(settings[key]) }, { onConflict: 'key' });
    });

    const results = await Promise.all(updates);
    
    const failedQuery = results.find(r => r.error);
    if (failedQuery) throw failedQuery.error;

    res.json({ status: 'success', message: 'App settings updated successfully' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ------------------------------------------
// TRANSACTIONS HISTORY ENDPOINT
// ------------------------------------------
app.get(['/api/transactions', '/api/history', '/api/vtu/history', '/api/user/transactions'], authMiddleware, async (req, res) => {
    try {
        const { data: transactions, error } = await supabase
            .from('transactions')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;

        const formattedTransactions = (transactions || []).map(tx => {
            const rawType = (tx.type || 'VTU').toString().toUpperCase();
            const txDesc = tx.description || `${rawType} Transaction`;
            const uniqueReference = tx.flw_ref || tx.flutterwave_id || tx.tx_ref || tx.id;
            
            return {
                id: tx.id,
                user_id: tx.user_id,
                type: rawType,
                transaction_type: rawType,
                service: rawType.toLowerCase(),
                category: rawType,
                description: txDesc,
                amount: parseFloat(tx.amount || 0),
                status: (tx.status || 'SUCCESS').toUpperCase(),
                reference: uniqueReference,
                tx_ref: uniqueReference,
                target: txDesc,
                phone: txDesc,
                date: tx.created_at,
                created_at: tx.created_at
            };
        });

        return res.json({ 
            success: true, 
            transactions: formattedTransactions,
            history: formattedTransactions,
            data: formattedTransactions 
        });
    } catch (err) {
        console.error('Error fetching transactions:', err);
        return res.status(500).json({ success: false, message: 'Failed to fetch transactions', error: err.message });
    }
});

// ------------------------------------------
// PURCHASES ENDPOINTS
// ------------------------------------------

// 1. AIRTIME
app.post(['/api/services/airtime', '/api/vtu/buy-airtime', '/api/buy-airtime', '/api/airtime'], authMiddleware, async (req, res) => {
  const rawPhone = req.body.phone || req.body.phoneNumber || req.body.phone_number || req.body.mobileNo || req.body.mobile_number || req.body.MobileNo || req.body.MobileNumber || req.body.PhoneNo || req.body.target || req.body.recipient || '';
  const targetPhone = sanitizePhoneNumber(rawPhone);
  
  const network = req.body.network || req.body.MobileNetwork || req.body.network_id || 'MTN';
  const numAmount = parseFloat(req.body.amount || req.body.Amount) || 0;
  const userId = req.user.id;

  if (!targetPhone || targetPhone.length !== 11) {
    return res.status(400).json({ success: false, message: `Invalid phone number received: "${rawPhone}". Must be an 11-digit number.` });
  }
  if (numAmount < 50) {
    return res.status(400).json({ success: false, message: "Minimum airtime amount is ₦50." });
  }

  try {
    const { data: user } = await supabase.from('users').select('balance, wallet_balance').eq('id', userId).single();
    const currentBal = parseFloat(user?.wallet_balance ?? user?.balance ?? 0);

    if (!user || currentBal < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    const netCode = NETWORK_CODES[network.toString().toUpperCase()] || '01';
    const requestId = `CK_AIR_${Date.now()}`;
    const ckUrl = `https://www.nellobytesystems.com/APIAirtimeV1.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&MobileNetwork=${netCode}&Amount=${numAmount}&MobileNumber=${targetPhone}&MobileNo=${targetPhone}&RequestID=${requestId}`;

    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data;
    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      const newBalance = currentBal - numAmount;
      await supabase.from('users').update({ balance: newBalance, wallet_balance: newBalance }).eq('id', userId);
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'AIRTIME',
        amount: numAmount,
        status: 'SUCCESS',
        tx_ref: requestId,
        description: `Airtime purchase to ${targetPhone}`
      }]);

      return res.status(200).json({ success: true, message: "Airtime purchase successful!", newBalance });
    } else {
      return res.status(400).json({ success: false, message: `Provider Error: ${data.substatus || data.status || 'Transaction Failed'}` });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// 2. DATA
app.post(['/api/services/data', '/api/vtu/buy-data', '/api/buy-data', '/api/data'], authMiddleware, async (req, res) => {
  const rawPhone = req.body.phone || req.body.phoneNumber || req.body.phone_number || req.body.mobileNo || req.body.mobile_number || req.body.MobileNo || req.body.MobileNumber || req.body.PhoneNo || req.body.target || req.body.recipient || '';
  const targetPhone = sanitizePhoneNumber(rawPhone);
  
  const network = req.body.network || req.body.MobileNetwork || req.body.network_id || 'MTN';
  const dataPlan = req.body.planId || req.body.data_plan || req.body.plan || req.body.dataplan || req.body.DataPlan;
  const numAmount = parseFloat(req.body.amount || req.body.Amount) || 0;
  const userId = req.user.id;

  if (!targetPhone || targetPhone.length !== 11) {
    return res.status(400).json({ success: false, message: `Invalid phone number received: "${rawPhone}". Must be an 11-digit number.` });
  }
  if (!dataPlan) {
    return res.status(400).json({ success: false, message: "Data plan code is required." });
  }

  try {
    const { data: user } = await supabase.from('users').select('balance, wallet_balance').eq('id', userId).single();
    const currentBal = parseFloat(user?.wallet_balance ?? user?.balance ?? 0);

    if (!user || currentBal < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    const netCode = NETWORK_CODES[network.toString().toUpperCase()] || '01';
    const requestId = `CK_DATA_${Date.now()}`;
    const ckUrl = `https://www.nellobytesystems.com/APIDatabundleV1.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&MobileNetwork=${netCode}&DataPlan=${dataPlan}&MobileNumber=${targetPhone}&MobileNo=${targetPhone}&RequestID=${requestId}`;

    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data;
    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      const newBalance = currentBal - numAmount;
      await supabase.from('users').update({ balance: newBalance, wallet_balance: newBalance }).eq('id', userId);
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'DATA',
        amount: numAmount,
        status: 'SUCCESS',
        tx_ref: requestId,
        description: `Data purchase to ${targetPhone}`
      }]);

      return res.status(200).json({ success: true, message: "Data purchase successful!", newBalance });
    } else {
      return res.status(400).json({ success: false, message: `Provider Error: ${data.substatus || data.status || 'Transaction Failed'}` });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ------------------------------------------
// FLUTTERWAVE WEBHOOK (AUTOMATIC FUNDING)
// ------------------------------------------
app.post('/webhook/flutterwave', async (req, res) => {
    const signature = req.headers['verif-hash'] || req.headers['flutterwave-signature'];
    if (process.env.FLW_SECRET_HASH && signature !== process.env.FLW_SECRET_HASH) {
        console.error("Webhook Signature Mismatch!");
        return res.status(401).send('Unauthorized webhook call');
    }

    res.status(200).send('Webhook Received');

    const payload = req.body;
    console.log("--> Flutterwave Event Received:", payload?.event || payload?.["event.type"]);

    const isSuccessfulCharge = payload && 
        (payload.event === 'charge.completed' || payload["event.type"] === 'BANK_TRANSFER_TRANSACTION' || payload.status === 'successful') && 
        (payload.data?.status === 'successful' || payload.status === 'successful');

    if (isSuccessfulCharge) {
        const data = payload.data || payload;
        const rawEmail = data.customer?.email || data.email || "";
        const customerEmail = rawEmail.trim().toLowerCase();
        
        let accountNumber = data.account_number || data.virtual_account_number || data.data?.account_number;
        if (accountNumber === 'undefined' || accountNumber === 'null') {
            accountNumber = null;
        }

        const amountPaid = parseFloat(data.amount || data.charged_amount || data.settled_amount || 0);

        // Generate a UNIQUE transaction reference using Flutterwave's unique ID/flw_ref
        const flwId = data.id || data.flw_ref;
        const uniqueTxRef = flwId ? `FLW_${flwId}` : (data.tx_ref ? `${data.tx_ref}_${Date.now()}` : `FLW_${Date.now()}`);

        console.log(`--> Processing Payment: ₦${amountPaid} | Acc: ${accountNumber || 'N/A'} | Email: ${customerEmail} | UniqueTxRef: ${uniqueTxRef}`);

        if (amountPaid <= 0) {
            console.log("--> Invalid amount paid, skipping.");
            return;
        }

        try {
            // Check Supabase using the guaranteed UNIQUE reference string
            const { data: existingTx, error: txError } = await supabase
                .from('transactions')
                .select('id')
                .eq('tx_ref', uniqueTxRef)
                .maybeSingle();

            if (txError) {
                console.error("--> Supabase Tx Check Error:", txError.message);
            }

            if (existingTx) {
                console.log(`--> Transaction already processed: ${uniqueTxRef}`);
                return;
            }

            let user = null;

            if (accountNumber) {
                const { data: uByAcc, error: accErr } = await supabase
                    .from('users')
                    .select('id, balance, wallet_balance, email')
                    .eq('va_account_number', accountNumber)
                    .maybeSingle();

                if (accErr) console.error("--> Account Lookup Error:", accErr.message);
                user = uByAcc;
            }

            if (!user && customerEmail) {
                console.log(`--> Account lookup yielded no user. Falling back to email lookup: ${customerEmail}`);
                const { data: uByEmail, error: emailErr } = await supabase
                    .from('users')
                    .select('id, balance, wallet_balance, email')
                    .ilike('email', customerEmail)
                    .maybeSingle();

                if (emailErr) console.error("--> Email Lookup Error:", emailErr.message);
                user = uByEmail;
            }

            if (!user) {
                console.error(`--> CRITICAL: User NOT FOUND in Supabase for Account: ${accountNumber} or Email: ${customerEmail}`);
                return;
            }

            const currentBal = parseFloat(user.wallet_balance ?? user.balance ?? 0);
            const newBalance = currentBal + amountPaid;

            console.log(`--> User Found (ID: ${user.id}). Old Balance: ₦${currentBal} | Adding: ₦${amountPaid} | New Balance: ₦${newBalance}`);

            const { error: updateError } = await supabase
                .from('users')
                .update({ 
                    balance: newBalance,
                    wallet_balance: newBalance 
                })
                .eq('id', user.id);

            if (updateError) {
                console.error("--> Supabase Balance Update Error:", updateError.message);
                return;
            }

            // Insert uniqueTxRef so every transaction in history has a distinct ID
            const { error: insertError } = await supabase
                .from('transactions')
                .insert([{
                    user_id: user.id,
                    type: 'WALLET_FUNDING',
                    amount: amountPaid,
                    status: 'SUCCESS',
                    tx_ref: uniqueTxRef,
                    description: `Wallet Funding via Bank Transfer`
                }]);

            if (insertError) {
                console.error("--> Supabase Insert Tx Record Error:", insertError.message);
            } else {
                console.log(`--> SUCCESS! User ${user.id} (${user.email}) credited with ₦${amountPaid}. New Balance: ₦${newBalance}`);
            }

        } catch (err) {
            console.error("--> Webhook Exception Catch:", err.message);
        }
    } else {
        console.log("--> Webhook event ignored (Not a successful charge).");
    }
});

// Local dev listener & Vercel Export
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

module.exports = app;