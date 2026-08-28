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

// Termii Pricing Configuration
const COST_PER_SMS = parseFloat(process.env.COST_PER_SMS || "4.00"); // Cost per SMS unit in NGN
const TERMII_BASE_URL = process.env.TERMII_BASE_URL || "https://v4.api.termii.com";

// Auth Middleware (User JWT protection)
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

// Helper to sanitize and convert phone numbers to international format (234...)
function formatPhoneNumber(phone) {
  if (!phone) return '';
  let str = phone.toString().replace(/[^0-9]/g, '');
  if (str.startsWith('0')) {
    str = '234' + str.substring(1);
  }
  return str;
}

// Helper: Virtual Account Generator via Flutterwave
async function generateVirtualAccount(user) {
    const nameParts = (user.fullname || "User").trim().split(" ");
    const firstName = nameParts[0] || "User";
    const lastName = nameParts.slice(1).join(" ") || "SMS";

    const response = await axios.post(
        'https://api.flutterwave.com/v3/virtual-account-numbers',
        {
            email: user.email,
            is_permanent: true,
            currency: "NGN",
            firstname: firstName,
            lastname: lastName,
            phonenumber: user.phone || "08000000000",
            narration: `${user.fullname || 'User'} - SMS Wallet`,
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
    res.send("Welcome to Bulk SMS Backend API");
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
// TERMII BULK SMS ENDPOINT
// ------------------------------------------
app.post(['/api/sms/send-bulk', '/api/sms/send', '/api/send-sms'], authMiddleware, async (req, res) => {
    const { recipients, message, senderId, channel } = req.body;
    const userId = req.user.id;

    if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
        return res.status(400).json({ success: false, message: "Recipients must be a non-empty array of phone numbers." });
    }

    if (!message || typeof message !== 'string' || message.trim() === '') {
        return res.status(400).json({ success: false, message: "Message body cannot be empty." });
    }

    // Standardize phone numbers to international format
    const formattedNumbers = recipients.map(formatPhoneNumber).filter(Boolean);

    if (formattedNumbers.length === 0) {
        return res.status(400).json({ success: false, message: "No valid phone numbers provided." });
    }

    const totalRecipients = formattedNumbers.length;
    const totalCost = totalRecipients * COST_PER_SMS;

    try {
        // Step A: Get current user balance
        const { data: user, error: userErr } = await supabase
            .from('users')
            .select('balance, wallet_balance')
            .eq('id', userId)
            .single();

        if (userErr || !user) {
            return res.status(404).json({ success: false, message: "User account not found." });
        }

        const currentBal = parseFloat(user.wallet_balance ?? user.balance ?? 0);

        if (currentBal < totalCost) {
            return res.status(400).json({ 
                success: false, 
                message: `Insufficient wallet balance. Total cost: ₦${totalCost.toFixed(2)}, Available balance: ₦${currentBal.toFixed(2)}` 
            });
        }

        // Step B: Call Termii Bulk SMS API
        const termiiPayload = {
            to: formattedNumbers,
            from: senderId || "talert",
            sms: message,
            type: "plain",
            channel: channel || "generic",
            api_key: process.env.TERMII_API_KEY
        };

        const termiiRes = await axios.post(`${TERMII_BASE_URL}/api/sms/send/bulk`, termiiPayload, { timeout: 20000 });
        const termiiData = termiiRes.data;

        // Step C: Deduct balance and record transaction
        const newBalance = currentBal - totalCost;

        await supabase
            .from('users')
            .update({ balance: newBalance, wallet_balance: newBalance })
            .eq('id', userId);

        const requestId = termiiData.message_id || `SMS_${Date.now()}`;

        await supabase.from('transactions').insert([{
            user_id: userId,
            type: 'BULK_SMS',
            amount: totalCost,
            status: 'SUCCESS',
            tx_ref: requestId,
            description: `Sent SMS to ${totalRecipients} recipients (${senderId || 'talert'})`
        }]);

        // Log to sms_logs if table exists
        await supabase.from('sms_logs').insert([{
            user_id: userId,
            sender_id: senderId || 'talert',
            recipients: formattedNumbers,
            recipient_count: totalRecipients,
            message: message,
            cost: totalCost,
            termii_message_id: termiiData.message_id || null,
            status: 'SUCCESS'
        }]).catch(() => {}); // Ignore error if sms_logs table isn't created yet

        return res.status(200).json({
            success: true,
            message: "SMS sent successfully!",
            totalCost,
            newBalance,
            data: termiiData
        });

    } catch (err) {
        const errorMsg = err.response?.data?.message || err.response?.data || err.message;
        return res.status(500).json({ success: false, message: "Failed to dispatch SMS", error: errorMsg });
    }
});

// ------------------------------------------
// ADMIN ENDPOINTS
// ------------------------------------------
app.get('/api/admin/users', async (req, res) => {
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

app.post('/api/admin/adjust-wallet', async (req, res) => {
  const { userId, amount, action, reason } = req.body; 

  if (!userId || !amount || !action) {
    return res.status(400).json({ status: 'error', message: 'Missing required parameters (userId, amount, action)' });
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
      return res.status(400).json({ status: 'error', message: 'Insufficient funds for debit operation' });
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

// ------------------------------------------
// TRANSACTIONS HISTORY ENDPOINT
// ------------------------------------------
app.get(['/api/transactions', '/api/history', '/api/sms/history', '/api/user/transactions'], authMiddleware, async (req, res) => {
    try {
        const { data: transactions, error } = await supabase
            .from('transactions')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;

        const formattedTransactions = (transactions || []).map(tx => {
            const rawType = (tx.type || 'SMS').toString().toUpperCase();
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

        const flwId = data.id || data.flw_ref;
        const uniqueTxRef = flwId ? `FLW_${flwId}` : (data.tx_ref ? `${data.tx_ref}_${Date.now()}` : `FLW_${Date.now()}`);

        console.log(`--> Processing Payment: ₦${amountPaid} | Acc: ${accountNumber || 'N/A'} | Email: ${customerEmail} | UniqueTxRef: ${uniqueTxRef}`);

        if (amountPaid <= 0) {
            console.log("--> Invalid amount paid, skipping.");
            return;
        }

        try {
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
