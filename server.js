require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// STRICT CORS HEADERS & PREFLIGHT HANDLER (Solves 'Failed to fetch' & file:// issues)
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

app.use(express.json());

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_123";

// Network Codes Map for ClubKonnect
const NETWORK_CODES = {
  'MTN': '01',
  'GLO': '02',
  '9MOBILE': '03',
  'ETISALAT': '03',
  'AIRTEL': '04'
};

// Middleware to authenticate JWT token
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token missing' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Home Route
app.get("/", (req, res) => {
    res.send("Welcome to TOURE VTU Backend");
});

// Helper: Flutterwave Virtual Account Generator
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

// Generate/Retrieve Virtual Account
app.post("/api/wallet/generate-virtual-account", authMiddleware, async (req, res) => {
    try {
        const { data: user, error: userErr } = await supabase
            .from('users')
            .select('id, email, fullname, phone, bvn, va_account_number, va_bank_name')
            .eq('id', req.user.id)
            .single();

        if (userErr || !user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        if (user.va_account_number && user.va_bank_name) {
            return res.json({
                success: true,
                accountNumber: user.va_account_number,
                bankName: user.va_bank_name,
                va_account_number: user.va_account_number,
                va_bank_name: user.va_bank_name,
                account_number: user.va_account_number,
                bank_name: user.va_bank_name
            });
        }

        if (!user.bvn) {
            return res.status(400).json({ 
                success: false, 
                message: "BVN missing. Please contact support or re-register." 
            });
        }

        const vaDetails = await generateVirtualAccount(user);

        if (vaDetails && vaDetails.account_number) {
            await supabase
                .from('users')
                .update({ 
                    va_account_number: vaDetails.account_number,
                    va_bank_name: vaDetails.bank_name 
                })
                .eq('id', user.id);

            return res.json({
                success: true,
                accountNumber: vaDetails.account_number,
                bankName: vaDetails.bank_name,
                va_account_number: vaDetails.account_number,
                va_bank_name: vaDetails.bank_name,
                account_number: vaDetails.account_number,
                bank_name: vaDetails.bank_name
            });
        } else {
            return res.status(400).json({ 
                success: false, 
                message: "Failed to generate live account with Flutterwave." 
            });
        }
    } catch (err) {
        const flwError = err.response?.data?.message || err.message;
        console.error("Virtual Account Endpoint Error:", flwError);
        return res.status(400).json({ success: false, message: flwError });
    }
});

// Register API
app.post("/api/auth/register", async (req, res) => {
    const fullname = req.body.fullname || req.body.fullName;
    const email = req.body.email;
    const password = req.body.password;
    const phone = req.body.phone || req.body.phoneNumber;
    const bvn = req.body.bvn;

    if (!fullname || !email || !password || !bvn) {
        return res.status(400).json({ 
            success: false, 
            message: "Fullname, email, password, and BVN are required" 
        });
    }

    if (bvn.length !== 11 || isNaN(bvn)) {
        return res.status(400).json({ 
            success: false, 
            message: "Please enter a valid 11-digit BVN" 
        });
    }

    try {
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .maybeSingle();

        if (existingUser) {
            return res.status(400).json({ success: false, message: "Email is already registered" });
        }

        let vaDetails;
        try {
            vaDetails = await generateVirtualAccount({ fullname, email, phone, bvn });
        } catch (flwErr) {
            const errorMsg = flwErr.response?.data?.message || flwErr.message;
            console.error("Flutterwave Live Error:", errorMsg);
            return res.status(400).json({
                success: false,
                message: `Virtual Account Generation Failed: ${errorMsg}`
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{
                fullname,
                email,
                password: hashedPassword,
                phone: phone || null,
                bvn: bvn,
                va_account_number: vaDetails.account_number,
                va_bank_name: vaDetails.bank_name,
                balance: 0
            }])
            .select('id, fullname, email, phone, balance, va_account_number, va_bank_name, created_at')
            .single();

        if (error) throw error;

        res.status(201).json({
            success: true,
            message: "User registered successfully!",
            user: newUser
        });

    } catch (err) {
        console.error("Register Error:", err.message);
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// Login API
app.post("/api/auth/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email)
            .maybeSingle();

        if (error || !user) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "Login successful!",
            token,
            user: {
                id: user.id,
                fullname: user.fullname,
                email: user.email,
                phone: user.phone,
                balance: user.balance,
                va_account_number: user.va_account_number,
                va_bank_name: user.va_bank_name
            }
        });

    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).json({ success: false, message: "Server error", error: err.message });
    }
});

// Protected User Profile API
const getProfileHandler = async (req, res) => {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('id, fullname, email, phone, balance, va_account_number, va_bank_name, created_at')
            .eq('id', req.user.id)
            .single();

        if (error || !user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.json({
            success: true,
            user: user
        });
    } catch (err) {
        console.error("Profile Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
};

app.get("/profile", authMiddleware, getProfileHandler);
app.get("/api/user/profile", authMiddleware, getProfileHandler);

// Get Wallet Details & Balance
app.get('/api/wallet', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id || req.user.userId;

    if (!userId) {
      return res.status(400).json({ success: false, message: 'User ID missing from token' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, balance, va_account_number, va_bank_name')
      .eq('id', userId)
      .single();

    if (error) {
      console.error('Supabase Error:', error.message);
      return res.status(400).json({ success: false, message: error.message });
    }

    return res.status(200).json({
      success: true,
      balance: user.balance || 0,
      wallet: {
        balance: user.balance || 0,
        email: user.email,
        va_account_number: user.va_account_number,
        va_bank_name: user.va_bank_name
      },
      virtual_account: {
        account_number: user.va_account_number,
        bank_name: user.va_bank_name
      }
    });
  } catch (err) {
    console.error('Wallet Route Server Error:', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
});

// Fetch Transactions Endpoint
app.get('/api/transactions', authMiddleware, async (req, res) => {
    try {
        const { data: transactions, error } = await supabase
            .from('transactions')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;

        return res.status(200).json({
            success: true,
            transactions: transactions || []
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: err.message });
    }
});

// AIRTIME ENDPOINT - STRICT OVERRIDE & WALLET DEDUCTION
app.post(['/api/services/airtime', '/api/vtu/buy-airtime'], authMiddleware, async (req, res) => {
  console.log("-----------------------------------------");
  console.log("👉 AIRTIME ENDPOINT HIT!");

  // CLEAN UP BODY TO PREVENT PROVIDER CONFUSION
  delete req.body.planId;
  delete req.body.plan_id;
  delete req.body.plan;
  delete req.body.dataplan;
  delete req.body.data_plan;
  delete req.body.type;

  const network = req.body.network || 'MTN';
  const targetPhone = (req.body.phone || req.body.phoneNumber || req.body.mobileNo || '').toString().replace(/[^0-9]/g, '');
  const numAmount = parseFloat(req.body.amount) || 0;
  const userId = req.user.id;

  if (!targetPhone || targetPhone.length < 11) {
    return res.status(400).json({ success: false, message: "Invalid phone number provided." });
  }

  if (numAmount < 50) {
    return res.status(400).json({ success: false, message: "Minimum airtime amount is N50." });
  }

  try {
    // 1. Check user wallet balance
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('balance')
      .eq('id', userId)
      .single();

    if (userErr || !user) {
      return res.status(404).json({ success: false, message: "User record not found." });
    }

    if (parseFloat(user.balance) < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    // 2. Call ClubKonnect API
    const netCode = NETWORK_CODES[network.toString().toUpperCase()] || '01';
    const userID = process.env.CLUBKONNECT_USER_ID;
    const apiKey = process.env.CLUBKONNECT_API_KEY;
    const requestId = `CK_AIR_${Date.now()}`;

    const ckUrl = `https://www.nellobytesystems.com/APIBuy.asp?UserID=${userID}&APIKey=${apiKey}&MobileNetwork=${netCode}&Amount=${numAmount}&MobileNo=${targetPhone}&RequestID=${requestId}`;

    console.log(`🚀 EXECUTING AIRTIME URL: ${ckUrl}`);
    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data;

    console.log("📥 CLUBKONNECT RESPONSE:", data);

    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      // 3. Deduct User Balance
      const newBalance = parseFloat(user.balance) - numAmount;
      await supabase
        .from('users')
        .update({ balance: newBalance })
        .eq('id', userId);

      // 4. Record Transaction
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'AIRTIME',
        amount: numAmount,
        status: 'SUCCESS',
        reference: requestId
      }]);

      return res.status(200).json({
        success: true,
        message: "Airtime purchase successful!",
        orderId: data.orderid || requestId,
        newBalance: newBalance
      });
    } else {
      return res.status(400).json({
        success: false,
        message: `Provider Error: ${data.substatus || data.status || "Transaction rejected by provider"}`
      });
    }
  } catch (err) {
    console.error("Airtime Error:", err.message);
    return res.status(500).json({ success: false, message: err.message });
  }
});

// Webhook Route for Flutterwave
app.post('/webhook/flutterwave', async (req, res) => {
    const signature = req.headers['verif-hash'] || req.headers['flutterwave-signature'];

    if (process.env.FLW_SECRET_HASH && signature !== process.env.FLW_SECRET_HASH) {
        console.log("❌ Webhook signature mismatch! Received:", signature);
        return res.status(401).send('Unauthorized webhook call');
    }

    res.status(200).send('Webhook Received');

    const payload = req.body;
    if (payload && payload.event === 'charge.completed' && payload.data?.status === 'successful') {
        const rawEmail = payload.data.customer?.email || "";
        const customerEmail = rawEmail.trim().toLowerCase();
        const accountNumber = payload.data.account_number;
        const amountPaid = parseFloat(payload.data.amount);
        const txRef = payload.data.tx_ref || `FLW_${payload.data.id}`;

        try {
            const { data: existingTx } = await supabase
                .from('transactions')
                .select('id')
                .eq('reference', txRef)
                .maybeSingle();

            if (existingTx) {
                console.log("⚠️ Transaction already processed previously.");
                return;
            }

            let userQuery = supabase.from('users').select('id, fullname, email, balance');
            if (accountNumber) {
                userQuery = userQuery.eq('va_account_number', accountNumber);
            } else {
                userQuery = userQuery.ilike('email', customerEmail);
            }

            const { data: user, error: userErr } = await userQuery.maybeSingle();

            if (userErr || !user) {
                console.log(`❌ No user found matching criteria`);
                return;
            }

            let credited = false;
            try {
                const { error: rpcErr } = await supabase.rpc('increment_balance', { 
                    user_id_input: user.id, 
                    amount_input: amountPaid 
                });
                if (!rpcErr) credited = true;
            } catch (e) {
                console.log("RPC increment failed, switching to direct update...");
            }

            if (!credited) {
                const newBalance = (parseFloat(user.balance) || 0) + amountPaid;
                const { error: updateErr } = await supabase
                    .from('users')
                    .update({ balance: newBalance })
                    .eq('id', user.id);

                if (updateErr) {
                    console.error("❌ Direct Balance Update Failed:", updateErr.message);
                    return;
                }
            }

            await supabase
                .from('transactions')
                .insert([{
                    user_id: user.id,
                    type: 'FUND_WALLET',
                    amount: amountPaid,
                    status: 'SUCCESS',
                    reference: txRef
                }]);

            console.log(`✅ SUCCESS: Credited ${amountPaid} to ${user.email}`);

        } catch (err) {
            console.error('Webhook processing error:', err.message);
        }
    }
});

// Run local server if not on Vercel
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

module.exports = app;