require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// Enable CORS & JSON Body Parsing
app.use(cors());
app.use(express.json());

const supabaseUrl = process.env.SUPABASE_URL;
// Use Service Role Key to bypass RLS policies on the server
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_123";

// Network Codes Map for ClubKonnect
const NETWORK_CODES = {
  'MTN': '01',
  'GLO': '02',
  '9MOBILE': '03',
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

// Helper: Flutterwave Virtual Account Generator (Live Mode)
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

// Explicit API Endpoint to Generate or Retrieve Virtual Account
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

        // Return existing account if already created
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

        // Generate new virtual account via Flutterwave
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

        // Try generating account first
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

// Protected User Profile API (Handles both /profile and /api/user/profile)
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

// Core Purchase Controller (Handles ClubKonnect Logic)
const processPurchase = async (req, res) => {
  const { type, network, planId, phoneNumber, phone, amount } = req.body;
  const targetPhone = phoneNumber || phone;
  const userId = req.user.id;
  const numAmount = parseFloat(amount);

  if (!numAmount || numAmount <= 0) {
    return res.status(400).json({ success: false, message: "Valid purchase amount is required" });
  }

  try {
    // Check User Wallet Balance
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('balance')
      .eq('id', userId)
      .single();

    if (userErr || !user || user.balance < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance" });
    }

    const netCode = NETWORK_CODES[network?.toUpperCase()] || '01';
    const userID = process.env.CLUBKONNECT_USER_ID;
    const apiKey = process.env.CLUBKONNECT_API_KEY;
    const requestId = `CK_${Date.now()}`;

    let ckUrl = "";

    // Build ClubKonnect API Request URL
    const serviceType = type ? type.toUpperCase() : 'AIRTIME';
    if (serviceType === 'AIRTIME') {
      ckUrl = `https://www.nellobytesystems.com/APIBuy.asp?UserID=${userID}&APIKey=${apiKey}&MobileNetwork=${netCode}&Amount=${numAmount}&MobileNo=${targetPhone}&RequestID=${requestId}`;
    } else if (serviceType === 'DATA') {
      ckUrl = `https://www.nellobytesystems.com/APIBuyData.asp?UserID=${userID}&APIKey=${apiKey}&MobileNetwork=${netCode}&DataPlan=${planId}&MobileNo=${targetPhone}&RequestID=${requestId}`;
    } else {
      return res.status(400).json({ success: false, message: "Unsupported service type requested" });
    }

    // Call ClubKonnect API
    const response = await axios.get(ckUrl);
    const data = response.data;

    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      // Deduct User Wallet
      try {
        await supabase.rpc('decrement_balance', { user_id_input: userId, amount_input: numAmount });
      } catch (rpcErr) {
        await supabase.from('users').update({ balance: user.balance - numAmount }).eq('id', userId);
      }

      // Record Transaction
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: serviceType,
        amount: numAmount,
        status: 'SUCCESS',
        reference: data.orderid || requestId
      }]);

      return res.status(200).json({
        success: true,
        message: `${serviceType} purchase successful!`,
        orderId: data.orderid || requestId,
        data: data
      });

    } else {
      return res.status(400).json({
        success: false,
        message: data.substatus || data.status || "Transaction rejected by ClubKonnect"
      });
    }

  } catch (error) {
    console.error("ClubKonnect API Error:", error.message);
    return res.status(500).json({
      success: false,
      message: error.response?.data?.message || "Server error communicating with ClubKonnect provider."
    });
  }
};

// Generic VTU Routes
app.post('/api/vtu/buy', authMiddleware, processPurchase);

// Explicit Route Mapping to prevent 404 errors (Both /api/services/* and /api/vtu/*)
app.post('/api/services/airtime', authMiddleware, (req, res) => { req.body.type = 'AIRTIME'; return processPurchase(req, res); });
app.post('/api/vtu/buy-airtime', authMiddleware, (req, res) => { req.body.type = 'AIRTIME'; return processPurchase(req, res); });

app.post('/api/services/data', authMiddleware, (req, res) => { req.body.type = 'DATA'; return processPurchase(req, res); });
app.post('/api/vtu/buy-data', authMiddleware, (req, res) => { req.body.type = 'DATA'; return processPurchase(req, res); });

app.post('/api/services/cable', authMiddleware, (req, res) => { req.body.type = 'CABLE'; return processPurchase(req, res); });
app.post('/api/vtu/buy-cable', authMiddleware, (req, res) => { req.body.type = 'CABLE'; return processPurchase(req, res); });

app.post('/api/services/electricity', authMiddleware, (req, res) => { req.body.type = 'ELECTRICITY'; return processPurchase(req, res); });
app.post('/api/vtu/buy-electricity', authMiddleware, (req, res) => { req.body.type = 'ELECTRICITY'; return processPurchase(req, res); });

// Validate Meter or SmartCard Number
app.post('/api/vtu/validate', authMiddleware, async (req, res) => {
  const { service, customerId } = req.body;

  try {
    const userID = process.env.CLUBKONNECT_USER_ID;
    const apiKey = process.env.CLUBKONNECT_API_KEY;

    const response = await axios.get(
      `https://www.nellobytesystems.com/APIVerifyCableTV.asp?UserID=${userID}&APIKey=${apiKey}&TVNetwork=${service}&SmartCardNo=${customerId}`
    );

    return res.status(200).json({
      success: true,
      customerName: response.data.customer_name || "Verified Customer"
    });
  } catch (error) {
    return res.status(400).json({ success: false, message: "Invalid Account/Meter/SmartCard Number" });
  }
});

// Manual Wallet Funding API (Testing / Admin)
app.post("/fund-wallet", authMiddleware, async (req, res) => {
    const { amount } = req.body;
    const numAmount = parseFloat(amount);

    if (!numAmount || numAmount <= 0) {
        return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    try {
        const { data: user } = await supabase
            .from('users')
            .select('balance')
            .eq('id', req.user.id)
            .single();

        const newBalance = (user?.balance || 0) + numAmount;

        const { data: updatedUser } = await supabase
            .from('users')
            .update({ balance: newBalance })
            .eq('id', req.user.id)
            .select('id, fullname, email, balance')
            .single();

        const reference = `FUND_${Date.now()}`;
        await supabase
            .from('transactions')
            .insert([{
                user_id: req.user.id,
                type: "FUNDING",
                amount: numAmount,
                status: "SUCCESS",
                reference: reference
            }]);

        res.json({
            success: true,
            message: `Successfully funded wallet with ${numAmount}`,
            user: updatedUser
        });

    } catch (err) {
        console.error("Fund Wallet Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Automated Webhook Route for Flutterwave
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

// Export App for Vercel Serverless
module.exports = app;