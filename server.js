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

// Protected Profile API
app.get("/profile", authMiddleware, async (req, res) => {
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
            user
        });
    } catch (err) {
        console.error("Profile Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

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
      wallet: {
        balance: user.balance || 0,
        email: user.email,
        va_account_number: user.va_account_number,
        va_bank_name: user.va_bank_name
      }
    });
  } catch (err) {
    console.error('Wallet Route Server Error:', err.message);
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
});

// Buy Airtime / Data / Cable / Electricity
app.post('/api/vtu/buy', authMiddleware, async (req, res) => {
  const { type, network, planId, phoneNumber, amount } = req.body;
  const userId = req.user.id;

  try {
    const { data: user } = await supabase
      .from('users')
      .select('balance')
      .eq('id', userId)
      .single();

    if (!user || user.balance < amount) {
      return res.status(400).json({ success: false, message: "Insufficient balance" });
    }

    await supabase
      .from('users')
      .update({ balance: user.balance - amount })
      .eq('id', userId);

    const vtuResponse = await axios.post(
      'https://vtu-provider-domain.com/api/vending',
      {
        network: network,
        plan: planId,
        phone: phoneNumber,
        amount: amount,
        service_type: type
      },
      {
        headers: { 'Authorization': `Bearer ${process.env.VTU_PROVIDER_API_KEY}` }
      }
    );

    await supabase.from('transactions').insert([{
      user_id: userId,
      type: type,
      amount: amount,
      status: 'SUCCESS',
      reference: vtuResponse.data.reference || `TXN_${Date.now()}`
    }]);

    return res.status(200).json({
      success: true,
      message: `${type.toUpperCase()} purchase successful!`,
      data: vtuResponse.data
    });

  } catch (error) {
    await supabase.rpc('increment_balance', { user_id_input: userId, amount_input: amount });
    
    return res.status(500).json({
      success: false,
      message: "Transaction failed. Your wallet has been refunded."
    });
  }
});

// Validate Meter or SmartCard Number
app.post('/api/vtu/validate', authMiddleware, async (req, res) => {
  const { service, customerId } = req.body;

  try {
    const response = await axios.post(
      'https://vtu-provider-domain.com/api/merchant-verify',
      { service, customerId },
      { headers: { 'Authorization': `Bearer ${process.env.VTU_PROVIDER_API_KEY}` } }
    );

    return res.status(200).json({
      success: true,
      customerName: response.data.customer_name
    });
  } catch (error) {
    return res.status(400).json({ success: false, message: "Invalid Account/Meter Number" });
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
    // Check signature from either verif-hash or flutterwave-signature header
    const signature = req.headers['verif-hash'] || req.headers['flutterwave-signature'];

    // If FLW_SECRET_HASH is set, verify it matches
    if (process.env.FLW_SECRET_HASH && signature !== process.env.FLW_SECRET_HASH) {
        console.log("❌ Webhook signature mismatch! Received:", signature);
        return res.status(401).send('Unauthorized webhook call');
    }

    const payload = req.body;
    console.log("📥 Incoming Webhook Event:", payload.event);

    if (payload.event === 'charge.completed' && payload.data.status === 'successful') {
        const rawEmail = payload.data.customer?.email || "";
        const customerEmail = rawEmail.trim().toLowerCase();
        const amountPaid = parseFloat(payload.data.amount);
        const txRef = payload.data.tx_ref || `FLW_${payload.data.id}`;

        console.log(`Processing Payment: Email [${customerEmail}], Amount [${amountPaid}], Ref [${txRef}]`);

        try {
            // 1. Prevent duplicate transaction entries
            const { data: existingTx } = await supabase
                .from('transactions')
                .select('id')
                .eq('reference', txRef)
                .maybeSingle();

            if (existingTx) {
                console.log("⚠️ Transaction already processed previously.");
                return res.status(200).send('Transaction already processed');
            }

            // 2. Find matching user in database
            const { data: user, error: userErr } = await supabase
                .from('users')
                .select('id, fullname, email, balance')
                .ilike('email', customerEmail)
                .maybeSingle();

            if (userErr || !user) {
                console.log(`❌ No user found matching email: "${customerEmail}"`);
                return res.status(200).send('User not found');
            }

            console.log(`User found: ${user.fullname} (Current Balance: ${user.balance})`);

            // 3. Increment User Balance (RPC with Fallback)
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
                    return res.status(500).send("Database update failed");
                }
            }

            // 4. Record Transaction History
            await supabase
                .from('transactions')
                .insert([{
                    user_id: user.id,
                    type: 'FUND_WALLET',
                    amount: amountPaid,
                    status: 'SUCCESS',
                    reference: txRef
                }]);

            console.log(`✅ SUCCESS: Credited ${amountPaid} to ${customerEmail}`);

        } catch (err) {
            console.error('Webhook processing error:', err.message);
        }
    }

    res.status(200).send('Webhook Received');
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