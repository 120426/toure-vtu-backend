require("dotenv").config();
const express = require("express");
const cors = require("cors"); // 1. CORS imported
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// Enable CORS & JSON Body Parsing
app.use(cors()); // 2. Enable CORS for all incoming requests
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

// Helper: Flutterwave Virtual Account Generator
async function generateVirtualAccount(user) {
    try {
        const response = await axios.post(
            'https://api.flutterwave.com/v3/virtual-account-numbers',
            {
                email: user.email,
                is_permanent: true,
                currency: "XOF", // Updated currency to CFA Franc (XOF)
                firstname: user.fullname ? user.fullname.split(' ')[0] : 'User',
                lastname: user.fullname ? user.fullname.split(' ')[1] : 'Toure',
                phonenumber: user.phone,
                narration: `${user.fullname} - Toure Data Wallet`,
                bvn: user.bvn || "22222222222" 
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        if (response.data.status === 'success') {
            return {
                account_number: response.data.data.account_number,
                bank_name: response.data.data.bank_name
            };
        }
    } catch (error) {
        console.error('Flutterwave VA Error:', error.response?.data || error.message);
        return null;
    }
}

// Register API
app.post("/api/auth/register", async (req, res) => {
    const { fullname, email, password, phone } = req.body;

    if (!fullname || !email || !password) {
        return res.status(400).json({ success: false, message: "Fullname, email, and password are required" });
    }

    try {
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ success: false, message: "Email is already registered" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Optional: Generate Virtual Account upon registration
        const vaDetails = await generateVirtualAccount({ fullname, email, phone });
        const vaNumber = vaDetails ? vaDetails.account_number : null;
        const vaBank = vaDetails ? vaDetails.bank_name : null;

        const { data: newUser, error } = await supabase
            .from('users')
            .insert([{
                fullname,
                email,
                password: hashedPassword,
                phone: phone || null,
                va_account_number: vaNumber,
                va_bank_name: vaBank,
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
            .single();

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
      .select('id, email, balance')
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
        email: user.email
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
    // 1. Check User Wallet Balance
    const { data: user } = await supabase
      .from('users')
      .select('balance')
      .eq('id', userId)
      .single();

    if (!user || user.balance < amount) {
      return res.status(400).json({ success: false, message: "Insufficient balance" });
    }

    // 2. Deduct Balance (Pre-Debit)
    await supabase
      .from('users')
      .update({ balance: user.balance - amount })
      .eq('id', userId);

    // 3. Call External VTU Provider API
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

    // 4. Record Successful Transaction
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
    // 5. Refund user balance if VTU Provider fails
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

    if (!amount || amount <= 0) {
        return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    try {
        const { data: user } = await supabase
            .from('users')
            .select('balance')
            .eq('id', req.user.id)
            .single();

        const newBalance = (user?.balance || 0) + parseFloat(amount);

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
                amount: amount,
                status: "SUCCESS",
                reference: reference
            }]);

        res.json({
            success: true,
            message: `Successfully funded wallet with ${amount}`,
            user: updatedUser
        });

    } catch (err) {
        console.error("Fund Wallet Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Automated Webhook Route for Flutterwave
app.post('/webhook/flutterwave', async (req, res) => {
    const signature = req.headers['verif-hash'];
    if (!signature || signature !== process.env.FLW_SECRET_HASH) {
        return res.status(401).send('Unauthorized webhook call');
    }

    const payload = req.body;

    if (payload.event === 'charge.completed' && payload.data.status === 'successful') {
        const customerEmail = payload.data.customer.email;
        const amountPaid = payload.data.amount;
        const txRef = payload.data.tx_ref || `FLW_${payload.data.id}`;

        try {
            // Duplicate Check
            const { data: existingTx } = await supabase
                .from('transactions')
                .select('id')
                .eq('reference', txRef)
                .single();

            if (existingTx) {
                return res.status(200).send('Transaction already processed');
            }

            const { data: user } = await supabase
                .from('users')
                .select('*')
                .eq('email', customerEmail)
                .single();
            
            if (user) {
                await supabase
                    .from('users')
                    .update({ balance: user.balance + amountPaid })
                    .eq('id', user.id);

                await supabase
                    .from('transactions')
                    .insert([{
                        user_id: user.id,
                        type: 'FUND_WALLET',
                        amount: amountPaid,
                        status: 'SUCCESS',
                        reference: txRef
                    }]);

                console.log(`Successfully credited ${amountPaid} to ${customerEmail}`);
            }
        } catch (err) {
            console.error('Webhook processing error:', err);
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