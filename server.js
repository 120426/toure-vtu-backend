require("dotenv").config();
const db = require("./db");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const authMiddleware = require("./authMiddleware");

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_123";

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
                currency: "NGN",
                firstname: user.fullname.split(' ')[0] || 'User',
                lastname: user.fullname.split(' ')[1] || 'Toure',
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
app.post("/register", async (req, res) => {
    const { fullname, email, password, phone } = req.body;

    if (!fullname || !email || !password) {
        return res.status(400).json({ success: false, message: "Fullname, email, and password are required" });
    }

    try {
        const userCheck = await db.query("SELECT id FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ success: false, message: "Email is already registered" });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Optional: Generate Virtual Account upon registration
        const vaDetails = await generateVirtualAccount({ fullname, email, phone });
        const vaNumber = vaDetails ? vaDetails.account_number : null;
        const vaBank = vaDetails ? vaDetails.bank_name : null;

        const newUser = await db.query(
            "INSERT INTO users (fullname, email, password, phone, va_account_number, va_bank_name) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, fullname, email, phone, balance, va_account_number, va_bank_name, created_at",
            [fullname, email, hashedPassword, phone || null, vaNumber, vaBank]
        );

        res.status(201).json({
            success: true,
            message: "User registered successfully!",
            user: newUser.rows[0]
        });

    } catch (err) {
        console.error("Register Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Login API
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const userQuery = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userQuery.rows.length === 0) {
            return res.status(400).json({ success: false, message: "Invalid email or password" });
        }

        const user = userQuery.rows[0];

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
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Middleware to authenticate JWT token
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token missing' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Protected Profile API
app.get("/profile", authMiddleware, async (req, res) => {
    try {
        const userQuery = await db.query(
            "SELECT id, fullname, email, phone, balance, va_account_number, va_bank_name, created_at FROM users WHERE id = $1",
            [req.user.id]
        );

        if (userQuery.rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        res.json({
            success: true,
            user: userQuery.rows[0]
        });
    } catch (err) {
        console.error("Profile Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Manual Wallet Funding API (Testing / Admin)
app.post("/fund-wallet", authMiddleware, async (req, res) => {
    const { amount } = req.body;

    if (!amount || amount <= 0) {
        return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    try {
        const updatedUser = await db.query(
            "UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING id, fullname, email, balance",
            [amount, req.user.id]
        );

        const reference = `FUND_${Date.now()}`;
        await db.query(
            "INSERT INTO transactions (user_id, type, amount, status, reference) VALUES ($1, $2, $3, $4, $5)",
            [req.user.id, "FUNDING", amount, "SUCCESS", reference]
        );

        res.json({
            success: true,
            message: `Successfully funded wallet with ${amount}`,
            user: updatedUser.rows[0]
        });

    } catch (err) {
        console.error("Fund Wallet Error:", err.message);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// Buy Airtime / Data API
app.post("/buy-vtu", authMiddleware, async (req, res) => {
    const { type, network, phone, amount } = req.body;

    if (!type || !network || !phone || !amount || amount <= 0) {
        return res.status(400).json({ success: false, message: "Please provide all required transaction details" });
    }

    try {
        const userQuery = await db.query("SELECT balance FROM users WHERE id = $1", [req.user.id]);
        const currentBalance = parseFloat(userQuery.rows[0].balance);

        if (currentBalance < amount) {
            return res.status(400).json({ success: false, message: "Insufficient wallet balance" });
        }

        const newBalance = currentBalance - amount;
        await db.query("UPDATE users SET balance = $1 WHERE id = $2", [newBalance, req.user.id]);

        const reference = `VTU_${Date.now()}`;
        const newTx = await db.query(
            "INSERT INTO transactions (user_id, type, amount, status, reference) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [req.user.id, type.toUpperCase(), amount, "SUCCESS", reference]
        );

        res.json({
            success: true,
            message: `${type} purchase of ${amount} successful for ${phone} (${network})`,
            newBalance,
            transaction: newTx.rows[0]
        });

    } catch (err) {
        console.error("VTU Error:", err.message);
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
            // Duplicate Check (Prevent double funding)
            const existingTx = await db.query('SELECT id FROM transactions WHERE reference = $1', [txRef]);
            if (existingTx.rows.length > 0) {
                return res.status(200).send('Transaction already processed');
            }

            const userRes = await db.query('SELECT * FROM users WHERE email = $1', [customerEmail]);
            
            if (userRes.rows.length > 0) {
                const user = userRes.rows[0];

                await db.query(
                    'UPDATE users SET balance = balance + $1 WHERE id = $2',
                    [amountPaid, user.id]
                );

                await db.query(
                    `INSERT INTO transactions (user_id, type, amount, status, reference) 
                     VALUES ($1, $2, $3, $4, $5)`,
                    [user.id, 'FUND_WALLET', amountPaid, 'SUCCESS', txRef]
                );

                console.log(`Successfully credited ₦${amountPaid} to ${customerEmail}`);
            }
        } catch (err) {
            console.error('Webhook processing error:', err);
        }
    }

    res.status(200).send('Webhook Received');
});

// Export App for Serverless / Local Run
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

module.exports = app;

// Get User Wallet & History
app.get('/api/wallet', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Fetch wallet balance from Supabase/Database
    const { data: user, error } = await supabase
      .from('users')
      .select('balance, account_number, account_name')
      .eq('id', userId)
      .single();

    if (error) throw error;

    // Fetch user transactions
    const { data: transactions } = await supabase
      .from('transactions')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    return res.status(200).json({
      success: true,
      balance: user.balance,
      virtualAccount: {
        accountNumber: user.account_number,
        accountName: user.account_name
      },
      transactions: transactions || []
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Buy Airtime / Data / Cable / Electricity
app.post('/api/vtu/buy', authenticateUser, async (req, res) => {
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
app.post('/api/vtu/validate', authenticateUser, async (req, res) => {
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