require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    if (req.method === 'OPTIONS') return res.status(200).end();
    next();
});

app.use(express.json());

// Fallback values prevent top-level crashes if Vercel env vars are missing/loading
const supabaseUrl = process.env.SUPABASE_URL || "https://placeholder.supabase.co";
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || "placeholder-key";

const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || "your_super_secret_key_123";

const NETWORK_CODES = { 'MTN': '01', 'GLO': '02', '9MOBILE': '03', 'ETISALAT': '03', 'AIRTEL': '04' };

const ELECTRIC_CODES = {
  '01': '01', 'EKEDC': '01', 'EKO': '01', 'EKO ELECTRIC': '01', 'EKO ELECTRICITY': '01',
  '02': '02', 'IKEDC': '02', 'IKEJA': '02', 'IKEJA ELECTRIC': '02', 'IKEJA ELECTRICITY': '02',
  '03': '03', 'AEDC': '03', 'ABUJA': '03', 'ABUJA ELECTRIC': '03', 'ABUJA ELECTRICITY': '03',
  '04': '04', 'KEDC': '04', 'KEDCO': '04', 'KANO': '04', 'KANO ELECTRIC': '04',
  '05': '05', 'PHEDC': '05', 'PHED': '05', 'PORTHARCOURT': '05', 'PORT HARCOURT': '05',
  '06': '06', 'JEDC': '06', 'JED': '06', 'JOS': '06', 'JOS ELECTRIC': '06',
  '07': '07', 'IBEDC': '07', 'IBADAN': '07', 'IBADAN ELECTRIC': '07',
  '08': '08', 'KAEDC': '08', 'KAEDCO': '08', 'KADUNA': '08', 'KADUNA ELECTRIC': '08',
  '09': '09', 'EEDC': '09', 'ENUGU': '09', 'ENUGU ELECTRIC': '09',
  '10': '10', 'BEDC': '10', 'BENIN': '10', 'BENIN ELECTRIC': '10',
  '11': '11', 'YEDC': '11', 'YOLA': '11', 'YOLA ELECTRIC': '11',
  '12': '12', 'APLE': '12', 'ABA': '12', 'ABA ELECTRIC': '12'
};

const CABLE_CODES = { 'DSTV': '01', 'GOTV': '02', 'STARTIMES': '03', 'SHOWMAX': '04' };

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

// Root Health Route
app.get("/", (req, res) => {
    res.send("Welcome to TOURE VTU Backend API");
});

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

// Authentication Routes
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
                va_account_number: vaDetails.account_number, va_bank_name: vaDetails.bank_name, balance: 0
            }])
            .select('id, fullname, email, phone, balance, va_account_number, va_bank_name, created_at')
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

        res.json({
            success: true,
            message: "Login successful!",
            token,
            user: {
                id: user.id, fullname: user.fullname, email: user.email, phone: user.phone,
                balance: user.balance, va_account_number: user.va_account_number, va_bank_name: user.va_bank_name
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
            .select('id, fullname, email, phone, balance, va_account_number, va_bank_name, created_at')
            .eq('id', req.user.id)
            .single();

        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        res.json({ success: true, user });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
};

app.get("/profile", authMiddleware, getProfileHandler);
app.get("/api/user/profile", authMiddleware, getProfileHandler);

// Wallet Endpoints
app.get('/api/wallet', authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase.from('users').select('id, email, balance, va_account_number, va_bank_name').eq('id', req.user.id).single();
    if (error) return res.status(400).json({ success: false, message: error.message });

    return res.status(200).json({
      success: true,
      balance: user.balance || 0,
      wallet: { balance: user.balance || 0, email: user.email, va_account_number: user.va_account_number, va_bank_name: user.va_bank_name },
      virtual_account: { account_number: user.va_account_number, bank_name: user.va_bank_name }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Internal server error', error: err.message });
  }
});

// Electricity Verification
app.post('/api/services/electricity/verify', authMiddleware, async (req, res) => {
  try {
    const rawDisco = (req.body.disco || req.body.electricCompany || req.body.company || req.body.provider || '').toString().trim().toUpperCase();
    const meterNo = (req.body.meterNo || req.body.meterNumber || '').toString().replace(/[^0-9]/g, '');
    const meterType = (req.body.meterType || 'PREPAID').toString().toUpperCase();

    const discoCode = ELECTRIC_CODES[rawDisco] || (rawDisco.length === 1 ? `0${rawDisco}` : rawDisco);
    if (!discoCode) return res.status(400).json({ success: false, message: `Invalid electricity provider: "${rawDisco}"` });
    if (!meterNo || meterNo.length < 5) return res.status(400).json({ success: false, message: "Invalid meter number." });

    const meterTypeCode = (meterType === 'POSTPAID' || meterType === '02') ? '02' : '01';
    const ckUrl = `https://www.nellobytesystems.com/APIVerifyElectricityV1.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&ElectricCompany=${discoCode}&MeterNo=${meterNo}&MeterType=${meterTypeCode}`;

    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data || {};
    const name = data.customer_name || data.CustomerName || data.name;

    if (name && name !== 'INVALID_METERNO') {
      return res.status(200).json({ success: true, customerName: name, customer_name: name });
    } else {
      return res.status(400).json({ success: false, message: (name === 'INVALID_METERNO') ? "Invalid meter number." : "Could not verify meter number." });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: "Verification failed on server." });
  }
});

// Cable TV Verification
app.post('/api/services/cabletv/verify', authMiddleware, async (req, res) => {
  const provider = (req.body.provider || req.body.cableTV || '').toString().toUpperCase();
  const smartCardNo = (req.body.smartCardNo || req.body.smartcardno || '').toString().replace(/[^0-9]/g, '');

  if (!CABLE_CODES[provider]) return res.status(400).json({ success: false, message: "Unsupported cable TV provider." });
  if (!smartCardNo || smartCardNo.length < 5) return res.status(400).json({ success: false, message: "Invalid smart card / IUC number." });

  try {
    const providerCode = CABLE_CODES[provider];
    const ckUrl = `https://www.nellobytesystems.com/APIVerifyCableTVV1.0.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&cabletv=${providerCode}&smartcardno=${smartCardNo}`;

    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data;
    const name = data.customer_name || data.CustomerName || data.name;

    if (name) {
      return res.status(200).json({ success: true, customerName: name, customer_name: name });
    } else {
      return res.status(400).json({ success: false, message: "Could not verify smart card number." });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: "Verification service unavailable." });
  }
});

// 1. ALL TRANSACTIONS HISTORY ENDPOINT
app.get('/api/transactions', authMiddleware, async (req, res) => {
    try {
        const { data: transactions, error } = await supabase
            .from('transactions')
            .select('*')
            .eq('user_id', req.user.id)
            .order('created_at', { ascending: false });

        if (error) throw error;

        const formattedTransactions = (transactions || []).map(tx => ({
            id: tx.id,
            user_id: tx.user_id,
            type: tx.type || tx.transaction_type || 'VTU Transaction',
            transaction_type: tx.type || 'VTU Transaction',
            amount: parseFloat(tx.amount || 0),
            status: tx.status || 'SUCCESS',
            reference: tx.reference || tx.ref || '',
            token: tx.token || null,
            target: tx.target || null,
            date: tx.created_at || tx.date,
            created_at: tx.created_at
        }));

        return res.status(200).json({
            success: true,
            transactions: formattedTransactions,
            data: formattedTransactions
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: err.message });
    }
});

// 2. AIRTIME ENDPOINT
app.post(['/api/services/airtime', '/api/vtu/buy-airtime'], authMiddleware, async (req, res) => {
  const network = req.body.network || 'MTN';
  const targetPhone = (req.body.phone || req.body.phoneNumber || '').toString().replace(/[^0-9]/g, '');
  const numAmount = parseFloat(req.body.amount) || 0;
  const userId = req.user.id;

  if (!targetPhone || targetPhone.length < 11) return res.status(400).json({ success: false, message: "Invalid phone number." });
  if (numAmount < 50) return res.status(400).json({ success: false, message: "Minimum airtime is ₦50." });

  try {
    const { data: user } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (!user || parseFloat(user.balance) < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    const netCode = NETWORK_CODES[network.toString().toUpperCase()] || '01';
    const requestId = `CK_AIR_${Date.now()}`;
    const ckUrl = `https://www.nellobytesystems.com/APIBuy.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&MobileNetwork=${netCode}&Amount=${numAmount}&MobileNo=${targetPhone}&RequestID=${requestId}`;

    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data;
    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      const newBalance = parseFloat(user.balance) - numAmount;
      await supabase.from('users').update({ balance: newBalance }).eq('id', userId);
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'AIRTIME',
        amount: numAmount,
        status: 'SUCCESS',
        reference: requestId,
        target: targetPhone
      }]);

      return res.status(200).json({ success: true, message: "Airtime purchase successful!", newBalance });
    } else {
      return res.status(400).json({ success: false, message: `Provider Error: ${data.substatus || data.status}` });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// 3. DATA ENDPOINT
app.post(['/api/services/data', '/api/vtu/buy-data'], authMiddleware, async (req, res) => {
  const network = req.body.network || 'MTN';
  const targetPhone = (req.body.phone || req.body.phoneNumber || '').toString().replace(/[^0-9]/g, '');
  const dataPlan = req.body.planId || req.body.data_plan || req.body.plan;
  const numAmount = parseFloat(req.body.amount) || 0;
  const userId = req.user.id;

  if (!targetPhone || targetPhone.length < 11) return res.status(400).json({ success: false, message: "Invalid phone number." });
  if (!dataPlan) return res.status(400).json({ success: false, message: "Data plan code is required." });

  try {
    const { data: user } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (!user || parseFloat(user.balance) < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    const netCode = NETWORK_CODES[network.toString().toUpperCase()] || '01';
    const requestId = `CK_DATA_${Date.now()}`;
    const ckUrl = `https://www.nellobytesystems.com/APIBuyData.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&MobileNetwork=${netCode}&DataPlan=${dataPlan}&MobileNo=${targetPhone}&RequestID=${requestId}`;

    const response = await axios.get(ckUrl, { timeout: 15000 });
    const data = response.data;
    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      const newBalance = parseFloat(user.balance) - numAmount;
      await supabase.from('users').update({ balance: newBalance }).eq('id', userId);
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'DATA',
        amount: numAmount,
        status: 'SUCCESS',
        reference: requestId,
        target: targetPhone
      }]);

      return res.status(200).json({ success: true, message: "Data purchase successful!", newBalance });
    } else {
      return res.status(400).json({ success: false, message: `Provider Error: ${data.substatus || data.status}` });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// 4. ELECTRICITY ENDPOINT
app.post(['/api/services/electricity', '/api/vtu/buy-electricity'], authMiddleware, async (req, res) => {
  const rawDisco = (req.body.disco || req.body.company || '').toString().trim().toUpperCase();
  const meterType = (req.body.meterType || 'PREPAID').toString().toUpperCase();
  const meterNo = (req.body.meterNo || req.body.meterNumber || '').toString().replace(/[^0-9]/g, '');
  const targetPhone = (req.body.phone || '').toString().replace(/[^0-9]/g, '');
  const numAmount = parseFloat(req.body.amount) || 0;
  const userId = req.user.id;

  const discoCode = ELECTRIC_CODES[rawDisco] || (rawDisco.length === 1 ? `0${rawDisco}` : rawDisco);
  if (!discoCode) return res.status(400).json({ success: false, message: "Unsupported electricity company." });

  try {
    const { data: user } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (!user || parseFloat(user.balance) < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    const meterTypeCode = (meterType === 'POSTPAID' || meterType === '02') ? '02' : '01';
    const requestId = `CK_ELEC_${Date.now()}`;
    const ckUrl = `https://www.nellobytesystems.com/APIElectricityV1.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&ElectricCompany=${discoCode}&MeterType=${meterTypeCode}&MeterNo=${meterNo}&Amount=${numAmount}&PhoneNo=${targetPhone}&RequestID=${requestId}`;

    const response = await axios.get(ckUrl, { timeout: 20000 });
    const data = response.data;
    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      const newBalance = parseFloat(user.balance) - numAmount;
      const meterToken = data.metertoken || data.token || data.meter_token || null;

      await supabase.from('users').update({ balance: newBalance }).eq('id', userId);
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'ELECTRICITY',
        amount: numAmount,
        status: 'SUCCESS',
        reference: requestId,
        token: meterToken,
        target: meterNo
      }]);

      return res.status(200).json({ success: true, message: "Electricity payment successful!", token: meterToken, newBalance });
    } else {
      return res.status(400).json({ success: false, message: `Provider Error: ${data.substatus || data.status}` });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// 5. CABLE TV ENDPOINT
app.post(['/api/services/cabletv', '/api/vtu/buy-cabletv'], authMiddleware, async (req, res) => {
  const provider = (req.body.provider || req.body.cableTV || '').toString().toUpperCase();
  const smartCardNo = (req.body.smartCardNo || req.body.iucNumber || '').toString().replace(/[^0-9]/g, '');
  const packageCode = req.body.packageCode || req.body.package;
  const targetPhone = (req.body.phone || '').toString().replace(/[^0-9]/g, '');
  const numAmount = parseFloat(req.body.amount) || 0;
  const userId = req.user.id;

  if (!CABLE_CODES[provider]) return res.status(400).json({ success: false, message: "Unsupported cable TV provider." });

  try {
    const { data: user } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (!user || parseFloat(user.balance) < numAmount) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
    }

    const providerCode = CABLE_CODES[provider];
    const requestId = `CK_CTV_${Date.now()}`;
    const ckUrl = `https://www.nellobytesystems.com/APICableTVV1.asp?UserID=${process.env.CLUBKONNECT_USER_ID}&APIKey=${process.env.CLUBKONNECT_API_KEY}&CableTV=${providerCode}&Package=${packageCode}&SmartCardNo=${smartCardNo}&PhoneNo=${targetPhone}&RequestID=${requestId}`;

    const response = await axios.get(ckUrl, { timeout: 20000 });
    const data = response.data;
    const isSuccess = data.status === 'ORDER_RECEIVED' || data.status === 'ORDER_COMPLETED' || data.status === '00';

    if (isSuccess) {
      const newBalance = parseFloat(user.balance) - numAmount;
      await supabase.from('users').update({ balance: newBalance }).eq('id', userId);
      await supabase.from('transactions').insert([{
        user_id: userId,
        type: 'CABLETV',
        amount: numAmount,
        status: 'SUCCESS',
        reference: requestId,
        target: smartCardNo
      }]);

      return res.status(200).json({ success: true, message: "Cable TV subscription successful!", newBalance });
    } else {
      return res.status(400).json({ success: false, message: `Provider Error: ${data.substatus || data.status}` });
    }
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// 6. WALLET FUNDING WEBHOOK (ADD FUND)
app.post('/webhook/flutterwave', async (req, res) => {
    const signature = req.headers['verif-hash'] || req.headers['flutterwave-signature'];
    if (process.env.FLW_SECRET_HASH && signature !== process.env.FLW_SECRET_HASH) {
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
            const { data: existingTx } = await supabase.from('transactions').select('id').eq('reference', txRef).maybeSingle();
            if (existingTx) return;

            let userQuery = supabase.from('users').select('id, balance');
            if (accountNumber) userQuery = userQuery.eq('va_account_number', accountNumber);
            else userQuery = userQuery.ilike('email', customerEmail);

            const { data: user } = await userQuery.maybeSingle();
            if (!user) return;

            const currentBalance = parseFloat(user.balance || 0);
            const newBalance = currentBalance + amountPaid;
            
            await supabase.from('users').update({ balance: newBalance }).eq('id', user.id);
            await supabase.from('transactions').insert([{
                user_id: user.id,
                type: 'WALLET_FUNDING',
                amount: amountPaid,
                status: 'SUCCESS',
                reference: txRef,
                target: 'Wallet Funding'
            }]);

        } catch (err) {
            console.error("Webhook Processing Error:", err.message);
        }
    }
});

// VERCEL SERVERLESS EXPORT DEFINITION
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

// THIS SOLVES "No exports found in module /var/task/server.js":
module.exports = app;