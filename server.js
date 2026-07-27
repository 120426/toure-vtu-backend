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