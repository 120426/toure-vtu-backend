const express = require('express');
const router = express.Router();
const axios = require('axios');
const { supabase } = require('../db');

router.post('/api/services/sms', async (req, res) => {
  const { sender, countryCode, phone, message, userId } = req.body;

  if (!sender || !phone || !message || !userId) {
    return res.status(400).json({ success: false, message: "Missing required parameters" });
  }

  try {
    // 1. Sanitize local phone number to E.164 format
    let cleanPhone = phone.replace(/\D/g, '');
    if (cleanPhone.startsWith('0')) {
      cleanPhone = cleanPhone.substring(1);
    }
    const cleanCountry = countryCode ? countryCode.replace(/\+/g, '') : '234';
    const fullRecipient = `${cleanCountry}${cleanPhone}`;

    // 2. Calculate SMS Pages and Cost (Unicode aware)
    const isUnicode = /[^\u0000-\u007F]/.test(message);
    const charLimit = isUnicode ? 70 : 160;
    const multiLimit = isUnicode ? 67 : 153;
    const pages = message.length > charLimit ? Math.ceil(message.length / multiLimit) : 1;
    const totalCost = pages * 4.00; // ₦4.00 per page rate

    const reference = `SMS-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    // 3. Send SMS via Termii FIRST before deducting
    const termiiResponse = await axios.post('https://api.ng.termii.com/api/sms/send', {
      to: fullRecipient,
      from: sender,
      sms: message,
      type: "plain",
      channel: "generic", // Use 'dnd' or 'generic' depending on your Termii route setup
      api_key: process.env.TERMII_API_KEY
    });

    if (!termiiResponse.data || termiiResponse.data.code !== 'ok') {
      return res.status(502).json({ 
        success: false, 
        message: termiiResponse.data.message || "SMS provider failed to process request" 
      });
    }

    // 4. Atomic Balance Deduction & Transaction Logging via Postgres RPC
    const { data: success, error: rpcError } = await supabase.rpc('deduct_sms_balance', {
      p_user_id: userId,
      p_cost: totalCost,
      p_recipient: fullRecipient,
      p_sender: sender,
      p_pages: pages,
      p_ref: reference
    });

    if (rpcError || !success) {
      return res.status(400).json({ 
        success: false, 
        message: "Insufficient balance or transaction execution failed" 
      });
    }

    return res.json({ 
      success: true, 
      message: "SMS dispatched and billed successfully",
      reference 
    });

  } catch (err) {
    const errorDetails = err.response?.data?.message || err.message;
    return res.status(500).json({ success: false, message: errorDetails });
  }
});

module.exports = router;
