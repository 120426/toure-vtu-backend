// routes/sms.js
const express = require('express');
const router = express.Router();
const axios = require('axios');
const { supabase } = require('../db');

router.post('/api/services/sms', async (req, res) => {
  const { sender, countryCode, phone, message, userId } = req.body;

  try {
    // 1. Sanitize local phone number to International E.164 format
    let cleanPhone = phone.replace(/\D/g, '');
    if (cleanPhone.startsWith('0')) {
      cleanPhone = cleanPhone.substring(1);
    }
    const fullRecipient = (countryCode + cleanPhone).replace('+', '');

    // 2. Calculate SMS Pages and Cost
    const pages = message.length > 160 ? Math.ceil(message.length / 153) : 1;
    const totalCost = pages * 4.00; // ₦4.00 per page rate

    // 3. Verify and Deduct Wallet Balance
    const { data: user } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (!user || user.balance < totalCost) {
      return res.status(400).json({ success: false, message: "Insufficient wallet balance" });
    }

    await supabase.from('users').update({ balance: user.balance - totalCost }).eq('id', userId);

    // 4. Dispatch SMS Payload to SMS Gateway
    const response = await axios.post('https://api.ng.termii.com/api/sms/send', {
      to: fullRecipient,
      from: sender,
      sms: message,
      type: "plain",
      channel: "dnd",
      api_key: process.env.TERMII_API_KEY
    });

    // 5. Log Transaction Record
    await supabase.from('transactions').insert({
      user_id: userId,
      type: 'SINGLE_SMS',
      amount: totalCost,
      reference: 'SMS-' + Date.now(),
      status: 'SUCCESS',
      metadata: { recipient: fullRecipient, sender, pages }
    });

    return res.json({ success: true, message: "SMS dispatched successfully" });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

module.exports = router;
