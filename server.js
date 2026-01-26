const express = require('express');
const cors = require('cors');
const CryptoJS = require('crypto-js');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

// Encryption key - in production, use environment variable
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'alltalk-secure-key-2024';
const API_BASE = 'https://api.alltalkpro.com/api/v1';
const APP_URL = 'https://mobile-alltalk.com';

// Store registered users (in production, use a database)
const registeredUsers = {};

// Encrypt password
function encrypt(text) {
    return CryptoJS.AES.encrypt(text, ENCRYPTION_KEY).toString();
}

// Decrypt password
function decrypt(ciphertext) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// AllTalk API call helper
async function apiCall(endpoint, accessToken, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    try {
        const response = await fetch(url, { ...options, headers });
        return await response.json();
    } catch (err) {
        console.error('API call error:', err.message);
        return { error: err.message };
    }
}

// Login user and get access token
async function loginUser(email, password) {
    try {
        const response = await fetch(`${API_BASE}/auth/sign-in`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, remember_me: true })
        });
        
        const data = await response.json();
        
        if (data.data?.tokens?.access_token) {
            return {
                accessToken: data.data.tokens.access_token,
                user: data.data.user
            };
        }
        return null;
    } catch (err) {
        console.error('Login error:', err.message);
        return null;
    }
}

// Refresh user token
async function refreshUserToken(userId) {
    const user = registeredUsers[userId];
    if (!user) return null;
    
    const password = decrypt(user.encryptedPassword);
    const loginResult = await loginUser(user.email, password);
    
    if (loginResult) {
        user.accessToken = loginResult.accessToken;
        user.tokenExpiry = Date.now() + (23 * 60 * 60 * 1000);
        return user.accessToken;
    }
    return null;
}

// Get valid access token
async function getValidToken(userId) {
    const user = registeredUsers[userId];
    if (!user) return null;
    
    if (!user.accessToken || Date.now() > user.tokenExpiry) {
        return await refreshUserToken(userId);
    }
    return user.accessToken;
}

// Check for new messages and send batched SMS alert
async function checkUserMessages(userId) {
    const user = registeredUsers[userId];
    if (!user || !user.smsAlertNumber) return;
    
    try {
        const accessToken = await getValidToken(userId);
        if (!accessToken) {
            console.log(`[${userId}] Failed to get access token`);
            return;
        }
        
        // Get conversations
        const response = await apiCall('/conversations?page=1&limit=50&order=DESC', accessToken);
        
        if (!response.data?.results) {
            console.log(`[${userId}] No conversations found`);
            return;
        }
        
        const conversations = response.data.results;
        const newMessages = [];
        
        // Collect all new messages
        for (const conv of conversations) {
            // Skip if this is the alert number (don't notify about own alerts)
            if (conv.contact?.phone_number?.replace(/\D/g, '') === user.smsAlertNumber.replace(/\D/g, '')) continue;
            
            // Create unique message key
            const messageKey = `${conv.id}-${conv.last_message_at}-${conv.last_message}`;
            
            // Initialize lastMessageIds if needed
            if (!user.lastMessageIds) user.lastMessageIds = new Set();
            
            // Check if this is a new message
            if (!user.lastMessageIds.has(messageKey) && conv.last_message) {
                newMessages.push(conv);
                user.lastMessageIds.add(messageKey);
            }
        }
        
        // Keep set from growing too large
        if (user.lastMessageIds.size > 200) {
            const arr = Array.from(user.lastMessageIds);
            user.lastMessageIds = new Set(arr.slice(-100));
        }
        
        // Send ONE batched SMS if there are new messages
        if (newMessages.length > 0) {
            console.log(`[${userId}] ${newMessages.length} new message(s)`);
            await sendBatchedSmsAlert(userId, newMessages, accessToken);
        }
    } catch (err) {
        console.log(`[${userId}] Error checking messages:`, err.message);
    }
}

// Send batched SMS alert
async function sendBatchedSmsAlert(userId, newMessages, accessToken) {
    const user = registeredUsers[userId];
    if (!user) return;
    
    try {
        let alertText;
        
        if (newMessages.length === 1) {
            // Single message - show preview
            const conv = newMessages[0];
            const contact = conv.contact || {};
            const name = contact.first_name 
                ? `${contact.first_name} ${contact.last_name || ''}`.trim() 
                : formatPhone(contact.phone_number) || 'Unknown';
            const messagePreview = (conv.last_message || '').substring(0, 70);
            
            // Format: "AllTalk: Name - Message preview\n\nOpen AllTalk\nURL"
            alertText = `AllTalk: ${name} - ${messagePreview}\n\nOpen AllTalk\n${APP_URL}`;
        } else {
            // Multiple messages - show count only
            // Format: "AllTalk: You have X new messages\n\nOpen AllTalk\nURL"
            alertText = `AllTalk: You have ${newMessages.length} new messages\n\nOpen AllTalk\n${APP_URL}`;
        }
        
        // Find conversation with alert phone number
        const alertConvResponse = await apiCall(`/conversations?search=${user.smsAlertNumber}&limit=5`, accessToken);
        
        let alertConv = null;
        if (alertConvResponse.data?.results) {
            alertConv = alertConvResponse.data.results.find(c => 
                c.contact?.phone_number?.replace(/\D/g, '') === user.smsAlertNumber.replace(/\D/g, '')
            );
        }
        
        if (!alertConv) {
            console.log(`[${userId}] Alert conversation not found for ${user.smsAlertNumber}`);
            return;
        }
        
        // Determine which phone number to send FROM
        let sendFromId = user.smsAlertFromNumberId || alertConv.last_phone_number_id || newMessages[0]?.last_phone_number_id;
        
        if (!sendFromId) {
            console.log(`[${userId}] No phone number available to send SMS alert`);
            return;
        }
        
        // Send the SMS
        const sendResponse = await apiCall(`/conversations/${alertConv.id}/messages`, accessToken, {
            method: 'POST',
            body: JSON.stringify({
                phone_number_id: sendFromId,
                contact_id: alertConv.contact_id || alertConv.contact?.id,
                type: 'SMS',
                message: alertText,
                usha_dnc_override: true
            })
        });
        
        if (sendResponse.message === 'Success' || sendResponse.message?.includes('message_sent') || sendResponse.data) {
            console.log(`[${userId}] SMS alert sent to ${user.smsAlertNumber} (${newMessages.length} message(s))`);
        } else {
            console.log(`[${userId}] SMS alert failed:`, sendResponse.message);
        }
    } catch (err) {
        console.log(`[${userId}] SMS alert error:`, err.message);
    }
}

// Format phone number for display
function formatPhone(phone) {
    if (!phone) return '';
    const c = phone.replace(/\D/g, '');
    if (c.length === 10) return `(${c.slice(0,3)}) ${c.slice(3,6)}-${c.slice(6)}`;
    return phone;
}

// API Endpoints

// Register user for background alerts
app.post('/api/register', async (req, res) => {
    const { email, password, smsAlertNumber, smsAlertFromNumberId } = req.body;
    
    if (!email || !password || !smsAlertNumber) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }
    
    try {
        // Verify credentials by logging in
        const loginResult = await loginUser(email, password);
        
        if (!loginResult) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        const userId = loginResult.user.id;
        
        // Store user (encrypt password)
        registeredUsers[userId] = {
            email,
            encryptedPassword: encrypt(password),
            smsAlertNumber: smsAlertNumber.replace(/\D/g, ''),
            smsAlertFromNumberId,
            accessToken: loginResult.accessToken,
            tokenExpiry: Date.now() + (23 * 60 * 60 * 1000),
            lastMessageIds: new Set()
        };
        
        console.log(`User registered: ${email} (${userId})`);
        
        res.json({ success: true, message: 'Background alerts enabled', userId });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Unregister user
app.post('/api/unregister', (req, res) => {
    const { userId } = req.body;
    
    if (userId && registeredUsers[userId]) {
        delete registeredUsers[userId];
        console.log(`User unregistered: ${userId}`);
        res.json({ success: true, message: 'Background alerts disabled' });
    } else {
        res.status(404).json({ success: false, message: 'User not found' });
    }
});

// Check if user is registered
app.get('/api/status/:userId', (req, res) => {
    const { userId } = req.params;
    const isRegistered = !!registeredUsers[userId];
    res.json({ registered: isRegistered });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'running', 
        registeredUsers: Object.keys(registeredUsers).length,
        uptime: process.uptime()
    });
});

// Main polling loop - check all users every 15 seconds
setInterval(async () => {
    const userIds = Object.keys(registeredUsers);
    for (const userId of userIds) {
        await checkUserMessages(userId);
    }
}, 15000);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`AllTalk Notification Server running on port ${PORT}`);
    console.log(`Polling interval: 15 seconds`);
});
