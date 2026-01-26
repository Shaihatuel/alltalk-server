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
const APP_URL = 'https://adorable-monstera-b10a64.netlify.app';

// Store registered users (in production, use a database)
// Format: { odhi0294 { email, encryptedPassword, smsAlertNumber, smsAlertFromNumberId, accessToken, tokenExpiry, lastMessageIds } }
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
    const headers = {
        'Content-Type': 'application/json',
        'Accept-Language': 'en',
        ...options.headers
    };
    if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;
    
    const response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    return response.json();
}

// Login to AllTalk and get access token
async function loginUser(email, password) {
    const response = await apiCall('/auth/sign-in', null, {
        method: 'POST',
        body: JSON.stringify({ email, password, remember_me: true })
    });
    
    if (response.data?.tokens?.access_token) {
        return {
            accessToken: response.data.tokens.access_token,
            refreshToken: response.data.tokens.refresh_token,
            user: response.data.user
        };
    }
    return null;
}

// Refresh token if needed
async function refreshUserToken(userId) {
    const user = registeredUsers[userId];
    if (!user) return null;
    
    // Re-login with stored credentials
    const password = decrypt(user.encryptedPassword);
    const loginResult = await loginUser(user.email, password);
    
    if (loginResult) {
        user.accessToken = loginResult.accessToken;
        user.tokenExpiry = Date.now() + (23 * 60 * 60 * 1000); // 23 hours
        return loginResult.accessToken;
    }
    return null;
}

// Get valid access token for user
async function getValidToken(userId) {
    const user = registeredUsers[userId];
    if (!user) return null;
    
    // Check if token is expired or missing
    if (!user.accessToken || Date.now() > user.tokenExpiry) {
        return await refreshUserToken(userId);
    }
    return user.accessToken;
}

// Check for new messages and send SMS alerts
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
        
        // Check each conversation for new messages
        for (const conv of conversations) {
            // Skip if this is the alert number (don't notify about own alerts)
            if (conv.contact?.phone_number === user.smsAlertNumber) continue;
            
            // Create unique message key
            const messageKey = `${conv.id}-${conv.last_message_at}-${conv.last_message}`;
            
            // Check if we've already notified about this message
            if (!user.lastMessageIds) user.lastMessageIds = new Set();
            
            if (!user.lastMessageIds.has(messageKey) && conv.last_message) {
                // New message! Send SMS alert
                console.log(`[${userId}] New message from ${conv.contact?.first_name || conv.contact?.phone_number}`);
                
                await sendSmsAlert(userId, conv, accessToken);
                
                // Track this message
                user.lastMessageIds.add(messageKey);
                
                // Keep set from growing too large
                if (user.lastMessageIds.size > 200) {
                    const arr = Array.from(user.lastMessageIds);
                    user.lastMessageIds = new Set(arr.slice(-100));
                }
            }
        }
    } catch (err) {
        console.log(`[${userId}] Error checking messages:`, err.message);
    }
}

// Send SMS alert
async function sendSmsAlert(userId, conversation, accessToken) {
    const user = registeredUsers[userId];
    if (!user) return;
    
    try {
        const contact = conversation.contact || {};
        const name = contact.first_name 
            ? `${contact.first_name} ${contact.last_name || ''}`.trim() 
            : formatPhone(contact.phone_number) || 'Unknown';
        
        const messagePreview = (conversation.last_message || '').substring(0, 100);
        const chatLink = `${APP_URL}/?chat=${conversation.id}`;
        const alertText = `AllTalk Alert - "${name}: ${messagePreview}" Open: ${chatLink}`;
        
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
        let sendFromId = user.smsAlertFromNumberId || alertConv.last_phone_number_id || conversation.last_phone_number_id;
        
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
            console.log(`[${userId}] SMS alert sent to ${user.smsAlertNumber}`);
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
            tokenExpiry: Date.now() + (23 * 60 * 60 * 1000), // 23 hours
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

// Main polling loop - check all users every 10 seconds
setInterval(async () => {
    const userIds = Object.keys(registeredUsers);
    for (const userId of userIds) {
        await checkUserMessages(userId);
    }
}, 10000);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`AllTalk Notification Server running on port ${PORT}`);
    console.log(`Polling interval: 10 seconds`);
});
