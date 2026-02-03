const express = require('express');
const cors = require('cors');
const CryptoJS = require('crypto-js');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Encryption key - in production, use environment variable
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'alltalk-secure-key-2024';
const API_BASE = 'https://api.alltalkpro.com/api/v1';
const APP_URL = 'https://mobile-alltalk.com';

// File path for persistent storage
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'registered-users.json');

// Store registered users (loaded from file on startup)
let registeredUsers = {};

// Load users from file on startup
function loadUsers() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const data = fs.readFileSync(DATA_FILE, 'utf8');
            const parsed = JSON.parse(data);
            // Convert lastMessageIds arrays back to Sets
            for (const userId in parsed) {
                if (parsed[userId].lastMessageIds) {
                    parsed[userId].lastMessageIds = new Set(parsed[userId].lastMessageIds);
                }
            }
            registeredUsers = parsed;
            console.log(`Loaded ${Object.keys(registeredUsers).length} registered users from file`);
        } else {
            console.log('No existing users file found, starting fresh');
        }
    } catch (err) {
        console.error('Error loading users file:', err.message);
        registeredUsers = {};
    }
}

// Save users to file
function saveUsers() {
    try {
        // Convert Sets to arrays for JSON serialization
        const toSave = {};
        for (const userId in registeredUsers) {
            toSave[userId] = { ...registeredUsers[userId] };
            if (toSave[userId].lastMessageIds instanceof Set) {
                toSave[userId].lastMessageIds = Array.from(toSave[userId].lastMessageIds);
            }
        }
        fs.writeFileSync(DATA_FILE, JSON.stringify(toSave, null, 2));
        console.log(`Saved ${Object.keys(registeredUsers).length} users to file`);
    } catch (err) {
        console.error('Error saving users file:', err.message);
    }
}

// Load users on startup
loadUsers();

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
        
        // Debug: log the response structure
        console.log(`[${userId}] API response keys:`, response ? Object.keys(response) : 'null');
        
        if (!response.data?.results) {
            console.log(`[${userId}] No conversations found - response.data:`, JSON.stringify(response.data || response).substring(0, 200));
            return;
        }
        
        const conversations = response.data.results;
        const newMessages = [];
        
        // Collect all new INBOUND messages only
        for (const conv of conversations) {
            // Skip if this is the alert number (don't notify about own alerts)
            if (conv.contact?.phone_number?.replace(/\D/g, '') === user.smsAlertNumber.replace(/\D/g, '')) continue;
            
            // Only notify for INBOUND messages (unread_count > 0 means contact sent a message)
            if (conv.unread_count === 0) continue;
            
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
        
        // Save to persistent storage
        saveUsers();
        
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
        // Save to persistent storage
        saveUsers();
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

// ============================================
// PROXY ENDPOINTS - Route app requests through server
// This prevents the app from creating separate login sessions
// ============================================

// Middleware to validate user and get token
async function authenticateUser(req, res, next) {
    const userId = req.headers['x-user-id'];
    
    if (!userId || !registeredUsers[userId]) {
        return res.status(401).json({ success: false, message: 'User not authenticated. Please register first.' });
    }
    
    try {
        const accessToken = await getValidToken(userId);
        if (!accessToken) {
            return res.status(401).json({ success: false, message: 'Failed to get valid token. Please re-register.' });
        }
        
        req.userId = userId;
        req.accessToken = accessToken;
        req.user = registeredUsers[userId];
        next();
    } catch (err) {
        console.error('Auth middleware error:', err.message);
        res.status(500).json({ success: false, message: 'Authentication error' });
    }
}

// Login endpoint - validates credentials and registers user WITHOUT creating conflicts
// This replaces direct API login from the frontend
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Email and password required' });
    }
    
    try {
        // Check if user already exists by email
        let existingUserId = null;
        for (const [id, user] of Object.entries(registeredUsers)) {
            if (user.email === email) {
                existingUserId = id;
                break;
            }
        }
        
        if (existingUserId) {
            // User already registered - verify password and return existing session
            const user = registeredUsers[existingUserId];
            const storedPassword = decrypt(user.encryptedPassword);
            
            if (storedPassword !== password) {
                return res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
            
            // Get valid token (will refresh if needed, but won't create new login)
            const accessToken = await getValidToken(existingUserId);
            
            if (!accessToken) {
                // Token refresh failed, need to re-login (this will happen rarely)
                const loginResult = await loginUser(email, password);
                if (!loginResult) {
                    return res.status(401).json({ success: false, message: 'Invalid credentials' });
                }
                user.accessToken = loginResult.accessToken;
                user.tokenExpiry = Date.now() + (23 * 60 * 60 * 1000);
                saveUsers();
                
                return res.json({
                    success: true,
                    userId: existingUserId,
                    user: loginResult.user,
                    message: 'Login successful (re-authenticated)'
                });
            }
            
            // Return existing session info
            console.log(`User login (existing): ${email} (${existingUserId})`);
            return res.json({
                success: true,
                userId: existingUserId,
                user: { id: existingUserId, email: user.email },
                message: 'Login successful (existing session)'
            });
        }
        
        // New user - need to login to AllTalk API once
        const loginResult = await loginUser(email, password);
        
        if (!loginResult) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        const userId = loginResult.user.id;
        
        // Store user with encrypted password
        registeredUsers[userId] = {
            email,
            encryptedPassword: encrypt(password),
            smsAlertNumber: '',
            smsAlertFromNumberId: '',
            accessToken: loginResult.accessToken,
            tokenExpiry: Date.now() + (23 * 60 * 60 * 1000),
            lastMessageIds: new Set()
        };
        
        saveUsers();
        console.log(`User login (new): ${email} (${userId})`);
        
        res.json({
            success: true,
            userId: userId,
            user: loginResult.user,
            message: 'Login successful'
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Update SMS alert settings (doesn't require re-login)
app.post('/api/settings', authenticateUser, async (req, res) => {
    const { smsAlertNumber, smsAlertFromNumberId } = req.body;
    
    try {
        const user = registeredUsers[req.userId];
        
        if (smsAlertNumber !== undefined) {
            user.smsAlertNumber = smsAlertNumber.replace(/\D/g, '');
        }
        if (smsAlertFromNumberId !== undefined) {
            user.smsAlertFromNumberId = smsAlertFromNumberId;
        }
        
        saveUsers();
        
        res.json({ 
            success: true, 
            message: 'Settings updated',
            smsAlertNumber: user.smsAlertNumber,
            smsAlertFromNumberId: user.smsAlertFromNumberId
        });
    } catch (err) {
        console.error('Settings update error:', err);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get user settings
app.get('/api/settings', authenticateUser, async (req, res) => {
    const user = registeredUsers[req.userId];
    res.json({
        success: true,
        smsAlertNumber: user.smsAlertNumber || '',
        smsAlertFromNumberId: user.smsAlertFromNumberId || '',
        email: user.email
    });
});

// Proxy: Get conversations
app.get('/api/proxy/conversations', authenticateUser, async (req, res) => {
    try {
        const queryString = req.url.includes('?') ? req.url.split('?')[1] : 'page=1&limit=50&order=DESC';
        const response = await apiCall(`/conversations?${queryString}`, req.accessToken);
        res.json(response);
    } catch (err) {
        console.error('Proxy conversations error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Proxy: Get messages for a conversation
app.get('/api/proxy/conversations/:convId/messages/:phoneId', authenticateUser, async (req, res) => {
    try {
        const { convId, phoneId } = req.params;
        const limit = req.query.limit || 50;
        const response = await apiCall(`/conversations/${convId}/messages/${phoneId}?limit=${limit}`, req.accessToken);
        res.json(response);
    } catch (err) {
        console.error('Proxy messages error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Proxy: Send message
app.post('/api/proxy/conversations/:convId/messages', authenticateUser, async (req, res) => {
    try {
        const { convId } = req.params;
        const response = await apiCall(`/conversations/${convId}/messages`, req.accessToken, {
            method: 'POST',
            body: JSON.stringify(req.body)
        });
        res.json(response);
    } catch (err) {
        console.error('Proxy send message error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Proxy: Mark conversation as read
app.post('/api/proxy/conversations/:convId/read', authenticateUser, async (req, res) => {
    try {
        const { convId } = req.params;
        const response = await apiCall(`/conversations/${convId}/read`, req.accessToken, {
            method: 'POST'
        });
        res.json(response);
    } catch (err) {
        console.error('Proxy mark read error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Proxy: Get phone numbers
app.get('/api/proxy/phone-numbers', authenticateUser, async (req, res) => {
    try {
        const limit = req.query.limit || 50;
        const response = await apiCall(`/phone-numbers?limit=${limit}`, req.accessToken);
        res.json(response);
    } catch (err) {
        console.error('Proxy phone numbers error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Proxy: Get contact details
app.get('/api/proxy/contacts/:contactId', authenticateUser, async (req, res) => {
    try {
        const { contactId } = req.params;
        const response = await apiCall(`/contacts/${contactId}`, req.accessToken);
        res.json(response);
    } catch (err) {
        console.error('Proxy contact error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Proxy: Search conversations
app.get('/api/proxy/conversations/search', authenticateUser, async (req, res) => {
    try {
        const search = req.query.search || '';
        const limit = req.query.limit || 10;
        const response = await apiCall(`/conversations?search=${encodeURIComponent(search)}&limit=${limit}`, req.accessToken);
        res.json(response);
    } catch (err) {
        console.error('Proxy search error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Logout - removes user from server (optional - keeps background alerts if desired)
app.post('/api/logout', (req, res) => {
    const userId = req.headers['x-user-id'];
    
    // Note: We don't delete the user from registeredUsers
    // This allows background SMS alerts to continue working
    // User can explicitly disable alerts via /api/unregister
    
    res.json({ success: true, message: 'Logged out from app' });
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
    console.log(`Proxy endpoints enabled - app will not create separate sessions`);
});
