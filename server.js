const express = require('express');
const path = require('path');
const cors = require('cors');
const crypto = require('crypto');
// নোট: Node.js 18+ এ বিল্ট-ইন গ্লোবাল fetch() আছে, তাই আলাদা 'node-fetch' প্যাকেজ ইনস্টল করার দরকার নেই।
// আগে require('node-fetch') করা ছিল কিন্তু package.json এ dependency হিসেবে ছিল না — এই বাগ ফিক্স করা হয়েছে।

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ==================== JSONBin.io Configuration ====================
const BIN_ID = "6aa18606ffd5d16053f26c84"; // Replace with your Bin ID
const MASTER_KEY = "$2a$10$7CefWS3Sax1jJgJzujxdS.Xs3fN4Fy/788WH6cZps28qfBRH3qGj2"; // Replace with your Master Key
const JSONBIN_URL = `https://api.jsonbin.io/v3/b/${BIN_ID}`;

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const SID_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours — SID can be changed once per day

// ==================== Email Normalization (One Gmail = One Account) ====================
function normalizeEmail(email) {
    if (!email || typeof email !== 'string') return '';
    let e = email.trim().toLowerCase();
    const parts = e.split('@');
    if (parts.length !== 2) return e;
    let [local, domain] = parts;
    // Gmail (and Googlemail) ignore dots and anything after a "+" in the local part,
    // so "j.doe+promo@gmail.com" and "jdoe@gmail.com" are treated as the SAME account.
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
        local = local.split('+')[0].replace(/\./g, '');
        domain = 'gmail.com';
    }
    return `${local}@${domain}`;
}

function findUserByEmail(db, email) {
    const normalized = normalizeEmail(email);
    return db.users.find(u => normalizeEmail(u.email) === normalized);
}

// ==================== Password Hashing (PBKDF2) ====================
function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    if (!stored || typeof stored !== 'string') return { valid: false, needsRehash: false };
    if (!stored.includes(':')) {
        // Legacy plaintext password handling
        return { valid: stored === password, needsRehash: stored === password };
    }
    const [salt, hash] = stored.split(':');
    const check = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const valid = crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
    return { valid, needsRehash: false };
}

// ==================== JSONBin Cloud Database Functions ====================
async function readDB() {
    try {
        const response = await fetch(JSONBIN_URL, {
            method: 'GET',
            headers: {
                'X-Master-Key': MASTER_KEY,
                'X-Bin-Meta': 'false'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to fetch from JSONBin. Status: ${response.status}`);
        }

        const db = await response.json();
        
        // Ensure structure is correct
        if (!db.users) db.users = [];
        if (!db.keys) db.keys = [];
        if (!db.resellers) db.resellers = [];
        if (!db.sessions) db.sessions = [];
        if (!db.announcements) db.announcements = [];
        
        const hasAdmin = db.users.some(u => u.role === 'admin');
        if (!hasAdmin) {
            ensureAdminExists(db);
            await writeDB(db);
        }
        
        // বাগ ফিক্স: কী এক্সপায়ার হয়ে গেলে সেটা অটো-ডিলিট হবে এবং তার সাথে বাঁধা
        // ইউজারের SID verification বন্ধ হয়ে যাবে (একাউন্ট থাকবে, কিন্তু ভেরিফাই হবে না)
        purgeExpiredKeys(db);
        
        return db;
    } catch (error) {
        console.error("DEBUG ERROR [readDB]:", error.message);
        // Fallback default DB format if something fails
        const defaultDB = { users: [], keys: [], resellers: [], sessions: [] };
        ensureAdminExists(defaultDB);
        return defaultDB;
    }
}

async function writeDB(data) {
    try {
        const response = await fetch(JSONBIN_URL, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-Master-Key': MASTER_KEY
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`Failed to update JSONBin. Status: ${response.status}`);
        }
        return true;
    } catch (error) {
        console.error("DEBUG ERROR [writeDB]:", error.message);
        return false;
    }
}

function ensureAdminExists(db) {
    const adminExists = db.users.some(u => u.role === 'admin');
    if (!adminExists) {
        db.users.push({
            id: crypto.randomUUID(),
            username: 'admin',
            email: 'admin@tha3rdeye.com',
            password: hashPassword('admin123'),
            role: 'admin',
            provider: 'SYSTEM ADMIN',
            premiumStatus: 'active',
            premiumKey: 'ADMIN-KEY-0000',
            sid: 'ADMIN-SID',
            ip: '127.0.0.1',
            discordId: null,
            expiresAt: null,
            lastSidChange: null,
            createdAt: new Date().toISOString(),
            active: true
        });
    }
}

function generateKey() {
    return 'THA-' + crypto.randomBytes(12).toString('hex').toUpperCase().match(/.{1,4}/g).join('-');
}

function findUserByUsername(db, username) {
    return db.users.find(u => u.username === username);
}

function sidCooldownRemaining(user) {
    if (!user.lastSidChange) return 0;
    const remaining = SID_COOLDOWN_MS - (Date.now() - user.lastSidChange);
    return remaining > 0 ? remaining : 0;
}

function publicUser(user) {
    return {
        username: user.username,
        email: user.email,
        role: user.role,
        provider: user.provider,
        premiumStatus: user.premiumStatus,
        premiumKey: user.premiumKey,
        sid: user.sid,
        ip: user.ip,
        discordId: user.discordId,
        expiresAt: user.expiresAt || null,
        active: user.active,
        sidCooldownMs: sidCooldownRemaining(user)
    };
}

function purgeExpiredSessions(db) {
    const now = Date.now();
    db.sessions = db.sessions.filter(s => s.expiresAt > now);
}

function enforceExpiry(db, user) {
    if (user.premiumStatus === 'active' && user.expiresAt && Date.now() > user.expiresAt) {
        user.premiumStatus = 'expired';
    }
}

// ==================== Key <-> User Cascade Helpers (Bug Fixes) ====================
// একটি নির্দিষ্ট ইউজারের সব লগইন সেশন সার্ভার থেকে সরিয়ে দেয়, যাতে সে জোর করে লগআউট হয়ে যায়
function killSessionsForUser(db, username) {
    db.sessions = db.sessions.filter(s => s.username !== username);
}

// একটি key দিয়ে redeem করা ইউজারকে খুঁজে বের করে (key delete/ban করলে এটাই ব্যবহার হয়)
function findUserBoundToKey(db, key) {
    return db.users.find(u => u.premiumKey === key);
}

// বাগ ফিক্স ১: Key ban করলে সেই key দিয়ে redeem করা ইউজারের প্রিমিয়াম অ্যাক্সেস তখনই বন্ধ হয়ে যাবে
// (তাই /api/verify আর "active" রিটার্ন করবে না) এবং তার সব সেশন কেটে দেওয়া হবে (জোর করে লগআউট)।
function revokeUserAccessForKeyBan(db, key) {
    const user = findUserBoundToKey(db, key);
    if (!user) return;
    if (user.premiumStatus === 'active') user.premiumStatus = 'banned';
    killSessionsForUser(db, user.username);
}

// Key আনব্যান করলে, যদি সেই ইউজার এখনো একই key-এর সাথে বাঁধা থাকে এবং মেয়াদ শেষ না হয়ে থাকে,
// তাহলে তার প্রিমিয়াম অ্যাক্সেস আবার চালু হয়ে যাবে।
function restoreUserAccessForKeyUnban(db, key) {
    const user = findUserBoundToKey(db, key);
    if (!user) return;
    if (user.premiumStatus === 'banned') {
        const stillValid = !user.expiresAt || Date.now() < user.expiresAt;
        user.premiumStatus = stillValid ? 'active' : 'expired';
    }
}

// বাগ ফিক্স ২: Key ডিলিট করলে, সেই key দিয়ে বানানো একাউন্ট এবং তার SID/verification পুরোপুরি
// সার্ভার থেকে ডিলিট হয়ে যাবে, যাতে ইউজার আর টুল ব্যবহার করতে না পারে।
function deleteUserBoundToKey(db, key) {
    const index = db.users.findIndex(u => u.premiumKey === key);
    if (index === -1) return;
    const username = db.users[index].username;
    db.users.splice(index, 1);
    killSessionsForUser(db, username);
}

// Key-র মেয়াদ শেষ হয়ে গেলে সেই key এন্ট্রিটা অটোমেটিক ডিলিট হয়ে যাবে।
// একাউন্ট থাকবে, কিন্তু premiumStatus আগে থেকেই enforceExpiry() দিয়ে 'expired' হয়ে যায়,
// ফলে /api/verify আর কখনো active রিটার্ন করবে না।
function purgeExpiredKeys(db) {
    const now = Date.now();
    db.keys = db.keys.filter(k => {
        if (!k.isUsed || !k.usedBy) return true; // এখনো ব্যবহার হয়নি — রেখে দাও
        const user = db.users.find(u => u.username === k.usedBy && u.premiumKey === k.key);
        if (!user) return true;
        if (user.expiresAt && now > user.expiresAt) {
            enforceExpiry(db, user);
            return false; // মেয়াদ শেষ — key এন্ট্রি ডিলিট
        }
        return true;
    });
}

// ==================== Auth Middleware (Async Updated) ====================
async function authenticate(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized. Please login again.' });

    const db = await readDB();
    purgeExpiredSessions(db);
    
    const session = db.sessions.find(s => s.token === token);
    if (!session) {
        await writeDB(db);
        return res.status(401).json({ success: false, message: 'Session expired. Please login again.' });
    }
    
    const user = findUserByUsername(db, session.username);
    if (!user || !user.active) {
        await writeDB(db);
        return res.status(401).json({ success: false, message: 'Account not found or banned.' });
    }
    
    enforceExpiry(db, user);
    await writeDB(db);
    
    req.db = db;
    req.authUser = user;
    next();
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.authUser.role)) {
            return res.status(403).json({ success: false, message: 'Access denied for this role.' });
        }
        next();
    };
}

// ==================== Authentication Routes ====================
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.json({ success: false, message: 'All fields are required.' });
    }
    
    if (!/^\S+@\S+\.\S+$/.test(email)) {
        return res.json({ success: false, message: 'Please enter a valid email address.' });
    }

    const db = await readDB();
    if (findUserByUsername(db, username)) {
        return res.json({ success: false, message: 'Username already exists.' });
    }
    if (findUserByEmail(db, email)) {
        return res.json({ success: false, message: 'An account already exists with this email address. Only one account is allowed per email.' });
    }
    
    const newUser = {
        id: crypto.randomUUID(),
        username,
        email: email.trim().toLowerCase(),
        password: hashPassword(password),
        role: 'client',
        provider: null,
        premiumStatus: 'inactive',
        premiumKey: null,
        sid: null,
        ip: null,
        discordId: null,
        expiresAt: null,
        lastSidChange: null,
        createdAt: new Date().toISOString(),
        active: true
    };
    
    db.users.push(newUser);
    await writeDB(db);
    res.json({ success: true, message: 'Registration successful.' });
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const db = await readDB();
    const user = findUserByUsername(db, username);
    if (!user) return res.json({ success: false, message: 'Invalid credentials.' });

    const { valid, needsRehash } = verifyPassword(password, user.password);
    if (!valid) return res.json({ success: false, message: 'Invalid credentials.' });
    if (needsRehash) user.password = hashPassword(password);

    if (!user.active) {
        return res.json({ success: false, message: 'Account is banned or inactive.' });
    }
    enforceExpiry(db, user);

    purgeExpiredSessions(db);
    const token = crypto.randomBytes(32).toString('hex');
    db.sessions.push({ token, username: user.username, createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS });
    
    await writeDB(db);
    res.json({ success: true, token, user: publicUser(user) });
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
    const header = req.headers['authorization'] || '';
    const token = header.slice(7);
    const db = req.db;
    db.sessions = db.sessions.filter(s => s.token !== token);
    await writeDB(db);
    res.json({ success: true, message: 'Logged out.' });
});

// ==================== Client Routes ====================
app.post('/api/client/redeem', authenticate, async (req, res) => {
    const { key, ip, sid } = req.body;
    const db = req.db;
    const user = req.authUser;
    if (!key || !ip || !sid) return res.json({ success: false, message: 'Key, IP and SID are required.' });

    const foundKey = db.keys.find(k => k.key === key && !k.isUsed && k.active);
    if (!foundKey) {
        return res.json({ success: false, message: 'Invalid, already used, or inactive key.' });
    }

    foundKey.isUsed = true;
    foundKey.usedBy = user.username;
    user.premiumStatus = 'active';
    user.premiumKey = key;
    user.provider = foundKey.provider;
    user.sid = sid;
    user.ip = ip;
    user.lastSidChange = Date.now();
    user.expiresAt = foundKey.duration === 'lifetime'
        ? null
        : Date.now() + (parseInt(foundKey.duration, 10) * 24 * 60 * 60 * 1000);
        
    await writeDB(db);
    res.json({ success: true, message: 'Key redeemed successfully!', user: publicUser(user) });
});

app.post('/api/client/update-sid', authenticate, async (req, res) => {
    const { sid } = req.body;
    if (!sid) return res.json({ success: false, message: 'SID required.' });
    const db = req.db;
    const user = req.authUser;

    const remaining = sidCooldownRemaining(user);
    if (remaining > 0) {
        return res.json({
            success: false,
            message: 'You can only change your SID once every 24 hours.',
            cooldown: true,
            sidCooldownMs: remaining,
            user: publicUser(user)
        });
    }

    user.sid = sid;
    user.lastSidChange = Date.now();
    await writeDB(db);
    res.json({ success: true, message: 'SID updated. Next change available in 24 hours.', user: publicUser(user) });
});

app.post('/api/client/update-ip', authenticate, async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.json({ success: false, message: 'IP required.' });
    const db = req.db;
    req.authUser.ip = ip;
    await writeDB(db);
    res.json({ success: true, message: 'IP updated.', user: publicUser(req.authUser) });
});

app.post('/api/client/update-discord', authenticate, async (req, res) => {
    const { discordId } = req.body;
    if (!discordId) return res.json({ success: false, message: 'Discord ID required.' });
    const db = req.db;
    req.authUser.discordId = discordId;
    await writeDB(db);
    res.json({ success: true, message: 'Discord ID updated.', user: publicUser(req.authUser) });
});

// ==================== Admin Routes ====================
app.get('/api/admin/keys', authenticate, requireRole('admin'), (req, res) => {
    res.json({ success: true, keys: req.db.keys });
});

app.post('/api/admin/create-key', authenticate, requireRole('admin'), async (req, res) => {
    const { provider, duration } = req.body;
    if (!provider) return res.json({ success: false, message: 'Provider required.' });
    const db = req.db;
    const newKey = {
        key: generateKey(),
        provider,
        duration,
        isUsed: false,
        usedBy: null,
        createdAt: new Date().toISOString(),
        createdBy: 'admin',
        active: true
    };
    db.keys.push(newKey);
    await writeDB(db);
    res.json({ success: true, key: newKey.key });
});

app.post('/api/admin/toggle-key-active', authenticate, requireRole('admin'), async (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, message: 'Key required.' });
    const db = req.db;
    const foundKey = db.keys.find(k => k.key === key);
    if (!foundKey) return res.json({ success: false, message: 'Key not found.' });
    foundKey.active = !foundKey.active;
    await writeDB(db);
    res.json({ success: true, message: `Key ${foundKey.active ? 'activated' : 'banned'}`, active: foundKey.active });
});

app.delete('/api/admin/delete-key', authenticate, requireRole('admin'), async (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, message: 'Key required.' });
    const db = req.db;
    const index = db.keys.findIndex(k => k.key === key);
    if (index === -1) return res.json({ success: false, message: 'Key not found.' });
    db.keys.splice(index, 1);
    await writeDB(db);
    res.json({ success: true, message: 'Key deleted.' });
});

app.post('/api/admin/create-reseller', authenticate, requireRole('admin'), async (req, res) => {
    const { username, password, provider } = req.body;
    if (!username || !password || !provider) return res.json({ success: false, message: 'All fields required.' });
    const db = req.db;
    if (findUserByUsername(db, username)) {
        return res.json({ success: false, message: 'Username exists.' });
    }
    const newUser = {
        id: crypto.randomUUID(),
        username,
        email: username + '@reseller.local',
        password: hashPassword(password),
        role: 'reseller',
        provider,
        premiumStatus: 'inactive',
        premiumKey: null,
        sid: null,
        ip: null,
        discordId: null,
        expiresAt: null,
        createdAt: new Date().toISOString(),
        active: true
    };
    db.users.push(newUser);
    db.resellers.push({ username, provider, createdAt: new Date().toISOString(), active: true });
    await writeDB(db);
    res.json({ success: true, message: 'Reseller created.' });
});

app.get('/api/admin/resellers', authenticate, requireRole('admin'), (req, res) => {
    res.json({ success: true, resellers: req.db.resellers });
});

app.post('/api/admin/toggle-reseller-active', authenticate, requireRole('admin'), async (req, res) => {
    const { username } = req.body;
    if (!username) return res.json({ success: false, message: 'Username required.' });
    const db = req.db;
    const user = findUserByUsername(db, username);
    if (!user || user.role !== 'reseller') return res.json({ success: false, message: 'Reseller not found.' });
    user.active = !user.active;
    const resellerEntry = db.resellers.find(r => r.username === username);
    if (resellerEntry) resellerEntry.active = user.active;
    await writeDB(db);
    res.json({ success: true, message: `Reseller ${user.active ? 'activated' : 'banned'}`, active: user.active });
});

app.delete('/api/admin/delete-reseller', authenticate, requireRole('admin'), async (req, res) => {
    const { username } = req.body;
    const db = req.db;
    const userIndex = db.users.findIndex(u => u.username === username);
    if (userIndex === -1) return res.json({ success: false, message: 'User not found.' });
    if (db.users[userIndex].role !== 'reseller') return res.json({ success: false, message: 'Not a reseller.' });
    db.users.splice(userIndex, 1);
    db.resellers = db.resellers.filter(r => r.username !== username);
    await writeDB(db);
    res.json({ success: true, message: 'Reseller deleted.' });
});

app.get('/api/admin/users', authenticate, requireRole('admin'), (req, res) => {
    const users = req.db.users.map(u => ({
        username: u.username,
        email: u.email,
        provider: u.provider,
        premiumStatus: u.premiumStatus,
        premiumKey: u.premiumKey,
        expiresAt: u.expiresAt || null,
        active: u.active,
        role: u.role
    }));
    res.json({ success: true, users });
});

app.post('/api/admin/toggle-user-active', authenticate, requireRole('admin'), async (req, res) => {
    const { username } = req.body;
    if (!username) return res.json({ success: false, message: 'Username required.' });
    const db = req.db;
    const user = findUserByUsername(db, username);
    if (!user) return res.json({ success: false, message: 'User not found.' });
    if (user.role === 'admin') return res.json({ success: false, message: 'Cannot ban admin.' });
    user.active = !user.active;
    await writeDB(db);
    res.json({ success: true, message: `User ${user.active ? 'activated' : 'banned'}`, active: user.active });
});

// ==================== Reseller Routes ====================
app.post('/api/reseller/create-key', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { duration } = req.body;
    const db = req.db;
    const user = req.authUser;
    const newKey = {
        key: generateKey(),
        provider: user.provider || 'Reseller Key',
        duration,
        isUsed: false,
        usedBy: null,
        createdAt: new Date().toISOString(),
        createdBy: user.username,
        active: true
    };
    db.keys.push(newKey);
    await writeDB(db);
    res.json({ success: true, key: newKey.key });
});

app.get('/api/reseller/keys', authenticate, requireRole('reseller', 'admin'), (req, res) => {
    const keys = req.db.keys.filter(k => k.createdBy === req.authUser.username);
    res.json({ success: true, keys });
});

// Reseller can ban/unban a key it created (own keys only)
app.post('/api/reseller/toggle-key-active', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, message: 'Key required.' });
    const db = req.db;
    const foundKey = db.keys.find(k => k.key === key && k.createdBy === req.authUser.username);
    if (!foundKey) return res.json({ success: false, message: 'Key not found or not owned by you.' });
    foundKey.active = !foundKey.active;
    await writeDB(db);
    res.json({ success: true, message: `Key ${foundKey.active ? 'activated' : 'banned'}`, active: foundKey.active });
});

// Reseller can permanently delete a key it created (own keys only)
app.delete('/api/reseller/delete-key', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, message: 'Key required.' });
    const db = req.db;
    const index = db.keys.findIndex(k => k.key === key && k.createdBy === req.authUser.username);
    if (index === -1) return res.json({ success: false, message: 'Key not found or not owned by you.' });
    db.keys.splice(index, 1);
    await writeDB(db);
    res.json({ success: true, message: 'Key deleted.' });
});

// Reseller can reset a used key back to "available", freeing the client who used it
app.post('/api/reseller/reset-key', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { key } = req.body;
    if (!key) return res.json({ success: false, message: 'Key required.' });
    const db = req.db;
    const foundKey = db.keys.find(k => k.key === key && k.createdBy === req.authUser.username);
    if (!foundKey) return res.json({ success: false, message: 'Key not found or not owned by you.' });

    if (foundKey.isUsed && foundKey.usedBy) {
        const boundUser = findUserByUsername(db, foundKey.usedBy);
        if (boundUser && boundUser.premiumKey === key) {
            boundUser.premiumStatus = 'inactive';
            boundUser.premiumKey = null;
            boundUser.expiresAt = null;
        }
    }
    foundKey.isUsed = false;
    foundKey.usedBy = null;
    await writeDB(db);
    res.json({ success: true, message: 'Key reset. It is available for redemption again.' });
});

// List clients that redeemed a key belonging to this reseller's provider
app.get('/api/reseller/clients', authenticate, requireRole('reseller', 'admin'), (req, res) => {
    const provider = req.authUser.provider;
    const clients = req.db.users
        .filter(u => u.role === 'client' && u.provider === provider)
        .map(u => ({
            username: u.username,
            email: u.email,
            premiumStatus: u.premiumStatus,
            premiumKey: u.premiumKey,
            sid: u.sid,
            expiresAt: u.expiresAt || null,
            active: u.active
        }));
    res.json({ success: true, clients });
});

// Reseller can ban/unban a client under its own provider
app.post('/api/reseller/toggle-client-active', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { username } = req.body;
    if (!username) return res.json({ success: false, message: 'Username required.' });
    const db = req.db;
    const client = findUserByUsername(db, username);
    if (!client || client.role !== 'client' || client.provider !== req.authUser.provider) {
        return res.json({ success: false, message: 'Client not found under your provider.' });
    }
    client.active = !client.active;
    await writeDB(db);
    res.json({ success: true, message: `Client ${client.active ? 'activated' : 'banned'}`, active: client.active });
});

// Reseller can delete a client under its own provider
app.delete('/api/reseller/delete-client', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { username } = req.body;
    if (!username) return res.json({ success: false, message: 'Username required.' });
    const db = req.db;
    const index = db.users.findIndex(u => u.username === username && u.role === 'client' && u.provider === req.authUser.provider);
    if (index === -1) return res.json({ success: false, message: 'Client not found under your provider.' });
    db.users.splice(index, 1);
    await writeDB(db);
    res.json({ success: true, message: 'Client deleted.' });
});

// Reseller can reset a client's SID lock (clears cooldown + SID so client can bind a fresh device immediately)
app.post('/api/reseller/reset-client-sid', authenticate, requireRole('reseller', 'admin'), async (req, res) => {
    const { username } = req.body;
    if (!username) return res.json({ success: false, message: 'Username required.' });
    const db = req.db;
    const client = findUserByUsername(db, username);
    if (!client || client.role !== 'client' || client.provider !== req.authUser.provider) {
        return res.json({ success: false, message: 'Client not found under your provider.' });
    }
    client.sid = null;
    client.lastSidChange = null;
    await writeDB(db);
    res.json({ success: true, message: 'Client SID reset. They can bind a new device now.' });
});

// ==================== Public Verification Route ====================
app.get('/api/verify', async (req, res) => {
    const { sid } = req.query;
    if (!sid) {
        return res.json({ status: 'inactive', message: 'SID required.' });
    }
    const db = await readDB();
    const user = db.users.find(u => u.sid === sid && u.active);
    if (!user) {
        return res.json({ status: 'inactive', message: 'Invalid or inactive SID.' });
    }
    enforceExpiry(db, user);
    await writeDB(db);
    if (user.premiumStatus !== 'active') {
        return res.json({ status: 'inactive', message: user.premiumStatus === 'expired' ? 'License expired.' : 'Invalid or inactive SID.' });
    }
    return res.json({
        status: 'active',
        provider: user.provider || 'Unknown',
        username: user.username,
        expiresAt: user.expiresAt || null
    });
});

// SPA ফলব্যাক — /api/* বাদে যেকোনো GET রিকোয়েস্টে index.html সার্ভ করবে
app.get(/^\/(?!api).*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 THA 3RD EYE Server running on port ${PORT}`);
});