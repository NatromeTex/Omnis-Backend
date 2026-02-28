// Use the same host (and port) as the frontend
const API_BASE = `${window.location.protocol}//${window.location.host}`;
const WS_BASE  = `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`;

// Debug: Log API base URL (check browser console on phone)
console.log('API_BASE:', API_BASE);
console.log('WS_BASE:', WS_BASE);
console.log('Frontend hostname:', window.location.hostname);

// ==================== CRYPTO MODULE ====================

const Crypto = {
    // Constants
    PBKDF2_ITERATIONS: 100000,
    AES_KEY_LENGTH: 256,
    EC_CURVE: 'P-384',

    // Encode/decode utilities
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    // Generate random bytes
    randomBytes(length) {
        return crypto.getRandomValues(new Uint8Array(length));
    },

    // Derive key from password using PBKDF2
    async deriveKeyFromPassword(password, salt) {
        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: this.AES_KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    },

    // Generate EC identity keypair (P-384)
    async generateIdentityKeyPair() {
        return crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.EC_CURVE },
            true,
            ['deriveKey', 'deriveBits']
        );
    },

    // Export public key to base64
    async exportPublicKey(publicKey) {
        const exported = await crypto.subtle.exportKey('spki', publicKey);
        return this.arrayBufferToBase64(exported);
    },

    // Import public key from base64
    async importPublicKey(base64) {
        const keyData = this.base64ToArrayBuffer(base64);
        return crypto.subtle.importKey(
            'spki',
            keyData,
            { name: 'ECDH', namedCurve: this.EC_CURVE },
            true,
            []
        );
    },

    // Export private key to base64
    async exportPrivateKey(privateKey) {
        const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
        return this.arrayBufferToBase64(exported);
    },

    // Import private key from base64
    async importPrivateKey(base64) {
        const keyData = this.base64ToArrayBuffer(base64);
        return crypto.subtle.importKey(
            'pkcs8',
            keyData,
            { name: 'ECDH', namedCurve: this.EC_CURVE },
            true,
            ['deriveKey', 'deriveBits']
        );
    },

    // Encrypt data with AES-GCM
    async encryptAESGCM(key, plaintext, nonce) {
        const encoder = new TextEncoder();
        const data = typeof plaintext === 'string' ? encoder.encode(plaintext) : plaintext;
        
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            data
        );
        
        return new Uint8Array(ciphertext);
    },

    // Decrypt data with AES-GCM
    async decryptAESGCM(key, ciphertext, nonce) {
        const data = ciphertext instanceof ArrayBuffer ? ciphertext : 
                     ciphertext.buffer ? ciphertext.buffer : ciphertext;
        
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            key,
            data
        );
        
        return plaintext;
    },

    // Encrypt identity private key with password-derived key
    async encryptIdentityPrivateKey(privateKey, password) {
        const salt = this.randomBytes(32);
        const nonce = this.randomBytes(12);
        const derivedKey = await this.deriveKeyFromPassword(password, salt);
        
        const privateKeyBase64 = await this.exportPrivateKey(privateKey);
        const ciphertext = await this.encryptAESGCM(derivedKey, privateKeyBase64, nonce);
        
        return {
            encrypted_identity_priv: this.arrayBufferToBase64(ciphertext),
            kdf_salt: this.arrayBufferToBase64(salt),
            aead_nonce: this.arrayBufferToBase64(nonce)
        };
    },

    // Decrypt identity private key with password-derived key
    async decryptIdentityPrivateKey(encryptedBlob, password) {
        const salt = this.base64ToArrayBuffer(encryptedBlob.kdf_salt);
        const nonce = this.base64ToArrayBuffer(encryptedBlob.aead_nonce);
        const ciphertext = this.base64ToArrayBuffer(encryptedBlob.encrypted_identity_priv);
        
        const derivedKey = await this.deriveKeyFromPassword(password, new Uint8Array(salt));
        const plaintextBuffer = await this.decryptAESGCM(derivedKey, ciphertext, new Uint8Array(nonce));
        
        const decoder = new TextDecoder();
        const privateKeyBase64 = decoder.decode(plaintextBuffer);
        
        return this.importPrivateKey(privateKeyBase64);
    },

    // Generate symmetric epoch key
    async generateEpochKey() {
        return crypto.subtle.generateKey(
            { name: 'AES-GCM', length: this.AES_KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );
    },

    // Export epoch key to raw bytes
    async exportEpochKey(key) {
        return crypto.subtle.exportKey('raw', key);
    },

    // Import epoch key from raw bytes
    async importEpochKey(rawKey) {
        const keyData = rawKey instanceof ArrayBuffer ? rawKey : 
                        rawKey.buffer ? rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) : rawKey;
        return crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM', length: this.AES_KEY_LENGTH },
            true,
            ['encrypt', 'decrypt']
        );
    },

    // Derive shared secret and wrap epoch key for recipient
    async wrapEpochKeyForRecipient(epochKey, myPrivateKey, recipientPublicKey) {
        // Derive shared secret using ECDH
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipientPublicKey },
            myPrivateKey,
            384 // P-384 gives 384 bits
        );

        // Use HKDF to derive a wrapping key from shared secret
        const sharedSecret = await crypto.subtle.importKey(
            'raw',
            sharedBits,
            'HKDF',
            false,
            ['deriveKey']
        );

        const wrapKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                salt: new Uint8Array(32), // Fixed salt for deterministic derivation
                info: new TextEncoder().encode('epoch-key-wrap'),
                hash: 'SHA-256'
            },
            sharedSecret,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        // Wrap the epoch key
        const rawEpochKey = await this.exportEpochKey(epochKey);
        const nonce = this.randomBytes(12);
        const wrapped = await this.encryptAESGCM(wrapKey, new Uint8Array(rawEpochKey), nonce);

        // Return nonce + wrapped key concatenated
        const result = new Uint8Array(nonce.length + wrapped.length);
        result.set(nonce, 0);
        result.set(wrapped, nonce.length);
        
        return this.arrayBufferToBase64(result);
    },

    // Unwrap epoch key received from sender
    async unwrapEpochKey(wrappedKeyBase64, myPrivateKey, senderPublicKey) {
        const wrappedData = new Uint8Array(this.base64ToArrayBuffer(wrappedKeyBase64));
        const nonce = wrappedData.slice(0, 12);
        const wrapped = wrappedData.slice(12);

        // Derive shared secret using ECDH
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: senderPublicKey },
            myPrivateKey,
            384
        );

        const sharedSecret = await crypto.subtle.importKey(
            'raw',
            sharedBits,
            'HKDF',
            false,
            ['deriveKey']
        );

        const wrapKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                salt: new Uint8Array(32),
                info: new TextEncoder().encode('epoch-key-wrap'),
                hash: 'SHA-256'
            },
            sharedSecret,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        // Unwrap the epoch key
        const rawEpochKey = await this.decryptAESGCM(wrapKey, wrapped, nonce);
        return this.importEpochKey(rawEpochKey);
    },

    // Encrypt a message with epoch key
    async encryptMessage(message, epochKey) {
        const nonce = this.randomBytes(12);
        const ciphertext = await this.encryptAESGCM(epochKey, message, nonce);
        
        return {
            ciphertext: this.arrayBufferToBase64(ciphertext),
            nonce: this.arrayBufferToBase64(nonce)
        };
    },

    // Decrypt a message with epoch key
    async decryptMessage(ciphertextBase64, nonceBase64, epochKey) {
        const ciphertext = this.base64ToArrayBuffer(ciphertextBase64);
        const nonce = new Uint8Array(this.base64ToArrayBuffer(nonceBase64));
        
        const plaintextBuffer = await this.decryptAESGCM(epochKey, ciphertext, nonce);
        const decoder = new TextDecoder();
        return decoder.decode(plaintextBuffer);
    }
};

// ==================== KEY STORAGE ====================

const KeyStore = {
    identityKeyPair: null,
    epochKeys: new Map(), // chatId -> Map(epochId -> { key, index })
    peerPublicKeys: new Map(), // username -> publicKey

    clear() {
        this.identityKeyPair = null;
        this.epochKeys.clear();
        this.peerPublicKeys.clear();
    },

    setIdentityKeyPair(keyPair) {
        this.identityKeyPair = keyPair;
    },

    getIdentityKeyPair() {
        return this.identityKeyPair;
    },

    setEpochKey(chatId, epochId, epochIndex, key) {
        if (!this.epochKeys.has(chatId)) {
            this.epochKeys.set(chatId, new Map());
        }
        this.epochKeys.get(chatId).set(epochId, { key, index: epochIndex });
    },

    getEpochKey(chatId, epochId) {
        const chatEpochs = this.epochKeys.get(chatId);
        if (!chatEpochs) return null;
        const epochData = chatEpochs.get(epochId);
        return epochData ? epochData.key : null;
    },

    getLatestEpoch(chatId) {
        const chatEpochs = this.epochKeys.get(chatId);
        if (!chatEpochs || chatEpochs.size === 0) return null;
        
        let latest = null;
        let latestIndex = -1;
        
        for (const [epochId, data] of chatEpochs) {
            if (data.index > latestIndex) {
                latestIndex = data.index;
                latest = { epochId, key: data.key, index: data.index };
            }
        }
        
        return latest;
    },

    setPeerPublicKey(username, publicKey) {
        this.peerPublicKeys.set(username, publicKey);
    },

    getPeerPublicKey(username) {
        return this.peerPublicKeys.get(username);
    }
};

// ==================== DEVICE ID ====================

function getDeviceId() {
    let deviceId = localStorage.getItem('deviceId');
    if (!deviceId) {
        deviceId = crypto.randomUUID();
        localStorage.setItem('deviceId', deviceId);
    }
    return deviceId;
}

const deviceId = getDeviceId();

// ==================== STATE ====================

let authToken = localStorage.getItem('authToken') || null;
let currentUserId = parseInt(localStorage.getItem('currentUserId')) || null;
let currentUsername = localStorage.getItem('currentUsername') || null;
let currentChatId = null;
let currentChatPeer = null; // username of peer in current chat
let chatSocket = null;       // active WebSocket for current chat
let wsReconnectTimer = null; // reconnect timer handle
let currentReplyMessage = null;

// ==================== DOM ELEMENTS ====================

const authSection = document.getElementById('auth-section');
const chatSection = document.getElementById('chat-section');
const loginForm = document.getElementById('login-form');
const signupForm = document.getElementById('signup-form');
const authError = document.getElementById('auth-error');
const chatList = document.getElementById('chat-list');
const chatPlaceholder = document.getElementById('chat-placeholder');
const chatView = document.getElementById('chat-view');
const chatWithUser = document.getElementById('chat-with-user');
const messagesContainer = document.getElementById('messages-container');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const replyBar = document.getElementById('reply-bar');
const replyPreview = document.getElementById('reply-preview');
const replyUsername = document.getElementById('reply-username');
const replyCancelBtn = document.getElementById('reply-cancel-btn');
const newChatUsername = document.getElementById('new-chat-username');
const newChatBtn = document.getElementById('new-chat-btn');
const logoutBtn = document.getElementById('logout-btn');
const tabBtns = document.querySelectorAll('.tab-btn');

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', async () => {
    if (authToken) {
        // We have a session token but need to check if we have identity keys
        if (!KeyStore.getIdentityKeyPair()) {
            // Need to prompt for password to decrypt keys
            showAuthSection();
            clearChatUi();
            authError.textContent = 'Session restored. Please enter your password to unlock encryption keys.';
            document.getElementById('login-username').value = currentUsername || '';
            // The login will handle fetching and decrypting keys
        } else {
            showChatSection();
            loadChats();
        }
    }
    setupEventListeners();
});

function setupEventListeners() {
    // Tab switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const tab = btn.dataset.tab;
            if (tab === 'login') {
                loginForm.classList.remove('hidden');
                signupForm.classList.add('hidden');
            } else {
                loginForm.classList.add('hidden');
                signupForm.classList.remove('hidden');
            }
            authError.textContent = '';
        });
    });

    // Login
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        await login(username, password);
    });

    // Signup
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('signup-username').value;
        const password = document.getElementById('signup-password').value;
        await signup(username, password);
    });

    // Logout
    logoutBtn.addEventListener('click', logout);

    // New chat
    newChatBtn.addEventListener('click', createNewChat);
    newChatUsername.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') createNewChat();
    });

    // Send message
    messageForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await sendMessage();
    });

    // Reply cancel
    replyCancelBtn.addEventListener('click', () => {
        clearReplyTarget();
    });
    
    // Account section
    document.getElementById('account-section').addEventListener('click', openAccountModal);
    document.getElementById('close-modal-btn').addEventListener('click', closeAccountModal);
    document.getElementById('revoke-other-btn').addEventListener('click', revokeOtherSessions);
    
    // Close modal when clicking outside
    document.getElementById('account-modal').addEventListener('click', (e) => {
        if (e.target.id === 'account-modal') closeAccountModal();
    });
}

// ==================== API CALLS ====================

async function apiCall(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-Device-ID': deviceId,
        ...options.headers
    };

    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers
    });

    if (!response.ok) {
        if (response.status === 401) {
            handleAuthBroken();
        }
        const error = await response.json().catch(() => ({ detail: 'Request failed' }));
        throw new Error(error.detail || 'Request failed');
    }

    return response.json();
}

// ==================== AUTH FUNCTIONS ====================

// Unlock keys with password when we have an existing session
async function unlockKeys(password) {
    try {
        authError.textContent = 'Decrypting identity keys...';
        
        const keyBlob = await apiCall('/auth/keyblob');
        const privateKey = await Crypto.decryptIdentityPrivateKey(keyBlob, password);
        const publicKey = await Crypto.importPublicKey(keyBlob.identity_pub);
        
        KeyStore.setIdentityKeyPair({ privateKey, publicKey });
        console.log('Identity keys unlocked successfully');
        
        authError.textContent = '';
        showChatSection();
        await loadChats();
        updateAccountSection();
        return true;
    } catch (error) {
        console.error('Failed to unlock keys:', error);
        authError.textContent = 'Failed to decrypt keys. Wrong password?';
        return false;
    }
}

async function login(username, password) {
    try {
        authError.textContent = '';
        
        // If we already have a valid session for this user, just unlock the keys
        if (authToken && currentUsername === username) {
            const unlocked = await unlockKeys(password);
            if (unlocked) return;
            // If unlock failed, continue with normal login
        }
        
        authError.textContent = 'Logging in...';
        
        const data = await apiCall('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        authToken = data.token;
        localStorage.setItem('authToken', authToken);
        localStorage.setItem('currentUsername', username);
        currentUsername = username;
        
        // Fetch current user info to get user ID
        const userInfo = await apiCall('/auth/me');
        currentUserId = userInfo.id;
        localStorage.setItem('currentUserId', currentUserId);
        
        // Fetch and decrypt identity key blob
        authError.textContent = 'Decrypting identity keys...';
        try {
            const keyBlob = await apiCall('/auth/keyblob');
            const privateKey = await Crypto.decryptIdentityPrivateKey(keyBlob, password);
            const publicKey = await Crypto.importPublicKey(keyBlob.identity_pub);
            
            KeyStore.setIdentityKeyPair({ privateKey, publicKey });
            console.log('Identity keys loaded successfully');
        } catch (cryptoError) {
            console.error('Failed to decrypt identity keys:', cryptoError);
            authError.textContent = 'Failed to decrypt identity keys. Wrong password?';
            // Logout since we can't use E2EE without keys
            await apiCall('/auth/logout', { method: 'POST' }).catch(() => {});
            clearAuthState();
            return;
        }
        
        authError.textContent = '';
        showChatSection();
        await loadChats();
        updateAccountSection();
    } catch (error) {
        console.error('Login error:', error);
        authError.textContent = error.message;
    }
}

async function signup(username, password) {
    try {
        authError.textContent = 'Generating encryption keys...';
        
        // Generate identity keypair
        const keyPair = await Crypto.generateIdentityKeyPair();
        const identityPub = await Crypto.exportPublicKey(keyPair.publicKey);
        
        // Encrypt private key with password
        const encryptedKeyBlob = await Crypto.encryptIdentityPrivateKey(keyPair.privateKey, password);
        
        authError.textContent = 'Creating account...';
        
        await apiCall('/auth/signup', {
            method: 'POST',
            body: JSON.stringify({
                username,
                password,
                identity_pub: identityPub,
                encrypted_identity_priv: encryptedKeyBlob.encrypted_identity_priv,
                kdf_salt: encryptedKeyBlob.kdf_salt,
                aead_nonce: encryptedKeyBlob.aead_nonce
            })
        });

        // Auto login after signup
        await login(username, password);
    } catch (error) {
        authError.textContent = error.message;
    }
}

async function logout() {
    try {
        await apiCall('/auth/logout', { method: 'POST' });
    } catch (error) {
        console.error('Logout error:', error);
    }

    clearAuthState();
    showAuthSection();
}

// ==================== UI FUNCTIONS ====================

function showAuthSection() {
    authSection.classList.remove('hidden');
    chatSection.classList.add('hidden');
    
    // Clear forms
    loginForm.reset();
    signupForm.reset();
    authError.textContent = '';
}

function clearChatUi() {
    chatList.innerHTML = '';
    messagesContainer.innerHTML = '';
    chatWithUser.textContent = 'Chat';
    messageInput.value = '';
    clearReplyTarget();
    chatView.classList.add('hidden');
    chatPlaceholder.classList.remove('hidden');
}

function clearAuthState() {
    authToken = null;
    currentUserId = null;
    currentUsername = null;
    currentChatId = null;
    currentChatPeer = null;
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUserId');
    localStorage.removeItem('currentUsername');

    // Clear crypto state
    KeyStore.clear();

    closeChatWebSocket();
    closeAccountModal();
    clearChatUi();
}

function handleAuthBroken() {
    clearAuthState();
    showAuthSection();
    authError.textContent = 'Session expired. Please log in again.';
}

function showChatSection() {
    authSection.classList.add('hidden');
    chatSection.classList.remove('hidden');
    updateAccountSection();
}

// ==================== CHAT FUNCTIONS ====================

async function loadChats() {
    try {
        const chats = await apiCall('/chat/list');
        renderChatList(chats);
    } catch (error) {
        console.error('Failed to load chats:', error);
        // Only logout if explicitly unauthorized, not on other errors
        if (error.message === 'Unauthorized' || error.message === 'Invalid authorization header') {
            logout();
        }
    }
}

function renderChatList(chats) {
    chatList.innerHTML = '';
    
    if (chats.length === 0) {
        chatList.innerHTML = '<div class="chat-item"><span class="username" style="color: var(--text-secondary)">No chats yet</span></div>';
        return;
    }

    chats.forEach(chat => {
        const item = document.createElement('div');
        item.className = 'chat-item' + (chat.chat_id === currentChatId ? ' active' : '');
        item.dataset.chatId = chat.chat_id;
        item.innerHTML = `<span class="username">${escapeHtml(chat.with_user)}</span>`;
        item.addEventListener('click', () => openChat(chat.chat_id, chat.with_user));
        chatList.appendChild(item);
    });
}

async function createNewChat() {
    const username = newChatUsername.value.trim();
    if (!username) return;

    try {
        const data = await apiCall('/chat/create', {
            method: 'POST',
            body: JSON.stringify({ username })
        });

        newChatUsername.value = '';
        await loadChats();
        openChat(data.chat_id, username);
    } catch (error) {
        alert(error.message);
    }
}

// Fetch peer's public key (cached)
async function getPeerPublicKey(username) {
    let pubKey = KeyStore.getPeerPublicKey(username);
    if (pubKey) return pubKey;
    
    const data = await apiCall(`/user/pkey/get?username=${encodeURIComponent(username)}`);
    pubKey = await Crypto.importPublicKey(data.identity_pub);
    KeyStore.setPeerPublicKey(username, pubKey);
    return pubKey;
}

// Create a new epoch for the chat
async function createEpoch(chatId, peerUsername) {
    const keyPair = KeyStore.getIdentityKeyPair();
    if (!keyPair) throw new Error('No identity keys loaded');
    
    const peerPubKey = await getPeerPublicKey(peerUsername);
    
    // Generate a new symmetric epoch key
    const epochKey = await Crypto.generateEpochKey();
    
    // Wrap the key for both parties using ECDH
    // The recipient will unwrap using: unwrap(wrapped, recipient_priv, sender_pub)
    // So we wrap using: wrap(key, sender_priv, recipient_pub)
    
    // For ourselves: wrap using our private key with peer's public key
    // We'll unwrap later using our private key with peer's public key (same shared secret)
    const wrappedKeyForSelf = await Crypto.wrapEpochKeyForRecipient(
        epochKey, 
        keyPair.privateKey, 
        peerPubKey
    );
    
    // For peer: wrap using our private key with peer's public key
    // Peer will unwrap using their private key with our public key (same shared secret)
    // NOTE: Since ECDH(A_priv, B_pub) == ECDH(B_priv, A_pub), both wrapped keys are the SAME!
    const wrappedKeyForPeer = wrappedKeyForSelf; // Same key due to ECDH symmetry
    
    const response = await apiCall(`/chat/${chatId}/epoch`, {
        method: 'POST',
        body: JSON.stringify({
            wrapped_key_a: wrappedKeyForSelf,
            wrapped_key_b: wrappedKeyForPeer
        })
    });
    
    // Cache the epoch key
    KeyStore.setEpochKey(chatId, response.epoch_id, response.epoch_index, epochKey);
    
    return {
        epochId: response.epoch_id,
        epochIndex: response.epoch_index,
        key: epochKey
    };
}

async function fetchEpochKey(chatId, epochId, peerUsername) {
    const cached = KeyStore.getEpochKey(chatId, epochId);
    if (cached) {
        return { epochId, key: cached };
    }

    const keyPair = KeyStore.getIdentityKeyPair();
    if (!keyPair) throw new Error('No identity keys loaded');

    const peerPubKey = await getPeerPublicKey(peerUsername);
    const epoch = await apiCall(`/chat/${chatId}/${epochId}/fetch`);

    if (!epoch.wrapped_key) {
        throw new Error('Epoch not initialized');
    }

    const epochKey = await Crypto.unwrapEpochKey(
        epoch.wrapped_key,
        keyPair.privateKey,
        peerPubKey
    );

    KeyStore.setEpochKey(chatId, epoch.epoch_id, epoch.epoch_index, epochKey);

    return {
        epochId: epoch.epoch_id,
        epochIndex: epoch.epoch_index,
        key: epochKey
    };
}

async function getLatestEpochFromMessages(chatId, peerUsername) {
    const data = await apiCall(`/chat/fetch/${chatId}?limit=1`);
    if (!data.messages || data.messages.length === 0) return null;

    const latestMsg = data.messages[data.messages.length - 1];
    return fetchEpochKey(chatId, latestMsg.epoch_id, peerUsername);
}

// Get or create latest epoch for sending messages
async function getOrCreateEpoch(chatId, peerUsername) {
    const cached = KeyStore.getLatestEpoch(chatId);
    if (cached) {
        return { epochId: cached.epochId, epochIndex: cached.index, key: cached.key };
    }

    const latestEpoch = await getLatestEpochFromMessages(chatId, peerUsername);
    if (latestEpoch) return latestEpoch;

    // No messages yet, create the first epoch
    try {
        return await createEpoch(chatId, peerUsername);
    } catch (e) {
        if (e.message.includes('throttled')) {
            // Wait and retry
            await new Promise(resolve => setTimeout(resolve, 5000));
            return await createEpoch(chatId, peerUsername);
        }
        if (e.message.includes('Epoch rotation not allowed yet')) {
            const fallbackEpoch = await getLatestEpochFromMessages(chatId, peerUsername);
            if (fallbackEpoch) return fallbackEpoch;
        }
        throw e;
    }
}

async function openChat(chatId, username) {
    currentChatId = chatId;
    currentChatPeer = username;
    clearReplyTarget();
    
    // Update UI
    chatPlaceholder.classList.add('hidden');
    chatView.classList.remove('hidden');
    chatWithUser.textContent = username;
    
    // Update active state in list using data-chat-id
    document.querySelectorAll('.chat-item').forEach(item => {
        item.classList.toggle('active', parseInt(item.dataset.chatId) === chatId);
    });

    // Pre-fetch peer's public key
    try {
        await getPeerPublicKey(username);
    } catch (e) {
        console.error('Failed to fetch peer public key:', e);
    }

    // Open WebSocket (replaces polling)
    connectChatWebSocket(chatId);
}

async function loadMessages() {
    if (!currentChatId) return;

    try {
        const data = await apiCall(`/chat/fetch/${currentChatId}`);

        // Ensure we have keys for all epochs referenced in messages
        const epochIds = new Set(data.messages.map(msg => msg.epoch_id));
        if (currentChatPeer) {
            for (const epochId of epochIds) {
                if (!KeyStore.getEpochKey(currentChatId, epochId)) {
                    try {
                        await fetchEpochKey(currentChatId, epochId, currentChatPeer);
                    } catch (e) {
                        console.error(`Failed to fetch epoch ${epochId}:`, e);
                    }
                }
            }
        }
        
        // Decrypt messages
        const decryptedMessages = [];
        for (const msg of data.messages) {
            const epochKey = KeyStore.getEpochKey(currentChatId, msg.epoch_id);
            if (epochKey) {
                try {
                    const plaintext = await Crypto.decryptMessage(msg.ciphertext, msg.nonce, epochKey);
                    decryptedMessages.push({
                        ...msg,
                        body: plaintext
                    });
                } catch (e) {
                    console.error('Failed to decrypt message:', e);
                    decryptedMessages.push({
                        ...msg,
                        body: '[Decryption failed]'
                    });
                }
            } else {
                decryptedMessages.push({
                    ...msg,
                    body: '[Missing epoch key]'
                });
            }
        }
        
        renderMessages(decryptedMessages);
    } catch (error) {
        console.error('Failed to load messages:', error);
    }
}

function renderMessages(messages) {
    messagesContainer.innerHTML = '';

    const messageMap = new Map();
    messages.forEach(msg => {
        messageMap.set(msg.id, msg);
    });
    
    messages.forEach(msg => {
        const isSent = msg.sender_id === currentUserId;
        const div = document.createElement('div');
        div.className = `message ${isSent ? 'sent' : 'received'}`;
        div.dataset.msgId = msg.id;
        div.dataset.senderId = msg.sender_id;
        
        const time = parseUTCDate(msg.created_at).toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
        
        let replyHtml = '';
        if (msg.reply_id) {
            const replyTarget = messageMap.get(msg.reply_id);
            const replySender = replyTarget ? getSenderLabel(replyTarget.sender_id) : 'Original message';
            const replyText = replyTarget ? getReplyPreviewText(replyTarget.body, 140) : '[Original message unavailable]';
            replyHtml = `
                <div class="reply-snippet">
                    <div class="reply-snippet-label">${escapeHtml(replySender)}</div>
                    <div class="reply-snippet-text">${escapeHtml(replyText)}</div>
                </div>
            `;
        }

        div.innerHTML = `
            ${replyHtml}
            <div class="text">${escapeHtml(msg.body)}</div>
            <div class="time">${time}</div>
        `;

        const actions = document.createElement('div');
        actions.className = 'message-actions';

        const replyBtn = document.createElement('button');
        replyBtn.type = 'button';
        replyBtn.className = 'reply-btn';
        replyBtn.title = 'Reply';
        replyBtn.innerHTML = '<i class="fa-solid fa-reply"></i>';
        replyBtn.addEventListener('click', (event) => {
            event.stopPropagation();
            setReplyTarget(msg);
        });

        actions.appendChild(replyBtn);
        div.appendChild(actions);
        
        messagesContainer.appendChild(div);
    });

    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

async function sendMessage() {
    const body = messageInput.value.trim();
    if (!body || !currentChatId || !currentChatPeer) return;

    try {
        messageInput.value = '';
        
        // Get or create an epoch for this chat
        let epoch = KeyStore.getLatestEpoch(currentChatId);
        
        if (!epoch) {
            // Need to fetch or create an epoch
            epoch = await getOrCreateEpoch(currentChatId, currentChatPeer);
        }
        
        // Encrypt the message
        const encrypted = await Crypto.encryptMessage(body, epoch.key);
        
        await apiCall(`/chat/${currentChatId}/message`, {
            method: 'POST',
            body: JSON.stringify({
                epoch_id: epoch.epochId,
                ciphertext: encrypted.ciphertext,
                nonce: encrypted.nonce,
                reply_id: currentReplyMessage ? currentReplyMessage.id : null
            })
        });
        clearReplyTarget();
        // If WebSocket is not open (e.g. connection dropped), fall back to HTTP fetch
        if (!chatSocket || chatSocket.readyState !== WebSocket.OPEN) {
            await loadMessages();
        }
        // Otherwise the server broadcasts the new message via WebSocket
    } catch (error) {
        console.error('Send message error:', error);
        
        // Handle stale epoch error - refetch and retry
        if (error.message.includes('Stale epoch') || error.message.includes('Unknown epoch')) {
            try {
                KeyStore.epochKeys.delete(currentChatId);
                const epoch = await getOrCreateEpoch(currentChatId, currentChatPeer);
                const encrypted = await Crypto.encryptMessage(body, epoch.key);
                
                await apiCall(`/chat/${currentChatId}/message`, {
                    method: 'POST',
                    body: JSON.stringify({
                        epoch_id: epoch.epochId,
                        ciphertext: encrypted.ciphertext,
                        nonce: encrypted.nonce,
                        reply_id: currentReplyMessage ? currentReplyMessage.id : null
                    })
                });
                clearReplyTarget();
                return;
            } catch (retryError) {
                alert(retryError.message);
            }
        } else if (error.message.includes('Epoch not initialized')) {
            try {
                const epoch = await createEpoch(currentChatId, currentChatPeer);
                const encrypted = await Crypto.encryptMessage(body, epoch.key);
                
                await apiCall(`/chat/${currentChatId}/message`, {
                    method: 'POST',
                    body: JSON.stringify({
                        epoch_id: epoch.epochId,
                        ciphertext: encrypted.ciphertext,
                        nonce: encrypted.nonce,
                        reply_id: currentReplyMessage ? currentReplyMessage.id : null
                    })
                });
                clearReplyTarget();
                return;
            } catch (retryError) {
                alert(retryError.message);
            }
        } else {
            alert(error.message);
        }
        
        messageInput.value = body;
    }
}

// ==================== WEBSOCKET ====================

function connectChatWebSocket(chatId) {
    // Close any existing connection
    closeChatWebSocket();

    if (!authToken) return;

    const url = `${WS_BASE}/chat/ws/${chatId}?token=${encodeURIComponent(authToken)}&device_id=${encodeURIComponent(deviceId)}`;
    chatSocket = new WebSocket(url);

    chatSocket.addEventListener('open', () => {
        console.log(`WS connected to chat ${chatId}`);
    });

    chatSocket.addEventListener('message', async (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'history') {
                // Full history payload – render it
                await handleHistoryPayload(data);
            } else if (data.type === 'new_message') {
                // Single new message pushed from server
                await handleNewMessagePayload(data.message);
            } else if (data.type === 'pong') {
                // heartbeat ack – ignore
            }
        } catch (err) {
            console.error('WS message handling error:', err);
        }
    });

    chatSocket.addEventListener('close', (evt) => {
        console.log(`WS closed (code=${evt.code})`);
        chatSocket = null;
        // Reconnect unless we intentionally closed, auth failed (4001), or chat not found (4004)
        if (evt.code !== 4001 && evt.code !== 4004 && currentChatId === chatId && authToken) {
            wsReconnectTimer = setTimeout(() => connectChatWebSocket(chatId), 3000);
        }
    });

    chatSocket.addEventListener('error', (err) => {
        console.error('WS error:', err);
    });

    // Heartbeat every 30s to keep connection alive
    startWsHeartbeat();
}

function closeChatWebSocket() {
    if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }
    stopWsHeartbeat();
    if (chatSocket) {
        chatSocket.close();
        chatSocket = null;
    }
}

let wsHeartbeatTimer = null;

function startWsHeartbeat() {
    stopWsHeartbeat();
    wsHeartbeatTimer = setInterval(() => {
        if (chatSocket && chatSocket.readyState === WebSocket.OPEN) {
            chatSocket.send(JSON.stringify({ type: 'ping' }));
        }
    }, 30000);
}

function stopWsHeartbeat() {
    if (wsHeartbeatTimer) {
        clearInterval(wsHeartbeatTimer);
        wsHeartbeatTimer = null;
    }
}

// Handle initial history payload from WS
async function handleHistoryPayload(data) {
    if (!currentChatPeer) return;

    const messages = data.messages || [];

    // Fetch epoch keys for all epochs referenced
    const epochIds = new Set(messages.map(m => m.epoch_id));
    for (const epochId of epochIds) {
        if (!KeyStore.getEpochKey(currentChatId, epochId)) {
            try {
                await fetchEpochKey(currentChatId, epochId, currentChatPeer);
            } catch (e) {
                console.error(`Failed to fetch epoch ${epochId}:`, e);
            }
        }
    }

    const decrypted = await decryptMessageBatch(messages);
    renderMessages(decrypted);
}

// Handle a single new_message pushed over WS
async function handleNewMessagePayload(msg) {
    if (!currentChatPeer) return;

    // Ensure we have the epoch key
    if (!KeyStore.getEpochKey(currentChatId, msg.epoch_id)) {
        try {
            await fetchEpochKey(currentChatId, msg.epoch_id, currentChatPeer);
        } catch (e) {
            console.error(`Failed to fetch epoch ${msg.epoch_id}:`, e);
        }
    }

    const epochKey = KeyStore.getEpochKey(currentChatId, msg.epoch_id);
    let body;
    if (epochKey) {
        try {
            body = await Crypto.decryptMessage(msg.ciphertext, msg.nonce, epochKey);
        } catch (e) {
            console.error('Failed to decrypt message:', e);
            body = '[Decryption failed]';
        }
    } else {
        body = '[Missing epoch key]';
    }

    appendMessage({ ...msg, body });
}

// Decrypt a batch of raw messages
async function decryptMessageBatch(messages) {
    const decrypted = [];
    for (const msg of messages) {
        const epochKey = KeyStore.getEpochKey(currentChatId, msg.epoch_id);
        if (epochKey) {
            try {
                const plaintext = await Crypto.decryptMessage(msg.ciphertext, msg.nonce, epochKey);
                decrypted.push({ ...msg, body: plaintext });
            } catch (e) {
                console.error('Failed to decrypt message:', e);
                decrypted.push({ ...msg, body: '[Decryption failed]' });
            }
        } else {
            decrypted.push({ ...msg, body: '[Missing epoch key]' });
        }
    }
    return decrypted;
}

// Append a single decrypted message to the chat view
function appendMessage(msg) {
    const isSent = msg.sender_id === currentUserId;
    const div = document.createElement('div');
    div.className = `message ${isSent ? 'sent' : 'received'}`;
    div.dataset.msgId = msg.id;
    div.dataset.senderId = msg.sender_id;

    const time = parseUTCDate(msg.created_at).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit'
    });

    let replyHtml = '';
    if (msg.reply_id) {
        // Try to find the reply target from already-rendered messages
        const allRendered = messagesContainer.querySelectorAll('.message');
        let replySender = 'Reply';
        let replyText = '';
        for (const el of allRendered) {
            if (parseInt(el.dataset.msgId) === msg.reply_id) {
                replySender = el.dataset.senderId == currentUserId ? 'You' : (currentChatPeer || 'User');
                replyText = el.querySelector('.text')?.textContent || '';
                break;
            }
        }
        replyHtml = `
            <div class="reply-snippet">
                <div class="reply-snippet-label">${escapeHtml(replySender)}</div>
                ${replyText ? `<div class="reply-snippet-text">${escapeHtml(getReplyPreviewText(replyText, 140))}</div>` : ''}
            </div>
        `;
    }

    div.innerHTML = `
        ${replyHtml}
        <div class="text">${escapeHtml(msg.body)}</div>
        <div class="time">${time}</div>
    `;

    const actions = document.createElement('div');
    actions.className = 'message-actions';
    const replyBtn = document.createElement('button');
    replyBtn.type = 'button';
    replyBtn.className = 'reply-btn';
    replyBtn.title = 'Reply';
    replyBtn.innerHTML = '<i class="fa-solid fa-reply"></i>';
    replyBtn.addEventListener('click', (event) => {
        event.stopPropagation();
        setReplyTarget(msg);
    });
    actions.appendChild(replyBtn);
    div.appendChild(actions);

    messagesContainer.appendChild(div);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// ==================== ACCOUNT SECTION ====================

function updateAccountSection() {
    const accountSection = document.getElementById('account-section');
    const accountPfp = document.getElementById('account-pfp');
    const accountUsername = document.getElementById('account-username');
    
    if (currentUsername) {
        const firstLetter = currentUsername.charAt(0).toUpperCase();
        accountPfp.textContent = firstLetter;
        accountPfp.style.backgroundColor = getColorForLetter(firstLetter);
        accountUsername.textContent = currentUsername;
    }
}

function getColorForLetter(letter) {
    const colors = [
        '#e94560', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4',
        '#ffeaa7', '#dfe6e9', '#a29bfe', '#fd79a8', '#00b894'
    ];
    const index = letter.charCodeAt(0) % colors.length;
    return colors[index];
}

function getDeviceIcon(userAgent) {
    if (!userAgent) return '<i class="fa-solid fa-desktop"></i>';
    const ua = userAgent.toLowerCase();
    
    // Mobile devices
    if (ua.includes('iphone') || ua.includes('ipad')) return '<i class="fa-solid fa-mobile-screen"></i>';
    if (ua.includes('android')) return '<i class="fa-solid fa-mobile-screen"></i>';
    
    // Desktop OS
    if (ua.includes('windows')) return '<i class="fa-brands fa-windows"></i>';
    if (ua.includes('macintosh') || ua.includes('mac os')) return '<i class="fa-brands fa-apple"></i>';
    if (ua.includes('linux')) return '<i class="fa-brands fa-linux"></i>';
    
    return '<i class="fa-solid fa-desktop"></i>';
}

function getDeviceName(userAgent) {
    if (!userAgent) return 'Unknown Device';
    const ua = userAgent.toLowerCase();
    
    if (ua.includes('iphone')) return 'iPhone';
    if (ua.includes('ipad')) return 'iPad';
    if (ua.includes('android')) return 'Android';
    if (ua.includes('windows')) return 'Windows';
    if (ua.includes('macintosh') || ua.includes('mac os')) return 'macOS';
    if (ua.includes('linux')) return 'Linux';
    
    return 'Unknown Device';
}

async function openAccountModal() {
    const modal = document.getElementById('account-modal');
    modal.classList.remove('hidden');
    await loadSessions();
}

function closeAccountModal() {
    const modal = document.getElementById('account-modal');
    if (modal) modal.classList.add('hidden');
}

async function loadSessions() {
    const sessionsList = document.getElementById('sessions-list');
    sessionsList.innerHTML = '<div class="loading-sessions">Loading sessions...</div>';
    
    try {
        const sessions = await apiCall('/users/sessions');
        renderSessions(sessions);
    } catch (error) {
        sessionsList.innerHTML = '<div class="error-sessions">Failed to load sessions</div>';
        console.error('Failed to load sessions:', error);
    }
}

function renderSessions(sessions) {
    const sessionsList = document.getElementById('sessions-list');
    sessionsList.innerHTML = '';
    
    sessions.forEach(session => {
        const item = document.createElement('div');
        item.className = 'session-item' + (session.current ? ' current' : '');
        
        const icon = getDeviceIcon(session.user_agent);
        const deviceName = getDeviceName(session.user_agent);
        const lastAccessed = parseUTCDate(session.last_accessed).toLocaleString([], {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        
        item.innerHTML = `
            <div class="session-info">
                <span class="session-icon">${icon}</span>
                <div class="session-details">
                    <span class="session-device">${deviceName}${session.current ? ' (Current)' : ''}</span>
                    <span class="session-time">Last active: ${lastAccessed}</span>
                </div>
            </div>
            ${!session.current ? `<button class="btn small revoke-btn" data-session-id="${session.id}">Revoke</button>` : ''}
        `;
        
        sessionsList.appendChild(item);
    });
    
    // Add event listeners to revoke buttons
    document.querySelectorAll('.revoke-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const sessionId = e.target.dataset.sessionId;
            await revokeSession(sessionId);
        });
    });
}

async function revokeSession(sessionId) {
    try {
        await apiCall(`/users/sessions/revoke/${sessionId}`, { method: 'DELETE' });
        await loadSessions();
    } catch (error) {
        alert('Failed to revoke session: ' + error.message);
    }
}

async function revokeOtherSessions() {
    if (!confirm('Are you sure you want to log out of all other sessions?')) return;
    
    try {
        await apiCall('/users/sessions/revoke_other', { method: 'DELETE' });
        await loadSessions();
    } catch (error) {
        alert('Failed to revoke other sessions: ' + error.message);
    }
}

// ==================== REPLY UI ====================

function getSenderLabel(senderId) {
    if (senderId === currentUserId) return 'You';
    return currentChatPeer || 'User';
}

function getReplyPreviewText(text, limit = 180) {
    if (!text) return '';
    const trimmed = text.trim();
    if (trimmed.length <= limit) return trimmed;
    return `${trimmed.slice(0, limit)}...`;
}

function setReplyTarget(message) {
    currentReplyMessage = {
        id: message.id,
        sender_id: message.sender_id,
        body: message.body
    };

    replyUsername.textContent = getSenderLabel(message.sender_id);
    replyPreview.textContent = getReplyPreviewText(message.body);
    replyBar.classList.remove('hidden');
}

function clearReplyTarget() {
    currentReplyMessage = null;
    replyUsername.textContent = 'User';
    replyPreview.textContent = '';
    replyBar.classList.add('hidden');
}

// ==================== UTILITY FUNCTIONS ====================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function parseUTCDate(dateString) {
    // Server returns UTC timestamps without Z suffix
    // Append Z to ensure it's parsed as UTC
    if (dateString && !dateString.endsWith('Z') && !dateString.includes('+')) {
        return new Date(dateString + 'Z');
    }
    return new Date(dateString);
}
