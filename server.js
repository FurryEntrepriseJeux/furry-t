'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');

const port = Number(process.env.PORT || 8787);
const host = process.env.HOST || '127.0.0.1';
const dataPath = process.env.FURRY_DATA_PATH || path.join(__dirname, 'data', 'accounts.json');
const bootstrapKey = process.env.BOOTSTRAP_ADMIN_KEY || '';
const supportedCultures = new Set(['fr-FR', 'en-US']);
const sessions = new Map();
const loginAttempts = new Map();
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const passwordIterations = 310000;

class ApiError extends Error {
    constructor(status, message) {
        super(message);
        this.status = status;
    }
}

function loadStore() {
    if (!fs.existsSync(dataPath)) {
        return { users: [], settings: { defaultLanguageCulture: 'fr-FR' } };
    }

    try {
        const parsed = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
        return {
            users: Array.isArray(parsed.users) ? parsed.users : [],
            settings: {
                defaultLanguageCulture: supportedCultures.has(parsed.settings?.defaultLanguageCulture)
                    ? parsed.settings.defaultLanguageCulture
                    : 'fr-FR'
            }
        };
    } catch {
        throw new Error('Account database is unreadable; refusing to overwrite it.');
    }
}

function saveStore(store) {
    fs.mkdirSync(path.dirname(dataPath), { recursive: true });
    const temporaryPath = `${dataPath}.${process.pid}.tmp`;
    fs.writeFileSync(temporaryPath, JSON.stringify(store, null, 2), { mode: 0o600 });
    fs.renameSync(temporaryPath, dataPath);
}

function safeUser(user) {
    return {
        id: user.id,
        userName: user.userName,
        languageCulture: user.languageCulture,
        isAdmin: Boolean(user.isAdmin),
        enabled: Boolean(user.enabled),
        createdAt: user.createdAt
    };
}

function validateUserName(value) {
    const userName = String(value || '').trim();
    if (userName.length < 3 || userName.length > 32) {
        throw new ApiError(400, 'Le nom doit contenir entre 3 et 32 caractères.');
    }
    return userName;
}

function validatePassword(value) {
    const password = String(value || '');
    if (password.length < 8 || password.length > 256) {
        throw new ApiError(400, 'Le mot de passe doit contenir entre 8 et 256 caractères.');
    }
    return password;
}

function createUser(store, userName, password, isAdmin) {
    const normalizedName = validateUserName(userName);
    const validPassword = validatePassword(password);
    if (store.users.some((user) => user.userName.toLowerCase() === normalizedName.toLowerCase())) {
        throw new ApiError(409, 'Ce nom d’utilisateur existe déjà.');
    }

    const salt = crypto.randomBytes(16);
    const passwordHash = crypto.pbkdf2Sync(validPassword, salt, passwordIterations, 32, 'sha256');
    const user = {
        id: crypto.randomUUID(),
        userName: normalizedName,
        passwordSalt: salt.toString('base64'),
        passwordHash: passwordHash.toString('base64'),
        passwordIterations,
        passwordAlgorithm: 'pbkdf2-sha256',
        languageCulture: store.settings.defaultLanguageCulture,
        isAdmin: Boolean(isAdmin),
        enabled: true,
        createdAt: new Date().toISOString()
    };
    store.users.push(user);
    return user;
}

function passwordsMatch(user, password) {
    try {
        const salt = Buffer.from(user.passwordSalt, 'base64');
        const expected = Buffer.from(user.passwordHash, 'base64');
        const actual = crypto.pbkdf2Sync(password, salt, user.passwordIterations, expected.length, 'sha256');
        return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
    } catch {
        return false;
    }
}

function issueSession(user) {
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(token, { userId: user.id, expiresAt: Date.now() + sessionLifetimeMs });
    return token;
}

function requestIp(request) {
    return request.socket.remoteAddress || 'unknown';
}

function enforceLoginLimit(request) {
    const ip = requestIp(request);
    const recent = (loginAttempts.get(ip) || []).filter((time) => Date.now() - time < 10 * 60 * 1000);
    if (recent.length >= 10) {
        loginAttempts.set(ip, recent);
        throw new ApiError(429, 'Trop de tentatives. Réessaie dans quelques minutes.');
    }
    loginAttempts.set(ip, recent);
}

function recordFailedLogin(request) {
    const ip = requestIp(request);
    const recent = (loginAttempts.get(ip) || []).filter((time) => Date.now() - time < 10 * 60 * 1000);
    recent.push(Date.now());
    loginAttempts.set(ip, recent);
}

function getAuthenticatedUser(request, requireAdmin = false) {
    const authorization = String(request.headers.authorization || '');
    const match = authorization.match(/^Bearer ([A-Za-z0-9_-]+)$/);
    if (!match) {
        throw new ApiError(401, 'Connexion requise.');
    }

    const session = sessions.get(match[1]);
    if (!session || session.expiresAt <= Date.now()) {
        sessions.delete(match[1]);
        throw new ApiError(401, 'Session expirée. Reconnecte-toi.');
    }

    const user = loadStore().users.find((item) => item.id === session.userId && item.enabled);
    if (!user) {
        sessions.delete(match[1]);
        throw new ApiError(401, 'Compte désactivé.');
    }
    if (requireAdmin && !user.isAdmin) {
        throw new ApiError(403, 'Droits administrateur requis.');
    }
    return user;
}

function timingSafeStringEquals(first, second) {
    const left = Buffer.from(String(first));
    const right = Buffer.from(String(second));
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function send(response, status, value) {
    const body = value === undefined ? '' : JSON.stringify(value);
    response.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Length': Buffer.byteLength(body)
    });
    response.end(body);
}

function readJson(request) {
    return new Promise((resolve, reject) => {
        let body = '';
        request.setEncoding('utf8');
        request.on('data', (chunk) => {
            body += chunk;
            if (Buffer.byteLength(body, 'utf8') > 16384) {
                reject(new ApiError(413, 'Requête trop volumineuse.'));
                request.destroy();
            }
        });
        request.on('end', () => {
            if (!body) {
                resolve({});
                return;
            }
            try {
                resolve(JSON.parse(body));
            } catch {
                reject(new ApiError(400, 'JSON invalide.'));
            }
        });
        request.on('error', reject);
    });
}

function isSecureRequest(request) {
    return Boolean(request.socket.encrypted) || request.headers['x-forwarded-proto'] === 'https';
}

function storeSettings() {
    return loadStore().settings;
}

async function route(request, response) {
    if (process.env.NODE_ENV === 'production' && !isSecureRequest(request)) {
        throw new ApiError(426, 'HTTPS obligatoire.');
    }

    const url = new URL(request.url, 'http://localhost');
    const pathname = decodeURIComponent(url.pathname);
    const method = request.method;

    if (method === 'GET' && pathname === '/api/health') {
        send(response, 200, { ok: true });
        return;
    }

    if (method === 'GET' && pathname === '/api/setup/status') {
        const store = loadStore();
        send(response, 200, { hasActiveAdmin: store.users.some((user) => user.isAdmin && user.enabled) });
        return;
    }

    if (method === 'POST' && pathname === '/api/bootstrap') {
        const body = await readJson(request);
        const store = loadStore();
        if (store.users.some((user) => user.isAdmin && user.enabled)) {
            throw new ApiError(409, 'Un administrateur actif existe déjà.');
        }
        if (!bootstrapKey || !timingSafeStringEquals(body.bootstrapKey, bootstrapKey)) {
            throw new ApiError(403, 'Clé de configuration invalide.');
        }
        const user = createUser(store, body.userName, body.password, true);
        saveStore(store);
        send(response, 201, { user: safeUser(user) });
        return;
    }

    if (method === 'POST' && pathname === '/api/register') {
        const body = await readJson(request);
        const store = loadStore();
        const user = createUser(store, body.userName, body.password, false);
        saveStore(store);
        send(response, 201, { token: issueSession(user), user: safeUser(user) });
        return;
    }

    if (method === 'POST' && pathname === '/api/auth/login') {
        enforceLoginLimit(request);
        const body = await readJson(request);
        const store = loadStore();
        const user = store.users.find((item) => item.userName.toLowerCase() === String(body.userName || '').trim().toLowerCase());
        if (!user || !user.enabled || !passwordsMatch(user, String(body.password || ''))) {
            recordFailedLogin(request);
            throw new ApiError(401, 'Nom d’utilisateur ou mot de passe incorrect.');
        }
        loginAttempts.delete(requestIp(request));
        send(response, 200, { token: issueSession(user), user: safeUser(user) });
        return;
    }

    if (method === 'GET' && pathname === '/api/me') {
        send(response, 200, { user: safeUser(getAuthenticatedUser(request)) });
        return;
    }

    if (method === 'PATCH' && pathname === '/api/me/language') {
        const user = getAuthenticatedUser(request);
        const body = await readJson(request);
        if (!supportedCultures.has(body.languageCulture)) {
            throw new ApiError(400, 'Langue non prise en charge.');
        }
        const store = loadStore();
        const storedUser = store.users.find((item) => item.id === user.id);
        storedUser.languageCulture = body.languageCulture;
        saveStore(store);
        send(response, 200, { user: safeUser(storedUser) });
        return;
    }

    if (method === 'GET' && pathname === '/api/admin/users') {
        getAuthenticatedUser(request, true);
        send(response, 200, { users: loadStore().users.map(safeUser) });
        return;
    }

    if (method === 'POST' && pathname === '/api/admin/users') {
        getAuthenticatedUser(request, true);
        const body = await readJson(request);
        const store = loadStore();
        const user = createUser(store, body.userName, body.password, Boolean(body.isAdmin));
        saveStore(store);
        send(response, 201, { user: safeUser(user) });
        return;
    }

    if (method === 'GET' && pathname === '/api/admin/settings') {
        getAuthenticatedUser(request, true);
        send(response, 200, storeSettings());
        return;
    }

    if (method === 'PUT' && pathname === '/api/admin/settings') {
        getAuthenticatedUser(request, true);
        const body = await readJson(request);
        if (!supportedCultures.has(body.defaultLanguageCulture)) {
            throw new ApiError(400, 'Langue par défaut non prise en charge.');
        }
        const store = loadStore();
        store.settings.defaultLanguageCulture = body.defaultLanguageCulture;
        saveStore(store);
        send(response, 200, store.settings);
        return;
    }

    const userRoute = pathname.match(/^\/api\/admin\/users\/([A-Za-z0-9-]+)$/);
    if (userRoute && method === 'PATCH') {
        getAuthenticatedUser(request, true);
        const body = await readJson(request);
        const store = loadStore();
        const user = store.users.find((item) => item.id === userRoute[1]);
        if (!user) {
            throw new ApiError(404, 'Compte introuvable.');
        }

        if (body.action === 'enabled') {
            if (!body.enabled && user.isAdmin && store.users.filter((item) => item.isAdmin && item.enabled).length <= 1) {
                throw new ApiError(409, 'Il faut conserver au moins un administrateur actif.');
            }
            user.enabled = Boolean(body.enabled);
        } else if (body.action === 'resetPassword') {
            const password = validatePassword(body.password);
            const salt = crypto.randomBytes(16);
            const hash = crypto.pbkdf2Sync(password, salt, passwordIterations, 32, 'sha256');
            user.passwordSalt = salt.toString('base64');
            user.passwordHash = hash.toString('base64');
            user.passwordIterations = passwordIterations;
            user.passwordAlgorithm = 'pbkdf2-sha256';
        } else {
            throw new ApiError(400, 'Action de compte inconnue.');
        }

        saveStore(store);
        send(response, 200, { user: safeUser(user) });
        return;
    }

    if (userRoute && method === 'DELETE') {
        getAuthenticatedUser(request, true);
        const store = loadStore();
        const user = store.users.find((item) => item.id === userRoute[1]);
        if (!user) {
            throw new ApiError(404, 'Compte introuvable.');
        }
        if (user.isAdmin && store.users.filter((item) => item.isAdmin && item.enabled).length <= 1) {
            throw new ApiError(409, 'Il faut conserver au moins un administrateur actif.');
        }
        store.users = store.users.filter((item) => item.id !== user.id);
        saveStore(store);
        for (const [token, session] of sessions) {
            if (session.userId === user.id) {
                sessions.delete(token);
            }
        }
        send(response, 204);
        return;
    }

    throw new ApiError(404, 'Route introuvable.');
}

const handler = (request, response) => {
    route(request, response).catch((error) => {
        if (response.headersSent || response.destroyed) {
            return;
        }
        const status = error instanceof ApiError ? error.status : 500;
        if (status >= 500) {
            console.error(error.message);
            send(response, status, { error: 'Erreur interne du serveur.' });
        } else {
            send(response, status, { error: error.message });
        }
    });
};

let server;
const certificatePath = process.env.TLS_CERT_PATH;
const keyPath = process.env.TLS_KEY_PATH;
if (Boolean(certificatePath) !== Boolean(keyPath)) {
    throw new Error('TLS_CERT_PATH and TLS_KEY_PATH must both be configured.');
}
if (certificatePath && keyPath) {
    server = https.createServer({ cert: fs.readFileSync(certificatePath), key: fs.readFileSync(keyPath) }, handler);
} else {
    server = http.createServer(handler);
}

server.listen(port, host, () => {
    console.log(`Furry account API listening on ${host}:${port}`);
});
