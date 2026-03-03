const express = require('express');
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./swagger');
const { init, startCon, isValidDeviceId } = require('./connection');
const { authenticateUser, getApiKeys, createApiKey, deleteApiKey } = require('./database');

require('dotenv').config();

const app = express();
const server = http.createServer(app);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

function isAllowedOrigin(origin, req, allowNoOrigin = false) {
    if (!origin) return allowNoOrigin;
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return true;

    try {
        const host = req.headers['x-forwarded-host'] || req.headers.host;
        return Boolean(host && new URL(origin).host === host);
    } catch (e) {
        return false;
    }
}

const io = new Server(server, {
    cors: {
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true
    },
    allowRequest: (req, callback) => {
        if (isAllowedOrigin(req.headers.origin, req, true)) {
            return callback(null, true);
        }
        return callback('Not allowed by CORS', false);
    }
});

const parsedParameterLimit = Number.parseInt(process.env.PARAMETER_LIMIT || '1000', 10);
const parameterLimit = Number.isFinite(parsedParameterLimit) && parsedParameterLimit > 0 ? parsedParameterLimit : 1000;
const bodyLimit = process.env.BODY_LIMIT || '1mb';

app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: true, limit: bodyLimit, parameterLimit }));

// Apply Helmet for basic security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'", 'ws:', 'wss:']
        }
    }
}));

// Trust proxy for rate limiting and secure cookies behind Nginx/Cloudflare
app.set('trust proxy', 1);

// Global Rate Limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: 'Too many requests from this IP, please try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false
});
app.use(globalLimiter);

// Strict CORS Policy for API Routes
const corsOptionsDelegate = (req, callback) => {
    const corsOptions = {
        methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
        credentials: true,
        origin: false
    };

    const origin = req.header('Origin');
    if (!origin) {
        return callback(null, corsOptions);
    }

    if (isAllowedOrigin(origin, req, false)) {
        corsOptions.origin = true;
        return callback(null, corsOptions);
    }

    return callback(new Error('Not allowed by CORS'));
};

app.use('/wagateway', cors(corsOptionsDelegate));

// Login Specific Rate Limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts, please try again later.'
});

const isProduction = process.env.NODE_ENV === 'production';
if (isProduction && !process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET is required when NODE_ENV=production');
}

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
    console.warn('[SECURITY] SESSION_SECRET is not set. Generated ephemeral secret for this process.');
}

const sessionMiddleware = session({
    store: new SQLiteStore({
        db: 'wagarda.db',
        dir: './',
        table: 'sessions'
    }),
    secret: sessionSecret,
    name: 'wagarda.sid',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax',
        secure: 'auto'
    }
});

app.use(sessionMiddleware);
app.use(express.static('public'));

// Middleware to check if user is logged in
const requireAuth = (req, res, next) => {
    if (req.session && req.session.user) {
        return next();
    }
    return res.redirect('/login');
};

const enableApiDocs = process.env.ENABLE_API_DOCS === 'true' || !isProduction;
if (enableApiDocs) {
    app.use('/api-docs', requireAuth, swaggerUi.serve, swaggerUi.setup(swaggerSpec));
}

const router = express.Router();

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');

    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }

    const loginHtml = fs.readFileSync(`${__dirname}/login.html`, 'utf8');
    const htmlWithCsrf = loginHtml.replace('</form>', `<input type="hidden" name="csrfToken" value="${req.session.csrfToken}"></form>`);
    return res.send(htmlWithCsrf);
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password, csrfToken } = req.body;

    if (!req.session.csrfToken || !csrfToken || csrfToken !== req.session.csrfToken) {
        return res.redirect('/login');
    }

    try {
        const user = await authenticateUser(username, password, req.ip);
        if (user) {
            req.session.user = user;
            req.session.csrfToken = crypto.randomBytes(32).toString('hex');
            return res.redirect('/');
        }
        return res.redirect('/login?error=1');
    } catch (error) {
        console.error(error);
        if (error.message && error.message.includes('Account locked')) {
            return res.redirect('/login?error=locked');
        }
        return res.redirect('/login?error=1');
    }
});

// API Key Management Routes for UI
app.get('/api/keys', requireAuth, async (req, res) => {
    try {
        const keys = await getApiKeys();
        return res.json(keys);
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.post('/api/keys', requireAuth, async (req, res) => {
    try {
        const newKey = `wagarda-${crypto.randomBytes(16).toString('hex')}`;
        const descInput = typeof req.body.description === 'string' ? req.body.description.trim() : '';
        const desc = descInput.slice(0, 120) || 'Generated Key via UI';
        createApiKey(newKey, desc);
        return res.json({ success: true, key: newKey });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.delete('/api/keys/:id', requireAuth, async (req, res) => {
    try {
        const success = await deleteApiKey(req.params.id);
        return res.json({ success });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    return res.redirect('/login');
});

app.get('/', requireAuth, (req, res) => {
    res.sendFile(`${__dirname}/index.html`);
});

app.get('/logs-view', requireAuth, (req, res) => {
    res.sendFile(`${__dirname}/logs.html`);
});

app.use(router);
require('./routes')(router);

io.engine.use(sessionMiddleware);

io.use((socket, next) => {
    if (socket.request.session && socket.request.session.user) {
        return next();
    }
    return next(new Error('Unauthorized'));
});

io.on('connection', (socket) => {
    socket.on('StartConnection', async (device) => {
        if (!isValidDeviceId(device)) {
            socket.emit('connection-status', { device: null, status: 'invalid-device-id' });
            return;
        }
        try {
            await startCon(device, socket);
        } catch (error) {
            console.error('StartConnection error:', error);
            socket.emit('connection-status', { device, status: 'error' });
        }
    });

    socket.on('LogoutDevice', async (device) => {
        if (!isValidDeviceId(device)) {
            socket.emit('connection-status', { device: null, status: 'invalid-device-id' });
            return;
        }
        try {
            await startCon(device, socket, true);
        } catch (error) {
            console.error('LogoutDevice error:', error);
            socket.emit('connection-status', { device, status: 'error' });
        }
    });
});

// Global Error Handler to ensure API routes always return JSON instead of HTML
app.use((err, req, res, next) => {
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ status: false, msg: 'Not allowed by CORS' });
    }

    console.error('Unhandled Error:', err);
    if (!res.headersSent) {
        return res.status(500).json({ status: false, msg: 'Internal Server Error' });
    }
    return next(err);
});

const PORT = process.env.PORT || 10000;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    init();
});
