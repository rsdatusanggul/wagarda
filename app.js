const express = require('express');
const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
const { init, startCon, } = require('./connection');
const { authenticateUser, getApiKeys, createApiKey, deleteApiKey } = require('./database');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const qrcode = require('qrcode');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const cors = require('cors');
require('dotenv').config();

app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '50mb', parameterLimit: 1000000 }))

// Apply Helmet for basic security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "ws:", "wss:"],
        },
    },
}));

// Global Rate Limiter
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: 'Too many requests from this IP, please try again after 15 minutes',
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);

// Strict CORS Policy for API Routes
const corsOptionsDelegate = (req, callback) => {
    let corsOptions = {
        methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
        credentials: true
    };

    const origin = req.header('Origin');
    if (!origin) {
        corsOptions.origin = false;
        return callback(null, corsOptions);
    }

    const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
    let isAllowed = false;

    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
        isAllowed = true;
    } else {
        try {
            // Allow same origin requests when running behind a tunnel/proxy
            const host = req.get('x-forwarded-host') || req.get('host');
            if (host && new URL(origin).host === host) {
                isAllowed = true;
            }
        } catch (e) { }
    }

    if (isAllowed) {
        corsOptions.origin = true;
        callback(null, corsOptions);
    } else {
        // Return an error which will be caught by the global error handler
        callback(new Error('Not allowed by CORS'));
    }
};

app.use('/wagateway', cors(corsOptionsDelegate));

// Trust proxy for rate limiting behind Nginx/Cloudflare
app.set('trust proxy', 1);

// Login Specific Rate Limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts, please try again later.'
});

app.use(session({
    store: new SQLiteStore({
        db: 'wagarda.db',
        dir: './',
        table: 'sessions'
    }),
    secret: process.env.SESSION_SECRET || 'wagarda-secret-session',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 7 * 24 * 60 * 60 * 1000, // Extend to 7 days
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production'
    }
}));

app.use(express.static('public'))

const router = express.Router()

// Middleware to check if user is logged in
const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
};

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    // Generate a simple CSRF token
    if (!req.session.csrfToken) {
        req.session.csrfToken = require('crypto').randomBytes(32).toString('hex');
    }

    // Inject CSRF token into the login form
    const fs = require('fs');
    const loginHtml = fs.readFileSync(__dirname + '/login.html', 'utf8');
    const htmlWithCsrf = loginHtml.replace('</form>', `<input type="hidden" name="csrfToken" value="${req.session.csrfToken}"></form>`);
    res.send(htmlWithCsrf);
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
            req.session.csrfToken = require('crypto').randomBytes(32).toString('hex');
            res.redirect('/');
        } else {
            res.redirect('/login?error=1');
        }
    } catch (error) {
        console.error(error);
        if (error.message && error.message.includes('Account locked')) {
            res.redirect('/login?error=locked');
        } else {
            res.redirect('/login?error=1');
        }
    }
});

// API Key Management Routes for UI
app.get('/api/keys', requireAuth, async (req, res) => {
    try {
        const keys = await getApiKeys();
        res.json(keys);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/keys', requireAuth, async (req, res) => {
    try {
        const crypto = require('crypto');
        const newKey = 'wagarda-' + crypto.randomBytes(16).toString('hex');
        const desc = req.body.description || 'Generated Key via UI';
        createApiKey(newKey, desc);
        res.json({ success: true, key: newKey });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/keys/:id', requireAuth, async (req, res) => {
    try {
        const success = await deleteApiKey(req.params.id);
        res.json({ success });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/', requireAuth, (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

app.get('/logs-view', requireAuth, (req, res) => {
    res.sendFile(__dirname + '/logs.html');
});

app.use(router);

require('./routes')(router)

io.on('connection', (socket) => {
    socket.on('StartConnection', async (device) => {
        startCon(device, socket)
        return;
    })
    socket.on('LogoutDevice', (device) => {
        startCon(device, socket, true)
        return
    })
})

// Global Error Handler to ensure API routes always return JSON instead of HTML
app.use((err, req, res, next) => {
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ status: false, msg: 'Not allowed by CORS' });
    }

    console.error('Unhandled Error:', err);
    if (!res.headersSent) {
        res.status(500).json({ status: false, msg: 'Internal Server Error' });
    }
});

const PORT = process.env.PORT || 10000;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    init();
});
