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
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
        if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

app.use('/wagateway', cors(corsOptions));

// Trust proxy for rate limiting behind Nginx/Cloudflare
app.set('trust proxy', 1);

// Login Specific Rate Limiter
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts, please try again later.'
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'wagarda-secret-session',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000,
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
            res.send('Invalid username or password. <a href="/login">Try again</a>');
        }
    } catch (error) {
        console.error(error);
        if (error.message.includes('Account locked')) {
            res.status(429).send(`${error.message} <a href="/login">Go back</a>`);
        } else {
            res.status(500).send('Internal Server Error');
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

const PORT = process.env.PORT || 10000;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    init();
});
