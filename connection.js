const P = require('pino')
const {
    default: makeWASocket,
    DisconnectReason,
    useMultiFileAuthState,
    fetchLatestBaileysVersion
} = require("@whiskeysockets/baileys");
const fs = require('fs');
const path = require('path');
const qrcode = require('qrcode');

const sessions = new Map();
const SESSIONS_DIR = path.resolve(__dirname, 'sessions');
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

function isValidDeviceId(deviceId) {
    return typeof deviceId === 'string' && DEVICE_ID_PATTERN.test(deviceId);
}

function assertValidDeviceId(deviceId) {
    if (!isValidDeviceId(deviceId)) {
        throw new Error('Invalid device id');
    }
    return deviceId;
}

function getSessionDir(deviceId) {
    const safeDeviceId = assertValidDeviceId(deviceId);
    const sessionDir = path.resolve(SESSIONS_DIR, safeDeviceId);
    if (!sessionDir.startsWith(`${SESSIONS_DIR}${path.sep}`)) {
        throw new Error('Invalid session path');
    }
    return sessionDir;
}

function ensureSessionsDir() {
    if (!fs.existsSync(SESSIONS_DIR)) {
        fs.mkdirSync(SESSIONS_DIR, { recursive: true });
    }
}

const startCon = async (device, socket = undefined, logout = undefined) => {
    const safeDevice = assertValidDeviceId(device);
    ensureSessionsDir();
    const sessionDir = getSessionDir(safeDevice);

    const { state, saveCreds } = await useMultiFileAuthState(sessionDir)

    // Fetch latest version of WA Web
    const { version, isLatest } = await fetchLatestBaileysVersion()
    console.log(`using WA v${version.join('.')}, isLatest: ${isLatest}`)

    const sock = makeWASocket({
        auth: state,
        version: version,
        logger: P({ level: 'silent' }),
        printQRInTerminal: false,
        browser: ['Ubuntu', 'Chrome', '20.0.04'],
        connectTimeoutMs: 60000,
        keepAliveIntervalMs: 10000,
        syncFullHistory: false
    })


    sock.ev.on("connection.update", async (update) => {
        const { qr, connection, lastDisconnect } = update
        if (connection === 'close') {
            const statusCode = (lastDisconnect.error)?.output?.statusCode;
            const shouldReconnect = statusCode !== DisconnectReason.loggedOut;

            console.log('connection closed due to ', lastDisconnect.error, ', reconnecting ', shouldReconnect)

            if (shouldReconnect) {
                // Reconnect dengan delay
                setTimeout(() => {
                    startCon(safeDevice, socket)
                }, 3000)
            } else if (statusCode === DisconnectReason.loggedOut) {
                if (socket) socket.emit('Unauthorized');
                if (fs.existsSync(sessionDir)) {
                    fs.rmSync(sessionDir, { recursive: true, force: true });
                    sessions.delete(safeDevice);
                    if (socket) socket.emit("message", "logout device " + safeDevice);
                }
            }
            if (socket) socket.emit('connection-status', { device: safeDevice, status: 'close' });

        } else if (connection === 'open') {

            if (socket !== undefined) socket.emit('connection-status', { device: safeDevice, status: 'open', user: sock.user });
            if (logout) {
                sock.logout().then(() => {
                    sessions.delete(safeDevice);
                    if (fs.existsSync(sessionDir)) {
                        fs.rmSync(sessionDir, { recursive: true, force: true });
                    }
                    socket.emit('Proccess')
                })
                return
            }

        }
        if (qr) {
            qrcode.toDataURL(qr, (err, url) => {
                if (err) console.log(err);
                if (socket !== undefined) socket.emit('qr', { device: safeDevice, qr: url });
            })
        }
    })
    sock.ev.on('creds.update', saveCreds)

    sessions.set(safeDevice, sock);

    return {
        conn: sock,
        state: state
    }

}

const init = async () => {
    ensureSessionsDir();
    const entries = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true });
    entries
        .filter(entry => entry.isDirectory() && isValidDeviceId(entry.name))
        .forEach(entry => {
            const device = entry.name;
            const credsPath = path.join(getSessionDir(device), 'creds.json');
            if (fs.existsSync(credsPath)) {
                startCon(device);
                console.log(`Success initialize ${device} Device`);
            }
        });
}

const getSession = (device) => {
    return sessions.get(device);
}

module.exports = {
    startCon,
    init,
    getSession,
    sessions,
    isValidDeviceId,
    getSessionDir
}
