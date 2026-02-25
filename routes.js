
const { sendMessage, sendBulkMessage } = require('./message')
const { getLogs, validateApiKey } = require('./database')
const { sessions, startCon } = require('./connection')
const { body } = require('express-validator')
const fs = require('fs');

const authenticate = async (req, res, next) => {
    // Allow access if logged in via Web UI (Admin Session override)
    if (req.session && req.session.user) {
        return next();
    }

    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey) {
        return res.status(401).json({ status: false, msg: 'API Key is missing or unauthorized' });
    }

    try {
        const key = await validateApiKey(apiKey);
        if (!key) {
            return res.status(403).json({ status: false, msg: 'Invalid API Key' });
        }
        next();
    } catch (err) {
        console.error(err);
        return res.status(500).json({ status: false, msg: 'Internal Server Error' });
    }
};

module.exports = function (router) {

    router.use('/wagateway/*', authenticate);

    /**
     * @swagger
     * /wagateway/kirimpesan:
     *   post:
     *     summary: Send a text message
     *     tags: [Messages]
     *     security:
     *       - ApiKeyAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required:
     *               - sender
     *               - number
     *               - message
     *             properties:
     *               sender:
     *                 type: string
     *                 description: Device ID to send from
     *               number:
     *                 type: string
     *                 description: Recipient phone number (e.g., 628123456789)
     *               message:
     *                 type: string
     *                 description: Message content
     *     responses:
     *       200:
     *         description: Message sent successfully
     *       410:
     *         description: Failed to send message
     */
    router.post('/wagateway/kirimpesan', [
        body('sender', 'Wrong Parameters!').notEmpty().trim().escape(),
        body('number', 'Wrong Parameters!').notEmpty().trim().escape(),
        body('message', 'Wrong Parameters!').notEmpty().trim().escape()
    ], sendMessage)

    /**
     * @swagger
     * /wagateway/kirimgambar:
     *   post:
     *     summary: Send an image message
     *     tags: [Messages]
     *     security:
     *       - ApiKeyAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required:
     *               - sender
     *               - number
     *               - message
     *               - url
     *             properties:
     *               sender:
     *                 type: string
     *               number:
     *                 type: string
     *               message:
     *                 type: string
     *                 description: Image caption
     *               url:
     *                 type: string
     *                 description: Image URL
     *     responses:
     *       200:
     *         description: Image sent successfully
     */
    router.post('/wagateway/kirimgambar', [
        body('sender', 'Wrong Parameters!').notEmpty(),
        body('number', 'Wrong Parameters!').notEmpty(),
        body('message', 'Wrong Parameters!').notEmpty(),
        body('url', 'Wrong Parameters!').notEmpty(),
    ], sendMessage)

    /**
     * @swagger
     * /wagateway/kirimfile:
     *   post:
     *     summary: Send a document/file
     *     tags: [Messages]
     *     security:
     *       - ApiKeyAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required:
     *               - sender
     *               - number
     *               - url
     *             properties:
     *               sender:
     *                 type: string
     *               number:
     *                 type: string
     *               url:
     *                 type: string
     *                 description: File URL
     *     responses:
     *       200:
     *         description: File sent successfully
     */
    router.post('/wagateway/kirimfile', [
        body('sender', 'Wrong Parameters!').notEmpty(),
        body('number', 'Wrong Parameters!').notEmpty(),
        body('url', 'Wrong Parameters!').notEmpty(),
    ], sendMessage)

    /**
     * @swagger
     * /wagateway/blast:
     *   post:
     *     summary: Send bulk messages (Blast)
     *     tags: [Bulk]
     *     security:
     *       - ApiKeyAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required:
     *               - numbers
     *               - messages
     *             properties:
     *               numbers:
     *                 type: array
     *                 items:
     *                   type: string
     *               messages:
     *                 type: array
     *                 items:
     *                   type: string
     *               type:
     *                 type: string
     *                 enum: [text, image, document]
     *                 default: text
     *               url:
     *                 type: string
     *                 description: Required if type is image/document
     *     responses:
     *       200:
     *         description: Bulk process started
     */
    router.post('/wagateway/blast', [
        body('numbers', 'Wrong Parameters!').isArray(),
        body('messages', 'Wrong Parameters!').isArray(),
    ], sendBulkMessage)

    /**
     * @swagger
     * /wagateway/logs:
     *   get:
     *     summary: Get message logs
     *     tags: [Logs]
     *     security:
     *       - ApiKeyAuth: []
     *     responses:
     *       200:
     *         description: List of message logs
     */
    router.get('/wagateway/logs', (req, res) => {
        getLogs(100, (err, rows) => {
            if (err) {
                res.status(500).json({ status: false, msg: err.message });
            } else {
                res.json({ status: true, data: rows });
            }
        });
    });

    /**
     * @swagger
     * /wagateway/devices:
     *   get:
     *     summary: Get registered devices
     *     tags: [Devices]
     *     security:
     *       - ApiKeyAuth: []
     *     responses:
     *       200:
     *         description: List of devices and their status
     */
    router.get('/wagateway/devices', (req, res) => {
        const connectedDevices = [];

        // Baileys menyimpan sesi di folder ./sessions/DEVICEID
        const entries = fs.readdirSync('./sessions', { withFileTypes: true });
        const allDevices = entries
            .filter(entry => entry.isDirectory())
            .map(entry => entry.name);

        allDevices.forEach(device => {
            const conn = sessions.get(device);
            const isConnected = conn && conn.user; // Check if socket exists and user is defined (logged in)

            connectedDevices.push({
                device_id: device,
                status: isConnected ? 'connected' : 'disconnected',
                phone: isConnected ? conn.user.id.split(':')[0] : null,
                name: isConnected ? conn.user.name : null
            });
        });

        res.json({
            status: true,
            data: connectedDevices
        });
    });

    /**
     * @swagger
     * /wagateway/delete-device:
     *   post:
     *     summary: Delete a device
     *     tags: [Devices]
     *     security:
     *       - ApiKeyAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required:
     *               - device_id
     *             properties:
     *               device_id:
     *                 type: string
     *     responses:
     *       200:
     *         description: Device deleted successfully
     */
    router.post('/wagateway/delete-device', [
        body('device_id', 'Wrong Parameters!').notEmpty(),
    ], async (req, res) => {
        const { device_id } = req.body;
        await cleanupDevice(device_id, sessions, fs, res);
    });

    // REST-style DELETE endpoint used by the dashboard UI
    router.delete('/wagateway/device/:device_id', async (req, res) => {
        const { device_id } = req.params;
        await cleanupDevice(device_id, sessions, fs, res);
    });

}

// Shared cleanup logic for deleting/logging out a device
async function cleanupDevice(device_id, sessions, fs, res) {
    const conn = sessions.get(device_id);

    if (conn) {
        try {
            if (conn.user) {
                await conn.logout();
            } else {
                conn.end(undefined);
            }
        } catch (error) {
            console.log('Error during logout, will still delete session files:', error.message);
        }
        sessions.delete(device_id);
    }

    // Always attempt to remove the session folder regardless of socket state
    const sessionDir = `./sessions/${device_id}`;
    if (fs.existsSync(sessionDir)) {
        try {
            fs.rmSync(sessionDir, { recursive: true, force: true });
            return res.json({ status: true, msg: `Device ${device_id} deleted successfully` });
        } catch (err) {
            return res.status(500).json({ status: false, msg: `Failed to delete session: ${err.message}` });
        }
    } else if (conn) {
        return res.json({ status: true, msg: `Device ${device_id} removed from memory` });
    } else {
        return res.status(404).json({ status: false, msg: `Device ${device_id} not found` });
    }
}

