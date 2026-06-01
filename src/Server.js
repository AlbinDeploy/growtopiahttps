const path = require('path');
const app = require(path.join(__dirname, 'MainApp.js'));
const https = require('https');
const fs = require('fs');
const tls = require('tls');
const connectionGuard = require(path.join(__dirname, 'security', 'ConnectionGuard.js'));
const antiDDoS = require(path.join(__dirname, 'security', 'AntiDDoS.js'));

// Helper to safely load certificates
function safeReadFileSync(filePath) {
    try {
        return fs.readFileSync(filePath);
    } catch (err) {
        console.error(`[CERT] Failed to read: ${filePath}`);
        return undefined;
    }
}

/**
 * Split PEM file containing multiple certificates into array
 * First cert = leaf, remaining = CA chain
 */
function splitPEMChain(pemBuffer) {
    if (!pemBuffer) return { cert: undefined, ca: undefined };
    const pemString = pemBuffer.toString();
    const certs = pemString.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
    if (!certs || certs.length === 0) return { cert: undefined, ca: undefined };
    if (certs.length === 1) return { cert: pemBuffer, ca: undefined };
    // First = leaf cert, rest = CA chain
    return {
        cert: Buffer.from(certs[0]),
        ca: certs.slice(1).map(c => Buffer.from(c))
    };
}

// Load certificates
const fullChainPEM = safeReadFileSync(path.join(__dirname, '..', 'certs', 'growtopia1.com-crt.pem'));
const privateKey = safeReadFileSync(path.join(__dirname, '..', 'certs', 'growtopia1.com-key.pem'));
const { cert: leafCert, ca: caChain } = splitPEMChain(fullChainPEM);

// Also load from subfolder as fallback
const gtCert = safeReadFileSync(path.join(__dirname, '..', 'certs', 'growtopia1.com', 'gt-crt.pem'));
const gtKey = safeReadFileSync(path.join(__dirname, '..', 'certs', 'growtopia1.com', 'gt-key.pem'));
const { cert: gtLeafCert, ca: gtCaChain } = splitPEMChain(gtCert);

// TLS error throttle - prevent log spam
const tlsErrorThrottle = new Map();
const TLS_ERROR_INTERVAL = 10000; // Only log same error type once per 10s

function shouldLogTLSError(errorType) {
    const now = Date.now();
    const lastLogged = tlsErrorThrottle.get(errorType) || 0;
    if (now - lastLogged > TLS_ERROR_INTERVAL) {
        tlsErrorThrottle.set(errorType, now);
        return true;
    }
    return false;
}

/**
 * SNI callback for dynamic certificate selection
 * Handles www.growtopia1.com and growtopia1.com
 */
const sniCallback = (serverName, callback) => {
    let cert = fullChainPEM;  // Send full chain (leaf + CA) as cert
    let key = privateKey;
    let ca = caChain;

    // Handle specific domains
    if (serverName === 'www.growtopia1.com' || serverName === 'growtopia1.com') {
        cert = fullChainPEM;
        key = privateKey;
        ca = caChain;
    }

    try {
        const ctx = tls.createSecureContext({
            cert: cert,
            key: key,
            ca: ca,
            // Allow self-signed CA to work
            // The client needs to trust our CA
        });
        callback(null, ctx);
    } catch (err) {
        if (shouldLogTLSError(`sni_${serverName}`)) {
            console.error(`[SNI] Failed to create context for ${serverName}: ${err.message}`);
        }
        callback(err);
    }
};

const serverOptions = {
    // Send the FULL chain file as cert (leaf + intermediates)
    cert: fullChainPEM,
    key: privateKey,
    ca: caChain,
    SNICallback: sniCallback,
    keepAliveTimeout: 60000,
    headersTimeout: 65000,
    // Important: Don't request/reject client certificates
    requestCert: false,
    rejectUnauthorized: false,
};

/**
 * HTTP server (port 80)
 */
const httpServer = app.listen(80, () => {
    console.log('Server started at http://localhost:80');
    console.log('[ANTI-DDOS] Protection active - HTTP layer');
});

// Apply connection-level guard
connectionGuard.protect(httpServer);

httpServer.on('request', (req, res) => {
    try {
        const currentTime = new Date().toISOString();
        const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || req.ip;
        console.log(
            `[HTTP][${req.get('host')}][${clientIP}] ${req.method} -> ${req.originalUrl} - ${currentTime}`,
        );
    } catch (error) {
        console.error('Error logging HTTP request:', error);
    }
}).on('tlsClientError', (err, socket) => {
    // Suppress TLS error spam - these are normal for self-signed certs
    if (shouldLogTLSError('http_tls_' + err.code)) {
        console.warn(`[HTTP] TLS error (${err.code || 'unknown'}): ${err.message}`);
    }
    socket.destroy();
}).on('clientError', (err, socket) => {
    if (shouldLogTLSError('http_client_' + err.code)) {
        console.warn(`[HTTP] Client error (${err.code || 'unknown'}): ${err.message}`);
    }
    if (!socket.destroyed) {
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    }
});

/**
 * HTTPS server (port 443)
 */
const httpsServer = https.createServer(serverOptions, app);
connectionGuard.protect(httpsServer);

httpsServer.listen(443, () => {
    console.log('Secure server started at https://localhost:443');
    console.log('[ANTI-DDOS] Protection active - HTTPS layer');
    console.log('[ANTI-DDOS] Connection Guard active - TCP/TLS layer');
});

httpsServer.on('request', (req, res) => {
    try {
        const currentTime = new Date().toISOString();
        const clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || req.ip;
        console.log(
            `[HTTPS][${req.get('host')}][${clientIP}] ${req.method} -> ${req.originalUrl} - ${currentTime}`,
        );
    } catch (error) {
        console.error('Error logging HTTPS request:', error);
    }
}).on('tlsClientError', (err, socket) => {
    // "unknown ca" errors are NORMAL for self-signed certs
    // Client doesn't trust our CA - this is expected behavior for Growtopia GTPS
    // Only log once per 10 seconds to prevent spam
    if (shouldLogTLSError('https_tls_' + (err.code || 'unknown_ca'))) {
        console.warn(`[HTTPS] TLS handshake rejected (${err.code || 'unknown_ca'}) - client doesn't trust CA (normal for self-signed)`);
    }
    socket.destroy();
}).on('clientError', (err, socket) => {
    // Same throttle for client errors
    if (shouldLogTLSError('https_client_' + (err.code || 'unknown'))) {
        console.warn(`[HTTPS] Client error (${err.code || 'unknown'}): ${err.message}`);
    }
    if (!socket.destroyed) {
        socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    }
});

// Anti-DDoS stats logging every 60 seconds
setInterval(() => {
    const ddosStats = antiDDoS.getStats();
    const connStats = connectionGuard.getStats();
    if (ddosStats.totalRequests > 0) {
        console.log(`[ANTI-DDOS STATS] Requests: ${ddosStats.totalRequests} | Blocked: ${ddosStats.blockedRequests} | Active Bans: ${ddosStats.activeBans} | Tracked IPs: ${ddosStats.trackedIPs} | Under Attack: ${ddosStats.underAttack}`);
        console.log(`[CONN-GUARD STATS] Active: ${connStats.activeConnections} | Dropped: ${connStats.droppedConnections} | Unique IPs: ${connStats.uniqueIPs} | Blocked: ${connStats.blockedIPs}`);
    }
}, 60000);