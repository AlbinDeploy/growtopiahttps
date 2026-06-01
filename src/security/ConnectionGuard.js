/**
 * Connection-level DDoS protection
 * Works at TCP/TLS layer BEFORE Express processes anything
 * This catches SYN floods, slowloris, and connection exhaustion attacks
 */

class ConnectionGuard {
    constructor(options = {}) {
        this.config = {
            maxConnectionsPerIP: options.maxConnectionsPerIP || 50,
            maxNewConnectionsPerSecond: options.maxNewConnectionsPerSecond || 20,
            maxTotalConnections: options.maxTotalConnections || 5000,
            connectionTimeout: options.connectionTimeout || 30000,
            slowlorisTimeout: options.slowlorisTimeout || 10000,
            whitelistedIPs: new Set(options.whitelistedIPs || ['127.0.0.1', '::1', '::ffff:127.0.0.1']),
        };

        // Active connections per IP
        this.connections = new Map();
        // New connections per second tracking
        this.newConnections = { count: 0, timestamp: Date.now() };
        // Total active connections
        this.totalConnections = 0;
        // Blocked IPs at connection level
        this.blockedIPs = new Set();

        // Stats
        this.stats = {
            totalConnections: 0,
            droppedConnections: 0,
            slowlorisDetected: 0,
            synFloodDetected: 0,
        };
    }

    /**
     * Apply connection guard to an HTTP/HTTPS server
     */
    protect(server) {
        server.on('connection', (socket) => {
            this._handleConnection(socket);
        });

        // For HTTPS/TLS servers
        server.on('secureConnection', (tlsSocket) => {
            this._handleConnection(tlsSocket);
        });

        return server;
    }

    /**
     * Handle new incoming connection
     */
    _handleConnection(socket) {
        const ip = socket.remoteAddress || 'unknown';
        this.stats.totalConnections++;
        this.totalConnections++;

        // Check whitelist
        if (this.config.whitelistedIPs.has(ip)) {
            this._trackDisconnect(socket, ip);
            return;
        }

        // Check if IP is blocked at connection level
        if (this.blockedIPs.has(ip)) {
            socket.destroy();
            this.stats.droppedConnections++;
            this.totalConnections--;
            return;
        }

        // Check total connection limit
        if (this.totalConnections > this.config.maxTotalConnections) {
            socket.destroy();
            this.stats.droppedConnections++;
            this.totalConnections--;
            return;
        }

        // Check per-IP connection limit
        const ipConns = this.connections.get(ip) || 0;
        if (ipConns >= this.config.maxConnectionsPerIP) {
            socket.destroy();
            this.stats.droppedConnections++;
            this.totalConnections--;
            // Temporarily block this IP if they keep trying
            if (ipConns >= this.config.maxConnectionsPerIP * 2) {
                this.blockedIPs.add(ip);
                setTimeout(() => this.blockedIPs.delete(ip), 60000);
            }
            return;
        }

        // Check new connection rate
        const now = Date.now();
        if (now - this.newConnections.timestamp >= 1000) {
            this.newConnections.count = 0;
            this.newConnections.timestamp = now;
        }
        this.newConnections.count++;

        if (this.newConnections.count > this.config.maxNewConnectionsPerSecond * 10) {
            // Global SYN flood - drop non-whitelisted
            socket.destroy();
            this.stats.droppedConnections++;
            this.stats.synFloodDetected++;
            this.totalConnections--;
            return;
        }

        // Track connection
        this.connections.set(ip, ipConns + 1);

        // Set connection timeout (anti-slowloris)
        socket.setTimeout(this.config.connectionTimeout);
        socket.on('timeout', () => {
            this.stats.slowlorisDetected++;
            socket.destroy();
        });

        // Track disconnect
        this._trackDisconnect(socket, ip);
    }

    /**
     * Track when connection closes
     */
    _trackDisconnect(socket, ip) {
        const onClose = () => {
            this.totalConnections--;
            const current = this.connections.get(ip) || 0;
            if (current <= 1) {
                this.connections.delete(ip);
            } else {
                this.connections.set(ip, current - 1);
            }
        };

        socket.once('close', onClose);
        socket.once('error', onClose);
    }

    /**
     * Get stats
     */
    getStats() {
        return {
            ...this.stats,
            activeConnections: this.totalConnections,
            uniqueIPs: this.connections.size,
            blockedIPs: this.blockedIPs.size,
        };
    }
}

module.exports = new ConnectionGuard();
module.exports.ConnectionGuard = ConnectionGuard;
