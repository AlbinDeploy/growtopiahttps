const EventEmitter = require('events');

class AntiDDoSEngine extends EventEmitter {
    constructor(options = {}) {
        super();

        this.config = {
            // Request rate thresholds
            maxRequestsPerSecond: options.maxRequestsPerSecond || 50,
            maxRequestsPer10Seconds: options.maxRequestsPer10Seconds || 200,
            maxRequestsPerMinute: options.maxRequestsPerMinute || 600,

            // Connection thresholds
            maxConnectionsPerIP: options.maxConnectionsPerIP || 30,
            maxNewConnectionsPerSecond: options.maxNewConnectionsPerSecond || 15,

            // Growtopia-specific
            maxServerDataRequestsPerMinute: options.maxServerDataRequestsPerMinute || 10,
            maxInvalidRouteRequests: options.maxInvalidRouteRequests || 30,

            // Ban escalation (minutes)
            banDurations: options.banDurations || [2, 5, 15, 30, 60, 120, 360],
            
            // Fingerprint scoring
            suspicionThreshold: options.suspicionThreshold || 70,
            instantBanThreshold: options.instantBanThreshold || 95,

            // Cleanup interval (ms)
            cleanupInterval: options.cleanupInterval || 30000,

            // Whitelist
            whitelistedIPs: new Set(options.whitelistedIPs || ['127.0.0.1', '::1', '::ffff:127.0.0.1']),

            // Known Growtopia paths
            validPaths: new Set([
                '/growtopia/server_data.php',
                '/player',
                '/',
                '/cache'
            ]),
        };

        // IP tracking data
        this.ipData = new Map();
        // Banned IPs with expiry
        this.bannedIPs = new Map();
        // Global request counter for overall load detection
        this.globalRequests = { count: 0, timestamp: Date.now() };
        // Attack mode flag
        this.underAttack = false;
        this.attackStartTime = null;

        // Stats
        this.stats = {
            totalRequests: 0,
            blockedRequests: 0,
            bannedIPs: 0,
            activeBans: 0,
            attacksDetected: 0,
        };

        // Start cleanup interval
        this._cleanupTimer = setInterval(() => this._cleanup(), this.config.cleanupInterval);
    }

    /**
     * Get or create IP tracking data
     */
    _getIPData(ip) {
        if (!this.ipData.has(ip)) {
            this.ipData.set(ip, {
                firstSeen: Date.now(),
                lastSeen: Date.now(),
                requests: [],           // timestamps of recent requests
                endpoints: new Map(),   // endpoint -> count
                methods: new Map(),     // method -> count
                userAgents: new Set(),  // unique user-agents
                contentTypes: new Set(),
                violations: 0,
                banCount: 0,
                suspicionScore: 0,
                isVerifiedPlayer: false,
                serverDataRequests: [], // timestamps of /server_data.php requests
                invalidRequests: 0,
                totalRequests: 0,
                hasValidGrowtopiaPattern: false,
            });
        }
        const data = this.ipData.get(ip);
        data.lastSeen = Date.now();
        return data;
    }

    /**
     * Core analysis - Calculate suspicion score for an IP
     * Lower = more likely real player, Higher = more likely attacker
     * Score 0-100
     */
    _calculateSuspicionScore(ipData, req) {
        let score = 0;
        const now = Date.now();

        // === POSITIVE INDICATORS (reduce score - signs of real player) ===

        // 1. Valid Growtopia User-Agent pattern
        const ua = req.headers['user-agent'] || '';
        if (ua === '' || ua.includes('UbiServices_SDK')) {
            score -= 15;
        }

        // 2. POST to /growtopia/server_data.php (primary Growtopia endpoint)
        if (req.method === 'POST' && req.path === '/growtopia/server_data.php') {
            score -= 10;
        }

        // 3. Has proper content-type for form data (Growtopia sends urlencoded)
        const contentType = req.headers['content-type'] || '';
        if (contentType.includes('application/x-www-form-urlencoded')) {
            score -= 10;
        }

        // 4. Previously verified as real player
        if (ipData.isVerifiedPlayer) {
            score -= 25;
        }

        // 5. Reasonable request interval (not too fast, not perfectly timed)
        if (ipData.requests.length >= 2) {
            const intervals = [];
            for (let i = 1; i < Math.min(ipData.requests.length, 10); i++) {
                intervals.push(ipData.requests[i] - ipData.requests[i - 1]);
            }
            const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
            // Real players have varied intervals (200ms - 30s typical)
            if (avgInterval > 200 && avgInterval < 30000) {
                score -= 5;
            }
            // Perfectly timed intervals suggest bot (variance near 0)
            const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;
            if (variance < 10 && intervals.length > 3) {
                score += 20; // Very suspicious - machine-like timing
            }
        }

        // === NEGATIVE INDICATORS (increase score - signs of attack) ===

        // 6. Request rate analysis
        const recentRequests = ipData.requests.filter(t => now - t < 1000);
        const last10sRequests = ipData.requests.filter(t => now - t < 10000);
        const lastMinRequests = ipData.requests.filter(t => now - t < 60000);

        if (recentRequests.length > this.config.maxRequestsPerSecond) {
            score += 40; // Extreme rate
        } else if (recentRequests.length > this.config.maxRequestsPerSecond * 0.7) {
            score += 25;
        } else if (recentRequests.length > this.config.maxRequestsPerSecond * 0.5) {
            score += 15;
        }

        if (last10sRequests.length > this.config.maxRequestsPer10Seconds) {
            score += 30;
        }

        if (lastMinRequests.length > this.config.maxRequestsPerMinute) {
            score += 35;
        }

        // 7. Hitting invalid/non-existent routes
        const pathBase = req.path.split('?')[0];
        let isValidPath = false;
        for (const validPath of this.config.validPaths) {
            if (pathBase === validPath || pathBase.startsWith(validPath + '/') || pathBase.startsWith('/cache')) {
                isValidPath = true;
                break;
            }
        }
        if (!isValidPath) {
            score += 10;
            if (ipData.invalidRequests > this.config.maxInvalidRouteRequests) {
                score += 20;
            }
        }

        // 8. Too many different User-Agents from same IP
        if (ipData.userAgents.size > 5) {
            score += 20;
        }

        // 9. Spamming server_data.php specifically
        const recentServerData = ipData.serverDataRequests.filter(t => now - t < 60000);
        if (recentServerData.length > this.config.maxServerDataRequestsPerMinute) {
            score += 25;
        }

        // 10. Using unusual HTTP methods
        if (!['GET', 'POST', 'HEAD'].includes(req.method)) {
            score += 15;
        }

        // 11. Missing common headers that real clients have
        if (!req.headers['host']) {
            score += 15;
        }

        // 12. Previous violations escalate suspicion
        score += Math.min(ipData.violations * 5, 30);

        // 13. During global attack, increase sensitivity
        if (this.underAttack) {
            score += 10;
        }

        // 14. Extremely large payload (potential slowloris/buffer overflow attempt)
        const contentLength = parseInt(req.headers['content-length'] || '0', 10);
        if (contentLength > 50000) {
            score += 20;
        }

        // 15. Connection flood detection - too many IPs in short time (checked globally)
        // This is handled at global level

        // Clamp score to 0-100
        return Math.max(0, Math.min(100, score));
    }

    /**
     * Verify if request matches real Growtopia client pattern
     */
    _verifyGrowtopiaClient(req, ipData) {
        const ua = req.headers['user-agent'] || '';
        const contentType = req.headers['content-type'] || '';
        const method = req.method;
        const path = req.path;

        // Growtopia client pattern:
        // - POST to /growtopia/server_data.php
        // - User-Agent is empty or contains "UbiServices_SDK"
        // - Content-Type: application/x-www-form-urlencoded
        if (method === 'POST' && 
            path === '/growtopia/server_data.php' &&
            (ua === '' || ua.includes('UbiServices_SDK')) &&
            contentType.includes('application/x-www-form-urlencoded')) {
            ipData.hasValidGrowtopiaPattern = true;
            ipData.isVerifiedPlayer = true;
            return true;
        }

        // Cache requests (GET to /cache/*)
        if (method === 'GET' && path.startsWith('/cache')) {
            return true;
        }

        return false;
    }

    /**
     * Check global attack status
     */
    _checkGlobalAttack() {
        const now = Date.now();
        const elapsed = now - this.globalRequests.timestamp;

        if (elapsed >= 1000) {
            const rps = this.globalRequests.count / (elapsed / 1000);

            // If global RPS > 500, likely under attack
            if (rps > 500 && !this.underAttack) {
                this.underAttack = true;
                this.attackStartTime = now;
                this.stats.attacksDetected++;
                this.emit('attack_detected', { rps, timestamp: now });
                console.warn(`[ANTI-DDOS] ⚠️  ATTACK DETECTED! Global RPS: ${rps.toFixed(0)}`);
            } else if (rps < 100 && this.underAttack && (now - this.attackStartTime > 30000)) {
                this.underAttack = false;
                this.emit('attack_ended', { duration: now - this.attackStartTime });
                console.log(`[ANTI-DDOS] ✅ Attack subsided. Duration: ${((now - this.attackStartTime) / 1000).toFixed(0)}s`);
            }

            this.globalRequests.count = 0;
            this.globalRequests.timestamp = now;
        }
        this.globalRequests.count++;
    }

    /**
     * Ban an IP with escalating duration
     */
    _banIP(ip, reason, ipData) {
        const banIndex = Math.min(ipData.banCount, this.config.banDurations.length - 1);
        const banDuration = this.config.banDurations[banIndex] * 60 * 1000; // convert to ms

        this.bannedIPs.set(ip, {
            bannedAt: Date.now(),
            expiresAt: Date.now() + banDuration,
            reason: reason,
            banCount: ipData.banCount + 1,
        });

        ipData.banCount++;
        this.stats.bannedIPs++;
        this.stats.activeBans++;

        const durationMin = (banDuration / 60000).toFixed(0);
        console.warn(`[ANTI-DDOS] 🚫 BANNED ${ip} for ${durationMin}m | Reason: ${reason} | Ban #${ipData.banCount}`);
        this.emit('ip_banned', { ip, reason, duration: banDuration, banCount: ipData.banCount });
    }

    /**
     * Main middleware function
     */
    middleware() {
        return (req, res, next) => {
            const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() 
                           || req.socket.remoteAddress 
                           || req.ip;

            this.stats.totalRequests++;

            // Check whitelist
            if (this.config.whitelistedIPs.has(clientIP)) {
                return next();
            }

            // Check if IP is banned
            if (this.bannedIPs.has(clientIP)) {
                const ban = this.bannedIPs.get(clientIP);
                if (Date.now() < ban.expiresAt) {
                    this.stats.blockedRequests++;
                    res.set('Retry-After', Math.ceil((ban.expiresAt - Date.now()) / 1000).toString());
                    return res.status(403).end();
                } else {
                    // Ban expired
                    this.bannedIPs.delete(clientIP);
                    this.stats.activeBans--;
                }
            }

            // Check global attack status
            this._checkGlobalAttack();

            // Get/create IP tracking data
            const ipData = this._getIPData(clientIP);
            ipData.totalRequests++;

            // Record request timestamp
            const now = Date.now();
            ipData.requests.push(now);

            // Track endpoints
            const endpoint = `${req.method}:${req.path}`;
            ipData.endpoints.set(endpoint, (ipData.endpoints.get(endpoint) || 0) + 1);

            // Track methods
            ipData.methods.set(req.method, (ipData.methods.get(req.method) || 0) + 1);

            // Track User-Agent
            if (req.headers['user-agent']) {
                ipData.userAgents.add(req.headers['user-agent']);
            }

            // Track content-type
            if (req.headers['content-type']) {
                ipData.contentTypes.add(req.headers['content-type']);
            }

            // Track server_data.php requests
            if (req.path === '/growtopia/server_data.php') {
                ipData.serverDataRequests.push(now);
            }

            // Track invalid routes
            const pathBase = req.path.split('?')[0];
            let isValidPath = false;
            for (const validPath of this.config.validPaths) {
                if (pathBase === validPath || pathBase.startsWith(validPath + '/') || pathBase.startsWith('/cache')) {
                    isValidPath = true;
                    break;
                }
            }
            if (!isValidPath) {
                ipData.invalidRequests++;
            }

            // Verify Growtopia client pattern
            this._verifyGrowtopiaClient(req, ipData);

            // Calculate suspicion score
            const suspicionScore = this._calculateSuspicionScore(ipData, req);
            ipData.suspicionScore = suspicionScore;

            // === DECISION ENGINE ===

            // Instant ban - very high confidence attacker
            if (suspicionScore >= this.config.instantBanThreshold) {
                ipData.violations++;
                this._banIP(clientIP, `Instant ban - suspicion score: ${suspicionScore}`, ipData);
                this.stats.blockedRequests++;
                return res.status(403).end();
            }

            // High suspicion - add violation, ban on repeated offenses
            if (suspicionScore >= this.config.suspicionThreshold) {
                ipData.violations++;
                
                if (ipData.violations >= 3) {
                    this._banIP(clientIP, `Repeated violations (${ipData.violations}x) - score: ${suspicionScore}`, ipData);
                    this.stats.blockedRequests++;
                    return res.status(403).end();
                }

                // During attack mode, be more aggressive
                if (this.underAttack && ipData.violations >= 2 && !ipData.isVerifiedPlayer) {
                    this._banIP(clientIP, `Attack mode + unverified + violations - score: ${suspicionScore}`, ipData);
                    this.stats.blockedRequests++;
                    return res.status(403).end();
                }
            }

            // Hard rate limit check (absolute maximum)
            const recentRequests = ipData.requests.filter(t => now - t < 1000);
            if (recentRequests.length > this.config.maxRequestsPerSecond * 2) {
                ipData.violations += 2;
                this._banIP(clientIP, `Extreme rate: ${recentRequests.length} req/s`, ipData);
                this.stats.blockedRequests++;
                return res.status(403).end();
            }

            // Slow down response for suspicious but not banned IPs
            if (suspicionScore >= 50 && suspicionScore < this.config.suspicionThreshold) {
                // Add artificial delay to slow down potential attackers
                const delay = Math.min((suspicionScore - 50) * 20, 500);
                return setTimeout(() => next(), delay);
            }

            // All clear - continue to next middleware
            next();
        };
    }

    /**
     * Connection-level protection (for raw socket tracking)
     */
    connectionFilter() {
        return (socket) => {
            const ip = socket.remoteAddress;
            
            if (this.bannedIPs.has(ip)) {
                const ban = this.bannedIPs.get(ip);
                if (Date.now() < ban.expiresAt) {
                    socket.destroy();
                    return;
                }
            }
        };
    }

    /**
     * Cleanup old data to prevent memory leaks
     */
    _cleanup() {
        const now = Date.now();

        // Clean expired bans
        for (const [ip, ban] of this.bannedIPs) {
            if (now > ban.expiresAt) {
                this.bannedIPs.delete(ip);
                this.stats.activeBans--;
            }
        }

        // Clean old IP data (inactive for > 5 minutes)
        for (const [ip, data] of this.ipData) {
            if (now - data.lastSeen > 300000) {
                // Keep ban count for repeat offenders
                if (data.banCount > 0) {
                    // Keep minimal data for known offenders (30 min retention)
                    if (now - data.lastSeen > 1800000) {
                        this.ipData.delete(ip);
                    }
                } else {
                    this.ipData.delete(ip);
                }
            } else {
                // Trim old request timestamps (keep last 60s only)
                data.requests = data.requests.filter(t => now - t < 60000);
                data.serverDataRequests = data.serverDataRequests.filter(t => now - t < 60000);
            }
        }
    }

    /**
     * Get current stats
     */
    getStats() {
        return {
            ...this.stats,
            trackedIPs: this.ipData.size,
            activeBans: this.bannedIPs.size,
            underAttack: this.underAttack,
            attackDuration: this.underAttack ? Date.now() - this.attackStartTime : 0,
        };
    }

    /**
     * Manually whitelist an IP
     */
    whitelistIP(ip) {
        this.config.whitelistedIPs.add(ip);
        this.bannedIPs.delete(ip);
    }

    /**
     * Manually ban an IP
     */
    manualBan(ip, durationMinutes = 60) {
        this.bannedIPs.set(ip, {
            bannedAt: Date.now(),
            expiresAt: Date.now() + (durationMinutes * 60000),
            reason: 'Manual ban',
            banCount: 999,
        });
        this.stats.activeBans++;
    }

    /**
     * Unban an IP
     */
    unbanIP(ip) {
        if (this.bannedIPs.has(ip)) {
            this.bannedIPs.delete(ip);
            this.stats.activeBans--;
            return true;
        }
        return false;
    }

    /**
     * Destroy the engine (cleanup timers)
     */
    destroy() {
        if (this._cleanupTimer) {
            clearInterval(this._cleanupTimer);
        }
        this.ipData.clear();
        this.bannedIPs.clear();
    }
}

// Create singleton instance
const antiDDoS = new AntiDDoSEngine();

// Export middleware and engine
module.exports = antiDDoS;
module.exports.AntiDDoSEngine = AntiDDoSEngine;
