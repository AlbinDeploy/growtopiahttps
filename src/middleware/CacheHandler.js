const express = require('express');

const CacheHandler = (req, res, next) => {
    if (req.path.startsWith('/cache/')) {
        // Remove compression/transfer headers that break Growtopia downloads
        if (req.get('host') == 'www.growtopia1.com') {
            res.removeHeader('Content-Encoding');
            res.removeHeader('Transfer-Encoding');
        }
        
        // Setting response headers for cache files
        // NOTE: Do NOT set Transfer-Encoding here - Growtopia needs Content-Length
        res.set({
            'Accept-Ranges': 'bytes',
            'Alt-Svc': 'quic=":443"; ma=93600; v="43"',
            'Cache-Control': 'max-age=31526583',
            'Content-Type': 'application/octet-stream',
            'Server': 'nginx',
            'ServerId': '02',
            'ServerLocation': 'apac',
            'X-Cache-Status': 'HIT',
            'Last-Modified': new Date().toUTCString(),
            'X-OpenStack-Request-Id': 'tx' + Math.random().toString(36).substring(2),
            'X-Timestamp': (Date.now() / 1000).toString(),
            'X-Trans-Id': 'tx' + Math.random().toString(36).substring(2)
        });

        // Set dynamic expiration date (1 year from now)
        const expirationDate = new Date();
        expirationDate.setFullYear(expirationDate.getFullYear() + 1);
        res.set('Expires', expirationDate.toUTCString());
    }
    next();
};

module.exports = CacheHandler;