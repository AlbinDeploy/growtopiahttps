const path   = require('path');
const fs     = require('fs');
const https  = require('https');
const http   = require('http');
const cnf    = require(path.join(__dirname, '..', '..', 'Config.js'));

const CACHE_DIR = path.join(__dirname, '..', '..', 'public', 'cache');

// Pastiin folder cache ada
if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });

/**
 * Fetch file dari Storj CDN dan stream ke response
 * @param {string} storjUrl  - Full URL ke file di Storj
 * @param {object} res       - Express response object
 * @param {string} localPath - Path lokal untuk disimpan (opsional)
 */
function fetchFromStorj(storjUrl, res, localPath) {
    return new Promise((resolve, reject) => {
        const protocol = storjUrl.startsWith('https') ? https : http;

        const options = {
            timeout: cnf.storj_timeout || 15000,
        };

        const request = protocol.get(storjUrl, options, (storjRes) => {
            // File tidak ditemukan di Storj
            if (storjRes.statusCode === 404 || storjRes.statusCode === 403) {
                storjRes.resume(); // Buang response body
                return resolve(false);
            }

            // Error dari Storj
            if (storjRes.statusCode !== 200) {
                storjRes.resume();
                return resolve(false);
            }

            // Set headers CDN Growtopia yang dibutuhkan client
            const expirationDate = new Date();
            expirationDate.setFullYear(expirationDate.getFullYear() + 1);

            res.set({
                'Content-Type':             'application/octet-stream',
                'Accept-Ranges':            'bytes',
                'Cache-Control':            'max-age=31526583',
                'Expires':                  expirationDate.toUTCString(),
                'Last-Modified':            new Date().toUTCString(),
                'Server':                   'nginx',
                'ServerId':                 '02',
                'ServerLocation':           'apac',
                'X-Cache-Status':           'MISS',
                'Alt-Svc':                  'quic=":443"; ma=93600; v="43"',
                'X-OpenStack-Request-Id':   'tx' + Math.random().toString(36).substring(2),
                'X-Timestamp':              (Date.now() / 1000).toString(),
                'X-Trans-Id':               'tx' + Math.random().toString(36).substring(2),
            });

            // Kalau cache local aktif, simpan file ke disk sambil stream ke client
            if (cnf.storj_cache_local && localPath) {
                const dir = path.dirname(localPath);
                if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

                const fileStream = fs.createWriteStream(localPath);

                // Pipe ke file dan ke response sekaligus
                storjRes.pipe(fileStream);
                storjRes.pipe(res);

                fileStream.on('finish', () => {
                    console.log(`[Storj] Cached locally: ${localPath}`);
                });

                fileStream.on('error', (err) => {
                    console.error(`[Storj] Failed to cache locally: ${err.message}`);
                    // Hapus file yang mungkin corrupt
                    try { fs.unlinkSync(localPath); } catch (_) {}
                });
            } else {
                // Langsung stream ke client tanpa simpan lokal
                storjRes.pipe(res);
            }

            storjRes.on('end', () => resolve(true));
            storjRes.on('error', (err) => reject(err));
        });

        request.on('timeout', () => {
            request.destroy();
            reject(new Error('Storj fetch timeout'));
        });

        request.on('error', (err) => reject(err));
    });
}

/**
 * StorjProxy Middleware
 * Intercept request /cache/* — cek lokal dulu, kalau ga ada fetch dari Storj
 */
const StorjProxy = async (req, res, next) => {
    // Hanya handle request ke /cache/
    if (!req.path.startsWith('/cache/')) return next();

    // Storj dimatiin di Config — skip
    if (!cnf.storj_enabled || !cnf.storj_cdn_url) return next();

    // Ambil path file relatif dari /cache/
    const fileSuffix = req.path.replace(/^\/cache\//, '');

    // Validasi — jangan sampai path traversal
    if (fileSuffix.includes('..') || fileSuffix.trim() === '') return next();

    const localPath = path.join(CACHE_DIR, fileSuffix);

    // 1. Cek local cache dulu
    if (fs.existsSync(localPath) && fs.statSync(localPath).isFile()) {
        // File ada lokal — biarkan express.static() yang serve
        return next();
    }

    // 2. File tidak ada lokal → fetch dari Storj
    const storjUrl = `${cnf.storj_cdn_url.replace(/\/$/, '')}/${fileSuffix}`;
    console.log(`[Storj] Cache miss: ${req.path} → fetching from Storj`);

    try {
        const found = await fetchFromStorj(storjUrl, res, localPath);

        if (!found) {
            // File ga ada di Storj juga — log dan return 200 kosong (sesuai behavior asli)
            console.warn(`[Storj] Not found on Storj: ${storjUrl}`);
            return res.sendStatus(200);
        }

        // Berhasil di-stream dari Storj
        console.log(`[Storj] Served from Storj: ${req.path}`);

    } catch (err) {
        console.error(`[Storj] Error fetching ${storjUrl}: ${err.message}`);
        // Kalau Storj error, tetap lanjut ke next() supaya server ga crash
        return next();
    }
};

module.exports = StorjProxy;
