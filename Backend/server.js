/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Sentinel Bridge v5.0 — Production-Ready Enterprise Backend
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *  Security:
 *  ► helmet()          — Sets secure HTTP headers (XSS, HSTS, etc.)
 *  ► express-rate-limit — 100 req/15min per IP (prevents API abuse)
 *  ► Input validation   — Strict regex IP check (prevents command injection)
 *  ► dotenv             — Secrets in .env, NOT in source code
 *
 *  Logging:
 *  ► morgan ('combined') — Full request log with timestamps
 *
 *  Database:
 *  ► Supabase upsert    — MAC as conflict target → updates last_seen
 *
 *  Run:   node server.js
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const fs = require('fs'); // Added fs
const path = require('path');
const net = require('net');
const dns = require('dns');
const { exec, spawn } = require('child_process');
const macLookup = require('mac-lookup');
const { createClient } = require('@supabase/supabase-js');

// ═══════════════════════════════════════════════════════════════════════════════
//  CONFIGURATION (from .env)
// ═══════════════════════════════════════════════════════════════════════════════

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HONEYPOT_PORT = parseInt(process.env.HONEYPOT_PORT, 10) || 2323;
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';

// ── Supabase Client ──────────────────────────────────────────────────────────
// Edge case: If URL/KEY missing, supabase calls fail gracefully (caught below).
const supabase = (SUPABASE_URL && SUPABASE_KEY)
    ? createClient(SUPABASE_URL, SUPABASE_KEY)
    : null;

// ═══════════════════════════════════════════════════════════════════════════════
//  EXPRESS APP + SECURITY MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════

const app = express();

// Security headers — configured to allow web frontend assets
// Security headers — configured to allow web frontend assets
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
            imgSrc: ["'self'", "data:", "blob:"], // Added blob:
            connectSrc: ["'self'"],
        }
    }
}));

// CORS — allow all origins for mobile app access
app.use(cors());

// Body parsing
app.use(express.json());

// Serve web frontend
app.use(express.static(path.join(__dirname, 'public')));
// Serve captured images directory
app.use('/captured_images', express.static(path.join(__dirname, '..', 'captured_images')));

// Request logging with timestamps
app.use(morgan(':date[iso] :method :url :status :response-time ms'));

// Rate limiting — 1000 requests per 15 minutes per IP (generous for local tool)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please wait a moment.' },
});
app.use('/api/', apiLimiter);

// ═══════════════════════════════════════════════════════════════════════════════
//  STATE
// ═══════════════════════════════════════════════════════════════════════════════

const IS_ROOT = process.getuid ? process.getuid() === 0 : false;
const honeypotLogs = [];
let totalDevicesLogged = 0;
let savedTargets = {};

// Load saved targets
const targetsFile = path.join(__dirname, 'targets.json');
if (fs.existsSync(targetsFile)) {
    try {
        savedTargets = JSON.parse(fs.readFileSync(targetsFile, 'utf8'));
    } catch (e) {
        console.error('Failed to load targets.json:', e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  STARTUP BANNER
// ═══════════════════════════════════════════════════════════════════════════════

console.log(`
╔═══════════════════════════════════════════════════════════╗
║         🛡️  SENTINEL BRIDGE v5.0 — ENTERPRISE            ║
╠═══════════════════════════════════════════════════════════╣
║  Supabase:    ${supabase ? '✅ Connected' : '⚠️  NOT CONFIGURED'}                            ║
║  Helmet:      ✅ Security headers active                  ║
║  Rate Limit:  ✅ 100 req / 15 min                         ║
║  Logging:     ✅ Morgan (combined)                        ║
║  Root:        ${IS_ROOT ? '✅ Yes' : '❌ No '}                                       ║
║  Honeypot:    Port ${HONEYPOT_PORT}                                    ║
║  Binding:     0.0.0.0:${PORT}                                  ║
╚═══════════════════════════════════════════════════════════╝
`);

// ═══════════════════════════════════════════════════════════════════════════════
//  INPUT VALIDATION — Prevents Command Injection
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Validate that a string is a valid IPv4 address.
 * SECURITY: This is the ONLY gate before the IP reaches exec().
 * Rejects anything that isn't exactly n.n.n.n with each octet 0-255.
 *
 * Edge cases:
 *   - Missing parameter     → returns false
 *   - Contains shell chars   → returns false (;, |, &, etc.)
 *   - Octet > 255            → returns false
 *   - Leading zeros          → allowed (some network tools use them)
 */
function isValidIPv4(ip) {
    if (!ip || typeof ip !== 'string') return false;

    // Strict pattern: only digits and dots
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;

    // Validate each octet is 0-255
    const octets = ip.split('.');
    return octets.every(o => {
        const num = parseInt(o, 10);
        return num >= 0 && num <= 255;
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HONEYPOT TRAP — TCP Server on Port 2323
// ═══════════════════════════════════════════════════════════════════════════════

const honeypot = net.createServer((socket) => {
    const intruderIP = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const timestamp = new Date().toISOString();

    honeypotLogs.push({
        ip: intruderIP,
        timestamp,
        port: HONEYPOT_PORT,
        message: `Unauthorized connection from ${intruderIP}`,
    });

    console.log(`🪤 HONEYPOT: ${intruderIP} at ${timestamp}`);

    // Fake SSH banner
    socket.write('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n');
    setTimeout(() => socket.destroy(), 3000);
});

honeypot.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`⚠️  Honeypot port ${HONEYPOT_PORT} in use, skipping.`);
    } else {
        console.error(`❌ Honeypot error: ${err.message}`);
    }
});

honeypot.listen(HONEYPOT_PORT, '0.0.0.0', () => {
    console.log(`🪤 Honeypot active on port ${HONEYPOT_PORT}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

const LOCAL_OUI_DB = {
    '00:03:93': 'Apple', '00:05:02': 'Apple', '00:0a:27': 'Apple', '00:0a:95': 'Apple', '00:0d:93': 'Apple',
    '34:af:2c': 'Apple', '44:4a:db': 'Apple', 'd0:03:4b': 'Apple', 'f0:d1:a9': 'Apple', 'fc:25:3f': 'Apple',
    '00:00:f0': 'Samsung', '00:07:ab': 'Samsung', '00:0d:ae': 'Samsung', '00:12:47': 'Samsung', 'a4:70:d6': 'Samsung',
    '8c:c7:01': 'Samsung', '60:af:6d': 'Samsung', '08:ee:8b': 'Samsung', '1c:5a:3e': 'Samsung',
    '00:1a:11': 'Google', '20:df:b9': 'Google', '3c:5a:b4': 'Google', '94:eb:cd': 'Google', 'da:a1:19': 'Google',
    '00:24:e4': 'Withings', '00:1d:c9': 'Nest', '18:b4:30': 'Nest',
    '00:1c:2b': 'Dell', '00:1d:09': 'Dell', '00:21:70': 'Dell',
    '00:1c:c0': 'HP', '00:1d:0f': 'HP', '00:21:5a': 'HP',
    '04:33:89': 'Huawei', '08:19:a6': 'Huawei',
    '00:19:70': 'ZTE', '00:1a:c4': 'ZTE',
    '00:22:6b': 'Linksys', '00:23:69': 'Linksys',
    '00:18:4d': 'Netgear', '00:1b:2f': 'Netgear', 'c0:3f:0e': 'Netgear',
    '00:1d:7e': 'TP-Link', '00:1e:a6': 'TP-Link', 'b0:4e:26': 'TP-Link', 'f8:1a:67': 'TP-Link',
    '00:26:bb': 'Sony', '00:24:33': 'Sony', '00:1d:ba': 'Sony',
    '00:1f:3b': 'Intel', '00:21:5d': 'Intel',
    'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
    '00:1e:c0': 'Micro-Star (MSI)', '00:24:21': 'Micro-Star (MSI)',
    '24:da:33': 'Tesla', '44:fb:42': 'Tesla',
    '40:9f:38': 'Ring', 'c4:7c:8d': 'Ring', 'f0:d8:19': 'Ring',
    '2c:f7:f1': 'Espressif (IoT)', '30:ae:a4': 'Espressif (IoT)', 'bc:dd:c2': 'Espressif (IoT)'
};

/**
 * Lookup MAC vendor with local cache + library fallback.
 */
function lookupVendor(mac) {
    return new Promise((resolve) => {
        if (!mac) return resolve('Unknown');

        const prefix = mac.substring(0, 8).toLowerCase();
        if (LOCAL_OUI_DB[prefix]) return resolve(LOCAL_OUI_DB[prefix]);

        try {
            const vendor = macLookup.lookup(mac);
            resolve(vendor || 'Unknown');
        } catch {
            resolve('Unknown');
        }
    });
}

/**
 * Classify device type based on vendor string.
 * Edge case: null/undefined vendor → defaults to 'Unknown Device'.
 */
function classifyDevice(vendor, mac) {
    const v = (vendor || 'Unknown').toLowerCase();

    // Check for Locally Administered Address (Randomized/Private MAC)
    // The second-least significant bit of the first octet is 1.
    // e.g. x2, x6, xA, xE in first octet.
    if (mac) {
        const firstOctet = parseInt(mac.split(':')[0], 16);
        if ((firstOctet & 0x02) === 0x02) return 'Privacy-Randomized MAC';
    }

    // Apple Ecosystem
    if (/apple|iphone|ipad|macbook|airpods|imac|watch|beats/.test(v)) return 'Apple Device';

    // Mobile & Tablets
    if (/samsung|galaxy|android|xiaomi|redmi|oppo|vivo|huawei|honor|realme|motorola|nokia|hmd|oneplus/.test(v)) return 'Mobile Device';
    if (/google|pixel|nest|chromecast/.test(v)) return 'Google Device';

    // Computers & Laptops
    if (/intel|dell|lenovo|hp|hewlett-packard|asustek|asus|microsoft|acer|msi|gigabyte|fujitsu|toshiba|sony/.test(v)) return 'PC/Laptop';

    // Networking
    if (/tp-link|netgear|asus|linksys|d-link|router|gateway|ubiquiti|cisco|meraki|mikrotik|zyxel|tenda|huawei|zte|aruba|juniper|synology/.test(v)) return 'Networking Gear';

    // IoT & Smart Home
    if (/amazon|alexa|echo|ring|blink|eero/.test(v)) return 'Amazon Smart Home';
    if (/espressif|tuya|shelly|sonoff|itead|aqara|xiaomi|yeelight|philips|hue|ikea|tradfri/.test(v)) return 'IoT Device';
    if (/tp-link.*smart|kasa|lifx|wemo|tplink|meross/.test(v)) return 'IoT Device';

    // Security / Cameras
    if (/camera|hikvision|dahua|axis|reolink|wyze|arlo|amcrest|ezviz|hanwha|uniview/.test(v)) return 'IP Camera';

    // Entertainment
    if (/sonos|roku|fire|tv|media|nvidia|shield|lg|vizio|panasonic|tcl|hisense|denon|marantz|yamaha|bose/.test(v)) return 'Media Device';
    if (/nintendo|playstation|xbox|sony/.test(v)) return 'Gaming Console';

    // Printers & Peripherals
    if (/printer|brother|canon|epson|xerox|kyocera|lexmark|ricoh|konica/.test(v)) return 'Printer';
    if (/raspberry|pi|arduino|stmicroelectronics|texas instruments|atmel/.test(v)) return 'Dev Board';

    return 'Unknown Device';
}

/**
 * Check if an IP is multicast (224-239.x.x.x) or broadcast.
 * These are protocol-level addresses, not real devices.
 */
function isMulticast(ip) {
    if (!ip || typeof ip !== 'string') return true;
    const parts = ip.split('.');
    if (parts.length !== 4) return true;
    const firstOctet = parseInt(parts[0], 10);
    if (firstOctet >= 224 && firstOctet <= 239) return true;
    if (ip === '255.255.255.255') return true;
    return false;
}

/**
 * Resolve hostname for a local device using multiple strategies:
 * 1. dns-sd (macOS mDNS/Bonjour) — resolves names like "Jerry's-iPhone"
 * 2. dns.reverse() — standard reverse DNS
 * 3. Fallback to "Unknown"
 *
 * dns-sd is run with a 3-second timeout.
 */
function resolveHostname(ip) {
    return new Promise((resolve) => {
        // Strategy 1: Use arp -a to see if hostname was broadcast
        exec(`arp -a | grep '(${ip})'`, { timeout: 3000 }, (err1, stdout1) => {
            if (!err1 && stdout1) {
                // macOS format: "hostname.local (192.168.1.x) at ..."
                const match = stdout1.match(/^([\w.-]+)\s+\(/);
                if (match && match[1] !== '?') {
                    return resolve(match[1].replace('.local', ''));
                }
            }

            // Strategy 2: Standard reverse DNS
            dns.promises.reverse(ip)
                .then(names => {
                    if (names && names.length > 0 && names[0] !== ip) {
                        resolve(names[0]);
                    } else {
                        resolve('Unknown');
                    }
                })
                .catch(() => resolve('Unknown'));
        });
    });
}

/**
 * Supabase upsert — saves devices with MAC as conflict target.
 * Only sends columns guaranteed to exist in the table.
 * Falls back to minimal upsert (mac + ip + last_seen) on schema errors.
 *
 * Required table schema (minimum):
 *   CREATE TABLE devices (
 *     mac TEXT PRIMARY KEY,
 *     ip TEXT,
 *     vendor TEXT,
 *     type TEXT,
 *     last_seen TIMESTAMPTZ DEFAULT now()
 *   );
 */
async function saveToSupabase(deviceList) {
    if (!supabase) {
        console.log('⚠️  Supabase not configured — skipping save.');
        return { saved: 0, error: null };
    }

    try {
        // Only include columns known to exist in Supabase schema
        const rows = deviceList.map(d => ({
            mac: d.mac,
            ip: d.ip,
            vendor: d.vendor || 'Unknown',
            type: d.type || 'Unknown Device',
            last_seen: new Date().toISOString(),
        }));

        const { error } = await supabase
            .from('devices')
            .upsert(rows, { onConflict: 'mac' });

        if (error) {
            // Schema mismatch — retry with minimal columns
            if (error.message.includes('schema cache') || error.message.includes('column')) {
                console.warn('⚠️  Schema mismatch, retrying minimal upsert...');
                const minimalRows = deviceList.map(d => ({
                    mac: d.mac,
                    ip: d.ip,
                    last_seen: new Date().toISOString(),
                }));
                const { error: retryErr } = await supabase
                    .from('devices')
                    .upsert(minimalRows, { onConflict: 'mac' });
                if (retryErr) {
                    console.error('❌ Supabase minimal upsert failed:', retryErr.message);
                    return { saved: 0, error: retryErr.message };
                }
                console.log(`💾 Upserted ${minimalRows.length} device(s) (minimal mode).`);
                return { saved: minimalRows.length, error: null };
            }
            console.error('❌ Supabase upsert error:', error.message);
            return { saved: 0, error: error.message };
        }

        console.log(`💾 Upserted ${rows.length} device(s) to Supabase.`);
        return { saved: rows.length, error: null };
    } catch (err) {
        console.error('❌ Supabase connection error:', err.message);
        return { saved: 0, error: err.message };
    }
}

/**
 * Get total device count from Supabase.
 * Edge case: Supabase offline → returns local counter.
 */
async function getDeviceCount() {
    if (!supabase) return totalDevicesLogged;

    try {
        const { count, error } = await supabase
            .from('devices')
            .select('*', { count: 'exact', head: true });

        if (error) return totalDevicesLogged;
        return count || 0;
    } catch {
        return totalDevicesLogged;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ── Health Check ──────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// ── Network Scan ──────────────────────────────────────────────────────────────
app.get('/api/scan', (req, res) => {
    console.log('📡 Scan requested...');

    const agentPath = path.join(__dirname, '../agent.py');

    exec(`python3 "${agentPath}"`, { timeout: 180000 }, async (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());

        if (error) {
            console.error('❌ Agent error:', error.message);
            return res.status(500).json({
                status: 'error',
                message: error.message,
                devices: [],
            });
        }

        try {
            const scanData = JSON.parse(stdout);

            const enrichedDevices = await Promise.all(
                (scanData.devices || []).map(async (device) => {
                    // Skip multicast/broadcast IPs
                    if (isMulticast(device.ip)) return null;

                    const vendor = await lookupVendor(device.mac);
                    const hostname = await resolveHostname(device.ip);
                    const customName = savedTargets[device.mac] || null;
                    return { ...device, vendor, type: classifyDevice(vendor, device.mac), hostname, name: customName };
                })
            );

            // Remove null entries (filtered multicast)
            const filteredDevices = enrichedDevices.filter(d => d !== null);

            // Supabase upsert
            const dbResult = await saveToSupabase(filteredDevices);
            totalDevicesLogged = Math.max(totalDevicesLogged, filteredDevices.length);
            const dbDeviceCount = await getDeviceCount();

            res.json({
                status: 'success',
                scan_mode: scanData.scan_mode || 'passive',
                methods: scanData.methods || [],
                subnet: scanData.subnet || 'unknown',
                count: filteredDevices.length,
                devices: filteredDevices,
                is_root: scanData.is_root || false,
                database: {
                    saved: dbResult.saved,
                    total_logged: dbDeviceCount,
                    error: dbResult.error,
                },
            });
        } catch (parseError) {
            console.error('❌ Parse error:', parseError.message);
            res.status(500).json({
                status: 'error',
                message: 'Failed to parse agent output',
                devices: [],
            });
        }
    });
});

// ── Deep Scan ─────────────────────────────────────────────────────────────────
app.get('/api/inspect', (req, res) => {
    const targetIP = req.query.ip;

    // SECURITY: Strict IP validation before exec()
    if (!isValidIPv4(targetIP)) {
        return res.status(400).json({ error: 'Invalid IP address format.' });
    }

    console.log(`🔍 Deep scan: ${targetIP}`);

    const agentPath = path.join(__dirname, '../agent.py');
    exec(`python3 "${agentPath}" ${targetIP}`, { timeout: 60000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());
        if (error) return res.status(500).json({ error: error.message });

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.status(500).json({ error: 'Failed to parse deep scan output' });
        }
    });
});

// ── Credential Audit ──────────────────────────────────────────────────────────
app.get('/api/audit', (req, res) => {
    const targetIP = req.query.ip;

    // SECURITY: Strict IP validation before exec()
    if (!isValidIPv4(targetIP)) {
        return res.status(400).json({ error: 'Invalid IP address format.' });
    }

    console.log(`🔐 Credential audit: ${targetIP}`);

    const agentPath = path.join(__dirname, '../agent.py');
    exec(`python3 "${agentPath}" audit ${targetIP}`, { timeout: 30000 }, (error, stdout, stderr) => {
        if (stderr) console.log('Agent:', stderr.trim());
        if (error) return res.status(500).json({ error: error.message });

        try {
            res.json(JSON.parse(stdout));
        } catch {
            res.status(500).json({ error: 'Failed to parse audit output' });
        }
    });
});

// ── Honeypot Logs ─────────────────────────────────────────────────────────────
app.get('/api/honeypot', (req, res) => {
    res.json(honeypotLogs);
});

// ── Device History (from Supabase) ────────────────────────────────────────
app.get('/api/device-history', async (req, res) => {
    const mac = req.query.mac;
    if (!mac || typeof mac !== 'string') {
        return res.status(400).json({ error: 'Missing mac parameter' });
    }

    if (!supabase) {
        return res.json({ mac, history: [], message: 'Supabase not configured' });
    }

    try {
        const { data, error } = await supabase
            .from('devices')
            .select('*')
            .eq('mac', mac)
            .order('last_seen', { ascending: false })
            .limit(20);

        if (error) {
            return res.status(500).json({ error: error.message });
        }

        res.json({ mac, history: data || [] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ── Rename Device (Persistence) ───────────────────────────────────────────────
app.post('/api/device/rename', (req, res) => {
    const { mac, name } = req.body;
    if (!mac || !name) return res.status(400).json({ error: 'MAC and Name required' });

    savedTargets[mac] = name;

    try {
        fs.writeFileSync(targetsFile, JSON.stringify(savedTargets, null, 2));
        res.json({ status: 'success', mac, name });
    } catch (e) {
        res.status(500).json({ error: 'Failed to save targets.json' });
    }
});

// ── Traffic Statistics ────────────────────────────────────────────────────────
app.get('/api/traffic', (req, res) => {
    // Use nettop on macOS or /proc/net/dev on Linux for traffic stats
    const platform = process.platform;

    if (platform === 'darwin') {
        // macOS: use netstat -ib for interface stats
        exec('netstat -ib', { timeout: 5000 }, (error, stdout) => {
            if (error) {
                return res.json({ error: 'Failed to get traffic stats', upload_bytes: 0, download_bytes: 0, connections: 0 });
            }

            let totalIn = 0;
            let totalOut = 0;
            const lines = stdout.split('\n');
            for (const line of lines) {
                // Skip header and loopback
                if (line.includes('Name') || line.includes('lo0') || !line.trim()) continue;
                const parts = line.trim().split(/\s+/);
                // Format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                if (parts.length >= 10) {
                    const ibytes = parseInt(parts[6], 10);
                    const obytes = parseInt(parts[9], 10);
                    if (!isNaN(ibytes)) totalIn += ibytes;
                    if (!isNaN(obytes)) totalOut += obytes;
                }
            }

            // Get active connection count
            exec('netstat -an | grep ESTABLISHED | wc -l', { timeout: 3000 }, (err2, stdout2) => {
                const connections = parseInt((stdout2 || '0').trim(), 10) || 0;
                res.json({
                    upload_bytes: totalOut,
                    download_bytes: totalIn,
                    connections,
                    upload_mb: (totalOut / (1024 * 1024)).toFixed(1),
                    download_mb: (totalIn / (1024 * 1024)).toFixed(1),
                    timestamp: new Date().toISOString(),
                });
            });
        });
    } else {
        // Linux: read /proc/net/dev
        exec('cat /proc/net/dev', { timeout: 3000 }, (error, stdout) => {
            if (error) {
                return res.json({ error: 'Failed to get traffic stats', upload_bytes: 0, download_bytes: 0, connections: 0 });
            }

            let totalIn = 0;
            let totalOut = 0;
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.includes('|') || line.includes('lo:') || !line.includes(':')) continue;
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 10) {
                    const rxBytes = parseInt(parts[1], 10);
                    const txBytes = parseInt(parts[9], 10);
                    if (!isNaN(rxBytes)) totalIn += rxBytes;
                    if (!isNaN(txBytes)) totalOut += txBytes;
                }
            }

            exec('netstat -an | grep ESTABLISHED | wc -l', { timeout: 3000 }, (err2, stdout2) => {
                const connections = parseInt((stdout2 || '0').trim(), 10) || 0;
                res.json({
                    upload_bytes: totalOut,
                    download_bytes: totalIn,
                    connections,
                    upload_mb: (totalOut / (1024 * 1024)).toFixed(1),
                    download_mb: (totalIn / (1024 * 1024)).toFixed(1),
                    timestamp: new Date().toISOString(),
                });
            });
        });
    }
});

// ── MitM / Traffic Monitor API ──────────────────────────────────────────────

// Multi-device monitoring: { "192.168.1.72": process, "192.168.1.65": process }
let activeMonitors = {};
let passiveMonitorProcess = null;

/**
 * Get active network interface (auto-detect for macOS & Linux)
 */
function getNetworkInterface() {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    const preferred = ['wlan0', 'en0', 'eth0', 'wlp2s0', 'enp0s3', 'Wi-Fi'];
    for (const name of preferred) {
        if (nets[name]) {
            const hasIPv4 = nets[name].some(n => n.family === 'IPv4' && !n.internal);
            if (hasIPv4) return name;
        }
    }
    for (const [name, addrs] of Object.entries(nets)) {
        if (addrs.some(n => n.family === 'IPv4' && !n.internal)) return name;
    }
    return process.platform === 'darwin' ? 'en0' : 'wlan0';
}

/**
 * Get Default Gateway IP
 */
function getGatewayIP() {
    return new Promise((resolve) => {
        const cmd = process.platform === 'darwin'
            ? "netstat -nr | grep default | awk '{print $2}' | head -n 1"
            : "ip route | grep default | awk '{print $3}' | head -n 1";
        exec(cmd, (err, stdout) => {
            if (err || !stdout) return resolve(null);
            // Parse only the first valid IPv4 gateway from potentially multi-line output
            const lines = stdout.trim().split('\n');
            for (const line of lines) {
                const ip = line.trim();
                if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
                    return resolve(ip);
                }
            }
            resolve(lines[0].trim());
        });
    });
}

/**
 * Start Passive DNS Monitor (auto-starts on server boot)
 */
function startPassiveMonitor() {
    if (passiveMonitorProcess) {
        console.log('⚠️  Passive monitor already running.');
        return;
    }
    const scriptPath = path.join(__dirname, '..', 'passive_monitor.py');
    if (!fs.existsSync(scriptPath)) {
        console.log('⚠️  passive_monitor.py not found, skipping.');
        return;
    }

    const iface = getNetworkInterface();
    console.log(`📡 Starting passive DNS monitor on ${iface}...`);

    const cmd = 'python3';
    const args = [scriptPath, '-i', iface];

    passiveMonitorProcess = spawn(cmd, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '..')
    });

    passiveMonitorProcess.stdout.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg) console.log(`[Passive] ${msg}`);
    });
    passiveMonitorProcess.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg && !msg.includes('WARNING')) console.error(`[Passive ERR] ${msg}`);
    });
    passiveMonitorProcess.on('exit', (code) => {
        console.log(`[Passive] Process exited: ${code}`);
        passiveMonitorProcess = null;
    });
}

// ── MITM: Start Targeted Monitoring ────────────────────────────────────────────
app.post('/api/mitm/start', async (req, res) => {
    const { ip, duration } = req.body;
    if (!ip) return res.status(400).json({ error: 'Target IP required' });

    // If already monitoring this IP, return success
    if (activeMonitors[ip]) {
        return res.json({ status: 'already_monitoring', target: ip });
    }

    // Start monitoring for this specific IP
    const gateway = await getGatewayIP();
    if (!gateway) return res.status(500).json({ error: 'Gateway not found' });

    const scriptPath = path.join(__dirname, '..', 'traffic_monitor.py');
    const iface = getNetworkInterface();

    console.log(`😈 Starting MITM on ${ip} via ${gateway}...`);

    const cmd = 'python3';
    const args = [scriptPath, '-t', ip, '-g', gateway, '-i', iface, '--action', 'monitor'];

    const proc = spawn(cmd, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '..')
    });

    proc.stdout.on('data', (data) => {
        console.log(`[MITM ${ip}] ${data.toString().trim()}`);
    });
    proc.stderr.on('data', (data) => {
        const msg = data.toString().trim();
        if (msg && !msg.includes('WARNING')) console.error(`[MITM ${ip} ERR] ${msg}`);
    });
    proc.on('exit', (code) => {
        console.log(`[MITM ${ip}] Process exited: ${code}`);
        delete activeMonitors[ip];
    });

    activeMonitors[ip] = proc;
    res.json({ status: 'started', target: ip, gateway, active_monitors: Object.keys(activeMonitors) });
});

// ── MITM: Stop (single target or all) ─────────────────────────────────────────
app.post('/api/mitm/stop', (req, res) => {
    const { ip } = req.body || {};

    if (ip && activeMonitors[ip]) {
        activeMonitors[ip].kill('SIGTERM');
        delete activeMonitors[ip];
        return res.json({ status: 'stopped', target: ip });
    }

    // Stop ALL monitors
    for (const [targetIp, proc] of Object.entries(activeMonitors)) {
        try { proc.kill('SIGTERM'); } catch (e) { }
    }
    activeMonitors = {};
    exec('pkill -f "traffic_monitor.py"', () => {
        res.json({ status: 'all_stopped' });
    });
});

// ── Monitor Status ────────────────────────────────────────────────────────────
app.get('/api/monitor/status', (req, res) => {
    const passiveStats = path.join(__dirname, '..', 'passive_stats.json');
    let passive = null;
    if (fs.existsSync(passiveStats)) {
        try { passive = JSON.parse(fs.readFileSync(passiveStats, 'utf8')); } catch { }
    }

    res.json({
        active_monitors: Object.keys(activeMonitors),
        passive_monitor: !!passiveMonitorProcess,
        passive_stats: passive,
        monitor_count: Object.keys(activeMonitors).length
    });
});

// ── MITM: Details (Traffic Inspector) ─────────────────────────────────────────
app.get('/api/mitm/details', (req, res) => {
    const statsFile = path.join(__dirname, '..', 'traffic_stats.json');
    if (fs.existsSync(statsFile)) {
        try {
            const data = JSON.parse(fs.readFileSync(statsFile, 'utf8'));
            data.active_monitors = Object.keys(activeMonitors);
            res.json(data);
        } catch { res.json({ error: 'Stats read error' }); }
    } else {
        res.json({ error: 'No stats yet', active_monitors: Object.keys(activeMonitors) });
    }
});

// ── FOOTPRINT: Per-Device Organized History ───────────────────────────────────
app.get('/api/footprint', (req, res) => {
    const footprintFile = path.join(__dirname, '..', 'footprint_db.json');
    const targetIP = req.query.ip;

    if (fs.existsSync(footprintFile)) {
        try {
            const db = JSON.parse(fs.readFileSync(footprintFile, 'utf8'));
            if (targetIP && db[targetIP]) {
                res.json({ ip: targetIP, ...db[targetIP] });
            } else if (targetIP) {
                res.json({ ip: targetIP, domains: {}, sessions: [], total_bytes: 0 });
            } else {
                res.json(db);
            }
        } catch (e) {
            res.status(500).json({ error: 'Footprint read error' });
        }
    } else {
        res.json(targetIP ? { ip: targetIP, domains: {}, sessions: [], total_bytes: 0 } : {});
    }
});

// ── BLOCK: Start Blocking (Deny Internet) ─────────────────────────────────────
app.post('/api/block/start', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ error: 'Target IP required' });

    // Kill existing monitor for this IP if any
    if (activeMonitors[`block_${ip}`]) {
        try { activeMonitors[`block_${ip}`].kill('SIGTERM'); } catch (e) { }
        delete activeMonitors[`block_${ip}`];
    }

    const gateway = await getGatewayIP();
    if (!gateway) return res.status(500).json({ error: 'Gateway not found' });

    const scriptPath = path.join(__dirname, '..', 'traffic_monitor.py');
    const iface = getNetworkInterface();
    console.log(`🚫 Blocking ${ip} via ${gateway}...`);

    const cmd = 'python3';
    const args = [scriptPath, '-t', ip, '-g', gateway, '-i', iface, '--action', 'block'];

    const proc = spawn(cmd, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        cwd: path.join(__dirname, '..')
    });
    proc.on('exit', (code) => {
        console.log(`[Block ${ip}] Exited: ${code}`);
        delete activeMonitors[`block_${ip}`];
    });

    activeMonitors[`block_${ip}`] = proc;
    res.json({ status: 'blocking_started', target: ip });
});

// ── BLOCK: Stop ───────────────────────────────────────────────────────────────
app.post('/api/block/stop', (req, res) => {
    const { ip } = req.body || {};
    if (ip && activeMonitors[`block_${ip}`]) {
        activeMonitors[`block_${ip}`].kill('SIGTERM');
        delete activeMonitors[`block_${ip}`];
        return res.json({ status: 'stopped', target: ip });
    }
    // Stop all blockers
    for (const key of Object.keys(activeMonitors)) {
        if (key.startsWith('block_')) {
            try { activeMonitors[key].kill('SIGTERM'); } catch (e) { }
            delete activeMonitors[key];
        }
    }
    res.json({ status: 'all_blocks_stopped' });
});

/**
 * Get Real-time MitM Stats
 */
app.get('/api/mitm/stats', (req, res) => {
    const statsFile = path.join(__dirname, '..', 'traffic_stats.json');

    fs.readFile(statsFile, 'utf8', (err, data) => {
        if (err) {
            return res.json({ status: 'no_data', error: err.message });
        }
        try {
            const json = JSON.parse(data);
            res.json(json);
        } catch (e) {
            res.json({ status: 'error', error: 'Invalid JSON' });
        }
    });
});

// ── Server Status ─────────────────────────────────────────────────────────────
app.get('/api/status', async (req, res) => {
    const dbDeviceCount = await getDeviceCount();

    res.json({
        server: 'Sentinel Bridge v5.0 Enterprise',
        is_root: IS_ROOT,
        supabase_connected: !!supabase,
        total_devices_logged: dbDeviceCount,
        honeypot_port: HONEYPOT_PORT,
        honeypot_triggers: honeypotLogs.length,
        uptime_seconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  KING-LEVEL KALI TOOLS — WiFi, Nmap, Traceroute, Vuln, PCAP, etc.
// ═══════════════════════════════════════════════════════════════════════════════

// ── WiFi Network Scanner ──────────────────────────────────────────────────────
app.get('/api/wifi', (req, res) => {
    const iface = getNetworkInterface();
    // Try iw first (modern), fallback to iwlist
    const cmd = `iw dev ${iface} scan 2>/dev/null || iwlist ${iface} scan 2>/dev/null`;

    exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
        if (error) {
            return res.json({ error: 'WiFi scan failed. Ensure root and wireless interface.', networks: [] });
        }

        const networks = [];
        // Parse iw scan output
        if (stdout.includes('BSS ')) {
            const blocks = stdout.split(/^BSS /m);
            blocks.forEach(block => {
                if (!block.trim()) return;
                const bssid = block.match(/^([0-9a-f:]{17})/i);
                const ssid = block.match(/SSID:\s*(.+)/);
                const signal = block.match(/signal:\s*(-?\d+\.?\d*)/);
                const freq = block.match(/freq:\s*(\d+)/);
                const security = block.includes('RSN') ? 'WPA2/WPA3' : block.includes('WPA') ? 'WPA' : block.includes('Privacy') ? 'WEP' : 'Open';
                const channel = block.match(/primary channel:\s*(\d+)/);

                if (bssid) {
                    networks.push({
                        bssid: bssid[1],
                        ssid: ssid ? ssid[1].trim() : '(Hidden)',
                        signal_dbm: signal ? parseFloat(signal[1]) : null,
                        signal_percent: signal ? Math.min(100, Math.max(0, 2 * (parseFloat(signal[1]) + 100))) : 0,
                        frequency: freq ? parseInt(freq[1]) : null,
                        channel: channel ? parseInt(channel[1]) : null,
                        security,
                    });
                }
            });
        } else {
            // Parse iwlist scan output
            const cells = stdout.split(/Cell \d+/);
            cells.forEach(cell => {
                const address = cell.match(/Address:\s*([0-9A-Fa-f:]+)/);
                const essid = cell.match(/ESSID:"([^"]*)"/);
                const quality = cell.match(/Quality[=:](\d+)\/(\d+)/);
                const signalLevel = cell.match(/Signal level[=:](-?\d+)/);
                const channelMatch = cell.match(/Channel[=:](\d+)/);
                const freqMatch = cell.match(/Frequency[=:](\d+\.?\d*)/);
                const encryption = cell.includes('WPA2') ? 'WPA2' : cell.includes('WPA') ? 'WPA' : cell.includes('on') ? 'WEP' : 'Open';

                if (address) {
                    const q = quality ? Math.round((parseInt(quality[1]) / parseInt(quality[2])) * 100) : 0;
                    networks.push({
                        bssid: address[1],
                        ssid: essid ? essid[1] : '(Hidden)',
                        signal_dbm: signalLevel ? parseInt(signalLevel[1]) : null,
                        signal_percent: q || (signalLevel ? Math.min(100, Math.max(0, 2 * (parseInt(signalLevel[1]) + 100))) : 0),
                        frequency: freqMatch ? parseFloat(freqMatch[1]) * 1000 : null,
                        channel: channelMatch ? parseInt(channelMatch[1]) : null,
                        security: encryption,
                    });
                }
            });
        }

        // Sort by signal strength (strongest first)
        networks.sort((a, b) => (b.signal_percent || 0) - (a.signal_percent || 0));

        res.json({
            interface: iface,
            count: networks.length,
            networks,
            timestamp: new Date().toISOString(),
        });
    });
});

// ── Nmap Deep Scan ────────────────────────────────────────────────────────────
app.get('/api/nmap', (req, res) => {
    const target = req.query.ip || req.query.target;
    if (!target || !isValidIPv4(target)) {
        return res.status(400).json({ error: 'Valid IP address required.' });
    }

    console.log(`🔬 Nmap scan: ${target}`);
    const cmd = `nmap -sV -O -T4 --top-ports 100 -oX - ${target} 2>/dev/null`;

    exec(cmd, { timeout: 120000 }, (error, stdout) => {
        if (error && !stdout) {
            return res.json({ error: 'Nmap scan failed. Is nmap installed?', target });
        }

        // Parse XML output
        const ports = [];
        const portMatches = stdout.matchAll(/<port protocol="(\w+)" portid="(\d+)">.*?<state state="(\w+)".*?\/>.*?<service name="(\w*)".*?product="([^"]*)".*?version="([^"]*)".*?\/>/gs);
        for (const m of portMatches) {
            ports.push({
                protocol: m[1],
                port: parseInt(m[2]),
                state: m[3],
                service: m[4],
                product: m[5],
                version: m[6],
            });
        }

        // Simpler parse if XML regex didn't match
        if (ports.length === 0) {
            const simpleMatches = stdout.matchAll(/<port protocol="(\w+)" portid="(\d+)">/g);
            for (const m of simpleMatches) {
                const portSection = stdout.substring(stdout.indexOf(m[0]));
                const state = portSection.match(/<state state="(\w+)"/);
                const service = portSection.match(/<service name="([^"]*)"/) || [null, ''];
                const product = portSection.match(/product="([^"]*)"/) || [null, ''];
                ports.push({
                    protocol: m[1],
                    port: parseInt(m[2]),
                    state: state ? state[1] : 'unknown',
                    service: service[1],
                    product: product[1],
                    version: '',
                });
            }
        }

        // Parse OS detection
        const osMatch = stdout.match(/<osmatch name="([^"]*)" accuracy="(\d+)"/);
        const hostStateMatch = stdout.match(/<status state="(\w+)"/);

        res.json({
            target,
            host_state: hostStateMatch ? hostStateMatch[1] : 'unknown',
            os: osMatch ? { name: osMatch[1], accuracy: parseInt(osMatch[2]) } : null,
            ports,
            port_count: ports.length,
            timestamp: new Date().toISOString(),
        });
    });
});

// ── Traceroute ────────────────────────────────────────────────────────────────
app.get('/api/traceroute', (req, res) => {
    const target = req.query.target || req.query.ip;
    if (!target) return res.status(400).json({ error: 'Target required (IP or hostname).' });

    // Sanitize: only allow alphanumerics, dots, hyphens
    if (!/^[a-zA-Z0-9.\-]+$/.test(target)) {
        return res.status(400).json({ error: 'Invalid target format.' });
    }

    console.log(`🗺️ Traceroute: ${target}`);
    exec(`traceroute -m 20 -w 2 ${target} 2>/dev/null || tracepath ${target} 2>/dev/null`, { timeout: 60000 }, (error, stdout) => {
        if (error && !stdout) {
            return res.json({ error: 'Traceroute failed.', hops: [] });
        }

        const hops = [];
        const lines = stdout.split('\n');
        lines.forEach(line => {
            const m = line.match(/^\s*(\d+)\s+(.+)/);
            if (m) {
                const hopNum = parseInt(m[1]);
                const rest = m[2];
                const ipMatch = rest.match(/\(?((?:\d{1,3}\.){3}\d{1,3})\)?/);
                const hostMatch = rest.match(/^([a-zA-Z0-9.\-]+)\s/);
                const rttMatches = [...rest.matchAll(/([\d.]+)\s*ms/g)].map(r => parseFloat(r[1]));

                hops.push({
                    hop: hopNum,
                    ip: ipMatch ? ipMatch[1] : null,
                    hostname: hostMatch ? hostMatch[1] : (ipMatch ? ipMatch[1] : '*'),
                    rtt_ms: rttMatches.length > 0 ? rttMatches : null,
                    avg_ms: rttMatches.length > 0 ? Math.round(rttMatches.reduce((a, b) => a + b, 0) / rttMatches.length * 10) / 10 : null,
                    timeout: rest.includes('*'),
                });
            }
        });

        res.json({
            target,
            hop_count: hops.length,
            hops,
            timestamp: new Date().toISOString(),
        });
    });
});

// ── Vulnerability Scanner ─────────────────────────────────────────────────────
app.get('/api/vuln-scan', (req, res) => {
    const target = req.query.ip;
    if (!target || !isValidIPv4(target)) {
        return res.status(400).json({ error: 'Valid IP required.' });
    }

    console.log(`🛡️ Vulnerability scan: ${target}`);

    // Use nmap with vuln scripts
    const cmd = `nmap -sV --script=vuln --top-ports 50 -T4 ${target} 2>/dev/null`;

    exec(cmd, { timeout: 180000 }, (error, stdout) => {
        if (error && !stdout) {
            return res.json({ error: 'Vuln scan failed. Is nmap installed?', vulnerabilities: [] });
        }

        const vulnerabilities = [];
        const lines = stdout.split('\n');
        let currentPort = null;

        lines.forEach(line => {
            const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)/);
            if (portMatch) {
                currentPort = { port: parseInt(portMatch[1]), protocol: portMatch[2], state: portMatch[3], service: portMatch[4] };
            }

            // CVE references
            const cveMatch = line.match(/(CVE-\d{4}-\d+)/gi);
            if (cveMatch) {
                cveMatch.forEach(cve => {
                    vulnerabilities.push({
                        cve,
                        port: currentPort ? currentPort.port : null,
                        service: currentPort ? currentPort.service : null,
                        severity: 'HIGH',
                        detail: line.trim(),
                    });
                });
            }

            // VULNERABLE state
            if (line.includes('VULNERABLE') || line.includes('State: VULNERABLE')) {
                const vulnName = line.trim();
                vulnerabilities.push({
                    cve: null,
                    port: currentPort ? currentPort.port : null,
                    service: currentPort ? currentPort.service : null,
                    severity: 'CRITICAL',
                    detail: vulnName,
                });
            }
        });

        // Risk assessment based on open ports
        const openPorts = [];
        const portRegex = /^(\d+)\/(tcp|udp)\s+open\s+(\S+)/gm;
        let pMatch;
        while ((pMatch = portRegex.exec(stdout)) !== null) {
            openPorts.push({ port: parseInt(pMatch[1]), protocol: pMatch[2], service: pMatch[3] });
        }

        const riskyPorts = [21, 23, 25, 80, 110, 139, 445, 3389, 5900, 8080, 8443];
        const portRisks = openPorts.filter(p => riskyPorts.includes(p.port)).map(p => ({
            port: p.port,
            service: p.service,
            risk: p.port === 23 || p.port === 21 ? 'CRITICAL' : p.port === 445 || p.port === 3389 ? 'HIGH' : 'MEDIUM',
            reason: p.port === 23 ? 'Telnet — unencrypted remote access'
                : p.port === 21 ? 'FTP — credentials sent in plaintext'
                    : p.port === 445 ? 'SMB — common ransomware vector'
                        : p.port === 3389 ? 'RDP — remote desktop exposure'
                            : p.port === 5900 ? 'VNC — screen sharing exposure'
                                : `${p.service} — potentially exploitable`,
        }));

        const overallRisk = vulnerabilities.some(v => v.severity === 'CRITICAL') ? 'CRITICAL'
            : vulnerabilities.length > 0 || portRisks.some(p => p.risk === 'HIGH') ? 'HIGH'
                : portRisks.length > 0 ? 'MEDIUM' : 'LOW';

        res.json({
            target,
            overall_risk: overallRisk,
            vulnerabilities,
            risky_ports: portRisks,
            open_ports: openPorts,
            scan_output: stdout.substring(0, 5000),
            timestamp: new Date().toISOString(),
        });
    });
});

// ── Whois / GeoIP Lookup ──────────────────────────────────────────────────────
app.get('/api/whois', (req, res) => {
    const target = req.query.target || req.query.ip;
    if (!target) return res.status(400).json({ error: 'Target required.' });

    // Sanitize
    if (!/^[a-zA-Z0-9.\-]+$/.test(target)) {
        return res.status(400).json({ error: 'Invalid target.' });
    }

    console.log(`🌐 Whois: ${target}`);

    exec(`whois ${target} 2>/dev/null || echo ''`, { timeout: 15000 }, (error, stdout) => {
        const whoisData = {};
        try {
            if (stdout && stdout.trim()) {
                const fields = ['OrgName', 'Organization', 'org-name', 'Country', 'country', 'City', 'city',
                    'NetRange', 'inetnum', 'CIDR', 'route', 'descr', 'abuse-mailbox', 'OrgAbuseEmail',
                    'NetName', 'netname', 'RegDate', 'created', 'Updated', 'last-modified', 'address'];
                fields.forEach(field => {
                    const m = stdout.match(new RegExp(`^${field}:\\s*(.+)`, 'mi'));
                    if (m) whoisData[field.toLowerCase().replace(/-/g, '_')] = m[1].trim();
                });
                whoisData.raw = stdout.substring(0, 3000);
            }
        } catch (parseErr) {
            console.error('Whois parse error:', parseErr.message);
        }

        // Also try host lookup for DNS
        exec(`host ${target} 2>/dev/null || echo ''`, { timeout: 5000 }, (err2, hostOut) => {
            const dnsRecords = [];
            try {
                if (hostOut && hostOut.trim()) {
                    hostOut.split('\n').forEach(line => {
                        if (line.includes('has address') || line.includes('mail is') || line.includes('has IPv6')) {
                            dnsRecords.push(line.trim());
                        }
                    });
                }
            } catch (dnsErr) {
                console.error('DNS parse error:', dnsErr.message);
            }

            res.json({
                target,
                whois: whoisData,
                dns_records: dnsRecords,
                timestamp: new Date().toISOString(),
            });
        });
    });
});

// ── Packet Capture (tcpdump → PCAP) ──────────────────────────────────────────
let captureProcess = null;
const PCAP_FILE = path.join(__dirname, '..', 'capture.pcap');

app.post('/api/pcap/start', (req, res) => {
    if (captureProcess) {
        return res.json({ status: 'already_running' });
    }

    const iface = getNetworkInterface();
    const duration = Math.min(parseInt(req.body.duration) || 30, 300); // Max 5 min
    const filter = req.body.filter || '';

    console.log(`📦 Starting packet capture on ${iface} for ${duration}s...`);

    const args = ['-i', iface, '-c', '10000', '-w', PCAP_FILE];
    if (filter) args.push(filter);

    captureProcess = spawn('tcpdump', args, { stdio: ['ignore', 'pipe', 'pipe'] });

    // Auto-stop after duration
    setTimeout(() => {
        if (captureProcess) {
            try { captureProcess.kill('SIGTERM'); } catch (e) { }
            captureProcess = null;
        }
    }, duration * 1000);

    captureProcess.on('exit', () => { captureProcess = null; });

    res.json({ status: 'started', interface: iface, duration, pcap_file: 'capture.pcap' });
});

app.post('/api/pcap/stop', (req, res) => {
    if (captureProcess) {
        try { captureProcess.kill('SIGTERM'); } catch (e) { }
        captureProcess = null;
    }
    res.json({ status: 'stopped' });
});

app.get('/api/pcap/download', (req, res) => {
    if (fs.existsSync(PCAP_FILE)) {
        res.download(PCAP_FILE, 'sentinel_capture.pcap');
    } else {
        res.status(404).json({ error: 'No capture file found. Start a capture first.' });
    }
});

app.get('/api/pcap/status', (req, res) => {
    res.json({
        capturing: !!captureProcess,
        file_exists: fs.existsSync(PCAP_FILE),
        file_size: fs.existsSync(PCAP_FILE) ? fs.statSync(PCAP_FILE).size : 0,
    });
});

// ── ARP Table Viewer ──────────────────────────────────────────────────────────
app.get('/api/arp-table', (req, res) => {
    exec('arp -a 2>/dev/null || ip neigh show 2>/dev/null', { timeout: 5000 }, (error, stdout) => {
        if (error) return res.json({ error: 'Failed to read ARP table', entries: [] });

        const entries = [];
        stdout.split('\n').forEach(line => {
            if (!line.trim()) return;

            // Format: hostname (ip) at mac [ether] on iface
            const m1 = line.match(/^(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)\s+\[(\w+)\]\s+on\s+(\S+)/i);
            if (m1) {
                entries.push({ hostname: m1[1], ip: m1[2], mac: m1[3], type: m1[4], interface: m1[5] });
                return;
            }

            // ip neigh format: 192.168.1.1 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE
            const m2 = line.match(/^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]+)\s+(\S+)/i);
            if (m2) {
                entries.push({ hostname: '', ip: m2[1], mac: m2[3], type: 'ether', interface: m2[2], state: m2[4] });
            }
        });

        res.json({ count: entries.length, entries, timestamp: new Date().toISOString() });
    });
});

// ── System Info / Server Health ───────────────────────────────────────────────
app.get('/api/system-info', (req, res) => {
    const os = require('os');

    const commands = {
        kernel: 'uname -r',
        distro: 'cat /etc/os-release 2>/dev/null | head -5',
        cpu_usage: "top -bn1 | head -5 | grep 'Cpu'",
        memory: 'free -h | head -3',
        disk: 'df -h / | tail -1',
        uptime_sys: 'uptime -p 2>/dev/null || uptime',
        logged_in: 'who | wc -l',
        processes: 'ps aux | wc -l',
    };

    const results = {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        cpu_model: os.cpus()[0] ? os.cpus()[0].model : 'Unknown',
        total_memory_gb: (os.totalmem() / (1024 ** 3)).toFixed(2),
        free_memory_gb: (os.freemem() / (1024 ** 3)).toFixed(2),
        memory_usage_percent: ((1 - os.freemem() / os.totalmem()) * 100).toFixed(1),
        load_average: os.loadavg(),
        uptime_seconds: os.uptime(),
        server_uptime_seconds: Math.floor(process.uptime()),
        network_interfaces: {},
        is_root: IS_ROOT,
    };

    // Get network interfaces
    const nets = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(nets)) {
        results.network_interfaces[name] = addrs.filter(a => a.family === 'IPv4').map(a => ({
            address: a.address,
            netmask: a.netmask,
            mac: a.mac,
            internal: a.internal,
        }));
    }

    // Get additional system details
    exec('uname -r && uptime -p 2>/dev/null && df -h / | tail -1', { timeout: 5000 }, (err, stdout) => {
        if (stdout) {
            const lines = stdout.trim().split('\n');
            results.kernel = lines[0] || '';
            results.uptime_human = lines[1] || '';
            if (lines[2]) {
                const diskParts = lines[2].trim().split(/\s+/);
                results.disk = {
                    total: diskParts[1] || '',
                    used: diskParts[2] || '',
                    available: diskParts[3] || '',
                    usage_percent: diskParts[4] || '',
                };
            }
        }
        results.timestamp = new Date().toISOString();
        res.json(results);
    });
});

// ── Local Open Ports (on this machine) ────────────────────────────────────────
app.get('/api/local-ports', (req, res) => {
    exec('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null', { timeout: 5000 }, (error, stdout) => {
        if (error) return res.json({ error: 'Failed to list ports', ports: [] });

        const ports = [];
        stdout.split('\n').forEach(line => {
            if (line.includes('LISTEN')) {
                const parts = line.trim().split(/\s+/);
                // ss format: State Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process
                const localAddr = parts[3] || parts[2] || '';
                const portMatch = localAddr.match(/:(\d+)$/);
                const processMatch = line.match(/users:\(\("([^"]*)".*?pid=(\d+)/);

                if (portMatch) {
                    ports.push({
                        port: parseInt(portMatch[1]),
                        address: localAddr.replace(`:${portMatch[1]}`, ''),
                        process: processMatch ? processMatch[1] : 'unknown',
                        pid: processMatch ? parseInt(processMatch[2]) : null,
                        full_line: line.trim(),
                    });
                }
            }
        });

        // Sort by port number
        ports.sort((a, b) => a.port - b.port);
        res.json({ count: ports.length, ports, timestamp: new Date().toISOString() });
    });
});

// ── Firewall Rules (iptables) ─────────────────────────────────────────────────
app.get('/api/firewall', (req, res) => {
    exec('iptables -L -n -v --line-numbers 2>/dev/null', { timeout: 5000 }, (error, stdout) => {
        if (error) return res.json({ error: 'Failed to read iptables. Requires root.', chains: [] });

        const chains = [];
        let currentChain = null;

        stdout.split('\n').forEach(line => {
            const chainMatch = line.match(/^Chain\s+(\S+)\s+\(policy\s+(\S+)\s+(\d+)\s+packets/);
            if (chainMatch) {
                currentChain = {
                    name: chainMatch[1],
                    policy: chainMatch[2],
                    packets: parseInt(chainMatch[3]),
                    rules: [],
                };
                chains.push(currentChain);
                return;
            }

            if (currentChain && /^\d+/.test(line.trim())) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 8) {
                    currentChain.rules.push({
                        num: parts[0],
                        pkts: parts[1],
                        bytes: parts[2],
                        target: parts[3],
                        prot: parts[4],
                        opt: parts[5],
                        in: parts[6],
                        out: parts[7],
                        source: parts[8] || '*',
                        destination: parts[9] || '*',
                        extra: parts.slice(10).join(' '),
                    });
                }
            }
        });

        res.json({
            chains,
            raw: stdout.substring(0, 5000),
            is_root: IS_ROOT,
            timestamp: new Date().toISOString(),
        });
    });
});

// ── DNS Lookup ────────────────────────────────────────────────────────────────
app.get('/api/dns-lookup', (req, res) => {
    const target = req.query.target;
    if (!target) return res.status(400).json({ error: 'Target domain required.' });
    if (!/^[a-zA-Z0-9.\-]+$/.test(target)) return res.status(400).json({ error: 'Invalid domain.' });

    exec(`dig ${target} ANY +short 2>/dev/null && dig ${target} MX +short 2>/dev/null`, { timeout: 10000 }, (err, stdout) => {
        const records = stdout ? stdout.trim().split('\n').filter(l => l.trim()) : [];
        res.json({ target, records, timestamp: new Date().toISOString() });
    });
});

// ── Network Speed Test (simple bandwidth check) ──────────────────────────────
app.get('/api/speed-test', (req, res) => {
    console.log('⚡ Running speed test...');
    // Download a known file and measure speed
    const start = Date.now();
    exec('curl -sS -o /dev/null -w "%{speed_download} %{time_total} %{size_download}" http://speedtest.tele2.net/1MB.zip 2>/dev/null', { timeout: 30000 }, (err, stdout) => {
        if (err || !stdout) {
            return res.json({ error: 'Speed test failed', download_mbps: 0 });
        }
        const parts = stdout.trim().split(' ');
        const speedBps = parseFloat(parts[0]) || 0;
        const time = parseFloat(parts[1]) || 0;

        res.json({
            download_mbps: ((speedBps * 8) / (1024 * 1024)).toFixed(2),
            download_bytes_per_sec: Math.round(speedBps),
            time_seconds: time,
            timestamp: new Date().toISOString(),
        });
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTOMATED RECON — Full pipeline per device
// ═══════════════════════════════════════════════════════════════════════════════

// Store recon results in memory for quick retrieval
const reconResults = {};

/**
 * Run a single command and return stdout (helper for recon pipeline)
 */
function runCmd(cmd, timeout = 60000) {
    return new Promise((resolve) => {
        exec(cmd, { timeout }, (error, stdout, stderr) => {
            resolve({ error, stdout: stdout || '', stderr: stderr || '' });
        });
    });
}

/**
 * Full automated recon pipeline for a single target IP
 */
async function runFullRecon(targetIP) {
    const startTime = Date.now();
    const report = {
        target: targetIP,
        timestamp: new Date().toISOString(),
        status: 'running',
        phases: {},
        summary: {},
    };

    console.log(`🤖 AUTO-RECON: Starting full pipeline on ${targetIP}`);

    // ── Phase 1: Host status (quick ping) ────────────────────────────────
    try {
        const { error } = await runCmd(`ping -c 1 -W 2 ${targetIP}`, 5000);
        report.phases.host_status = {
            alive: !error,
            method: 'icmp_ping',
        };
    } catch (e) {
        report.phases.host_status = { alive: false, method: 'icmp_ping' };
    }

    // ── Phase 2: Port scan + Service + OS detection (nmap) ───────────────
    try {
        const { stdout } = await runCmd(
            `nmap -sV -O -T4 --top-ports 200 -oX - ${targetIP} 2>/dev/null`,
            120000
        );

        const ports = [];
        const portBlocks = stdout.match(/<port protocol.*?<\/port>/gs) || [];
        portBlocks.forEach(block => {
            const portNum = block.match(/portid="(\d+)"/)?.[1];
            const proto = block.match(/protocol="(\w+)"/)?.[1];
            const state = block.match(/state="(\w+)"/)?.[1];
            const service = block.match(/name="([^"]+)"/)?.[1];
            const product = block.match(/product="([^"]+)"/)?.[1];
            const version = block.match(/version="([^"]+)"/)?.[1];
            const extrainfo = block.match(/extrainfo="([^"]+)"/)?.[1];

            if (state === 'open') {
                ports.push({
                    port: parseInt(portNum),
                    protocol: proto || 'tcp',
                    service: service || 'unknown',
                    product: product || '',
                    version: version || '',
                    extra: extrainfo || '',
                    state,
                });
            }
        });

        // OS detection
        const osMatch = stdout.match(/<osmatch name="([^"]*)"[^>]*accuracy="(\d+)"/);
        const os = osMatch ? { name: osMatch[1], accuracy: osMatch[2] } : null;

        // Host state
        const hostState = stdout.match(/<status state="(\w+)"/)?.[1] || 'unknown';

        report.phases.port_scan = {
            ports,
            port_count: ports.length,
            os,
            host_state: hostState,
        };
    } catch (e) {
        report.phases.port_scan = { error: e.message, ports: [], port_count: 0 };
    }

    // ── Phase 3: Vulnerability scan (nmap scripts) ───────────────────────
    try {
        const { stdout } = await runCmd(
            `nmap --script=vuln -T4 --top-ports 50 ${targetIP} 2>/dev/null`,
            180000
        );

        const vulns = [];
        const vulnBlocks = stdout.split(/\|_?\s*/);
        vulnBlocks.forEach(block => {
            const cveMatch = block.match(/(CVE-\d{4}-\d+)/);
            if (cveMatch) {
                vulns.push({
                    cve: cveMatch[1],
                    detail: block.substring(0, 200).trim(),
                    severity: 'HIGH',
                });
            }
            // Also catch general vulnerability mentions
            if (block.includes('VULNERABLE') || block.includes('vulnerable')) {
                const lines = block.split('\n').filter(l => l.trim());
                vulns.push({
                    cve: cveMatch ? cveMatch[1] : 'N/A',
                    detail: lines.slice(0, 3).join(' ').substring(0, 200).trim(),
                    severity: cveMatch ? 'HIGH' : 'MEDIUM',
                });
            }
        });

        // Deduplicate vulns by CVE
        const seen = new Set();
        const uniqueVulns = vulns.filter(v => {
            const key = v.cve + v.detail.substring(0, 50);
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        report.phases.vuln_scan = {
            vulnerabilities: uniqueVulns,
            vuln_count: uniqueVulns.length,
        };
    } catch (e) {
        report.phases.vuln_scan = { error: e.message, vulnerabilities: [], vuln_count: 0 };
    }

    // ── Phase 4: Credential audit (HTTP basic auth) ──────────────────────
    try {
        const agentPath = path.join(__dirname, '../agent.py');
        const { stdout } = await runCmd(`python3 "${agentPath}" audit ${targetIP}`, 30000);
        report.phases.credential_audit = JSON.parse(stdout);
    } catch (e) {
        report.phases.credential_audit = { status: 'ERROR', error: e.message };
    }

    // ── Phase 5: Reverse DNS + hostname ──────────────────────────────────
    try {
        const hostname = await resolveHostname(targetIP);
        const vendor = await lookupVendor(''); // Will be filled by caller if MAC available
        report.phases.identity = { hostname, vendor };
    } catch (e) {
        report.phases.identity = { hostname: 'Unknown', vendor: 'Unknown' };
    }

    // ── Phase 6: Traceroute (quick) ──────────────────────────────────────
    try {
        const { stdout } = await runCmd(
            `traceroute -m 15 -w 2 ${targetIP} 2>/dev/null || tracepath ${targetIP} 2>/dev/null`,
            30000
        );
        const hops = [];
        const lines = stdout.trim().split('\n');
        lines.forEach(line => {
            const hopMatch = line.match(/^\s*(\d+)\s+(.+)$/);
            if (hopMatch) {
                const hopNum = parseInt(hopMatch[1]);
                const rest = hopMatch[2];
                const ipMatch = rest.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
                const rttMatch = rest.match(/([\d.]+)\s*ms/);
                hops.push({
                    hop: hopNum,
                    ip: ipMatch ? ipMatch[1] : null,
                    rtt_ms: rttMatch ? parseFloat(rttMatch[1]) : null,
                    raw: rest.trim(),
                });
            }
        });
        report.phases.traceroute = { hops, hop_count: hops.length };
    } catch (e) {
        report.phases.traceroute = { hops: [], hop_count: 0 };
    }

    // ── Build Summary ────────────────────────────────────────────────────
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const ps = report.phases.port_scan || {};
    const vs = report.phases.vuln_scan || {};
    const ca = report.phases.credential_audit || {};

    let riskLevel = 'LOW';
    if ((vs.vuln_count || 0) > 0 || ca.status === 'VULNERABLE') riskLevel = 'CRITICAL';
    else if ((ps.port_count || 0) > 10) riskLevel = 'HIGH';
    else if ((ps.port_count || 0) > 5) riskLevel = 'MEDIUM';

    report.summary = {
        risk_level: riskLevel,
        open_ports: ps.port_count || 0,
        vulnerabilities: vs.vuln_count || 0,
        credential_status: ca.status || 'UNKNOWN',
        os: ps.os ? ps.os.name : 'Unknown',
        scan_time_seconds: parseFloat(elapsed),
    };
    report.status = 'complete';

    console.log(`🤖 AUTO-RECON: ${targetIP} done in ${elapsed}s — ${riskLevel} risk`);

    // Cache result
    reconResults[targetIP] = report;
    return report;
}

// ── Auto-Recon: Single Target ─────────────────────────────────────────────
app.post('/api/auto-recon', async (req, res) => {
    const { ip } = req.body;

    if (!isValidIPv4(ip)) {
        return res.status(400).json({ error: 'Invalid IP address.' });
    }

    console.log(`🤖 Auto-recon requested for ${ip}`);

    try {
        const report = await runFullRecon(ip);
        res.json(report);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Batch Recon: All Devices ──────────────────────────────────────────────
app.post('/api/batch-recon', async (req, res) => {
    const { ips } = req.body;

    if (!Array.isArray(ips) || ips.length === 0) {
        return res.status(400).json({ error: 'Provide array of IPs.' });
    }

    // Validate all IPs
    const validIPs = ips.filter(ip => isValidIPv4(ip));
    if (validIPs.length === 0) {
        return res.status(400).json({ error: 'No valid IPs provided.' });
    }

    // Cap at 20 devices to prevent overload
    const targetIPs = validIPs.slice(0, 20);
    console.log(`🤖 Batch recon: ${targetIPs.length} targets`);

    try {
        // Run all recons in parallel (but cap concurrency with a simple batch)
        const batchSize = 5;
        const allResults = [];

        for (let i = 0; i < targetIPs.length; i += batchSize) {
            const batch = targetIPs.slice(i, i + batchSize);
            const results = await Promise.allSettled(
                batch.map(ip => runFullRecon(ip))
            );
            results.forEach((r, idx) => {
                if (r.status === 'fulfilled') {
                    allResults.push(r.value);
                } else {
                    allResults.push({
                        target: batch[idx],
                        status: 'error',
                        error: r.reason?.message || 'Unknown error',
                    });
                }
            });
        }

        // Overall summary
        const critCount = allResults.filter(r => r.summary?.risk_level === 'CRITICAL').length;
        const highCount = allResults.filter(r => r.summary?.risk_level === 'HIGH').length;

        res.json({
            status: 'complete',
            total_targets: allResults.length,
            critical: critCount,
            high: highCount,
            results: allResults,
            timestamp: new Date().toISOString(),
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── Get Cached Recon Results ──────────────────────────────────────────────
app.get('/api/recon-results', (req, res) => {
    const ip = req.query.ip;
    if (ip && reconResults[ip]) {
        return res.json(reconResults[ip]);
    }
    res.json({
        cached_targets: Object.keys(reconResults),
        count: Object.keys(reconResults).length,
    });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  GLOBAL ERROR HANDLER — Always return JSON, never HTML
// ═══════════════════════════════════════════════════════════════════════════════

app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err.message);
    res.status(500).json({ error: err.message || 'Internal server error' });
});

// Catch 404s (unknown routes) and return JSON
app.use((req, res) => {
    res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  START — 0.0.0.0 for physical device access
// ═══════════════════════════════════════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
    const { networkInterfaces } = require('os');
    const nets = networkInterfaces();
    let localIP = 'localhost';

    for (const name of Object.keys(nets)) {
        for (const net of nets[name]) {
            if (net.family === 'IPv4' && !net.internal) {
                localIP = net.address;
                break;
            }
        }
    }

    console.log(`\n🚀 Server on http://0.0.0.0:${PORT}`);
    console.log(`   → Phone:    http://${localIP}:${PORT}`);
    console.log(`   → Emulator: http://10.0.2.2:${PORT}`);
    console.log(`   → Local:    http://localhost:${PORT}\n`);

    // Auto-start passive DNS monitor
    const IS_ROOT = process.getuid && process.getuid() === 0;
    if (IS_ROOT) {
        startPassiveMonitor();
    } else {
        console.log('⚠️  Not root — passive DNS monitor requires sudo. Run: sudo node Backend/server.js');
    }
});