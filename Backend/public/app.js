// ═══════════════════════════════════════════════════════════════════════════════
//  SENTINEL CLIENT — v6.0 KING EDITION
// ═══════════════════════════════════════════════════════════════════════════════

let scanInterval = null;
let currentDevices = [];
let monitorInterval = null;
let inspectorInterval = null;
let selectedDevice = null;
let radarAngle = 0;

/**
 * Safe fetch wrapper — always returns parsed JSON, never throws on parse errors.
 * If the response is not valid JSON, returns { error: '...' }
 */
async function safeFetch(url, options) {
    const res = await fetch(url, options);
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch (e) {
        console.error(`JSON parse error from ${url}:`, text.substring(0, 200));
        return { error: `Server returned invalid response (HTTP ${res.status}). ${text.substring(0, 100)}` };
    }
}

// ══ SOCKET.IO ═══════════════════════════════════════════════════════════════
const socket = io();

socket.on('connect', () => {
    log('Connected to Sentinel Core via WebSocket');
});

socket.on('scan:complete', (data) => {
    if (!data || data.status !== 'success') return;
    log(`[NET] Real-time update: ${data.count} devices found.`);

    currentDevices = data.devices;
    renderDevices(data.devices);
    renderTargets();
    renderRadar(data.devices);

    document.getElementById('deviceCount').innerText = data.count;
    document.getElementById('subnetInfo').innerText = data.subnet;

    const methodsEl = document.getElementById('scanMethods');
    if (methodsEl && data.methods) methodsEl.innerText = data.methods.join(' + ');
});

// ══ INIT ═════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
    log('Sentinel v6.0 initialized. Systems armed.');
    initMatrixRain();
    initRadarSweep();
    updateStats();

    // Load cached devices instantly, then trigger full scan in background
    loadCachedDevices().then(() => scanNetwork());

    // Auto-refresh stats
    setInterval(updateStats, 5000);
});

async function loadCachedDevices() {
    try {
        const data = await safeFetch('/api/devices');
        if (data.status !== 'no_cache' && data.devices && data.devices.length > 0) {
            currentDevices = data.devices;
            renderDevices(data.devices);
            renderTargets();
            renderRadar(data.devices);
            document.getElementById('deviceCount').innerText = data.count;
            document.getElementById('subnetInfo').innerText = data.subnet;
            const methodsEl = document.getElementById('scanMethods');
            if (methodsEl && data.methods) methodsEl.innerText = data.methods.join(' + ') + ' (cached)';
            log(`Loaded ${data.count} cached devices from previous scan.`);
        }
    } catch (e) {
        // Silently continue to live scan
    }
}

// ══ MATRIX RAIN ═════════════════════════════════════════════════════════════
function initMatrixRain() {
    const canvas = document.getElementById('matrixCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = 'SENTINEL01アイウエオカキクケコ10110100101';
    const fontSize = 12;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = new Array(columns).fill(1);

    function drawMatrix() {
        ctx.fillStyle = 'rgba(10, 10, 15, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00f2ff';
        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const text = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
            drops[i]++;
        }
    }

    setInterval(drawMatrix, 50);
    window.addEventListener('resize', () => { canvas.width = window.innerWidth; canvas.height = window.innerHeight; });
}

// ══ RADAR SWEEP ═════════════════════════════════════════════════════════════
function initRadarSweep() {
    function animate() {
        radarAngle += 0.02;
        if (radarAngle > Math.PI * 2) radarAngle -= Math.PI * 2;
        if (currentDevices.length > 0) renderRadar(currentDevices);
        requestAnimationFrame(animate);
    }
    requestAnimationFrame(animate);
}

// ══ NAVIGATION ══════════════════════════════════════════════════════════════
function switchTab(tabId) {
    document.querySelectorAll('.view-section').forEach(el => { el.style.display = 'none'; el.classList.remove('active'); });
    const target = document.getElementById(`view-${tabId}`);
    if (target) { target.style.display = 'block'; setTimeout(() => target.classList.add('active'), 10); }

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const nav = document.getElementById(`nav-${tabId}`);
    if (nav) nav.classList.add('active');

    // Auto-load data for tabs
    if (tabId === 'targets') renderTargets();
    if (tabId === 'footprint') renderGlobalFootprint();
    if (tabId === 'sysinfo') loadSystemInfo();
    if (tabId === 'firewall') loadFirewall();
    if (tabId === 'history') loadScanHistory();
    if (tabId === 'topology') setTimeout(() => renderTopology(), 100);

    if (tabId === 'attack') startAttackLogPolling();
    else stopAttackLogPolling();
}

// ══ NETWORK SCAN ════════════════════════════════════════════════════════════
async function scanNetwork() {
    const statusEl = document.getElementById('scanStatus');
    if (statusEl) { statusEl.innerText = 'SCANNING...'; statusEl.className = 'badge warning'; }
    log('Initiating active network scan...');

    try {
        const data = await safeFetch('/api/scan');

        if (data.status === 'success') {
            currentDevices = data.devices;
            renderDevices(data.devices);
            renderTargets();
            renderRadar(data.devices);
            document.getElementById('deviceCount').innerText = data.count;
            document.getElementById('subnetInfo').innerText = data.subnet;
            const methodsEl = document.getElementById('scanMethods');
            if (methodsEl && data.methods) methodsEl.innerText = data.methods.join(' + ');
            if (statusEl) { statusEl.innerText = 'IDLE'; statusEl.className = 'badge'; }
            log(`Scan complete. ${data.count} devices found on ${data.subnet}`);
        } else {
            throw new Error(data.message || 'Unknown error');
        }
    } catch (error) {
        console.error('Scan Error:', error);
        log(`Scan failed: ${error.message}`);
        if (statusEl) { statusEl.innerText = 'ERROR'; statusEl.className = 'badge danger'; }
    }
}

async function updateStats() {
    try {
        const res = await fetch('/api/traffic');
        const stats = await res.json();
        if (stats.error) return;
        document.getElementById('uploadStats').innerText = stats.upload_mb + ' MB';
        document.getElementById('downloadStats').innerText = stats.download_mb + ' MB';
        document.getElementById('connectionCount').innerText = stats.connections;
    } catch (e) { }
}

// ══ RENDERING ═══════════════════════════════════════════════════════════════
function renderDevices(devices) {
    const grid = document.getElementById('deviceGrid');
    grid.innerHTML = '';
    if (!devices.length) { grid.innerHTML = '<div class="empty-state">No devices found. Try rescanning.</div>'; return; }
    devices.forEach(d => grid.appendChild(createDeviceCard(d)));
}

function renderTargets() {
    const grid = document.getElementById('targetGrid');
    grid.innerHTML = '';
    const targets = currentDevices.filter(d => d.name);
    if (!targets.length) { grid.innerHTML = '<div class="empty-state">No named targets yet. Rename a device to pin it here.</div>'; return; }
    targets.forEach(d => grid.appendChild(createDeviceCard(d)));
}

function createDeviceCard(device) {
    const card = document.createElement('div');
    card.className = 'device-card';
    card.onclick = () => openDeviceModal(device);

    const isRandom = device.type === 'Privacy-Randomized MAC';
    const icon = getIconForType(device.type);
    const name = device.name || device.hostname || device.vendor || 'Unknown Device';
    const sub = device.name ? (device.hostname || device.vendor) : (device.vendor || device.type);

    card.innerHTML = `
        <div class="ip-badge">${device.ip}</div>
        <div class="header">
            <div class="device-icon">${icon}</div>
            <div class="device-details">
                <h3>${name}</h3>
                <p>${sub}</p>
                <p style="font-family:monospace;opacity:0.5;font-size:10px;">${device.mac}</p>
            </div>
        </div>
        <div class="meta-tags">
            <span class="tag online">ONLINE</span>
            ${isRandom ? '<span class="tag random">RANDOM MAC</span>' : ''}
            <span class="tag apple">${device.vendor || 'Unknown'}</span>
            ${device.discovery_method ? `<span class="tag" style="background:rgba(0,242,255,0.1);color:var(--accent);font-size:8px;">${device.discovery_method}</span>` : ''}
        </div>
        <div style="margin-top:8px;display:flex;gap:6px;">
            <button class="btn btn-danger" onclick="event.stopPropagation();autoReconIP('${device.ip}')" style="flex:1;font-size:9px;padding:4px 8px;">RECON</button>
        </div>`;
    return card;
}

function getIconForType(type) {
    // Return SVG icons instead of emojis
    const laptop = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20"/></svg>';
    const phone = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><path d="M12 18h.01"/></svg>';
    const server = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>';
    const router = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="13" width="20" height="8" rx="2" /><path d="M6 13V10" /><path d="M18 13V10" /><path d="M6 7l6-3 6 3" /></svg>';
    const iot = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-6 9 6v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V9z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>';
    const generic = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

    if (!type) return generic;
    if (type.includes('Apple') || type.includes('Android') || type.includes('Mobile')) return phone;
    if (type.includes('PC') || type.includes('Laptop') || type.includes('Desktop')) return laptop;
    if (type.includes('Server') || type.includes('Linux')) return server;
    if (type.includes('Router') || type.includes('Network') || type.includes('Gateway')) return router;
    if (type.includes('IoT') || type.includes('Home')) return iot;
    return generic;
}

// ══ RADAR ════════════════════════════════════════════════════════════════════
function renderRadar(devices) {
    const canvas = document.getElementById('radarCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Handle retina/high-DPI
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();

    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);
    canvas.style.width = `${rect.width}px`;
    canvas.style.height = `${rect.height}px`;

    const cx = rect.width / 2;
    const cy = rect.height / 2;
    const maxR = Math.min(rect.width, rect.height) / 2 - 20;

    ctx.clearRect(0, 0, rect.width, rect.height);

    // Grid circles (Concentric rings)
    ctx.strokeStyle = 'rgba(0, 242, 255, 0.1)';
    ctx.lineWidth = 1;
    [0.25, 0.5, 0.75, 1.0].forEach(s => {
        ctx.beginPath();
        ctx.arc(cx, cy, maxR * s, 0, Math.PI * 2);
        ctx.stroke();
    });

    // Crosshairs
    ctx.beginPath();
    ctx.moveTo(cx, cy - maxR); ctx.lineTo(cx, cy + maxR);
    ctx.moveTo(cx - maxR, cy); ctx.lineTo(cx + maxR, cy);
    ctx.stroke();

    // Rotating Sweep (Gradient)
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(radarAngle);

    const grad = ctx.createLinearGradient(0, 0, maxR, 0);
    grad.addColorStop(0, 'rgba(0, 242, 255, 0)');
    grad.addColorStop(1, 'rgba(0, 242, 255, 0.15)');

    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, maxR, -0.2, 0);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Lead line
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(maxR, 0);
    ctx.strokeStyle = '#00f2ff';
    ctx.lineWidth = 2;
    ctx.shadowBlur = 10;
    ctx.shadowColor = '#00f2ff';
    ctx.stroke();

    ctx.restore();

    // Device blips
    devices.forEach(d => {
        // Deterministic position based on IP
        const octets = d.ip.split('.').map(Number);
        const lastOctet = octets[3] || 1;
        const dist = maxR * (0.2 + (lastOctet / 255) * 0.7);
        const angle = (lastOctet * 137.5) * (Math.PI / 180); // Golden angle distribution

        const x = cx + Math.cos(angle) * dist;
        const y = cy + Math.sin(angle) * dist;

        const isGateway = d.ip.endsWith('.1') || d.ip.endsWith('.254');

        // Dot
        ctx.beginPath();
        ctx.arc(x, y, isGateway ? 4 : 2, 0, Math.PI * 2);
        ctx.fillStyle = isGateway ? '#fff' : '#00f2ff';
        ctx.shadowBlur = isGateway ? 10 : 5;
        ctx.shadowColor = '#00f2ff';
        ctx.fill();

        // Ring
        ctx.beginPath();
        ctx.arc(x, y, isGateway ? 8 : 4, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 242, 255, ${Math.random() * 0.3 + 0.1})`;
        ctx.lineWidth = 1;
        ctx.stroke();
    });
}

// ══ MODAL ════════════════════════════════════════════════════════════════════
function openDeviceModal(device) {
    selectedDevice = device;
    document.getElementById('modalTitle').innerText = device.name || device.hostname || device.vendor || 'Unknown';
    document.getElementById('modalIp').innerText = device.ip;
    document.getElementById('modalMac').innerText = device.mac;
    document.getElementById('modalVendor').innerText = device.vendor;
    document.getElementById('renameInput').value = device.name || '';
    document.getElementById('modalConsole').innerText = `Target: ${device.ip}\nWaiting for command...`;
    document.getElementById('deviceModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('deviceModal').style.display = 'none';
    selectedDevice = null;
}

window.onclick = function (event) {
    if (event.target === document.getElementById('deviceModal')) closeModal();
};

// ══ DEVICE ACTIONS ══════════════════════════════════════════════════════════
async function saveDeviceName() {
    if (!selectedDevice) return;
    const name = document.getElementById('renameInput').value.trim();
    if (!name) return alert('Enter a name');
    log(`Renaming ${selectedDevice.mac} → "${name}"...`);
    try {
        const res = await fetch('/api/device/rename', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mac: selectedDevice.mac, name }) });
        const data = await res.json();
        if (data.status === 'success') { log(`Renamed to ${name}`); closeModal(); scanNetwork(); }
        else alert('Failed: ' + data.error);
    } catch (e) { log('Error renaming.'); }
}

async function startMitm() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    log(`Starting MITM on ${ip}...`);
    appendToConsole(`> ARP SPOOFING ${ip}...`);
    try {
        const res = await fetch('/api/mitm/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, duration: 60 }) });
        const data = await res.json();
        if (data.error) { appendToConsole(`ERROR: ${data.error}`); }
        else {
            appendToConsole(`SUCCESS. Gateway: ${data.gateway}`);
            log('MITM active. Inspector open.');
            switchTab('targets'); showInspector(selectedDevice); closeModal();
        }
    } catch (e) { appendToConsole(`Error: ${e.message}`); }
}

function showInspector(device) {
    document.getElementById('inspectorPanel').style.display = 'block';
    document.getElementById('inspectorName').innerText = device.name || device.hostname || device.vendor;
    document.getElementById('inspectorIp').innerText = device.ip;
    if (inspectorInterval) clearInterval(inspectorInterval);
    inspectorInterval = setInterval(updateInspector, 2000);
}

async function updateInspector() {
    try {
        const res = await fetch('/api/mitm/details');
        const data = await res.json();
        if (data.error) return;

        document.getElementById('inspUp').innerText = formatBytes(data.upload_bytes);
        document.getElementById('inspDown').innerText = formatBytes(data.download_bytes);

        const domainList = document.getElementById('inspDomains');
        if (data.recent_sites && data.recent_sites.length > 0) {
            domainList.innerHTML = data.recent_sites.map(s => `
                <div class="domain-item">
                    <span class="time">${new Date(s.timestamp * 1000).toLocaleTimeString()}</span>
                    <span class="url">${s.url || s.domain}</span>
                </div>`).join('');
        }

        const imageList = document.getElementById('inspImages');
        if (data.captured_images && data.captured_images.length > 0) {
            imageList.innerHTML = data.captured_images.map(img => `
                <div class="media-item" onclick="window.open('/captured_images/${img.filename}','_blank')">
                    <img src="/captured_images/${img.filename}" loading="lazy">
                </div>`).join('');
        } else {
            imageList.innerHTML = '<div class="empty-media">No images captured yet.</div>';
        }
        updateFootprint();
    } catch (e) { }
}

async function stopMitm() {
    try {
        await fetch('/api/mitm/stop', { method: 'POST' });
        clearInterval(inspectorInterval);
        document.getElementById('inspectorPanel').style.display = 'none';
        log('Monitoring stopped.');
    } catch (e) { log('Error stopping.'); }
}

async function blockInternet() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    log(`Blocking ${ip}...`);
    appendToConsole(`> CUTTING ${ip}...`);
    try {
        const res = await fetch('/api/block/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
        const data = await res.json();
        if (data.error) appendToConsole(`ERROR: ${data.error}`);
        else { appendToConsole('SUCCESS: Target isolated.'); log(`Block active on ${ip}`); }
    } catch (e) { appendToConsole(`Error: ${e.message}`); }
}

async function deepScan() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    log(`Deep scanning ${ip}...`);
    appendToConsole(`> PORT SCANNING ${ip}...\n> Please wait...`);
    try {
        const data = await safeFetch(`/api/inspect?ip=${ip}`);
        if (data.error) appendToConsole(`ERROR: ${data.error}`);
        else {
            const ports = data.ports ? data.ports.join(', ') : 'None';
            appendToConsole(`DONE.\nOpen Ports: ${ports}\nOS: ${data.os || 'Unknown'}`);
        }
    } catch (e) { appendToConsole(`Error: ${e.message}`); }
}

async function quickNmap() {
    if (!selectedDevice) return;
    const ip = selectedDevice.ip;
    appendToConsole(`> NMAP SCAN ${ip}...\n> This may take 30-60s...`);
    try {
        const data = await safeFetch(`/api/nmap?ip=${ip}`);
        if (data.error) { appendToConsole(`ERROR: ${data.error}`); return; }
        let out = `HOST: ${data.host_state}\n`;
        if (data.os) out += `OS: ${data.os.name} (${data.os.accuracy}%)\n`;
        out += `PORTS (${data.port_count}):\n`;
        data.ports.forEach(p => { out += `  ${p.port}/${p.protocol} ${p.state} ${p.service} ${p.product} ${p.version}\n`; });
        appendToConsole(out);
    } catch (e) { appendToConsole(`Error: ${e.message}`); }
}

function appendToConsole(text) {
    const box = document.getElementById('modalConsole');
    box.innerText += '\n' + text;
    box.scrollTop = box.scrollHeight;
}

// ══ WIFI SCANNER ════════════════════════════════════════════════════════════
async function scanWifi() {
    const container = document.getElementById('wifiResults');
    container.innerHTML = '<div class="empty-state">Scanning WiFi networks...</div>';
    log('Scanning WiFi...');

    try {
        const data = await safeFetch('/api/wifi');

        if (data.error && (!data.networks || data.networks.length === 0)) {
            container.innerHTML = `<div class="empty-state">${data.error}</div>`;
            return;
        }

        if (!data.networks || data.networks.length === 0) {
            container.innerHTML = '<div class="empty-state">No networks found.</div>';
            return;
        }

        let html = `<div style="margin-bottom:10px;font-size:11px;color:var(--text-muted);">Found ${data.count} networks on ${data.interface}</div>`;

        data.networks.forEach(net => {
            const bars = 4;
            const activeBars = Math.ceil((net.signal_percent / 100) * bars);
            let barsHtml = '';
            for (let i = 0; i < bars; i++) {
                const h = 6 + i * 4;
                barsHtml += `<div class="wifi-bar${i < activeBars ? ' active' : ''}" style="height:${h}px;"></div>`;
            }

            const secClass = net.security === 'Open' ? 'open' : 'secure';
            const connectedClass = net.connected ? 'connected-wifi' : '';
            const connectedBadge = net.connected ? '<span class="badge" style="background:var(--accent);color:#000;font-weight:700;margin-left:8px;">CONNECTED</span>' : '';

            html += `
                <div class="wifi-card ${connectedClass}" style="${net.connected ? 'border-color:var(--accent);background:rgba(0,242,255,0.05);' : ''}">
                    <div class="wifi-info">
                        <h4>${net.ssid} ${connectedBadge}</h4>
                        <span>${net.bssid} • CH ${net.channel || '?'} • ${net.signal_dbm || '?'} dBm</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:12px;">
                        <button class="btn btn-danger" onclick="deauthNetwork('${net.bssid}', '${net.channel}')" style="font-size:10px;padding:4px 8px;">DEAUTH</button>
                        <span class="security-badge ${secClass}">${net.security}</span>
                        <div class="wifi-signal">${barsHtml}</div>
                        <span style="font-size:11px;color:var(--accent);font-weight:700;">${net.signal_percent}%</span>
                    </div>
                </div>`;
        });

        container.innerHTML = html;
        log(`WiFi scan: ${data.count} networks found.`);
    } catch (e) {
        container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
        log('WiFi scan failed.');
    }
}

async function deauthNetwork(bssid, channel) {
    if (!confirm(`ATTACK WARNING\n\nAre you authorized to test this network (${bssid})?\n\nThis will disconnect clients temporarily.`)) return;

    const count = prompt('How many deauth packets? (Default 10, Max 50)', '10');
    if (count === null) return;

    log(`Initiating Deauth attack on ${bssid} (CH ${channel})...`);
    try {
        const data = await safeFetch('/api/wifi/deauth', {
            method: 'POST',
            body: JSON.stringify({ bssid, channel, count: parseInt(count) || 10 })
        });

        if (data.status === 'success') {
            log(`[>] Attack Sent: ${data.message}`);
            alert(`Attack Sent!\n${data.message}`);
        } else {
            throw new Error(data.error || 'Unknown error');
        }
    } catch (e) {
        log(`[!] Attack Failed: ${e.message}`);
        alert(`Attack Failed:\n${e.message}\n\nCheck if interface is in Monitor Mode?\n(e.g., airmon-ng start wlan0)`);
    }
}

// ══ NMAP SCANNER ════════════════════════════════════════════════════════════
async function runNmap() {
    const target = document.getElementById('nmapTarget').value.trim();
    if (!target) return alert('Enter target IP');
    const box = document.getElementById('nmapResults');
    box.innerText = `Scanning ${target} with Nmap...\nThis may take 30-60 seconds...`;
    log(`Nmap: ${target}`);

    try {
        const data = await safeFetch(`/api/nmap?ip=${target}`);
        if (data.error) { box.innerText = `ERROR: ${data.error}`; return; }

        let out = `═══ NMAP SCAN RESULTS ═══\nTarget: ${data.target}\nState: ${data.host_state}\n`;
        if (data.os) out += `OS: ${data.os.name} (accuracy: ${data.os.accuracy}%)\n`;
        out += `\nOpen Ports: ${data.port_count}\n${'─'.repeat(60)}\n`;
        out += 'PORT      STATE    SERVICE         PRODUCT\n';
        out += '─'.repeat(60) + '\n';
        (data.ports || []).forEach(p => {
            out += `${(p.port + '/' + p.protocol).padEnd(10)}${p.state.padEnd(9)}${(p.service || '').padEnd(16)}${p.product || ''} ${p.version || ''}\n`;
        });
        box.innerText = out;
        log(`Nmap: ${data.port_count} ports on ${target}`);
    } catch (e) { box.innerText = `Error: ${e.message}`; }
}

// ══ TRACEROUTE ══════════════════════════════════════════════════════════════
async function runTraceroute() {
    const target = document.getElementById('tracerouteTarget').value.trim();
    if (!target) return alert('Enter target');
    const container = document.getElementById('tracerouteResults');
    container.innerHTML = '<div class="empty-state">Tracing route... This may take up to 60 seconds.</div>';
    log(`Traceroute: ${target}`);

    try {
        const data = await safeFetch(`/api/traceroute?target=${encodeURIComponent(target)}`);
        if (data.error && (!data.hops || data.hops.length === 0)) {
            container.innerHTML = `<div class="empty-state">${data.error}</div>`;
            return;
        }

        let html = `<div style="font-size:11px;color:var(--text-muted);margin-bottom:10px;">Route to ${data.target} — ${data.hop_count} hops</div><div class="hop-vis">`;

        data.hops.forEach((hop, i) => {
            const dotClass = hop.timeout && !hop.ip ? 'timeout' : '';
            const rtt = hop.avg_ms !== null ? `${hop.avg_ms} ms` : '* * *';
            const rttColor = hop.avg_ms === null ? 'var(--danger)' : hop.avg_ms < 10 ? 'var(--success)' : hop.avg_ms < 50 ? 'var(--warning)' : 'var(--danger)';

            html += `
                <div class="hop-row">
                    <div class="hop-num">${hop.hop}</div>
                    <div class="hop-dot ${dotClass}"></div>
                    <div class="hop-detail">
                        <div class="hop-host">${hop.hostname || '*'}</div>
                        <div class="hop-ip">${hop.ip || 'timeout'}</div>
                    </div>
                    <div class="hop-rtt" style="color:${rttColor}">${rtt}</div>
                </div>`;
            if (i < data.hops.length - 1) html += '<div class="hop-line"></div>';
        });

        html += '</div>';
        container.innerHTML = html;
        log(`Traceroute: ${data.hop_count} hops to ${target}`);
    } catch (e) { container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`; }
}

// ══ VULN SCANNER ════════════════════════════════════════════════════════════
async function runVulnScan() {
    const target = document.getElementById('vulnTarget').value.trim();
    if (!target) return alert('Enter target IP');
    const container = document.getElementById('vulnResults');
    container.innerHTML = '<div class="empty-state">Scanning for vulnerabilities... This may take 2-3 minutes.</div>';
    log(`Vuln scan: ${target}`);

    try {
        const data = await safeFetch(`/api/vuln-scan?ip=${target}`);
        if (data.error) { container.innerHTML = `<div class="empty-state">Error: ${data.error}</div>`; return; }

        let html = `<div class="tool-panel" style="margin-bottom:16px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h3>Risk Assessment: ${data.target}</h3>
                <span class="sev ${(data.overall_risk || 'low').toLowerCase()}">${data.overall_risk || 'UNKNOWN'} RISK</span>
            </div></div>`;

        if ((data.vulnerabilities || []).length > 0) {
            html += `<div class="tool-panel"><h3 style="color:var(--danger);">[!] Vulnerabilities Found (${data.vulnerabilities.length})</h3>
                <table class="data-table"><thead><tr><th>CVE</th><th>PORT</th><th>SERVICE</th><th>SEVERITY</th><th>DETAIL</th></tr></thead><tbody>`;
            data.vulnerabilities.forEach(v => {
                html += `<tr><td>${v.cve || '—'}</td><td>${v.port || '—'}</td><td>${v.service || '—'}</td>
                    <td><span class="sev ${v.severity.toLowerCase()}">${v.severity}</span></td><td style="font-size:10px;">${v.detail.substring(0, 80)}</td></tr>`;
            });
            html += '</tbody></table></div>';
        }

        if (data.risky_ports.length > 0) {
            html += `<div class="tool-panel" style="margin-top:12px;"><h3 style="color:var(--warning);">[!] Risky Open Ports</h3>
                <table class="data-table"><thead><tr><th>PORT</th><th>SERVICE</th><th>RISK</th><th>REASON</th></tr></thead><tbody>`;
            data.risky_ports.forEach(p => {
                html += `<tr><td>${p.port}</td><td>${p.service}</td><td><span class="sev ${p.risk.toLowerCase()}">${p.risk}</span></td><td>${p.reason}</td></tr>`;
            });
            html += '</tbody></table></div>';
        }

        if (data.open_ports.length > 0) {
            html += `<div class="tool-panel" style="margin-top:12px;"><h3>[+] All Open Ports (${data.open_ports.length})</h3>
                <table class="data-table"><thead><tr><th>PORT</th><th>PROTOCOL</th><th>SERVICE</th></tr></thead><tbody>`;
            data.open_ports.forEach(p => {
                html += `<tr><td>${p.port}</td><td>${p.protocol}</td><td>${p.service}</td></tr>`;
            });
            html += '</tbody></table></div>';
        }

        container.innerHTML = html;
        log(`Vuln scan done: ${data.overall_risk} risk, ${data.vulnerabilities.length} vulns`);
    } catch (e) { container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`; }
}

// ══ WHOIS / DNS ═════════════════════════════════════════════════════════════
async function runWhois() {
    const target = document.getElementById('whoisTarget').value.trim();
    if (!target) return alert('Enter target');
    const box = document.getElementById('whoisResults');
    box.innerText = `Looking up ${target}...`;
    log(`Whois: ${target}`);

    try {
        const data = await safeFetch(`/api/whois?target=${encodeURIComponent(target)}`);
        if (data.error) { box.innerText = `Error: ${data.error}`; return; }
        let out = `═══ WHOIS: ${data.target} ═══\n\n`;

        const w = data.whois || {};
        for (const [key, val] of Object.entries(w)) {
            if (key === 'raw') continue;
            out += `${key.toUpperCase().padEnd(20)} ${val}\n`;
        }

        if (data.dns_records && data.dns_records.length > 0) {
            out += `\n═══ DNS RECORDS ═══\n`;
            data.dns_records.forEach(r => { out += `  ${r}\n`; });
        }

        box.innerText = out || 'No whois data found for this target.';
        log(`Whois complete for ${target}`);
    } catch (e) { box.innerText = `Error: ${e.message}`; }
}

async function runDnsLookup() {
    const target = document.getElementById('whoisTarget').value.trim();
    if (!target) return alert('Enter target');
    const box = document.getElementById('whoisResults');
    box.innerText = `DNS lookup: ${target}...`;

    try {
        const data = await safeFetch(`/api/dns-lookup?target=${encodeURIComponent(target)}`);
        if (data.error) { box.innerText = `Error: ${data.error}`; return; }
        let out = `═══ DNS: ${data.target} ═══\n\n`;
        (data.records || []).forEach(r => { out += `  ${r}\n`; });
        box.innerText = out || 'No records found.';
    } catch (e) { box.innerText = `Error: ${e.message}`; }
}

// ══ PACKET CAPTURE ══════════════════════════════════════════════════════════
async function startCapture() {
    const duration = document.getElementById('pcapDuration').value || 30;
    const filter = document.getElementById('pcapFilter').value || '';
    const box = document.getElementById('pcapStatus');
    box.innerText = 'Starting capture...';
    log(`PCAP: starting ${duration}s capture`);

    try {
        const res = await fetch('/api/pcap/start', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ duration: parseInt(duration), filter })
        });
        const data = await res.json();
        box.innerText = `Capture ${data.status}.\nInterface: ${data.interface}\nDuration: ${data.duration}s\nFile: ${data.pcap_file}\n\nCapturing packets...`;
        log(`PCAP: capturing on ${data.interface}`);

        // Poll status
        const poll = setInterval(async () => {
            try {
                const sr = await fetch('/api/pcap/status');
                const sd = await sr.json();
                if (!sd.capturing) {
                    clearInterval(poll);
                    box.innerText += `\n\nCapture complete. File size: ${formatBytes(sd.file_size)}\nClick DOWNLOAD to save.`;
                    log('PCAP: capture complete.');
                }
            } catch (e) { clearInterval(poll); }
        }, 2000);
    } catch (e) { box.innerText = `Error: ${e.message}`; }
}

async function stopCapture() {
    try {
        await fetch('/api/pcap/stop', { method: 'POST' });
        document.getElementById('pcapStatus').innerText += '\nCapture stopped.';
        log('PCAP: stopped.');
    } catch (e) { }
}

function downloadPcap() {
    window.open('/api/pcap/download', '_blank');
}

// ══ FIREWALL ════════════════════════════════════════════════════════════════
async function loadFirewall() {
    const container = document.getElementById('firewallResults');
    container.innerHTML = '<div class="empty-state">Loading iptables rules...</div>';

    try {
        const res = await fetch('/api/firewall');
        const data = await res.json();

        if (data.error) { container.innerHTML = `<div class="empty-state">${data.error}</div>`; return; }

        let html = '';
        data.chains.forEach(chain => {
            html += `<div class="tool-panel" style="margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <h3>Chain: ${chain.name}</h3>
                    <div><span class="sev ${chain.policy === 'ACCEPT' ? 'low' : chain.policy === 'DROP' ? 'critical' : 'medium'}">${chain.policy}</span>
                    <span style="font-size:10px;color:var(--text-muted);margin-left:8px;">${chain.packets} pkts</span></div>
                </div>`;

            if (chain.rules.length > 0) {
                html += `<table class="data-table"><thead><tr><th>#</th><th>PKTS</th><th>TARGET</th><th>PROT</th><th>SOURCE</th><th>DEST</th><th>EXTRA</th></tr></thead><tbody>`;
                chain.rules.forEach(r => {
                    html += `<tr><td>${r.num}</td><td>${r.pkts}</td><td><span class="sev ${r.target === 'DROP' || r.target === 'REJECT' ? 'critical' : 'low'}">${r.target}</span></td>
                        <td>${r.prot}</td><td>${r.source}</td><td>${r.destination}</td><td style="font-size:10px;">${r.extra}</td></tr>`;
                });
                html += '</tbody></table>';
            } else {
                html += '<div style="font-size:11px;color:var(--text-muted);text-align:center;padding:10px;">No rules</div>';
            }
            html += '</div>';
        });

        container.innerHTML = html || '<div class="empty-state">No firewall chains found.</div>';
    } catch (e) { container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`; }
}

// ══ SYSTEM INFO ═════════════════════════════════════════════════════════════
async function loadSystemInfo() {
    const container = document.getElementById('sysInfoContainer');
    const arpContainer = document.getElementById('arpTableContainer');
    const portsContainer = document.getElementById('localPortsContainer');

    try {
        const res = await fetch('/api/system-info');
        const d = await res.json();

        const memPct = parseFloat(d.memory_usage_percent);
        const memColor = memPct > 85 ? 'red' : memPct > 60 ? 'cyan' : 'green';

        let html = `<div class="sys-grid">
            <div class="sys-card"><div class="sys-label">HOSTNAME</div><div class="sys-value accent">${d.hostname}</div></div>
            <div class="sys-card"><div class="sys-label">KERNEL</div><div class="sys-value">${d.kernel || d.platform}</div></div>
            <div class="sys-card"><div class="sys-label">ARCH</div><div class="sys-value">${d.arch}</div></div>
            <div class="sys-card"><div class="sys-label">CPU</div><div class="sys-value accent">${d.cpus} cores</div><div style="font-size:9px;color:var(--text-muted);margin-top:3px;">${d.cpu_model}</div></div>
            <div class="sys-card"><div class="sys-label">MEMORY</div><div class="sys-value">${d.memory_usage_percent}%</div>
                <div class="progress-bar"><div class="progress-fill ${memColor}" style="width:${d.memory_usage_percent}%"></div></div>
                <div style="font-size:9px;color:var(--text-muted);margin-top:3px;">${d.free_memory_gb} / ${d.total_memory_gb} GB free</div></div>
            <div class="sys-card"><div class="sys-label">DISK</div><div class="sys-value">${d.disk ? d.disk.usage_percent : '?'}</div>
                ${d.disk ? `<div style="font-size:9px;color:var(--text-muted);margin-top:3px;">${d.disk.available} free / ${d.disk.total}</div>` : ''}</div>
            <div class="sys-card"><div class="sys-label">UPTIME</div><div class="sys-value green">${d.uptime_human || formatDuration(d.uptime_seconds)}</div></div>
            <div class="sys-card"><div class="sys-label">LOAD AVG</div><div class="sys-value">${d.load_average ? d.load_average.map(l => l.toFixed(2)).join(' ') : '?'}</div></div>
            <div class="sys-card"><div class="sys-label">SERVER UPTIME</div><div class="sys-value accent">${formatDuration(d.server_uptime_seconds)}</div></div>
            <div class="sys-card"><div class="sys-label">ROOT ACCESS</div><div class="sys-value ${d.is_root ? 'green' : ''}">${d.is_root ? 'YES' : 'NO'}</div></div>
        </div>

        <div class="tool-panel" style="margin-top:16px;"><h3>[NET] Network Interfaces</h3>
            <table class="data-table"><thead><tr><th>INTERFACE</th><th>ADDRESS</th><th>NETMASK</th><th>MAC</th></tr></thead><tbody>`;

        for (const [name, addrs] of Object.entries(d.network_interfaces || {})) {
            addrs.forEach(a => {
                if (!a.internal) html += `<tr><td>${name}</td><td>${a.address}</td><td>${a.netmask}</td><td>${a.mac}</td></tr>`;
            });
        }
        html += '</tbody></table></div>';
        container.innerHTML = html;

        // Load ARP table
        const arpRes = await fetch('/api/arp-table');
        const arpData = await arpRes.json();
        if (arpData.entries && arpData.entries.length > 0) {
            let arpHtml = `<div class="tool-panel"><h3>ARP Table (${arpData.count} entries)</h3>
                <table class="data-table"><thead><tr><th>IP</th><th>MAC</th><th>INTERFACE</th><th>STATE</th></tr></thead><tbody>`;
            arpData.entries.forEach(e => {
                arpHtml += `<tr><td>${e.ip}</td><td style="font-family:monospace;">${e.mac}</td><td>${e.interface}</td><td>${e.state || e.type}</td></tr>`;
            });
            arpHtml += '</tbody></table></div>';
            arpContainer.innerHTML = arpHtml;
        }

        // Load local ports
        const portsRes = await fetch('/api/local-ports');
        const portsData = await portsRes.json();
        if (portsData.ports && portsData.ports.length > 0) {
            let portsHtml = `<div class="tool-panel"><h3>Open Ports on This Machine (${portsData.count})</h3>
                <table class="data-table"><thead><tr><th>PORT</th><th>ADDRESS</th><th>PROCESS</th><th>PID</th></tr></thead><tbody>`;
            portsData.ports.forEach(p => {
                portsHtml += `<tr><td style="font-weight:700;color:var(--accent);">${p.port}</td><td>${p.address}</td><td>${p.process}</td><td>${p.pid || '—'}</td></tr>`;
            });
            portsHtml += '</tbody></table></div>';
            portsContainer.innerHTML = portsHtml;
        }
    } catch (e) {
        container.innerHTML = `<div class="empty-state">Error loading system info: ${e.message}</div>`;
    }
}

// ══ SPEED TEST ══════════════════════════════════════════════════════════════
async function runSpeedTest() {
    const container = document.getElementById('sysInfoContainer');
    const banner = document.createElement('div');
    banner.className = 'tool-panel';
    banner.innerHTML = '<h3>⚡ Running Speed Test...</h3><div style="font-size:11px;color:var(--text-muted);">Downloading test file...</div>';
    container.prepend(banner);
    log('Speed test...');

    try {
        const res = await fetch('/api/speed-test');
        const data = await res.json();
        if (data.error) { banner.innerHTML = `<h3>⚡ Speed Test</h3><div style="color:var(--danger);">${data.error}</div>`; return; }
        banner.innerHTML = `<h3>⚡ Speed Test Result</h3>
            <div class="sys-grid" style="margin-top:10px;">
                <div class="sys-card"><div class="sys-label">DOWNLOAD</div><div class="sys-value accent">${data.download_mbps} Mbps</div></div>
                <div class="sys-card"><div class="sys-label">TIME</div><div class="sys-value">${data.time_seconds}s</div></div>
            </div>`;
        log(`Speed: ${data.download_mbps} Mbps`);
    } catch (e) { banner.innerHTML = `<h3>⚡ Speed Test</h3><div style="color:var(--danger);">Error: ${e.message}</div>`; }
}

// ══ FOOTPRINT ═══════════════════════════════════════════════════════════════
async function updateFootprint() {
    if (!selectedDevice) return;
    try {
        const res = await fetch(`/api/footprint?ip=${selectedDevice.ip}`);
        const fp = await res.json();
        const el = document.getElementById('inspHistory');
        if (!el) return;

        const domains = fp.domains || {};
        const keys = Object.keys(domains);
        if (!keys.length) { el.innerHTML = '<div class="empty-media">No footprint data yet.</div>'; return; }

        keys.sort((a, b) => (domains[b].last_seen || 0) - (domains[a].last_seen || 0));

        let html = `<div class="fp-summary">
            <span><b>${keys.length}</b> domains</span>
            <span><b>${formatBytes(fp.total_bytes || 0)}</b></span>
            <span><b>${(fp.sessions || []).length}</b> sessions</span></div>`;

        keys.forEach(domain => {
            const d = domains[domain];
            const dur = d.last_seen && d.first_seen ? formatDuration(d.last_seen - d.first_seen) : '-';
            const last = d.last_seen ? new Date(d.last_seen * 1000).toLocaleTimeString() : '-';
            html += `<div class="fp-domain-card">
                <div class="fp-domain-header"><span class="fp-domain-name">${domain}</span><span class="fp-domain-visits">${d.visit_count || 0}×</span></div>
                <div class="fp-domain-stats"><span>${dur}</span><span>${formatBytes(d.bytes_total || 0)}</span><span>${last}</span></div></div>`;
        });
        el.innerHTML = html;
    } catch (e) { }
}

async function renderGlobalFootprint() {
    const container = document.getElementById('footprintContainer');
    if (!container) return;
    container.innerHTML = '<div class="empty-state">Loading...</div>';

    try {
        const res = await fetch('/api/footprint');
        const db = await res.json();
        const devices = Object.keys(db);

        if (!devices.length) { container.innerHTML = '<div class="empty-state">No history recorded yet.</div>'; return; }

        devices.sort((a, b) => (db[b].total_bytes || 0) - (db[a].total_bytes || 0));
        let html = '';

        devices.forEach(ip => {
            const data = db[ip];
            const domains = data.domains || {};
            const keys = Object.keys(domains);
            keys.sort((a, b) => (domains[b].visit_count || 0) - (domains[a].visit_count || 0));

            html += `<div class="device-card" style="cursor:default;margin-bottom:12px;">
                <div class="header" onclick="this.nextElementSibling.style.display = this.nextElementSibling.style.display === 'none' ? 'block' : 'none'" style="cursor:pointer;">
                    <div class="ip-badge">${ip}</div>
                    <div class="device-details">
                        <h3>${data.hostname || 'Unknown'}</h3>
                        <p>${keys.length} domains • ${formatBytes(data.total_bytes)} • Last ${new Date((data.last_seen || 0) * 1000).toLocaleTimeString()}</p>
                    </div>
                    <div class="device-icon">▼</div>
                </div>
                <div style="display:none;padding-top:15px;border-top:1px solid rgba(255,255,255,0.1);margin-top:10px;">
                    ${keys.map(d => {
                const dm = domains[d];
                return `<div class="fp-domain-card">
                            <div class="fp-domain-header"><span class="fp-domain-name">${d}</span><span class="fp-domain-visits">${dm.visit_count}×</span></div>
                            <div class="fp-domain-stats"><span>${formatDuration((dm.last_seen || 0) - (dm.first_seen || 0))}</span><span>${formatBytes(dm.bytes_total)}</span></div>
                        </div>`;
            }).join('')}
                </div>
            </div>`;
        });
        container.innerHTML = html;
    } catch (e) { container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`; }
}

// ══ UTILITIES ═══════════════════════════════════════════════════════════════
function formatBytes(bytes, dm = 2) {
    if (!+bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function formatDuration(seconds) {
    if (!seconds || seconds < 0) return '< 1s';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function log(msg) {
    const container = document.getElementById('activityLog');
    if (!container) return;
    const el = document.createElement('div');
    el.className = 'log-line';
    el.innerHTML = `<span class="timestamp">${new Date().toLocaleTimeString()}</span> ${msg}`;
    container.appendChild(el);
    if (container.parentElement) container.parentElement.scrollTop = container.parentElement.scrollHeight;
}

function clearLogs() {
    const c = document.getElementById('activityLog');
    if (c) c.innerHTML = '';
}

// ══ AUTO-RECON (per device) ═════════════════════════════════════════════════
async function autoReconDevice() {
    if (!selectedDevice) return;
    autoReconIP(selectedDevice.ip);
    closeModal();
}

async function autoReconIP(ip) {
    switchTab('recon');
    const progress = document.getElementById('reconProgress');
    const progressText = document.getElementById('reconProgressText');
    const progressDetail = document.getElementById('reconProgressDetail');
    const progressBar = document.getElementById('reconProgressBar');
    const container = document.getElementById('reconResults');

    progress.style.display = 'block';
    progressText.innerText = `Running full recon on ${ip}...`;
    progressDetail.innerText = 'Phase 1/6: Host status → Ports → OS → Vulns → Creds → Traceroute';
    progressBar.style.width = '10%';
    log(`🤖 Auto-recon started: ${ip}`);

    // Simulate progress phases
    const phases = [
        { pct: '20%', text: 'Phase 2/6: Port scanning + service detection...' },
        { pct: '40%', text: 'Phase 3/6: Vulnerability scanning...' },
        { pct: '60%', text: 'Phase 4/6: Credential audit...' },
        { pct: '80%', text: 'Phase 5/6: Identity resolution...' },
        { pct: '90%', text: 'Phase 6/6: Traceroute...' },
    ];
    let phaseIdx = 0;
    const phaseTimer = setInterval(() => {
        if (phaseIdx < phases.length) {
            progressBar.style.width = phases[phaseIdx].pct;
            progressDetail.innerText = phases[phaseIdx].text;
            phaseIdx++;
        }
    }, 5000);

    try {
        const res = await fetch('/api/auto-recon', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const report = await res.json();

        clearInterval(phaseTimer);
        progressBar.style.width = '100%';
        progressText.innerText = `Recon complete for ${ip}`;
        progressDetail.innerText = `Risk: ${report.summary?.risk_level || '?'} • ${report.summary?.open_ports || 0} ports • ${report.summary?.vulnerabilities || 0} vulns • ${report.summary?.scan_time_seconds || '?'}s`;

        setTimeout(() => { progress.style.display = 'none'; }, 3000);

        renderReconReport(report, container, true);
        log(`🤖 Recon done: ${ip} — ${report.summary?.risk_level} risk`);
    } catch (e) {
        clearInterval(phaseTimer);
        progress.style.display = 'none';
        container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
        log(`🤖 Recon failed: ${ip}`);
    }
}

// ══ BATCH RECON ALL ══════════════════════════════════════════════════════════
async function batchReconAll() {
    if (currentDevices.length === 0) {
        alert('No devices found. Run a network scan first.');
        return;
    }

    switchTab('recon');
    const progress = document.getElementById('reconProgress');
    const progressText = document.getElementById('reconProgressText');
    const progressDetail = document.getElementById('reconProgressDetail');
    const progressBar = document.getElementById('reconProgressBar');
    const container = document.getElementById('reconResults');

    const ips = currentDevices.map(d => d.ip);
    progress.style.display = 'block';
    progressText.innerText = `Batch recon: ${ips.length} targets`;
    progressDetail.innerText = 'Running full pipeline on all devices... This may take several minutes.';
    progressBar.style.width = '5%';
    container.innerHTML = '';
    log(`🔥 Batch recon started: ${ips.length} targets`);

    // Animate progress
    let fakePct = 5;
    const timer = setInterval(() => {
        if (fakePct < 90) { fakePct += 2; progressBar.style.width = fakePct + '%'; }
    }, 3000);

    try {
        const res = await fetch('/api/batch-recon', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips }),
        });
        const data = await res.json();

        clearInterval(timer);
        progressBar.style.width = '100%';
        progressText.innerText = `Batch recon complete: ${data.total_targets} targets`;
        progressDetail.innerText = `${data.critical || 0} CRITICAL • ${data.high || 0} HIGH risk devices`;

        setTimeout(() => { progress.style.display = 'none'; }, 3000);

        // Sort by risk: CRITICAL first
        const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        const sorted = (data.results || []).sort((a, b) => {
            return (riskOrder[a.summary?.risk_level] ?? 4) - (riskOrder[b.summary?.risk_level] ?? 4);
        });

        sorted.forEach(report => renderReconReport(report, container, false));
        log(`🔥 Batch recon done: ${data.critical} critical, ${data.high} high`);
    } catch (e) {
        clearInterval(timer);
        progress.style.display = 'none';
        container.innerHTML = `<div class="empty-state">Batch recon error: ${e.message}</div>`;
        log(`🔥 Batch recon failed`);
    }
}

// ══ RENDER RECON REPORT ═════════════════════════════════════════════════════
function renderReconReport(report, container, prepend) {
    if (!report || report.status === 'error') {
        const errEl = document.createElement('div');
        errEl.className = 'recon-card';
        errEl.innerHTML = `<div class="recon-header"><h3>${report.target}</h3><span class="risk-badge high">ERROR</span></div><div style="color:var(--danger);font-size:11px;">${report.error || 'Unknown error'}</div>`;
        if (prepend) container.prepend(errEl); else container.appendChild(errEl);
        return;
    }

    const s = report.summary || {};
    const ps = report.phases?.port_scan || {};
    const vs = report.phases?.vuln_scan || {};
    const ca = report.phases?.credential_audit || {};
    const tr = report.phases?.traceroute || {};
    const id = report.phases?.identity || {};
    const hs = report.phases?.host_status || {};
    const riskClass = (s.risk_level || 'low').toLowerCase();
    const uid = 'recon_' + report.target.replace(/\./g, '_') + '_' + Date.now();

    const card = document.createElement('div');
    card.className = 'recon-card';
    card.innerHTML = `
        <div class="recon-header">
            <div>
                <h3>${report.target} ${id.hostname && id.hostname !== 'Unknown' ? `<span style="font-size:11px;color:var(--text-muted);font-weight:400;">(${id.hostname})</span>` : ''}</h3>
                <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">Scanned in ${s.scan_time_seconds || '?'}s • ${report.timestamp ? new Date(report.timestamp).toLocaleTimeString() : ''}</div>
            </div>
            <span class="risk-badge ${riskClass}">${s.risk_level || 'UNKNOWN'} RISK</span>
        </div>

        <div class="recon-phases">
            <div class="recon-phase">
                <h4>🟢 Host Status</h4>
                <div class="value">${hs.alive ? 'ALIVE' : 'DOWN'}</div>
            </div>
            <div class="recon-phase">
                <h4>📡 Open Ports</h4>
                <div class="value" style="color:${(ps.port_count || 0) > 5 ? 'var(--warning)' : 'var(--accent)'}">${ps.port_count || 0}</div>
                <div class="detail">${(ps.ports || []).slice(0, 5).map(p => p.port + '/' + p.service).join(', ') || 'None'}${(ps.port_count || 0) > 5 ? '...' : ''}</div>
            </div>
            <div class="recon-phase">
                <h4>💻 OS Detection</h4>
                <div class="value" style="font-size:12px;">${ps.os ? ps.os.name : 'Unknown'}</div>
                ${ps.os ? `<div class="detail">Accuracy: ${ps.os.accuracy}%</div>` : ''}
            </div>
            <div class="recon-phase">
                <h4>🚨 Vulnerabilities</h4>
                <div class="value" style="color:${(vs.vuln_count || 0) > 0 ? '#ff4444' : '#00ff64'}">${vs.vuln_count || 0}</div>
            </div>
            <div class="recon-phase">
                <h4>🔐 Credentials</h4>
                <div class="value" style="color:${ca.status === 'VULNERABLE' ? '#ff4444' : '#00ff64'}">${ca.status || 'N/A'}</div>
                <div class="detail">${ca.message || ''}</div>
            </div>
            <div class="recon-phase">
                <h4>🌐 Traceroute</h4>
                <div class="value">${tr.hop_count || 0} hops</div>
            </div>
        </div>

        <div class="recon-expand" onclick="document.getElementById('${uid}').classList.toggle('open');this.innerText = this.innerText.includes('▼') ? '▲ COLLAPSE DETAILS' : '▼ EXPAND FULL DETAILS';">▼ EXPAND FULL DETAILS</div>

        <div class="recon-details" id="${uid}">
            ${renderReconPortTable(ps.ports || [])}
            ${renderReconVulnTable(vs.vulnerabilities || [])}
            ${renderReconCredTable(ca)}
            ${renderReconTraceTable(tr.hops || [])}
        </div>`;

    if (prepend) container.prepend(card); else container.appendChild(card);
}

function renderReconPortTable(ports) {
    if (!ports.length) return '<div style="padding:8px;color:var(--text-muted);font-size:11px;">No open ports found.</div>';
    let html = '<div class="tool-panel" style="margin-top:10px;"><h3>📡 Port Details</h3><table class="data-table"><thead><tr><th>PORT</th><th>PROTO</th><th>SERVICE</th><th>PRODUCT</th><th>VERSION</th></tr></thead><tbody>';
    ports.forEach(p => {
        html += `<tr><td style="font-weight:700;color:var(--accent);">${p.port}</td><td>${p.protocol}</td><td>${p.service}</td><td>${p.product}</td><td>${p.version}</td></tr>`;
    });
    return html + '</tbody></table></div>';
}

function renderReconVulnTable(vulns) {
    if (!vulns.length) return '';
    let html = '<div class="tool-panel" style="margin-top:10px;"><h3 style="color:var(--danger);">🚨 Vulnerabilities</h3><table class="data-table"><thead><tr><th>CVE</th><th>SEVERITY</th><th>DETAIL</th></tr></thead><tbody>';
    vulns.forEach(v => {
        html += `<tr><td>${v.cve}</td><td><span class="sev ${v.severity.toLowerCase()}">${v.severity}</span></td><td style="font-size:10px;">${v.detail.substring(0, 120)}</td></tr>`;
    });
    return html + '</tbody></table></div>';
}

function renderReconCredTable(ca) {
    if (!ca.details || !ca.details.length) return '';
    let html = '<div class="tool-panel" style="margin-top:10px;"><h3>🔐 Credential Audit</h3><table class="data-table"><thead><tr><th>CREDENTIALS</th><th>STATUS</th></tr></thead><tbody>';
    ca.details.forEach(c => {
        const color = c.status === 'VULNERABLE' ? 'color:#ff4444;font-weight:700;' : '';
        html += `<tr><td style="font-family:monospace;">${c.credential}</td><td style="${color}">${c.status}</td></tr>`;
    });
    return html + '</tbody></table></div>';
}

function renderReconTraceTable(hops) {
    if (!hops.length) return '';
    let html = '<div class="tool-panel" style="margin-top:10px;"><h3>🌐 Traceroute Hops</h3><table class="data-table"><thead><tr><th>#</th><th>IP</th><th>RTT</th></tr></thead><tbody>';
    hops.forEach(h => {
        html += `<tr><td>${h.hop}</td><td>${h.ip || '*'}</td><td>${h.rtt_ms ? h.rtt_ms + ' ms' : '*'}</td></tr>`;
    });
    return html + '</tbody></table></div>';
}

async function loadCachedRecon() {
    const container = document.getElementById('reconResults');
    try {
        const res = await fetch('/api/recon-results');
        const data = await res.json();
        if (data.cached_targets && data.cached_targets.length > 0) {
            container.innerHTML = '';
            for (const ip of data.cached_targets) {
                const r = await fetch(`/api/recon-results?ip=${ip}`);
                const report = await r.json();
                renderReconReport(report, container, false);
            }
        } else {
            container.innerHTML = '<div class="empty-state">No cached recon results.</div>';
        }
    } catch (e) {
        container.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
    }
}

// ══ SCAN HISTORY ════════════════════════════════════════════════════════════
async function loadScanHistory() {
    const container = document.getElementById('historyResults');
    if (!container) return;
    container.innerHTML = '<div class="empty-state">Loading history...</div>';

    try {
        const data = await safeFetch('/api/scan-history');
        if (data.error) throw new Error(data.error);

        if (!data || data.length === 0) {
            container.innerHTML = '<div class="empty-state">No scan history recorded yet.</div>';
            return;
        }

        let html = '';
        data.forEach(scan => {
            const date = new Date(scan.timestamp).toLocaleString();
            const duration = scan.duration_seconds ? `${scan.duration_seconds}s` : '?';

            html += `
            <div class="device-card" style="display:flex;justify-content:space-between;align-items:center;padding:12px 18px;margin-bottom:8px;cursor:default;">
                <div style="display:flex;flex-direction:column;gap:4px;">
                    <div style="font-weight:700;color:#fff;display:flex;align-items:center;gap:8px;">
                        <span>${date}</span>
                        <span class="badge" style="font-size:9px;">${scan.scan_mode.toUpperCase()}</span>
                    </div>
                    <div style="font-size:11px;color:var(--text-muted);">
                        Subnet: ${scan.subnet} • Duration: ${duration}
                    </div>
                </div>
                <div style="text-align:right;">
                    <div class="sys-value accent" style="font-size:18px;">${scan.device_count}</div>
                    <div style="font-size:9px;color:var(--text-muted);letter-spacing:1px;">DEVICES</div>
                </div>
            </div>`;
        });

        container.innerHTML = html;
        log(`Loaded ${data.length} historical records.`);
    } catch (e) {
        container.innerHTML = `<div class="empty-state">Error loading history: ${e.message}</div>`;
        log(`History load error: ${e.message}`);
    }
}


// ══ TOPOLOGY ════════════════════════════════════════════════════════════════
let cy = null;

// ══ TOPOLOGY ════════════════════════════════════════════════════════════════


function renderTopology(devices) {
    if (!devices) devices = currentDevices;
    const container = document.getElementById('cy');
    if (!container || !window.cytoscape) return;

    // Build Graph Elements
    const elements = [];

    // Gateway Node
    elements.push({
        data: { id: 'gateway', label: 'GATEWAY', type: 'router' },
        classes: 'gateway'
    });

    devices.forEach(d => {
        const id = d.mac || d.ip;
        // Determine type class
        let typeClass = 'generic';
        if (d.type) {
            if (d.type.includes('Mobile') || d.type.includes('Phone')) typeClass = 'mobile';
            else if (d.type.includes('PC') || d.type.includes('Desktop')) typeClass = 'desktop';
            else if (d.type.includes('IoT')) typeClass = 'iot';
        }

        elements.push({
            data: {
                id: id,
                label: d.name || d.hostname || d.ip,
                ip: d.ip,
                vendor: d.vendor,
                type: d.type
            },
            classes: typeClass
        });

        elements.push({
            data: {
                source: id,
                target: 'gateway'
            },
            classes: 'link'
        });
    });

    if (cy) {
        cy.destroy();
        cy = null;
    }

    try {
        cy = cytoscape({
            container: container,
            elements: elements,
            wheelSensitivity: 0.2,
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': '#111',
                        'border-width': 2,
                        'border-color': '#00f2ff',
                        'label': 'data(label)',
                        'color': '#00f2ff',
                        'font-size': '10px',
                        'font-family': 'JetBrains Mono',
                        'text-valign': 'bottom',
                        'text-margin-y': 8,
                        'width': 40,
                        'height': 40,
                        'text-background-opacity': 0,
                        'text-shadow-blur': 4,
                        'text-shadow-color': '#000',
                        'text-shadow-opacity': 1,
                        'overlay-padding': 6,
                        'overlay-color': '#00f2ff',
                        'overlay-opacity': 0
                    }
                },
                {
                    selector: 'node:selected',
                    style: {
                        'border-color': '#fff',
                        'border-width': 3,
                        'shadow-blur': 10,
                        'shadow-color': '#00f2ff',
                        'overlay-opacity': 0.2
                    }
                },
                {
                    selector: '.gateway',
                    style: {
                        'background-color': '#00f2ff',
                        'border-color': '#fff',
                        'width': 60,
                        'height': 60,
                        'color': '#fff',
                        'font-weight': 'bold',
                        'text-margin-y': 10
                    }
                },
                {
                    selector: '.mobile',
                    style: { 'shape': 'rectangle', 'width': 25, 'height': 40, 'border-radius': 4 }
                },
                {
                    selector: '.desktop',
                    style: { 'shape': 'rectangle', 'width': 50, 'height': 35 }
                },
                {
                    selector: '.iot',
                    style: { 'shape': 'diamond', 'width': 35, 'height': 35 }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 1,
                        'line-color': '#333',
                        'curve-style': 'bezier',
                        'target-arrow-shape': 'none'
                    }
                }
            ],
            layout: {
                name: 'concentric',
                fit: true,
                padding: 60,
                startAngle: 3 / 2 * Math.PI,
                minNodeSpacing: 50,
                concentric: function (node) {
                    return node.id() === 'gateway' ? 2 : 1;
                },
                levelWidth: function () { return 1; },
                animate: true,
                animationDuration: 800,
                animationEasing: 'ease-out-cubic'
            }
        });

        // Hover events
        cy.on('mouseover', 'node', function (e) {
            e.target.style({
                'border-color': '#fff',
                'text-background-opacity': 0.8,
                'text-background-color': '#000',
                'z-index': 9999
            });
            document.body.style.cursor = 'pointer';
        });

        cy.on('mouseout', 'node', function (e) {
            e.target.style({
                'border-color': '#00f2ff',
                'text-background-opacity': 0,
                'z-index': 1
            });
            document.body.style.cursor = 'default';
        });

        cy.on('tap', 'node', function (e) {
            const node = e.target;
            // Find device in currentDevices by IP or MAC
            const dev = currentDevices.find(d => d.ip === node.data('ip') || d.mac === node.data('id'));
            if (dev) openDeviceModal(dev);
        });

    } catch (e) {
        console.error('Topology error:', e);
        container.innerHTML = '<div class="empty-state">Topology render failed.</div>';
    }
}
// ══ ATTACK LAB (MITM) ═══════════════════════════════════════════════════════
let attackLogInterval = null;

async function startAttack() {
    const target = document.getElementById('attackTarget').value.trim();
    const gateway = document.getElementById('attackGateway').value.trim();
    const mode = document.getElementById('attackMode').value;
    const domains = document.getElementById('attackDomains').value.trim();

    if (!target || !gateway) return alert('Target and Gateway IPs are required!');
    if (!confirm('⚠️ AUTHORIZED USE ONLY ⚠️\n\nStarting MITM Attack.\nEnsure you have permission to audit this network.')) return;

    log(`🚀 Launching MITM Attack against ${target}...`);
    try {
        const res = await fetch('/api/attack/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, gateway, mode, spoof_domains: domains })
        });
        const data = await res.json();
        if (data.status === 'success') {
            log('✅ Attack Process Started.');
            startAttackLogPolling();
        } else {
            alert('Error: ' + data.error);
        }
    } catch (e) {
        log('❌ Attack Start Failed: ' + e.message);
    }
}

async function stopAttack() {
    log('🛑 Stopping Attack...');
    try {
        await fetch('/api/attack/stop', { method: 'POST' });
        log('✅ Stop signal sent.');
    } catch (e) {
        log('❌ Stop Failed: ' + e.message);
    }
}

function startAttackLogPolling() {
    if (attackLogInterval) clearInterval(attackLogInterval);
    pollAttackLogs(); // Immediate
    attackLogInterval = setInterval(pollAttackLogs, 2000);
}

function stopAttackLogPolling() {
    if (attackLogInterval) clearInterval(attackLogInterval);
    attackLogInterval = null;
}

async function pollAttackLogs() {
    const consoleBox = document.getElementById('attackConsole');
    if (!consoleBox) return; // Tab not active

    try {
        const res = await fetch('/api/attack/logs');
        const data = await res.json();

        if (data.logs && data.logs.length > 0) {
            consoleBox.innerHTML = data.logs.map(l => {
                const color = l.type === 'error' ? '#ff4444' : l.type === 'system' ? '#00ccff' : '#00ff00';
                return `<span style="color:${color}">[${l.time.split('T')[1].split('.')[0]}] ${l.msg}</span>`;
            }).join('\n');
            consoleBox.scrollTop = consoleBox.scrollHeight;
        }
    } catch (e) {
        console.log('Log poll error', e);
    }
}

// ══ NETWORK MODE CONTROL ════════════════════════════════════════════════════
let currentNetworkMode = 'managed';

async function toggleNetworkMode() {
    const btn = document.getElementById('modeSwitchBtn');
    const targetMode = currentNetworkMode === 'managed' ? 'monitor' : 'managed';

    // Warning
    if (targetMode === 'monitor') {
        if (!confirm('ENTER MONITOR MODE?\n\n- You will LOSE Internet connection.\n- "Connected Devices" scan will stop working.\n- Required for Deauth/Handshake attacks.\n\nProceed?')) return;
    } else {
        if (!confirm('RESTORE MANAGED MODE?\n\n- Internet connection will be restored.\n- Monitor Mode attacks will stop.\n- Connection interrupt: 10-30s.\n\nProceed?')) return;
    }

    // UI Feedback
    btn.innerHTML = `SWITCHING...`;
    btn.disabled = true;

    try {
        const res = await fetch('/api/network/mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: targetMode })
        });
        const data = await res.json();

        if (data.status === 'success') {
            currentNetworkMode = targetMode;
            if (targetMode === 'monitor') {
                btn.innerHTML = `MODE: MONITOR`;
                btn.className = 'btn btn-danger';
                alert('Monitor Mode Enabled.\n\nProceed to Attack Lab for Deauth attacks.');
            } else {
                btn.innerHTML = `MODE: MANAGED`;
                btn.className = 'btn btn-secondary';
                alert('Switching to Managed Mode.\n\nPlease wait 30s for WiFi to reconnect, then reload the page.');
            }
        } else {
            throw new Error(data.error);
        }
    } catch (e) {
        alert('Mode Switch Failed: ' + e.message);
        // Reset UI
        if (currentNetworkMode === 'managed') {
            btn.innerHTML = `MODE: MANAGED`;
            btn.className = 'btn btn-secondary';
        } else {
            btn.innerHTML = `MODE: MONITOR`;
            btn.className = 'btn btn-danger';
        }
    } finally {
        btn.disabled = false;
    }
}
