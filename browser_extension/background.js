// NetSentinel Guardian - Background Service Worker
const API_BASE = 'http://localhost:8080';
let monitoringEnabled = true;
let scanCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Initialize
chrome.runtime.onInstalled.addListener(() => {
    console.log('NetSentinel Guardian installed');
    chrome.storage.local.set({ monitoringEnabled: true, scanHistory: [] });
});

// Monitor navigation
chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (!monitoringEnabled || details.frameId !== 0) return;

    const url = details.url;
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) return;

    // Check cache first
    const cached = scanCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
        if (cached.result.risk_score >= 50) {
            showWarning(details.tabId, cached.result);
        }
        return;
    }

    try {
        const result = await scanUrl(url);

        // Cache result
        scanCache.set(url, { result, timestamp: Date.now() });

        // Update badge
        updateBadge(details.tabId, result);

        // Show warning if dangerous
        if (result.risk_score >= 50) {
            showWarning(details.tabId, result);
            sendNotification(url, result);
        }

        // Save to history
        saveToHistory(url, result);

    } catch (error) {
        console.error('Scan failed:', error);
    }
});

async function scanUrl(url) {
    const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls: [url] })
    });

    const results = await response.json();
    return results[0] || { risk_score: 0, verdict: 'ERROR' };
}

function updateBadge(tabId, result) {
    let color, text;

    if (result.risk_score >= 80) {
        color = '#ff0033';
        text = 'X';
    } else if (result.risk_score >= 50) {
        color = '#ff6600';
        text = '!';
    } else if (result.risk_score >= 25) {
        color = '#ffcc00';
        text = '?';
    } else {
        color = '#00ff41';
        text = '✓';
    }

    chrome.action.setBadgeBackgroundColor({ tabId, color });
    chrome.action.setBadgeText({ tabId, text });
}

function showWarning(tabId, result) {
    chrome.tabs.sendMessage(tabId, {
        type: 'SHOW_WARNING',
        result: result
    });
}

function sendNotification(url, result) {
    const domain = new URL(url).hostname;

    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/shield128.png',
        title: '⚠️ NetSentinel Alert',
        message: `${domain} scored ${result.risk_score}/100 - ${result.verdict}\nThreats: ${result.threat_badges?.join(', ') || 'Unknown'}`,
        priority: 2
    });
}

function saveToHistory(url, result) {
    chrome.storage.local.get(['scanHistory'], (data) => {
        const history = data.scanHistory || [];
        history.unshift({
            url,
            result,
            timestamp: new Date().toISOString()
        });

        // Keep last 100
        chrome.storage.local.set({ scanHistory: history.slice(0, 100) });
    });
}

// Listen for popup messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_STATUS') {
        chrome.storage.local.get(['monitoringEnabled', 'scanHistory'], (data) => {
            sendResponse({
                enabled: data.monitoringEnabled ?? true,
                history: (data.scanHistory || []).slice(0, 10)
            });
        });
        return true;
    }

    if (message.type === 'TOGGLE_MONITORING') {
        monitoringEnabled = message.enabled;
        chrome.storage.local.set({ monitoringEnabled: message.enabled });
        sendResponse({ success: true });
        return true;
    }

    if (message.type === 'SCAN_CURRENT') {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            if (tabs[0]) {
                try {
                    const result = await scanUrl(tabs[0].url);
                    updateBadge(tabs[0].id, result);
                    sendResponse({ result });
                } catch (e) {
                    sendResponse({ error: e.message });
                }
            }
        });
        return true;
    }
});
