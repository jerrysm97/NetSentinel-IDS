// NetSentinel Guardian - Popup Script
document.addEventListener('DOMContentLoaded', async () => {
    const toggleBtn = document.getElementById('toggleBtn');
    const statusText = document.getElementById('statusText');
    const statusBar = document.getElementById('statusBar');
    const scanBtn = document.getElementById('scanBtn');
    const dashboardBtn = document.getElementById('dashboardBtn');
    const loadingState = document.getElementById('loadingState');
    const pageInfo = document.getElementById('pageInfo');

    // Load initial status
    chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
        if (response) {
            updateToggle(response.enabled);
            updateHistory(response.history);
        }
    });

    // Scan current page
    scanCurrentPage();

    // Toggle monitoring
    toggleBtn.addEventListener('click', () => {
        const isActive = toggleBtn.classList.contains('active');
        const newState = !isActive;

        chrome.runtime.sendMessage({ type: 'TOGGLE_MONITORING', enabled: newState }, () => {
            updateToggle(newState);
        });
    });

    // Scan button
    scanBtn.addEventListener('click', () => {
        loadingState.style.display = 'block';
        pageInfo.style.display = 'none';
        scanCurrentPage();
    });

    // Dashboard button
    dashboardBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: 'http://localhost:8080' });
    });

    function updateToggle(enabled) {
        if (enabled) {
            toggleBtn.classList.add('active');
            statusText.textContent = '● Monitoring Active';
            statusText.className = 'status safe';
            statusBar.className = 'status-bar';
        } else {
            toggleBtn.classList.remove('active');
            statusText.textContent = '○ Monitoring Paused';
            statusText.className = 'status';
            statusBar.className = 'status-bar';
        }
    }

    function scanCurrentPage() {
        chrome.runtime.sendMessage({ type: 'SCAN_CURRENT' }, (response) => {
            loadingState.style.display = 'none';
            pageInfo.style.display = 'flex';

            if (response?.result) {
                updatePageInfo(response.result);
            } else if (response?.error) {
                document.getElementById('pageUrl').textContent = 'Scan failed';
                document.getElementById('pageVerdict').textContent = response.error;
            }
        });

        // Also get current tab URL
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                try {
                    const url = new URL(tabs[0].url);
                    document.getElementById('pageUrl').textContent = url.hostname;
                } catch (e) {
                    document.getElementById('pageUrl').textContent = tabs[0].url?.substring(0, 30) || '-';
                }
            }
        });
    }

    function updatePageInfo(result) {
        const score = result.risk_score || 0;
        const scoreCircle = document.getElementById('scoreCircle');

        scoreCircle.textContent = score;
        scoreCircle.className = 'score-circle ' + getScoreClass(score);

        document.getElementById('pageVerdict').textContent = result.verdict || 'UNKNOWN';

        // Update badges
        const badgesDiv = document.getElementById('pageBadges');
        badgesDiv.innerHTML = '';

        (result.threat_badges || []).forEach(badge => {
            const span = document.createElement('span');
            span.className = 'badge badge-' + getBadgeClass(badge);
            span.textContent = badge;
            badgesDiv.appendChild(span);
        });

        if (!result.threat_badges?.length && score < 25) {
            const span = document.createElement('span');
            span.className = 'badge badge-safe';
            span.textContent = 'SAFE';
            badgesDiv.appendChild(span);
        }
    }

    function updateHistory(history) {
        const listDiv = document.getElementById('historyList');

        if (!history?.length) {
            listDiv.innerHTML = '<div style="color: #666; font-size: 11px;">No recent scans</div>';
            return;
        }

        listDiv.innerHTML = history.map(item => `
            <div class="history-item">
                <span class="history-score" style="color: ${getScoreColor(item.result?.risk_score || 0)}">${item.result?.risk_score || 0}</span>
                <span class="history-url">${getDomain(item.url)}</span>
            </div>
        `).join('');
    }

    function getScoreClass(score) {
        if (score >= 50) return 'danger';
        if (score >= 25) return 'warning';
        return 'safe';
    }

    function getScoreColor(score) {
        if (score >= 50) return '#ff0033';
        if (score >= 25) return '#ff9900';
        return '#00ff41';
    }

    function getBadgeClass(badge) {
        const b = badge.toLowerCase();
        if (b.includes('piracy') || b.includes('warez')) return 'piracy';
        if (b.includes('phish')) return 'phishing';
        if (b.includes('malware')) return 'malware';
        return 'piracy';
    }

    function getDomain(url) {
        try {
            return new URL(url).hostname;
        } catch {
            return url?.substring(0, 30) || '-';
        }
    }
});
