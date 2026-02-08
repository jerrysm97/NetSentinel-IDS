// NetSentinel Guardian - Content Script
// Injects warnings into dangerous pages

let warningShown = false;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'SHOW_WARNING' && !warningShown) {
        showWarningBanner(message.result);
        warningShown = true;
    }
});

function showWarningBanner(result) {
    // Create warning overlay
    const overlay = document.createElement('div');
    overlay.id = 'netsentinel-warning';
    overlay.innerHTML = `
        <style>
            #netsentinel-warning {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                z-index: 2147483647;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }
            
            .ns-banner {
                background: linear-gradient(135deg, #1a0a2e 0%, #0d0015 100%);
                border-bottom: 3px solid #ff0033;
                padding: 15px 20px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                box-shadow: 0 4px 20px rgba(255, 0, 51, 0.3);
            }
            
            .ns-content {
                display: flex;
                align-items: center;
                gap: 15px;
            }
            
            .ns-icon {
                font-size: 28px;
                animation: ns-pulse 1s ease-in-out infinite;
            }
            
            @keyframes ns-pulse {
                0%, 100% { opacity: 1; transform: scale(1); }
                50% { opacity: 0.7; transform: scale(1.1); }
            }
            
            .ns-text h3 {
                color: #ff0033;
                margin: 0 0 5px 0;
                font-size: 16px;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            .ns-text p {
                color: #ffffff;
                margin: 0;
                font-size: 13px;
                opacity: 0.9;
            }
            
            .ns-badges {
                display: flex;
                gap: 8px;
                margin-top: 8px;
            }
            
            .ns-badge {
                background: rgba(255, 0, 51, 0.2);
                border: 1px solid #ff0033;
                color: #ff6666;
                padding: 3px 8px;
                font-size: 10px;
                font-weight: bold;
                border-radius: 3px;
            }
            
            .ns-score {
                background: #ff0033;
                color: white;
                padding: 8px 15px;
                border-radius: 5px;
                font-size: 18px;
                font-weight: bold;
            }
            
            .ns-actions {
                display: flex;
                gap: 10px;
            }
            
            .ns-btn {
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                font-size: 13px;
                font-weight: bold;
                cursor: pointer;
                transition: all 0.2s;
            }
            
            .ns-btn-leave {
                background: #ff0033;
                color: white;
            }
            
            .ns-btn-leave:hover {
                background: #cc0029;
                transform: scale(1.02);
            }
            
            .ns-btn-continue {
                background: transparent;
                border: 1px solid #666;
                color: #999;
            }
            
            .ns-btn-continue:hover {
                border-color: #999;
                color: #fff;
            }
            
            .ns-btn-close {
                background: transparent;
                border: none;
                color: #666;
                font-size: 20px;
                cursor: pointer;
                padding: 5px 10px;
            }
            
            .ns-btn-close:hover {
                color: #fff;
            }
        </style>
        
        <div class="ns-banner">
            <div class="ns-content">
                <span class="ns-icon">🛡️</span>
                <div class="ns-text">
                    <h3>⚠️ NetSentinel Warning: ${result.verdict}</h3>
                    <p>This site has been flagged as potentially dangerous. Risk Score: ${result.risk_score}/100</p>
                    <div class="ns-badges">
                        ${(result.threat_badges || []).map(b => `<span class="ns-badge">${b}</span>`).join('')}
                    </div>
                </div>
            </div>
            <div class="ns-actions">
                <span class="ns-score">${result.risk_score}/100</span>
                <button class="ns-btn ns-btn-leave" onclick="history.back()">← Leave Site</button>
                <button class="ns-btn ns-btn-continue" onclick="document.getElementById('netsentinel-warning').remove()">Continue Anyway</button>
                <button class="ns-btn ns-btn-close" onclick="document.getElementById('netsentinel-warning').remove()">×</button>
            </div>
        </div>
    `;

    document.body.insertBefore(overlay, document.body.firstChild);

    // Push page content down
    document.body.style.marginTop = '80px';
}

// Also scan page for suspicious patterns locally
function quickLocalScan() {
    const text = document.body?.innerText?.toLowerCase() || '';
    const piracyTerms = ['download', '1080p', '720p', 'dual audio', 'torrent', 'magnet', 'filmy'];

    let piracyScore = 0;
    piracyTerms.forEach(term => {
        const count = (text.match(new RegExp(term, 'gi')) || []).length;
        piracyScore += count;
    });

    if (piracyScore > 20) {
        console.log('[NetSentinel] High piracy indicator score:', piracyScore);
    }
}

// Run local scan after page load
setTimeout(quickLocalScan, 1000);
