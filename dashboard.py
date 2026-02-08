"""
dashboard.py
Web-based monitoring dashboard for NetSentinel IDS.
Provides real-time alert visualization in the browser.
"""

import sys
import os
import threading
import queue
import json
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, render_template_string, jsonify
from colorama import Fore, Style

# Try to import scapy components
try:
    from scapy.all import sniff, conf, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__)

# Global state
alerts = []
stats = {
    "packets_captured": 0,
    "alerts_total": 0,
    "start_time": None,
    "monitors": []
}
is_running = False

# HTML Template
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel IDS Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d0d1f 100%);
            color: #e0e0e0;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            text-align: center;
            padding: 30px 0;
            background: linear-gradient(90deg, rgba(0,255,136,0.1) 0%, rgba(0,136,255,0.1) 100%);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid rgba(0,255,136,0.2);
        }
        
        h1 {
            font-size: 2.5rem;
            background: linear-gradient(90deg, #00ff88, #00aaff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }
        
        .status-badge {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        
        .status-active {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            border: 1px solid #00ff88;
        }
        
        .status-demo {
            background: rgba(255, 170, 0, 0.2);
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,255,136,0.2);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #00ff88;
        }
        
        .stat-label {
            color: #888;
            margin-top: 5px;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }
        
        .alerts-section {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        
        .alerts-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .alerts-header h2 {
            color: #00aaff;
        }
        
        .refresh-btn {
            background: linear-gradient(90deg, #00ff88, #00aaff);
            border: none;
            padding: 10px 25px;
            border-radius: 8px;
            color: #000;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.2s;
        }
        
        .refresh-btn:hover {
            transform: scale(1.05);
        }
        
        .alert-list {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .alert-item {
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid;
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-critical {
            border-color: #ff4444;
            background: rgba(255,68,68,0.1);
        }
        
        .alert-danger {
            border-color: #ffaa00;
            background: rgba(255,170,0,0.1);
        }
        
        .alert-info {
            border-color: #00aaff;
        }
        
        .alert-time {
            font-size: 0.8rem;
            color: #666;
            margin-bottom: 5px;
        }
        
        .alert-message {
            font-family: 'Consolas', monospace;
            white-space: pre-wrap;
            font-size: 0.9rem;
        }
        
        .no-alerts {
            text-align: center;
            color: #666;
            padding: 40px;
        }
        
        .monitors-section {
            margin-top: 30px;
        }
        
        .monitor-card {
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .monitor-name {
            font-weight: bold;
            color: #00ff88;
        }
        
        .monitor-alerts {
            background: rgba(255,68,68,0.2);
            padding: 5px 15px;
            border-radius: 15px;
            color: #ff6666;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: #666;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ NetSentinel IDS</h1>
            <p style="color: #888; margin-bottom: 15px;">Polymorphic Intrusion Detection System</p>
            <span class="status-badge {{ 'status-active' if is_running else 'status-demo' }}">
                {{ '● MONITORING ACTIVE' if is_running else '● DEMO MODE' }}
            </span>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="packets">{{ stats.packets_captured }}</div>
                <div class="stat-label">Packets Captured</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="alerts-count" style="color: #ff6666;">{{ stats.alerts_total }}</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #00aaff;">{{ stats.monitors|length }}</div>
                <div class="stat-label">Active Monitors</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ffaa00;">{{ stats.start_time or 'N/A' }}</div>
                <div class="stat-label">Started</div>
            </div>
        </div>
        
        <div class="alerts-section">
            <div class="alerts-header">
                <h2>🚨 Live Alerts</h2>
                <button class="refresh-btn" onclick="refreshAlerts()">↻ Refresh</button>
            </div>
            <div class="alert-list" id="alert-list">
                {% if alerts %}
                    {% for alert in alerts|reverse %}
                    <div class="alert-item {{ 'alert-critical' if 'CRITICAL' in alert.message else ('alert-danger' if 'DANGER' in alert.message else 'alert-info') }}">
                        <div class="alert-time">{{ alert.time }}</div>
                        <div class="alert-message">{{ alert.message }}</div>
                    </div>
                    {% endfor %}
                {% else %}
                <div class="no-alerts">
                    <p style="font-size: 3rem; margin-bottom: 10px;">✅</p>
                    <p>No threats detected. System is secure.</p>
                </div>
                {% endif %}
            </div>
        </div>
        
        <div class="monitors-section">
            <h2 style="color: #00aaff; margin-bottom: 15px;">📊 Monitor Status</h2>
            {% for monitor in stats.monitors %}
            <div class="monitor-card">
                <span class="monitor-name">{{ monitor.name }}</span>
                <span class="monitor-alerts">{{ monitor.alerts }} alerts</span>
            </div>
            {% endfor %}
            {% if not stats.monitors %}
            <div class="monitor-card">
                <span style="color: #888;">No monitors registered (demo mode)</span>
            </div>
            {% endif %}
        </div>
        
        <footer>
            <p>NetSentinel IDS v2.0 - Polymorphic Threat Detection</p>
            <p style="margin-top: 5px;">Security Hardened • LRU Eviction • Fast Path Analysis</p>
        </footer>
    </div>
    
    <script>
        function refreshAlerts() {
            fetch('/api/alerts')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('packets').textContent = data.stats.packets_captured;
                    document.getElementById('alerts-count').textContent = data.stats.alerts_total;
                    
                    const list = document.getElementById('alert-list');
                    if (data.alerts.length === 0) {
                        list.innerHTML = '<div class="no-alerts"><p style="font-size: 3rem; margin-bottom: 10px;">✅</p><p>No threats detected. System is secure.</p></div>';
                    } else {
                        list.innerHTML = data.alerts.reverse().map(alert => `
                            <div class="alert-item ${alert.message.includes('CRITICAL') ? 'alert-critical' : (alert.message.includes('DANGER') ? 'alert-danger' : 'alert-info')}">
                                <div class="alert-time">${alert.time}</div>
                                <div class="alert-message">${alert.message}</div>
                            </div>
                        `).join('');
                    }
                });
        }
        
        // Auto-refresh every 3 seconds
        setInterval(refreshAlerts, 3000);
    </script>
</body>
</html>
'''

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML, 
                                  alerts=alerts[-50:], 
                                  stats=stats,
                                  is_running=is_running)

@app.route('/api/alerts')
def api_alerts():
    return jsonify({
        "alerts": alerts[-50:],
        "stats": stats
    })

@app.route('/api/demo-alert')
def demo_alert():
    """Add a demo alert for testing."""
    alerts.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": "[CRITICAL] Demo DoS Attack Detected from 192.168.1.100: 75 SYN packets/sec"
    })
    stats["alerts_total"] += 1
    return jsonify({"status": "ok", "message": "Demo alert added"})


def run_dashboard(host='0.0.0.0', port=5000):
    """Run the dashboard server."""
    global stats
    stats["start_time"] = datetime.now().strftime("%H:%M:%S")
    stats["monitors"] = [
        {"name": "SYN Flood Detector", "alerts": 0},
        {"name": "Plaintext Credential Detector", "alerts": 0},
        {"name": "ARP Spoofing Detector", "alerts": 0}
    ]
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"NetSentinel Dashboard")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Dashboard URL: http://localhost:{port}")
    print(f"Demo Alert: http://localhost:{port}/api/demo-alert")
    print(f"\nPress Ctrl+C to stop\n")
    
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
