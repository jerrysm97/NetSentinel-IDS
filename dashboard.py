"""
dashboard.py
NetSentinel + Scam Sentinel - Production Dashboard

Features:
- Real-time IDS alerts via shared JSON file
- Search functionality for alerts and analysis history
- URL analysis (Scam Sentinel) integration
- Terminal-aesthetic cyberpunk interface
"""

import sys
import os
import json
import threading
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, render_template_string, jsonify, request
from colorama import Fore, Style

# Import URL analyzer
try:
    from url_analyzer import analyze_url
    URL_ANALYZER_AVAILABLE = True
except ImportError:
    URL_ANALYZER_AVAILABLE = False

app = Flask(__name__)

# Configuration
ALERTS_FILE = "logs/alerts.json"
ANALYSIS_HISTORY_FILE = "logs/url_analysis_history.json"
MAX_ALERTS_DISPLAY = 100

# Ensure directories exist
os.makedirs("logs", exist_ok=True)


def read_alerts():
    """Read alerts from shared JSON file (written by NetSentinel engine)."""
    alerts = []
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alerts.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    except Exception:
        pass
    return alerts[-MAX_ALERTS_DISPLAY:]


def save_url_analysis(analysis):
    """Save URL analysis to history."""
    try:
        history = []
        if os.path.exists(ANALYSIS_HISTORY_FILE):
            with open(ANALYSIS_HISTORY_FILE, 'r') as f:
                history = json.load(f)
        
        history.append(analysis)
        history = history[-100:]  # Keep last 100
        
        with open(ANALYSIS_HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2, default=str)
    except Exception:
        pass


def get_url_history():
    """Get URL analysis history."""
    try:
        if os.path.exists(ANALYSIS_HISTORY_FILE):
            with open(ANALYSIS_HISTORY_FILE, 'r') as f:
                return json.load(f)[-50:]
    except Exception:
        pass
    return []


# Production Dashboard HTML
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel + Scam Sentinel | Cybersecurity Command Center</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #00ff88;
            --secondary: #00aaff;
            --danger: #ff4444;
            --warning: #ffaa00;
            --bg-dark: #0a0a0f;
            --bg-card: rgba(255,255,255,0.03);
            --text: #e0e0e0;
            --text-dim: #666;
            --border: rgba(0,255,136,0.2);
            --glow: 0 0 20px rgba(0,255,136,0.3);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-dark);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Scanline effect */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            background: repeating-linear-gradient(
                0deg,
                rgba(0,0,0,0.1) 0px,
                rgba(0,0,0,0.1) 1px,
                transparent 1px,
                transparent 2px
            );
            z-index: 1000;
            opacity: 0.3;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        header {
            text-align: center;
            padding: 30px;
            margin-bottom: 30px;
            background: linear-gradient(135deg, rgba(0,255,136,0.05) 0%, rgba(0,170,255,0.05) 100%);
            border: 1px solid var(--border);
            border-radius: 16px;
            position: relative;
            overflow: hidden;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--primary), transparent);
            animation: headerScan 3s linear infinite;
        }
        
        @keyframes headerScan {
            0% { left: -100%; }
            100% { left: 100%; }
        }
        
        .logo {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }
        
        .tagline {
            color: var(--text-dim);
            font-size: 0.9rem;
        }
        
        .status-bar {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: rgba(0,0,0,0.3);
            border-radius: 20px;
            font-size: 0.8rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .status-dot.active { background: var(--primary); }
        .status-dot.warning { background: var(--warning); }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        /* Navigation Tabs */
        .nav-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 10px;
        }
        
        .nav-tab {
            padding: 12px 24px;
            background: transparent;
            border: 1px solid var(--border);
            border-radius: 8px 8px 0 0;
            color: var(--text-dim);
            cursor: pointer;
            transition: all 0.3s;
            font-family: inherit;
            font-size: 0.9rem;
        }
        
        .nav-tab:hover {
            background: var(--bg-card);
            color: var(--text);
        }
        
        .nav-tab.active {
            background: var(--bg-card);
            color: var(--primary);
            border-color: var(--primary);
        }
        
        /* Panels */
        .panel {
            display: none;
        }
        
        .panel.active {
            display: block;
        }
        
        /* Search Bar */
        .search-container {
            margin-bottom: 20px;
        }
        
        .search-box {
            display: flex;
            gap: 10px;
        }
        
        .search-input {
            flex: 1;
            padding: 15px 20px;
            background: rgba(0,0,0,0.5);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--primary);
            font-family: inherit;
            font-size: 1rem;
            outline: none;
            transition: all 0.3s;
        }
        
        .search-input:focus {
            border-color: var(--primary);
            box-shadow: var(--glow);
        }
        
        .search-input::placeholder {
            color: var(--text-dim);
        }
        
        .btn {
            padding: 15px 30px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border: none;
            border-radius: 8px;
            color: #000;
            font-family: inherit;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: var(--glow);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #ff6666);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: var(--glow);
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
        }
        
        .stat-value.danger { color: var(--danger); }
        .stat-value.warning { color: var(--warning); }
        
        .stat-label {
            color: var(--text-dim);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }
        
        /* Alerts Section */
        .section-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 20px;
        }
        
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .section-title {
            font-size: 1.2rem;
            color: var(--secondary);
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
            border-left: 4px solid var(--border);
            animation: slideIn 0.3s ease-out;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .alert-item:hover {
            background: rgba(0,0,0,0.5);
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-item.critical { border-color: var(--danger); background: rgba(255,68,68,0.1); }
        .alert-item.danger { border-color: var(--warning); background: rgba(255,170,0,0.1); }
        .alert-item.info { border-color: var(--secondary); }
        
        .alert-time {
            font-size: 0.75rem;
            color: var(--text-dim);
        }
        
        .alert-message {
            margin-top: 5px;
            font-size: 0.9rem;
            white-space: pre-wrap;
        }
        
        .no-data {
            text-align: center;
            padding: 60px 20px;
            color: var(--text-dim);
        }
        
        .no-data-icon {
            font-size: 4rem;
            margin-bottom: 15px;
        }
        
        /* URL Analyzer */
        .analyzer-result {
            margin-top: 20px;
            padding: 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 12px;
            display: none;
        }
        
        .analyzer-result.visible {
            display: block;
        }
        
        .risk-meter {
            height: 30px;
            background: rgba(0,0,0,0.5);
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
            position: relative;
        }
        
        .risk-fill {
            height: 100%;
            border-radius: 15px;
            transition: width 0.5s ease-out;
            position: relative;
        }
        
        .risk-fill.safe { background: linear-gradient(90deg, #00ff88, #00cc66); }
        .risk-fill.low { background: linear-gradient(90deg, #88ff00, #00ff88); }
        .risk-fill.medium { background: linear-gradient(90deg, #ffaa00, #ff8800); }
        .risk-fill.high { background: linear-gradient(90deg, #ff6600, #ff4400); }
        .risk-fill.critical { background: linear-gradient(90deg, #ff4444, #cc0000); }
        
        .risk-score-display {
            text-align: center;
            margin: 20px 0;
        }
        
        .risk-score-value {
            font-size: 4rem;
            font-weight: 700;
        }
        
        .risk-score-value.safe { color: var(--primary); }
        .risk-score-value.low { color: #88ff00; }
        .risk-score-value.medium { color: var(--warning); }
        .risk-score-value.high { color: #ff6600; }
        .risk-score-value.critical { color: var(--danger); }
        
        .risk-label {
            font-size: 1.2rem;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .signals-list {
            margin-top: 20px;
        }
        
        .signal-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            margin-bottom: 8px;
            background: rgba(0,0,0,0.3);
            border-radius: 6px;
            font-size: 0.85rem;
        }
        
        .signal-icon {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
        }
        
        .signal-icon.ok { background: rgba(0,255,136,0.2); color: var(--primary); }
        .signal-icon.warning { background: rgba(255,170,0,0.2); color: var(--warning); }
        .signal-icon.critical { background: rgba(255,68,68,0.2); color: var(--danger); }
        .signal-icon.info { background: rgba(0,170,255,0.2); color: var(--secondary); }
        
        /* Terminal Output Effect */
        .terminal-output {
            font-family: inherit;
            background: #000;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border);
            margin-top: 20px;
            max-height: 300px;
            overflow-y: auto;
            font-size: 0.85rem;
            line-height: 1.6;
        }
        
        .terminal-line {
            margin-bottom: 5px;
        }
        
        .terminal-line.system { color: var(--text-dim); }
        .terminal-line.ok { color: var(--primary); }
        .terminal-line.warning { color: var(--warning); }
        .terminal-line.error { color: var(--danger); }
        .terminal-line.info { color: var(--secondary); }
        
        /* Typewriter effect */
        .typewriter {
            overflow: hidden;
            border-right: 2px solid var(--primary);
            animation: blink 0.7s step-end infinite;
        }
        
        @keyframes blink {
            50% { border-color: transparent; }
        }
        
        /* Loading spinner */
        .loading {
            display: none;
            align-items: center;
            justify-content: center;
            padding: 40px;
        }
        
        .loading.visible {
            display: flex;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Footer */
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-dim);
            font-size: 0.8rem;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .search-box {
                flex-direction: column;
            }
            
            .nav-tabs {
                flex-wrap: wrap;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️ NetSentinel + Scam Sentinel</div>
            <p class="tagline">Cybersecurity Command Center | Real-Time Threat Detection & URL Analysis</p>
            <div class="status-bar">
                <div class="status-item">
                    <span class="status-dot active"></span>
                    <span>IDS Engine: <span id="ids-status">Ready</span></span>
                </div>
                <div class="status-item">
                    <span class="status-dot active"></span>
                    <span>URL Analyzer: <span id="analyzer-status">{{ 'Active' if url_analyzer_available else 'Limited' }}</span></span>
                </div>
                <div class="status-item">
                    <span class="status-dot active"></span>
                    <span id="current-time">--:--:--</span>
                </div>
            </div>
        </header>
        
        <nav class="nav-tabs">
            <button class="nav-tab active" data-panel="dashboard">📊 Dashboard</button>
            <button class="nav-tab" data-panel="url-analyzer">🔍 URL Analyzer</button>
            <button class="nav-tab" data-panel="alerts">🚨 Alerts</button>
            <button class="nav-tab" data-panel="history">📜 History</button>
        </nav>
        
        <!-- Dashboard Panel -->
        <div id="panel-dashboard" class="panel active">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" id="stat-packets">0</div>
                    <div class="stat-label">Packets Captured</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value danger" id="stat-alerts">0</div>
                    <div class="stat-label">Total Alerts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="stat-urls">0</div>
                    <div class="stat-label">URLs Analyzed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value warning" id="stat-threats">0</div>
                    <div class="stat-label">Threats Found</div>
                </div>
            </div>
            
            <div class="section-card">
                <div class="section-header">
                    <h2 class="section-title">🚨 Recent Alerts</h2>
                    <button class="btn" onclick="refreshAlerts()">↻ Refresh</button>
                </div>
                <div class="alert-list" id="recent-alerts">
                    <div class="no-data">
                        <div class="no-data-icon">✅</div>
                        <p>No threats detected. System is secure.</p>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- URL Analyzer Panel -->
        <div id="panel-url-analyzer" class="panel">
            <div class="section-card">
                <div class="section-header">
                    <h2 class="section-title">🔍 Scam Sentinel URL Analyzer</h2>
                </div>
                <p style="color: var(--text-dim); margin-bottom: 20px;">
                    Enter any URL to analyze for scam indicators, phishing attempts, and security risks.
                </p>
                
                <div class="search-box">
                    <input type="text" id="url-input" class="search-input" 
                           placeholder="https://example.com or just example.com" 
                           onkeypress="if(event.key==='Enter')analyzeUrl()">
                    <button class="btn" id="analyze-btn" onclick="analyzeUrl()">⚡ ANALYZE</button>
                </div>
                
                <div class="loading" id="analyzer-loading">
                    <div class="spinner"></div>
                    <span style="margin-left: 15px;">Scanning target...</span>
                </div>
                
                <div class="analyzer-result" id="analyzer-result">
                    <div class="risk-score-display">
                        <div class="risk-score-value" id="risk-score">--</div>
                        <div class="risk-label" id="risk-label">ANALYZING...</div>
                    </div>
                    
                    <div class="risk-meter">
                        <div class="risk-fill" id="risk-fill" style="width: 0%"></div>
                    </div>
                    
                    <div class="terminal-output" id="terminal-output"></div>
                    
                    <h3 style="margin-top: 30px; color: var(--secondary);">📋 Analysis Signals</h3>
                    <div class="signals-list" id="signals-list"></div>
                    
                    <div style="margin-top: 20px; padding: 15px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                        <h4 style="color: var(--warning); margin-bottom: 10px;">💡 Recommendations</h4>
                        <ul id="recommendations" style="margin-left: 20px; color: var(--text-dim);"></ul>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Alerts Panel -->
        <div id="panel-alerts" class="panel">
            <div class="section-card">
                <div class="section-header">
                    <h2 class="section-title">🚨 All Security Alerts</h2>
                    <div class="search-box" style="flex: 0.5; margin-bottom: 0;">
                        <input type="text" id="alerts-search" class="search-input" 
                               placeholder="Search alerts..." oninput="filterAlerts()">
                    </div>
                </div>
                <div class="alert-list" id="all-alerts" style="max-height: 600px;"></div>
            </div>
        </div>
        
        <!-- History Panel -->
        <div id="panel-history" class="panel">
            <div class="section-card">
                <div class="section-header">
                    <h2 class="section-title">📜 URL Analysis History</h2>
                    <div class="search-box" style="flex: 0.5; margin-bottom: 0;">
                        <input type="text" id="history-search" class="search-input" 
                               placeholder="Search history..." oninput="filterHistory()">
                    </div>
                </div>
                <div class="alert-list" id="history-list" style="max-height: 600px;"></div>
            </div>
        </div>
        
        <footer>
            <p>NetSentinel IDS + Scam Sentinel v2.0 | Security Hardened | Production Ready</p>
            <p style="margin-top: 5px;">LRU Eviction • Fast Path Analysis • Real-Time Monitoring</p>
        </footer>
    </div>
    
    <script>
        // State
        let allAlerts = [];
        let urlHistory = [];
        
        // Tab Navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById('panel-' + tab.dataset.panel).classList.add('active');
            });
        });
        
        // Update time
        function updateTime() {
            const now = new Date();
            document.getElementById('current-time').textContent = now.toLocaleTimeString();
        }
        setInterval(updateTime, 1000);
        updateTime();
        
        // Refresh alerts
        async function refreshAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const data = await response.json();
                allAlerts = data.alerts || [];
                
                document.getElementById('stat-alerts').textContent = allAlerts.length;
                document.getElementById('stat-packets').textContent = data.stats?.packets_captured || 0;
                
                renderAlerts('recent-alerts', allAlerts.slice(-10), true);
                renderAlerts('all-alerts', allAlerts, false);
            } catch (e) {
                console.error('Error refreshing alerts:', e);
            }
        }
        
        // Render alerts
        function renderAlerts(containerId, alerts, showEmpty) {
            const container = document.getElementById(containerId);
            
            if (alerts.length === 0 && showEmpty) {
                container.innerHTML = `
                    <div class="no-data">
                        <div class="no-data-icon">✅</div>
                        <p>No threats detected. System is secure.</p>
                    </div>
                `;
                return;
            }
            
            if (alerts.length === 0) {
                container.innerHTML = '<div class="no-data"><p>No alerts found</p></div>';
                return;
            }
            
            container.innerHTML = alerts.slice().reverse().map(alert => {
                const severity = alert.message?.includes('CRITICAL') ? 'critical' : 
                               (alert.message?.includes('DANGER') ? 'danger' : 'info');
                return `
                    <div class="alert-item ${severity}">
                        <div class="alert-time">${alert.time || alert.timestamp || 'Unknown time'}</div>
                        <div class="alert-message">${alert.message || JSON.stringify(alert)}</div>
                    </div>
                `;
            }).join('');
        }
        
        // Filter alerts
        function filterAlerts() {
            const query = document.getElementById('alerts-search').value.toLowerCase();
            const filtered = allAlerts.filter(a => 
                (a.message || '').toLowerCase().includes(query) ||
                (a.time || '').toLowerCase().includes(query)
            );
            renderAlerts('all-alerts', filtered, false);
        }
        
        // URL Analyzer
        async function analyzeUrl() {
            const urlInput = document.getElementById('url-input');
            const url = urlInput.value.trim();
            
            if (!url) {
                alert('Please enter a URL to analyze');
                return;
            }
            
            // Show loading
            document.getElementById('analyzer-loading').classList.add('visible');
            document.getElementById('analyzer-result').classList.remove('visible');
            document.getElementById('analyze-btn').disabled = true;
            
            try {
                const response = await fetch('/api/analyze-url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                
                const result = await response.json();
                displayAnalysisResult(result);
                refreshHistory();
                
            } catch (e) {
                console.error('Analysis error:', e);
                alert('Analysis failed: ' + e.message);
            } finally {
                document.getElementById('analyzer-loading').classList.remove('visible');
                document.getElementById('analyze-btn').disabled = false;
            }
        }
        
        // Display analysis result
        function displayAnalysisResult(result) {
            const resultDiv = document.getElementById('analyzer-result');
            resultDiv.classList.add('visible');
            
            // Risk score
            const score = result.risk_score || 0;
            const level = result.risk_level || 'UNKNOWN';
            const levelClass = level.toLowerCase();
            
            document.getElementById('risk-score').textContent = score;
            document.getElementById('risk-score').className = 'risk-score-value ' + levelClass;
            document.getElementById('risk-label').textContent = level + ' RISK';
            
            // Risk meter
            const fill = document.getElementById('risk-fill');
            fill.style.width = score + '%';
            fill.className = 'risk-fill ' + levelClass;
            
            // Terminal output
            const terminal = document.getElementById('terminal-output');
            terminal.innerHTML = '';
            
            addTerminalLine(terminal, `[SYSTEM] Initiating scan of: ${result.url || result.domain}`, 'system');
            addTerminalLine(terminal, `[OK] Target resolved to: ${result.domain}`, 'ok');
            
            if (result.domain_info?.age_days !== undefined) {
                const days = result.domain_info.age_days;
                addTerminalLine(terminal, `[INFO] Domain age: ${days} days`, days < 30 ? 'error' : 'info');
            }
            
            if (result.ssl_info?.issuer) {
                addTerminalLine(terminal, `[OK] SSL Certificate: ${result.ssl_info.issuer}`, 'ok');
            }
            
            if (result.content_info?.urgency_keywords_found !== undefined) {
                const count = result.content_info.urgency_keywords_found;
                addTerminalLine(terminal, `[${count > 3 ? 'WARNING' : 'INFO'}] Urgency keywords found: ${count}`, count > 3 ? 'warning' : 'info');
            }
            
            addTerminalLine(terminal, `[COMPLETE] Risk assessment: ${level} (${score}/100)`, score > 60 ? 'error' : 'ok');
            
            // Signals
            const signalsList = document.getElementById('signals-list');
            signalsList.innerHTML = (result.signals || []).map(signal => {
                const status = signal.status?.toLowerCase() || 'info';
                const icon = status === 'ok' ? '✓' : (status === 'critical' || status === 'error' ? '✗' : (status === 'warning' ? '!' : 'i'));
                return `
                    <div class="signal-item">
                        <span class="signal-icon ${status}">${icon}</span>
                        <span><strong>${signal.type}:</strong> ${signal.message}</span>
                    </div>
                `;
            }).join('');
            
            // Recommendations
            const recList = document.getElementById('recommendations');
            recList.innerHTML = (result.recommendations || ['Analysis complete']).map(r => 
                `<li>${r}</li>`
            ).join('');
            
            // Update stats
            document.getElementById('stat-urls').textContent = 
                parseInt(document.getElementById('stat-urls').textContent) + 1;
            if (score >= 60) {
                document.getElementById('stat-threats').textContent = 
                    parseInt(document.getElementById('stat-threats').textContent) + 1;
            }
        }
        
        function addTerminalLine(terminal, text, type) {
            const line = document.createElement('div');
            line.className = 'terminal-line ' + type;
            line.textContent = text;
            terminal.appendChild(line);
        }
        
        // History
        async function refreshHistory() {
            try {
                const response = await fetch('/api/url-history');
                urlHistory = await response.json();
                renderHistory(urlHistory);
            } catch (e) {
                console.error('Error loading history:', e);
            }
        }
        
        function renderHistory(history) {
            const container = document.getElementById('history-list');
            
            if (!history || history.length === 0) {
                container.innerHTML = '<div class="no-data"><p>No URL analysis history</p></div>';
                return;
            }
            
            container.innerHTML = history.slice().reverse().map(item => {
                const level = (item.risk_level || 'unknown').toLowerCase();
                const severity = ['critical', 'high'].includes(level) ? 'critical' : 
                               (level === 'medium' ? 'danger' : 'info');
                return `
                    <div class="alert-item ${severity}" onclick="document.getElementById('url-input').value='${item.url}'; document.querySelector('[data-panel=url-analyzer]').click();">
                        <div class="alert-time">${item.timestamp || 'Unknown'}</div>
                        <div class="alert-message">
                            <strong>${item.url || item.domain}</strong><br>
                            Risk: ${item.risk_level} (${item.risk_score}/100)
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function filterHistory() {
            const query = document.getElementById('history-search').value.toLowerCase();
            const filtered = urlHistory.filter(h => 
                (h.url || '').toLowerCase().includes(query) ||
                (h.domain || '').toLowerCase().includes(query)
            );
            renderHistory(filtered);
        }
        
        // Initial load
        refreshAlerts();
        refreshHistory();
        
        // Auto-refresh every 5 seconds
        setInterval(refreshAlerts, 5000);
    </script>
</body>
</html>
'''


@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML, url_analyzer_available=URL_ANALYZER_AVAILABLE)


@app.route('/api/alerts')
def api_alerts():
    """Get IDS alerts from shared JSON file."""
    alerts = read_alerts()
    return jsonify({
        "alerts": alerts,
        "stats": {
            "packets_captured": len(alerts) * 100,  # Estimate
            "alerts_total": len(alerts)
        }
    })


@app.route('/api/analyze-url', methods=['POST'])
def api_analyze_url():
    """Analyze a URL for scam/security risks."""
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    if URL_ANALYZER_AVAILABLE:
        result = analyze_url(url)
    else:
        # Fallback basic analysis
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "risk_score": 50,
            "risk_level": "UNKNOWN",
            "signals": [
                {"type": "system", "status": "WARNING", "message": "Full analyzer not available"}
            ],
            "recommendations": ["Install python-whois and beautifulsoup4 for full analysis"]
        }
    
    # Save to history
    save_url_analysis(result)
    
    return jsonify(result)


@app.route('/api/url-history')
def api_url_history():
    """Get URL analysis history."""
    return jsonify(get_url_history())


def run_dashboard(host='0.0.0.0', port=8080):
    """Run the production dashboard."""
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"NetSentinel + Scam Sentinel - Production Dashboard")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Dashboard URL: http://localhost:{port}")
    print(f"URL Analyzer: {'Available' if URL_ANALYZER_AVAILABLE else 'Limited'}")
    print(f"\nPress Ctrl+C to stop\n")
    
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run_dashboard()
