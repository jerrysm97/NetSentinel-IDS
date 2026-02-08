"""
dashboard.py
NetSentinel + Scam Sentinel - Cyberpunk NetRunner Dashboard

THEME: Neon green/pink on void black with CRT scanlines
FEATURES:
- Terminal typing effect for live logs
- Google Dork intelligence links
- Forensic-grade URL analysis
- Real-time threat visualization
"""

import sys
import os
import json
import asyncio
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, render_template_string, jsonify, request
from colorama import Fore, Style

try:
    from url_analyzer import analyze_url_async, get_analyzer
    URL_ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: URL analyzer import failed: {e}")
    URL_ANALYZER_AVAILABLE = False

app = Flask(__name__)

ALERTS_FILE = "logs/alerts.json"
HISTORY_FILE = "logs/analysis_history.json"
os.makedirs("logs", exist_ok=True)


def read_alerts():
    alerts = []
    try:
        if os.path.exists(ALERTS_FILE):
            with open(ALERTS_FILE, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            alerts.append(json.loads(line))
                        except:
                            pass
    except:
        pass
    return alerts[-100:]


def save_analysis(result):
    try:
        history = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        history.append(result)
        history = history[-50:]
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2, default=str)
    except:
        pass


def get_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)[-30:]
    except:
        pass
    return []


DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SCAM SENTINEL // NetRunner Interface</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@700&display=swap" rel="stylesheet">
    <style>
        :root {
            --neon-green: #00ff41;
            --neon-pink: #ff00ff;
            --neon-cyan: #00ffff;
            --neon-red: #ff0040;
            --neon-yellow: #ffff00;
            --void-black: #0a0a0a;
            --dark-gray: #1a1a1a;
            --terminal-green: #33ff33;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'JetBrains Mono', monospace;
            background: var(--void-black);
            color: var(--neon-green);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* CRT Scanlines */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            background: 
                repeating-linear-gradient(
                    0deg,
                    rgba(0,0,0,0.15) 0px,
                    rgba(0,0,0,0.15) 1px,
                    transparent 1px,
                    transparent 2px
                );
            z-index: 10000;
        }
        
        /* CRT Flicker */
        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            background: rgba(0,255,65,0.02);
            animation: flicker 0.15s infinite;
            z-index: 9999;
        }
        
        @keyframes flicker {
            0%, 100% { opacity: 0.97; }
            50% { opacity: 1; }
        }
        
        /* Glow effects */
        .glow-green { text-shadow: 0 0 10px var(--neon-green), 0 0 20px var(--neon-green), 0 0 30px var(--neon-green); }
        .glow-pink { text-shadow: 0 0 10px var(--neon-pink), 0 0 20px var(--neon-pink); }
        .glow-cyan { text-shadow: 0 0 10px var(--neon-cyan), 0 0 20px var(--neon-cyan); }
        .glow-red { text-shadow: 0 0 10px var(--neon-red), 0 0 20px var(--neon-red); }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
            z-index: 1;
        }
        
        /* Header */
        header {
            text-align: center;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid var(--neon-green);
            background: linear-gradient(180deg, rgba(0,255,65,0.1) 0%, transparent 100%);
            position: relative;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--neon-green), var(--neon-pink), var(--neon-cyan), transparent);
            animation: scanline 2s linear infinite;
        }
        
        @keyframes scanline {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .logo {
            font-family: 'Orbitron', sans-serif;
            font-size: 2.5rem;
            color: var(--neon-green);
            letter-spacing: 4px;
        }
        
        .logo span {
            color: var(--neon-pink);
        }
        
        .subtitle {
            color: var(--neon-cyan);
            font-size: 0.8rem;
            letter-spacing: 6px;
            margin-top: 10px;
            opacity: 0.8;
        }
        
        .status-bar {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 20px;
            font-size: 0.75rem;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            animation: blink 1s infinite;
        }
        
        .status-dot.active { background: var(--neon-green); box-shadow: 0 0 10px var(--neon-green); }
        .status-dot.warning { background: var(--neon-yellow); }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        /* Input Section */
        .input-section {
            margin-bottom: 30px;
            padding: 25px;
            border: 1px solid rgba(0,255,65,0.3);
            background: rgba(0,0,0,0.5);
        }
        
        .input-label {
            color: var(--neon-cyan);
            font-size: 0.8rem;
            letter-spacing: 2px;
            margin-bottom: 10px;
            display: block;
        }
        
        .input-wrapper {
            display: flex;
            gap: 15px;
        }
        
        .target-input {
            flex: 1;
            padding: 15px 20px;
            background: var(--void-black);
            border: 2px solid var(--neon-green);
            color: var(--neon-green);
            font-family: inherit;
            font-size: 1.1rem;
            outline: none;
            transition: all 0.3s;
        }
        
        .target-input:focus {
            border-color: var(--neon-pink);
            box-shadow: 0 0 20px rgba(255,0,255,0.3);
        }
        
        .target-input::placeholder {
            color: rgba(0,255,65,0.4);
        }
        
        .scan-btn {
            padding: 15px 40px;
            background: transparent;
            border: 2px solid var(--neon-pink);
            color: var(--neon-pink);
            font-family: 'Orbitron', sans-serif;
            font-size: 1rem;
            letter-spacing: 2px;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
        }
        
        .scan-btn:hover {
            background: var(--neon-pink);
            color: var(--void-black);
            box-shadow: 0 0 30px rgba(255,0,255,0.5);
        }
        
        .scan-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        
        /* Terminal Output */
        .terminal {
            background: #000;
            border: 1px solid var(--neon-green);
            padding: 20px;
            font-size: 0.85rem;
            line-height: 1.8;
            max-height: 400px;
            overflow-y: auto;
            display: none;
        }
        
        .terminal.active {
            display: block;
        }
        
        .terminal-line {
            opacity: 0;
            animation: typeIn 0.05s forwards;
        }
        
        @keyframes typeIn {
            to { opacity: 1; }
        }
        
        .terminal-line.info { color: var(--neon-green); }
        .terminal-line.warning { color: var(--neon-yellow); }
        .terminal-line.error, .terminal-line.critical { color: var(--neon-red); }
        .terminal-line.success { color: var(--neon-cyan); }
        
        .cursor {
            display: inline-block;
            width: 10px;
            height: 18px;
            background: var(--neon-green);
            animation: cursorBlink 0.7s infinite;
            vertical-align: text-bottom;
        }
        
        @keyframes cursorBlink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0; }
        }
        
        /* Results Section */
        .results {
            display: none;
            margin-top: 30px;
        }
        
        .results.active {
            display: block;
        }
        
        .verdict-display {
            text-align: center;
            padding: 40px;
            margin-bottom: 30px;
            border: 2px solid;
        }
        
        .verdict-display.safe {
            border-color: var(--neon-green);
            background: rgba(0,255,65,0.05);
        }
        
        .verdict-display.suspicious {
            border-color: var(--neon-yellow);
            background: rgba(255,255,0,0.05);
        }
        
        .verdict-display.malicious {
            border-color: var(--neon-red);
            background: rgba(255,0,64,0.05);
            animation: dangerPulse 1s infinite;
        }
        
        @keyframes dangerPulse {
            0%, 100% { box-shadow: 0 0 20px rgba(255,0,64,0.3); }
            50% { box-shadow: 0 0 40px rgba(255,0,64,0.6); }
        }
        
        .score-display {
            font-family: 'Orbitron', sans-serif;
            font-size: 5rem;
            margin-bottom: 10px;
        }
        
        .verdict-text {
            font-size: 1.5rem;
            letter-spacing: 4px;
        }
        
        /* Threat Grid */
        .threat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .threat-card {
            background: rgba(0,0,0,0.5);
            border: 1px solid rgba(0,255,65,0.3);
            padding: 20px;
        }
        
        .threat-card h3 {
            color: var(--neon-cyan);
            font-size: 0.9rem;
            letter-spacing: 2px;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(0,255,65,0.2);
        }
        
        .threat-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 0;
            font-size: 0.85rem;
        }
        
        .threat-icon {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.7rem;
        }
        
        .threat-icon.danger { background: rgba(255,0,64,0.3); color: var(--neon-red); }
        .threat-icon.warning { background: rgba(255,255,0,0.3); color: var(--neon-yellow); }
        .threat-icon.ok { background: rgba(0,255,65,0.3); color: var(--neon-green); }
        
        /* Intel Links */
        .intel-section {
            background: rgba(0,0,0,0.5);
            border: 1px solid var(--neon-cyan);
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .intel-section h3 {
            color: var(--neon-cyan);
            font-size: 0.9rem;
            letter-spacing: 2px;
            margin-bottom: 15px;
        }
        
        .intel-links {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }
        
        .intel-link {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 15px;
            background: rgba(0,255,255,0.1);
            border: 1px solid rgba(0,255,255,0.3);
            color: var(--neon-cyan);
            text-decoration: none;
            font-size: 0.8rem;
            transition: all 0.3s;
        }
        
        .intel-link:hover {
            background: var(--neon-cyan);
            color: var(--void-black);
        }
        
        /* Risk Summary */
        .risk-summary {
            background: rgba(0,0,0,0.5);
            border: 1px solid var(--neon-pink);
            padding: 25px;
            margin-bottom: 30px;
            white-space: pre-wrap;
            font-size: 0.9rem;
            line-height: 1.8;
        }
        
        /* History */
        .history-section {
            margin-top: 40px;
            padding-top: 30px;
            border-top: 1px solid rgba(0,255,65,0.2);
        }
        
        .history-section h2 {
            color: var(--neon-cyan);
            font-size: 1rem;
            letter-spacing: 3px;
            margin-bottom: 20px;
        }
        
        .history-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            border: 1px solid rgba(0,255,65,0.2);
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .history-item:hover {
            border-color: var(--neon-green);
            background: rgba(0,255,65,0.05);
        }
        
        .history-item.safe { border-left: 3px solid var(--neon-green); }
        .history-item.suspicious { border-left: 3px solid var(--neon-yellow); }
        .history-item.malicious { border-left: 3px solid var(--neon-red); }
        
        .history-domain {
            font-size: 0.9rem;
        }
        
        .history-score {
            font-family: 'Orbitron', sans-serif;
        }
        
        /* Loading */
        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }
        
        .loading.active {
            display: block;
        }
        
        .loading-text {
            color: var(--neon-pink);
            animation: loadingPulse 1s infinite;
        }
        
        @keyframes loadingPulse {
            0%, 100% { opacity: 0.5; }
            50% { opacity: 1; }
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--void-black);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--neon-green);
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: rgba(0,255,65,0.4);
            font-size: 0.7rem;
            letter-spacing: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo glow-green">SCAM <span class="glow-pink">SENTINEL</span></div>
            <div class="subtitle">// NETRUNNER THREAT INTELLIGENCE INTERFACE //</div>
            <div class="status-bar">
                <div class="status-item">
                    <span class="status-dot active"></span>
                    <span>ANALYZER: ONLINE</span>
                </div>
                <div class="status-item">
                    <span class="status-dot active"></span>
                    <span>FORENSICS: READY</span>
                </div>
                <div class="status-item">
                    <span id="clock">--:--:--</span>
                </div>
            </div>
        </header>
        
        <div class="input-section">
            <label class="input-label">&gt; ENTER TARGET URL FOR ANALYSIS</label>
            <div class="input-wrapper">
                <input type="text" id="target-input" class="target-input" 
                       placeholder="https://suspicious-site.com" 
                       onkeypress="if(event.key==='Enter')initiateScan()">
                <button class="scan-btn" id="scan-btn" onclick="initiateScan()">SCAN</button>
            </div>
        </div>
        
        <div class="terminal" id="terminal">
            <div id="terminal-output"></div>
            <span class="cursor"></span>
        </div>
        
        <div class="loading" id="loading">
            <div class="loading-text">[ANALYZING TARGET...]</div>
        </div>
        
        <div class="results" id="results">
            <div class="verdict-display" id="verdict-display">
                <div class="score-display" id="score-display">--</div>
                <div class="verdict-text" id="verdict-text">ANALYZING...</div>
            </div>
            
            <div class="risk-summary" id="risk-summary"></div>
            
            <div class="intel-section" id="intel-section">
                <h3>&gt; INTELLIGENCE LINKS (GOOGLE DORKS)</h3>
                <div class="intel-links" id="intel-links"></div>
            </div>
            
            <div class="threat-grid" id="threat-grid"></div>
        </div>
        
        <div class="history-section">
            <h2>&gt; SCAN HISTORY</h2>
            <div id="history-list"></div>
        </div>
        
        <footer>
            SCAM SENTINEL v3.0 // FORENSIC URL ANALYSIS ENGINE // STAY VIGILANT
        </footer>
    </div>
    
    <script>
        // Clock
        function updateClock() {
            const now = new Date();
            document.getElementById('clock').textContent = now.toLocaleTimeString('en-US', {hour12: false});
        }
        setInterval(updateClock, 1000);
        updateClock();
        
        // Terminal typing effect
        async function typeLine(container, text, level, delay = 30) {
            const line = document.createElement('div');
            line.className = 'terminal-line ' + level;
            container.appendChild(line);
            
            for (let i = 0; i < text.length; i++) {
                line.textContent += text[i];
                container.scrollTop = container.scrollHeight;
                await new Promise(r => setTimeout(r, delay));
            }
            return line;
        }
        
        async function typeLog(log) {
            const container = document.getElementById('terminal-output');
            const time = log.timestamp || '--:--:--';
            const module = log.module || 'SYS';
            const msg = log.message || '';
            const level = log.level || 'info';
            
            const prefix = `[${time}] [${module}] `;
            await typeLine(container, prefix + msg, level, 15);
        }
        
        // Main scan function
        async function initiateScan() {
            const input = document.getElementById('target-input');
            const url = input.value.trim();
            
            if (!url) {
                alert('Enter a target URL');
                return;
            }
            
            // Reset UI
            document.getElementById('terminal').classList.add('active');
            document.getElementById('terminal-output').innerHTML = '';
            document.getElementById('results').classList.remove('active');
            document.getElementById('scan-btn').disabled = true;
            
            // Initial messages
            const output = document.getElementById('terminal-output');
            await typeLine(output, '[SYSTEM] Initializing forensic analysis engine...', 'info', 20);
            await typeLine(output, '[SYSTEM] Target acquired: ' + url, 'success', 20);
            await new Promise(r => setTimeout(r, 300));
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url})
                });
                
                const result = await response.json();
                
                if (result.error) {
                    await typeLine(output, '[ERROR] ' + result.error, 'error', 20);
                    return;
                }
                
                // Type out logs with effect
                for (const log of result.logs || []) {
                    await typeLog(log);
                    await new Promise(r => setTimeout(r, 100));
                }
                
                await new Promise(r => setTimeout(r, 500));
                await typeLine(output, '[COMPLETE] Analysis finished in ' + result.analysis_duration_ms + 'ms', 'success', 20);
                
                // Show results
                displayResults(result);
                loadHistory();
                
            } catch (e) {
                await typeLine(output, '[FATAL] Connection failed: ' + e.message, 'error', 20);
            } finally {
                document.getElementById('scan-btn').disabled = false;
            }
        }
        
        function displayResults(result) {
            document.getElementById('results').classList.add('active');
            
            // Verdict
            const verdictDiv = document.getElementById('verdict-display');
            verdictDiv.className = 'verdict-display ' + result.verdict.toLowerCase();
            
            document.getElementById('score-display').textContent = result.score;
            document.getElementById('score-display').className = 'score-display glow-' + 
                (result.verdict === 'SAFE' ? 'green' : (result.verdict === 'SUSPICIOUS' ? 'pink' : 'red'));
            
            document.getElementById('verdict-text').textContent = result.verdict;
            
            // Risk summary
            document.getElementById('risk-summary').textContent = result.risk_summary;
            
            // Intel links
            const intelContainer = document.getElementById('intel-links');
            intelContainer.innerHTML = '';
            const dorks = result.google_dorks || {};
            const dorkLabels = {
                site_search: '🔍 Site Index',
                reputation: '⚠️ Reputation Check',
                whois_lookup: '📋 WHOIS Data',
                virustotal: '🦠 VirusTotal',
                urlscan: '🔬 URLScan.io',
                wayback: '📜 Wayback Machine',
                shodan: '🌐 Shodan',
                abuse_report: '🚨 Report Phishing'
            };
            
            for (const [key, url] of Object.entries(dorks)) {
                const link = document.createElement('a');
                link.href = url;
                link.target = '_blank';
                link.className = 'intel-link';
                link.textContent = dorkLabels[key] || key;
                intelContainer.appendChild(link);
            }
            
            // Threat indicators
            const grid = document.getElementById('threat-grid');
            grid.innerHTML = '';
            
            // SSL Card
            if (result.ssl_forensics) {
                const card = createThreatCard('SSL FORENSICS', [
                    {icon: result.ssl_forensics.issuer_trust === 'COMMERCIAL_EV' ? 'ok' : 'warning', 
                     text: 'Issuer: ' + (result.ssl_forensics.certificate?.issuer || 'Unknown')},
                    {icon: result.ssl_forensics.certificate?.expiry_days > 30 ? 'ok' : 'warning',
                     text: 'Expires in: ' + (result.ssl_forensics.certificate?.expiry_days || '?') + ' days'},
                    {icon: result.ssl_forensics.issuer_trust === 'SELF-SIGNED' ? 'danger' : 'ok',
                     text: 'Trust Level: ' + (result.ssl_forensics.issuer_trust || 'Unknown')}
                ]);
                grid.appendChild(card);
            }
            
            // Domain Intel Card
            if (result.domain_intel) {
                const card = createThreatCard('DOMAIN INTELLIGENCE', [
                    {icon: (result.domain_intel.age_days || 0) > 365 ? 'ok' : 'warning',
                     text: 'Age: ' + (result.domain_intel.age_days || '?') + ' days'},
                    {icon: 'ok', text: 'Registrar: ' + (result.domain_intel.registrar || 'Unknown')},
                    {icon: result.domain_intel.privacy_protected ? 'warning' : 'ok',
                     text: result.domain_intel.privacy_protected ? 'Privacy Protected' : 'Public WHOIS'}
                ]);
                grid.appendChild(card);
            }
            
            // Content Analysis Card
            if (result.content_analysis) {
                const card = createThreatCard('CONTENT ANALYSIS', [
                    {icon: result.content_analysis.urgency_score > 30 ? 'danger' : 'ok',
                     text: 'Urgency Score: ' + (result.content_analysis.urgency_score || 0)},
                    {icon: result.content_analysis.financial_score > 30 ? 'danger' : 'ok',
                     text: 'Financial Keywords: ' + (result.content_analysis.financial_score || 0)},
                    {icon: result.content_analysis.forms?.suspicious ? 'danger' : 'ok',
                     text: 'Forms: ' + (result.content_analysis.forms?.count || 0) + ' detected'}
                ]);
                grid.appendChild(card);
            }
            
            // Tech Stack Card
            if (result.tech_stack) {
                const card = createThreatCard('TECHNOLOGY STACK', [
                    {icon: result.tech_stack.detected?.includes('Phishing') ? 'danger' : 'ok',
                     text: 'Platform: ' + (result.tech_stack.detected || 'Unknown')},
                    {icon: 'ok', text: 'Confidence: ' + (result.tech_stack.confidence || 0) + '%'}
                ]);
                grid.appendChild(card);
            }
            
            // Threat Indicators Card
            if (result.threat_indicators && result.threat_indicators.length > 0) {
                const items = result.threat_indicators.slice(0, 5).map(t => ({icon: 'danger', text: t}));
                const card = createThreatCard('⚠️ THREAT INDICATORS', items);
                grid.appendChild(card);
            }
            
            // Recommendations Card
            if (result.recommendations && result.recommendations.length > 0) {
                const items = result.recommendations.slice(0, 5).map(r => ({icon: r.startsWith('🚫') ? 'danger' : 'ok', text: r}));
                const card = createThreatCard('📋 RECOMMENDATIONS', items);
                grid.appendChild(card);
            }
        }
        
        function createThreatCard(title, items) {
            const card = document.createElement('div');
            card.className = 'threat-card';
            card.innerHTML = '<h3>' + title + '</h3>';
            
            items.forEach(item => {
                const div = document.createElement('div');
                div.className = 'threat-item';
                div.innerHTML = '<span class="threat-icon ' + item.icon + '">' + 
                    (item.icon === 'danger' ? '!' : (item.icon === 'warning' ? '?' : '✓')) + 
                    '</span><span>' + item.text + '</span>';
                card.appendChild(div);
            });
            
            return card;
        }
        
        // History
        async function loadHistory() {
            try {
                const response = await fetch('/api/history');
                const history = await response.json();
                
                const container = document.getElementById('history-list');
                container.innerHTML = '';
                
                history.slice().reverse().forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'history-item ' + (item.verdict || 'unknown').toLowerCase();
                    div.innerHTML = `
                        <span class="history-domain">${item.domain || item.target}</span>
                        <span class="history-score">${item.score}/100</span>
                    `;
                    div.onclick = () => {
                        document.getElementById('target-input').value = item.target;
                        initiateScan();
                    };
                    container.appendChild(div);
                });
            } catch (e) {
                console.error('History load failed:', e);
            }
        }
        
        // Initial load
        loadHistory();
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    if URL_ANALYZER_AVAILABLE:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(analyze_url_async(url))
        finally:
            loop.close()
    else:
        result = {
            "target": url,
            "score": 50,
            "verdict": "UNKNOWN",
            "risk_summary": "Analyzer not available",
            "logs": [{"module": "ERROR", "message": "URL analyzer module not loaded", "level": "error"}],
            "threat_indicators": [],
            "recommendations": []
        }
    
    save_analysis(result)
    return jsonify(result)


@app.route('/api/history')
def history():
    return jsonify(get_history())


@app.route('/api/alerts')
def alerts():
    return jsonify({"alerts": read_alerts()})


if __name__ == '__main__':
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.MAGENTA}SCAM SENTINEL{Fore.GREEN} // NetRunner Interface v3.0")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Dashboard: http://localhost:8080")
    print(f"Analyzer: {'ONLINE' if URL_ANALYZER_AVAILABLE else 'OFFLINE'}")
    print(f"\nPress Ctrl+C to terminate\n")
    
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
