"""
dashboard.py
NetSentinel v6.0 - GOD VIEW DASHBOARD

Theme: Digital God / Overwatch - Deep void style
Features:
- Temporal Timeline: Wayback Machine snapshots visualization
- Infrastructure Map: IP, Flag, Host, Ports
- Threat Vector: Badges for [WAREZ], [PHISHING], [MALWARE], [AD-FRAUD]
- Live Terminal: Streaming thought process
"""

from __future__ import annotations

import sys
import os
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, render_template_string, jsonify, request, Response
from colorama import Fore, Style

try:
    from url_analyzer import OmniscientAnalyzer, OmniscientResult
    ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Analyzer import failed: {e}", file=sys.stderr)
    ANALYZER_AVAILABLE = False

app = Flask(__name__)

HISTORY_FILE = "logs/analysis_history.json"
os.makedirs("logs", exist_ok=True)


def save_result(result: Dict[str, Any]) -> None:
    """Save analysis result to history."""
    try:
        history = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                history = json.load(f)
        history.append(result)
        history = history[-100:]
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2, default=str)
    except Exception as e:
        print(f"Save error: {e}", file=sys.stderr)


def get_history() -> List[Dict[str, Any]]:
    """Load analysis history."""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)[-50:]
    except:
        pass
    return []


DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel v6.0 // GOD VIEW</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --void-black: #000000;
            --void-deep: #050510;
            --void-mid: #0a0a1a;
            --god-gold: #ffd700;
            --god-orange: #ff6a00;
            --cyber-blue: #00d4ff;
            --cyber-purple: #9d00ff;
            --matrix-green: #00ff41;
            --blood-red: #ff0033;
            --warning-yellow: #ffcc00;
            --text-primary: #ffffff;
            --text-dim: #666688;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'JetBrains Mono', monospace;
            background: var(--void-black);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Grid background */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: 
                linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }
        
        .container {
            max-width: 1800px;
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
            border: 1px solid var(--god-gold);
            background: linear-gradient(135deg, var(--void-deep), var(--void-mid));
            position: relative;
        }
        
        header::before, header::after {
            content: '';
            position: absolute;
            width: 30px; height: 30px;
            border: 2px solid var(--god-gold);
        }
        header::before { top: -1px; left: -1px; border-right: none; border-bottom: none; }
        header::after { bottom: -1px; right: -1px; border-left: none; border-top: none; }
        
        .logo {
            font-family: 'Orbitron', sans-serif;
            font-size: 3rem;
            font-weight: 900;
            background: linear-gradient(135deg, var(--god-gold), var(--god-orange));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 8px;
            text-shadow: 0 0 50px rgba(255, 215, 0, 0.3);
        }
        
        .subtitle {
            font-family: 'Orbitron', sans-serif;
            color: var(--cyber-blue);
            font-size: 0.9rem;
            letter-spacing: 6px;
            margin-top: 10px;
        }
        
        .version-tag {
            display: inline-block;
            background: var(--god-gold);
            color: var(--void-black);
            padding: 3px 10px;
            font-size: 0.7rem;
            font-weight: bold;
            margin-top: 10px;
        }
        
        /* Input Section */
        .input-section {
            background: var(--void-mid);
            border: 1px solid var(--cyber-blue);
            padding: 25px;
            margin-bottom: 25px;
        }
        
        .input-label {
            color: var(--cyber-blue);
            font-size: 0.75rem;
            letter-spacing: 3px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .input-label::before { content: '⌘'; color: var(--god-gold); }
        
        .url-input {
            width: 100%;
            padding: 15px 20px;
            background: var(--void-black);
            border: 2px solid var(--text-dim);
            color: var(--text-primary);
            font-family: inherit;
            font-size: 1rem;
            outline: none;
            transition: all 0.3s;
        }
        
        .url-input:focus {
            border-color: var(--god-gold);
            box-shadow: 0 0 20px rgba(255, 215, 0, 0.2);
        }
        
        .btn-group {
            display: flex;
            gap: 15px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 15px 30px;
            font-family: 'Orbitron', sans-serif;
            font-size: 0.9rem;
            font-weight: bold;
            letter-spacing: 2px;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .btn-scan {
            background: linear-gradient(135deg, var(--god-gold), var(--god-orange));
            color: var(--void-black);
        }
        
        .btn-scan:hover {
            box-shadow: 0 0 40px rgba(255, 215, 0, 0.5);
            transform: translateY(-2px);
        }
        
        .btn-scan:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-export {
            background: transparent;
            border: 1px solid var(--cyber-blue);
            color: var(--cyber-blue);
        }
        
        .btn-export:hover { background: rgba(0, 212, 255, 0.1); }
        
        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 25px;
            margin-bottom: 25px;
        }
        
        @media (max-width: 1200px) {
            .dashboard-grid { grid-template-columns: 1fr; }
        }
        
        .panel {
            background: var(--void-mid);
            border: 1px solid var(--text-dim);
            position: relative;
        }
        
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: var(--void-deep);
            border-bottom: 1px solid var(--text-dim);
        }
        
        .panel-title {
            font-family: 'Orbitron', sans-serif;
            font-size: 0.8rem;
            letter-spacing: 2px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .panel-title.gold { color: var(--god-gold); }
        .panel-title.blue { color: var(--cyber-blue); }
        .panel-title.green { color: var(--matrix-green); }
        .panel-title.purple { color: var(--cyber-purple); }
        
        .panel-body {
            padding: 20px;
            min-height: 250px;
        }
        
        /* Risk Meter */
        .risk-display {
            text-align: center;
            padding: 30px;
        }
        
        .risk-score {
            font-family: 'Orbitron', sans-serif;
            font-size: 5rem;
            font-weight: 900;
            line-height: 1;
        }
        
        .risk-score.safe { color: var(--matrix-green); }
        .risk-score.low { color: var(--cyber-blue); }
        .risk-score.medium { color: var(--warning-yellow); }
        .risk-score.high { color: var(--god-orange); }
        .risk-score.critical { color: var(--blood-red); }
        
        .risk-label {
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-top: 10px;
            letter-spacing: 3px;
        }
        
        .verdict-badge {
            display: inline-block;
            padding: 10px 25px;
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            letter-spacing: 2px;
            margin-top: 20px;
        }
        
        .verdict-badge.safe { background: rgba(0,255,65,0.2); color: var(--matrix-green); border: 1px solid var(--matrix-green); }
        .verdict-badge.suspicious { background: rgba(255,204,0,0.2); color: var(--warning-yellow); border: 1px solid var(--warning-yellow); }
        .verdict-badge.high_risk { background: rgba(255,106,0,0.2); color: var(--god-orange); border: 1px solid var(--god-orange); }
        .verdict-badge.malicious { background: rgba(255,0,51,0.2); color: var(--blood-red); border: 1px solid var(--blood-red); }
        
        /* Threat Badges */
        .threat-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 20px;
            justify-content: center;
        }
        
        .threat-badge {
            padding: 8px 15px;
            font-size: 0.7rem;
            font-weight: bold;
            letter-spacing: 1px;
            border: 1px solid;
        }
        
        .threat-badge.warez { background: rgba(157,0,255,0.2); color: var(--cyber-purple); border-color: var(--cyber-purple); }
        .threat-badge.phishing { background: rgba(255,0,51,0.2); color: var(--blood-red); border-color: var(--blood-red); }
        .threat-badge.malware { background: rgba(255,0,51,0.3); color: #ff3366; border-color: #ff3366; }
        .threat-badge.impersonation { background: rgba(255,106,0,0.2); color: var(--god-orange); border-color: var(--god-orange); }
        .threat-badge.ad-fraud { background: rgba(255,204,0,0.2); color: var(--warning-yellow); border-color: var(--warning-yellow); }
        .threat-badge.bulletproof { background: rgba(128,0,128,0.2); color: #cc00cc; border-color: #cc00cc; }
        .threat-badge.history-fake { background: rgba(255,106,0,0.2); color: var(--god-orange); border-color: var(--god-orange); }
        
        /* Network Intel */
        .intel-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        
        .intel-item {
            background: var(--void-black);
            padding: 12px;
            border-left: 3px solid var(--cyber-blue);
        }
        
        .intel-label {
            font-size: 0.65rem;
            color: var(--text-dim);
            letter-spacing: 1px;
            margin-bottom: 5px;
        }
        
        .intel-value {
            font-size: 0.9rem;
            color: var(--cyber-blue);
            word-break: break-all;
        }
        
        .intel-value.warning { color: var(--warning-yellow); }
        .intel-value.danger { color: var(--blood-red); }
        
        .ports-list {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin-top: 5px;
        }
        
        .port-badge {
            background: var(--void-deep);
            border: 1px solid var(--matrix-green);
            color: var(--matrix-green);
            padding: 3px 8px;
            font-size: 0.7rem;
        }
        
        /* Temporal Timeline */
        .timeline-container {
            padding: 20px 0;
        }
        
        .timeline-bar {
            height: 40px;
            background: var(--void-black);
            border: 1px solid var(--text-dim);
            position: relative;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .timeline-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--cyber-purple), var(--cyber-blue));
            position: absolute;
            left: 0;
            transition: width 0.5s;
        }
        
        .timeline-markers {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 0.7rem;
            color: var(--text-dim);
        }
        
        .temporal-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 20px;
        }
        
        .temporal-stat {
            text-align: center;
            padding: 15px;
            background: var(--void-black);
            border: 1px solid var(--text-dim);
        }
        
        .temporal-stat-value {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.2rem;
            color: var(--cyber-purple);
        }
        
        .temporal-stat-label {
            font-size: 0.65rem;
            color: var(--text-dim);
            margin-top: 5px;
        }
        
        /* Live Terminal */
        .terminal {
            background: #000;
            border: 1px solid var(--matrix-green);
            min-height: 300px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 0.8rem;
            padding: 15px;
        }
        
        .terminal-line {
            margin: 3px 0;
            line-height: 1.6;
            opacity: 0;
            animation: fadeIn 0.1s forwards;
        }
        
        @keyframes fadeIn { to { opacity: 1; } }
        
        .terminal-line.info { color: var(--cyber-blue); }
        .terminal-line.success { color: var(--matrix-green); }
        .terminal-line.warning { color: var(--warning-yellow); }
        .terminal-line.error { color: var(--blood-red); }
        .terminal-line.threat { color: var(--cyber-purple); text-shadow: 0 0 10px var(--cyber-purple); }
        .terminal-line.gold { color: var(--god-gold); }
        
        /* Content Analysis */
        .scores-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
        }
        
        .score-card {
            background: var(--void-black);
            padding: 15px;
            text-align: center;
            border: 1px solid var(--text-dim);
        }
        
        .score-card-value {
            font-family: 'Orbitron', sans-serif;
            font-size: 2rem;
            font-weight: bold;
        }
        
        .score-card-label {
            font-size: 0.7rem;
            color: var(--text-dim);
            margin-top: 5px;
        }
        
        .score-card.piracy .score-card-value { color: var(--cyber-purple); }
        .score-card.phishing .score-card-value { color: var(--blood-red); }
        .score-card.malware .score-card-value { color: #ff3366; }
        .score-card.ad-fraud .score-card-value { color: var(--warning-yellow); }
        
        .indicators-list {
            margin-top: 15px;
            padding: 15px;
            background: var(--void-black);
            border: 1px solid var(--text-dim);
            max-height: 150px;
            overflow-y: auto;
        }
        
        .indicator-item {
            font-size: 0.75rem;
            padding: 5px 0;
            border-bottom: 1px solid var(--void-mid);
            color: var(--warning-yellow);
        }
        
        .indicator-item::before {
            content: '⚡';
            margin-right: 8px;
        }
        
        /* Results Table */
        .results-section {
            margin-top: 25px;
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
            background: var(--void-mid);
        }
        
        .results-table th {
            background: var(--void-deep);
            padding: 15px;
            text-align: left;
            font-size: 0.75rem;
            color: var(--god-gold);
            letter-spacing: 1px;
            border-bottom: 2px solid var(--god-gold);
        }
        
        .results-table td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--text-dim);
            font-size: 0.85rem;
        }
        
        .results-table tr:hover { background: rgba(255, 215, 0, 0.05); }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-dim);
            font-size: 0.7rem;
            letter-spacing: 3px;
        }
        
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--void-black); }
        ::-webkit-scrollbar-thumb { background: var(--text-dim); }
        ::-webkit-scrollbar-thumb:hover { background: var(--god-gold); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">NETSENTINEL</div>
            <div class="subtitle">// GOD VIEW // THE OMNISCIENT EDITION //</div>
            <div class="version-tag">v6.0</div>
        </header>
        
        <div class="input-section">
            <label class="input-label">ENTER TARGET URL FOR OMNISCIENT ANALYSIS</label>
            <input type="text" id="url-input" class="url-input" 
                   placeholder="https://suspicious-site.example.com">
            <div class="btn-group">
                <button class="btn btn-scan" id="scan-btn" onclick="initiateOmniscientScan()">
                    ⚡ OMNISCIENT SCAN
                </button>
                <button class="btn btn-export" onclick="exportJSON()">EXPORT JSON</button>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <!-- Risk Assessment Panel -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title gold">◉ RISK ASSESSMENT</span>
                </div>
                <div class="panel-body">
                    <div class="risk-display">
                        <div class="risk-score safe" id="risk-score">--</div>
                        <div class="risk-label">RISK SCORE</div>
                        <div class="verdict-badge" id="verdict-badge" style="display:none;"></div>
                        <div class="threat-badges" id="threat-badges"></div>
                    </div>
                </div>
            </div>
            
            <!-- Network Intel Panel -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title blue">◉ INFRASTRUCTURE MAP</span>
                </div>
                <div class="panel-body">
                    <div class="intel-grid" id="network-intel">
                        <div class="intel-item">
                            <div class="intel-label">IP ADDRESS</div>
                            <div class="intel-value" id="intel-ip">--</div>
                        </div>
                        <div class="intel-item">
                            <div class="intel-label">LOCATION</div>
                            <div class="intel-value" id="intel-location">--</div>
                        </div>
                        <div class="intel-item">
                            <div class="intel-label">ISP / ORG</div>
                            <div class="intel-value" id="intel-isp">--</div>
                        </div>
                        <div class="intel-item">
                            <div class="intel-label">ASN</div>
                            <div class="intel-value" id="intel-asn">--</div>
                        </div>
                        <div class="intel-item">
                            <div class="intel-label">CLOUD PROVIDER</div>
                            <div class="intel-value" id="intel-cloud">--</div>
                        </div>
                        <div class="intel-item">
                            <div class="intel-label">OPEN PORTS</div>
                            <div class="ports-list" id="intel-ports"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Temporal Forensics Panel -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title purple">◉ TEMPORAL FORENSICS</span>
                </div>
                <div class="panel-body">
                    <div class="timeline-container">
                        <div class="timeline-bar">
                            <div class="timeline-fill" id="timeline-fill" style="width: 0%;"></div>
                        </div>
                        <div class="timeline-markers">
                            <span id="timeline-start">--</span>
                            <span>WAYBACK MACHINE</span>
                            <span id="timeline-end">--</span>
                        </div>
                    </div>
                    <div class="temporal-stats">
                        <div class="temporal-stat">
                            <div class="temporal-stat-value" id="temporal-snapshots">--</div>
                            <div class="temporal-stat-label">SNAPSHOTS</div>
                        </div>
                        <div class="temporal-stat">
                            <div class="temporal-stat-value" id="temporal-age">--</div>
                            <div class="temporal-stat-label">DOMAIN AGE (DAYS)</div>
                        </div>
                        <div class="temporal-stat">
                            <div class="temporal-stat-value" id="temporal-anomaly">OK</div>
                            <div class="temporal-stat-label">ANOMALY STATUS</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Content Classification Panel -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title green">◉ CONTENT CLASSIFICATION</span>
                </div>
                <div class="panel-body">
                    <div class="scores-grid">
                        <div class="score-card piracy">
                            <div class="score-card-value" id="score-piracy">0</div>
                            <div class="score-card-label">PIRACY</div>
                        </div>
                        <div class="score-card phishing">
                            <div class="score-card-value" id="score-phishing">0</div>
                            <div class="score-card-label">PHISHING</div>
                        </div>
                        <div class="score-card malware">
                            <div class="score-card-value" id="score-malware">0</div>
                            <div class="score-card-label">MALWARE</div>
                        </div>
                        <div class="score-card ad-fraud">
                            <div class="score-card-value" id="score-adfraud">0</div>
                            <div class="score-card-label">AD-FRAUD</div>
                        </div>
                    </div>
                    <div class="indicators-list" id="indicators-list">
                        <div style="color: var(--text-dim); text-align: center;">
                            Awaiting scan...
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Live Terminal -->
        <div class="panel" style="margin-bottom: 25px;">
            <div class="panel-header">
                <span class="panel-title green">◉ LIVE TERMINAL // THOUGHT PROCESS</span>
                <button class="btn btn-export" onclick="clearTerminal()" style="padding: 5px 10px; font-size: 0.7rem;">CLEAR</button>
            </div>
            <div class="terminal" id="terminal">
                <div class="terminal-line info">>> NETSENTINEL v6.0 OMNISCIENT ENGINE READY</div>
                <div class="terminal-line info">>> Awaiting target for analysis...</div>
            </div>
        </div>
        
        <!-- Results Table -->
        <div class="results-section">
            <table class="results-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>RISK</th>
                        <th>CATEGORY</th>
                        <th>VERDICT</th>
                        <th>THREATS</th>
                        <th>DURATION</th>
                    </tr>
                </thead>
                <tbody id="results-body"></tbody>
            </table>
        </div>
        
        <footer>
            NETSENTINEL v6.0 // THE OMNISCIENT EDITION // ETHICAL USE ONLY
        </footer>
    </div>
    
    <script>
        let currentResult = null;
        let analysisHistory = [];
        
        async function initiateOmniscientScan() {
            const url = document.getElementById('url-input').value.trim();
            if (!url) {
                alert('Please enter a URL');
                return;
            }
            
            const btn = document.getElementById('scan-btn');
            btn.disabled = true;
            btn.textContent = 'SCANNING...';
            
            resetPanels();
            logToTerminal('>> INITIATING OMNISCIENT SCAN', 'gold');
            logToTerminal(`>> Target: ${url}`, 'info');
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({urls: [url]})
                });
                
                const results = await response.json();
                
                if (results.length > 0) {
                    currentResult = results[0];
                    analysisHistory.push(currentResult);
                    
                    // Stream evidence logs
                    for (const log of currentResult.evidence_log || []) {
                        await logToTerminal(log);
                        await sleep(30);
                    }
                    
                    updatePanels(currentResult);
                    addToResultsTable(currentResult);
                }
            } catch (e) {
                logToTerminal(`>> ERROR: ${e.message}`, 'error');
            }
            
            btn.disabled = false;
            btn.textContent = '⚡ OMNISCIENT SCAN';
        }
        
        function resetPanels() {
            document.getElementById('risk-score').textContent = '--';
            document.getElementById('risk-score').className = 'risk-score';
            document.getElementById('verdict-badge').style.display = 'none';
            document.getElementById('threat-badges').innerHTML = '';
            document.getElementById('intel-ip').textContent = '--';
            document.getElementById('intel-location').textContent = '--';
            document.getElementById('intel-isp').textContent = '--';
            document.getElementById('intel-asn').textContent = '--';
            document.getElementById('intel-cloud').textContent = '--';
            document.getElementById('intel-ports').innerHTML = '';
            document.getElementById('timeline-fill').style.width = '0%';
            document.getElementById('timeline-start').textContent = '--';
            document.getElementById('timeline-end').textContent = '--';
            document.getElementById('temporal-snapshots').textContent = '--';
            document.getElementById('temporal-age').textContent = '--';
            document.getElementById('temporal-anomaly').textContent = 'OK';
            document.getElementById('score-piracy').textContent = '0';
            document.getElementById('score-phishing').textContent = '0';
            document.getElementById('score-malware').textContent = '0';
            document.getElementById('score-adfraud').textContent = '0';
            document.getElementById('indicators-list').innerHTML = '<div style="color: var(--text-dim); text-align: center;">Scanning...</div>';
        }
        
        function updatePanels(result) {
            // Risk Score
            const scoreEl = document.getElementById('risk-score');
            scoreEl.textContent = result.risk_score;
            if (result.risk_score < 20) scoreEl.className = 'risk-score safe';
            else if (result.risk_score < 40) scoreEl.className = 'risk-score low';
            else if (result.risk_score < 60) scoreEl.className = 'risk-score medium';
            else if (result.risk_score < 80) scoreEl.className = 'risk-score high';
            else scoreEl.className = 'risk-score critical';
            
            // Verdict
            const verdictEl = document.getElementById('verdict-badge');
            verdictEl.textContent = result.verdict;
            verdictEl.className = 'verdict-badge ' + result.verdict.toLowerCase();
            verdictEl.style.display = 'inline-block';
            
            // Threat Badges
            const badgesEl = document.getElementById('threat-badges');
            badgesEl.innerHTML = (result.threat_badges || []).map(badge => 
                `<span class="threat-badge ${badge.toLowerCase()}">${badge}</span>`
            ).join('');
            
            // Network Intel
            const net = result.network_intel || {};
            document.getElementById('intel-ip').textContent = net.ip_address || '--';
            document.getElementById('intel-location').textContent = 
                net.geolocation ? `${net.geolocation.city || ''}, ${net.geolocation.country || ''}` : '--';
            document.getElementById('intel-isp').textContent = net.isp || net.org || '--';
            document.getElementById('intel-asn').textContent = net.asn || '--';
            document.getElementById('intel-cloud').textContent = net.cloud_provider || (net.is_bulletproof_host ? '⚠️ BULLETPROOF' : 'N/A');
            
            const portsEl = document.getElementById('intel-ports');
            portsEl.innerHTML = (net.open_ports || []).map(port => 
                `<span class="port-badge">${port}</span>`
            ).join('') || '<span style="color: var(--text-dim);">None detected</span>';
            
            // Temporal Forensics
            const temp = result.temporal_analysis || {};
            document.getElementById('timeline-start').textContent = temp.wayback_first_seen || '--';
            document.getElementById('timeline-end').textContent = temp.wayback_last_seen || '--';
            document.getElementById('temporal-snapshots').textContent = temp.wayback_snapshot_count || 0;
            document.getElementById('temporal-age').textContent = temp.domain_age_days || '--';
            
            if (temp.temporal_anomaly) {
                document.getElementById('temporal-anomaly').textContent = '⚠️ ANOMALY';
                document.getElementById('temporal-anomaly').style.color = 'var(--blood-red)';
            }
            
            // Timeline fill
            const fillWidth = Math.min(100, (temp.wayback_snapshot_count || 0) * 2);
            document.getElementById('timeline-fill').style.width = fillWidth + '%';
            
            // Content Classification
            const content = result.content_classification || {};
            document.getElementById('score-piracy').textContent = content.piracy_score || 0;
            document.getElementById('score-phishing').textContent = content.phishing_score || 0;
            document.getElementById('score-malware').textContent = content.malware_score || 0;
            document.getElementById('score-adfraud').textContent = content.ad_fraud_score || 0;
            
            // Indicators
            const indicators = [
                ...(content.piracy_indicators || []),
                ...(content.phishing_indicators || []),
                ...(content.shady_ad_networks || [])
            ].slice(0, 10);
            
            const indicatorsEl = document.getElementById('indicators-list');
            if (indicators.length > 0) {
                indicatorsEl.innerHTML = indicators.map(ind => 
                    `<div class="indicator-item">${ind}</div>`
                ).join('');
            } else {
                indicatorsEl.innerHTML = '<div style="color: var(--matrix-green); text-align: center;">✓ No suspicious indicators detected</div>';
            }
        }
        
        function addToResultsTable(result) {
            const tbody = document.getElementById('results-body');
            const row = document.createElement('tr');
            row.innerHTML = `
                <td title="${result.url}">${result.url.substring(0, 50)}${result.url.length > 50 ? '...' : ''}</td>
                <td><strong>${result.risk_score}</strong>/100</td>
                <td>${result.category}</td>
                <td><span class="verdict-badge ${result.verdict.toLowerCase()}" style="padding: 5px 10px; font-size: 0.7rem;">${result.verdict}</span></td>
                <td>${(result.threat_badges || []).join(', ') || 'None'}</td>
                <td>${result.analysis_duration_ms}ms</td>
            `;
            tbody.insertBefore(row, tbody.firstChild);
        }
        
        async function logToTerminal(message, type = 'info') {
            const terminal = document.getElementById('terminal');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            
            if (message.includes('LIE DETECTED') || message.includes('THREAT BADGE')) {
                line.className += ' threat';
            } else if (message.includes('ERROR')) {
                line.className += ' error';
            } else if (message.includes('⚠️') || message.includes('ANOMALY') || message.includes('BULLETPROOF')) {
                line.className += ' warning';
            } else if (message.includes('VERDICT')) {
                line.className += ' gold';
            } else if (message.includes('✓') || message.includes('SUCCESS')) {
                line.className += ' success';
            } else {
                line.className += ' ' + type;
            }
            
            line.textContent = message;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        function clearTerminal() {
            document.getElementById('terminal').innerHTML = 
                '<div class="terminal-line info">>> TERMINAL CLEARED</div>';
        }
        
        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
        
        function exportJSON() {
            if (!currentResult) {
                alert('No results to export');
                return;
            }
            const blob = new Blob([JSON.stringify(currentResult, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'netsentinel_omniscient.json';
            a.click();
        }
        
        // Load history on start
        fetch('/history')
            .then(r => r.json())
            .then(history => {
                history.slice(-3).forEach(r => addToResultsTable(r));
            });
    </script>
</body>
</html>
'''


@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    
    results = []
    
    if ANALYZER_AVAILABLE:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            async def run_analysis():
                analyzer = OmniscientAnalyzer()
                async for result in analyzer.analyze_urls(urls):
                    results.append(dict(result))
                    save_result(dict(result))
            
            loop.run_until_complete(run_analysis())
        finally:
            loop.close()
    else:
        for url in urls:
            results.append({
                'url': url,
                'risk_score': 0,
                'category': 'ERROR',
                'verdict': 'ERROR',
                'error': 'Analyzer not available',
                'evidence_log': ['>> ERROR: Analyzer module not loaded']
            })
    
    return jsonify(results)


@app.route('/history')
def history():
    return jsonify(get_history())


if __name__ == '__main__':
    print(f"\n{Fore.YELLOW}{'='*60}")
    print(f"{Fore.YELLOW}NetSentinel v6.0{Fore.WHITE} // THE OMNISCIENT EDITION")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"\nDashboard: {Fore.GREEN}http://localhost:8080{Style.RESET_ALL}")
    print(f"Analyzer: {Fore.GREEN if ANALYZER_AVAILABLE else Fore.RED}{'ONLINE' if ANALYZER_AVAILABLE else 'OFFLINE'}{Style.RESET_ALL}")
    print(f"\nPress Ctrl+C to terminate\n")
    
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
