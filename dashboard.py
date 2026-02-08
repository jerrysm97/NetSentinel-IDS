"""
dashboard.py
NetSentinel v5.0 - Minority Report Dashboard

Theme: Neuromancer-inspired deep purple and blue palette
Features:
- Reality Distortion Field Meter (truth gauge)
- Real-time evidence streaming via SSE
- Sortable results table with expandable evidence logs
- JSON/CSV export functionality
"""

from __future__ import annotations

import sys
import os
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Generator
import queue
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, render_template_string, jsonify, request, Response
from colorama import Fore, Style

try:
    from url_analyzer import NetSentinelAnalyzer, analyze_url_async, AnalysisResult
    ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Analyzer import failed: {e}", file=sys.stderr)
    ANALYZER_AVAILABLE = False

app = Flask(__name__)

# Storage for analysis history
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
    <title>NetSentinel v5.0 // Minority Report</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Orbitron:wght@700&display=swap" rel="stylesheet">
    <style>
        :root {
            --purple-deep: #301934;
            --purple-mid: #4a1259;
            --blue-dark: #0f3460;
            --blue-glow: #16c2d5;
            --cyan-bright: #00fff7;
            --magenta: #e100ff;
            --red-alert: #ff0044;
            --green-truth: #00ff88;
            --yellow-warn: #ffcc00;
            --bg-void: #0a0a12;
            --text-main: #e8e8f0;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'JetBrains Mono', monospace;
            background: linear-gradient(135deg, var(--bg-void) 0%, var(--purple-deep) 50%, var(--blue-dark) 100%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
        }
        
        /* Scanlines overlay */
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
            z-index: 10000;
        }
        
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
            border: 1px solid var(--magenta);
            background: rgba(48, 25, 52, 0.8);
            position: relative;
            overflow: hidden;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 200%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--magenta), var(--cyan-bright), transparent);
            animation: headerScan 3s linear infinite;
        }
        
        @keyframes headerScan {
            0% { transform: translateX(0); }
            100% { transform: translateX(50%); }
        }
        
        .logo {
            font-family: 'Orbitron', sans-serif;
            font-size: 2.5rem;
            background: linear-gradient(90deg, var(--cyan-bright), var(--magenta));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: 4px;
        }
        
        .subtitle {
            color: var(--blue-glow);
            font-size: 0.75rem;
            letter-spacing: 4px;
            margin-top: 10px;
            opacity: 0.9;
        }
        
        .philosophy {
            color: var(--yellow-warn);
            font-style: italic;
            font-size: 0.85rem;
            margin-top: 15px;
        }
        
        /* Input Section */
        .input-section {
            background: rgba(15, 52, 96, 0.6);
            border: 1px solid var(--blue-glow);
            padding: 25px;
            margin-bottom: 30px;
        }
        
        .input-label {
            color: var(--cyan-bright);
            font-size: 0.8rem;
            letter-spacing: 2px;
            margin-bottom: 15px;
            display: block;
        }
        
        .url-textarea {
            width: 100%;
            min-height: 100px;
            padding: 15px;
            background: var(--bg-void);
            border: 1px solid var(--purple-mid);
            color: var(--text-main);
            font-family: inherit;
            font-size: 0.9rem;
            resize: vertical;
            outline: none;
        }
        
        .url-textarea:focus {
            border-color: var(--magenta);
            box-shadow: 0 0 20px rgba(225, 0, 255, 0.2);
        }
        
        .url-textarea::placeholder {
            color: rgba(255,255,255,0.3);
        }
        
        .btn-group {
            display: flex;
            gap: 15px;
            margin-top: 15px;
        }
        
        .btn {
            padding: 12px 25px;
            font-family: 'Orbitron', sans-serif;
            font-size: 0.9rem;
            letter-spacing: 1px;
            border: none;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .btn-analyze {
            background: linear-gradient(135deg, var(--magenta), var(--purple-mid));
            color: white;
            border: 1px solid var(--magenta);
        }
        
        .btn-analyze:hover {
            box-shadow: 0 0 30px rgba(225, 0, 255, 0.5);
            transform: translateY(-2px);
        }
        
        .btn-analyze:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-export {
            background: transparent;
            color: var(--cyan-bright);
            border: 1px solid var(--cyan-bright);
        }
        
        .btn-export:hover {
            background: rgba(22, 194, 213, 0.2);
        }
        
        /* Reality Distortion Field Meter */
        .meter-section {
            display: none;
            margin-bottom: 30px;
        }
        
        .meter-section.active {
            display: block;
        }
        
        .meter-container {
            display: flex;
            justify-content: center;
            padding: 40px;
            background: rgba(10, 10, 18, 0.9);
            border: 1px solid var(--purple-mid);
        }
        
        .meter-wrapper {
            text-align: center;
        }
        
        .meter-title {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.2rem;
            color: var(--cyan-bright);
            margin-bottom: 20px;
            letter-spacing: 2px;
        }
        
        .gauge-container {
            position: relative;
            width: 250px;
            height: 150px;
            margin: 0 auto;
        }
        
        .gauge-bg {
            position: absolute;
            width: 100%;
            height: 100%;
        }
        
        .gauge-value {
            position: absolute;
            bottom: 10px;
            left: 50%;
            transform: translateX(-50%);
            font-family: 'Orbitron', sans-serif;
            font-size: 2.5rem;
        }
        
        .gauge-label {
            margin-top: 20px;
            font-size: 1rem;
            padding: 10px 20px;
            border-radius: 4px;
        }
        
        .gauge-label.truthful { background: rgba(0, 255, 136, 0.2); color: var(--green-truth); border: 1px solid var(--green-truth); }
        .gauge-label.suspicious { background: rgba(255, 204, 0, 0.2); color: var(--yellow-warn); border: 1px solid var(--yellow-warn); }
        .gauge-label.deceptive { background: rgba(255, 100, 0, 0.2); color: #ff6600; border: 1px solid #ff6600; }
        .gauge-label.malicious { background: rgba(255, 0, 68, 0.2); color: var(--red-alert); border: 1px solid var(--red-alert); }
        
        /* Evidence Terminal */
        .evidence-section {
            margin-bottom: 30px;
        }
        
        .evidence-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            background: var(--purple-deep);
            border: 1px solid var(--purple-mid);
            border-bottom: none;
        }
        
        .evidence-title {
            font-family: 'Orbitron', sans-serif;
            color: var(--cyan-bright);
            letter-spacing: 2px;
        }
        
        .evidence-terminal {
            background: #000;
            border: 1px solid var(--purple-mid);
            padding: 20px;
            min-height: 200px;
            max-height: 400px;
            overflow-y: auto;
            font-size: 0.85rem;
            line-height: 1.8;
        }
        
        .log-line {
            opacity: 0;
            animation: typeIn 0.1s forwards;
        }
        
        @keyframes typeIn {
            to { opacity: 1; }
        }
        
        .log-line.info { color: var(--cyan-bright); }
        .log-line.warn { color: var(--yellow-warn); }
        .log-line.error { color: var(--red-alert); }
        .log-line.success { color: var(--green-truth); }
        .log-line.lie { color: var(--magenta); text-shadow: 0 0 10px var(--magenta); }
        
        /* Results Table */
        .results-section {
            margin-bottom: 30px;
        }
        
        .results-table {
            width: 100%;
            border-collapse: collapse;
            background: rgba(10, 10, 18, 0.8);
        }
        
        .results-table th {
            background: var(--purple-deep);
            padding: 15px;
            text-align: left;
            font-family: 'Orbitron', sans-serif;
            font-size: 0.8rem;
            color: var(--cyan-bright);
            letter-spacing: 1px;
            border-bottom: 2px solid var(--magenta);
            cursor: pointer;
        }
        
        .results-table th:hover {
            background: var(--purple-mid);
        }
        
        .results-table td {
            padding: 12px 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            font-size: 0.85rem;
        }
        
        .results-table tr:hover {
            background: rgba(225, 0, 255, 0.1);
        }
        
        .truth-badge {
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .truth-badge.truthful { background: rgba(0, 255, 136, 0.2); color: var(--green-truth); }
        .truth-badge.suspicious { background: rgba(255, 204, 0, 0.2); color: var(--yellow-warn); }
        .truth-badge.deceptive { background: rgba(255, 100, 0, 0.2); color: #ff6600; }
        .truth-badge.malicious { background: rgba(255, 0, 68, 0.2); color: var(--red-alert); }
        .truth-badge.error { background: rgba(128, 128, 128, 0.2); color: #888; }
        
        .expand-btn {
            background: transparent;
            border: 1px solid var(--blue-glow);
            color: var(--blue-glow);
            padding: 4px 8px;
            cursor: pointer;
            font-size: 0.7rem;
        }
        
        .expand-btn:hover {
            background: rgba(22, 194, 213, 0.2);
        }
        
        .evidence-row {
            display: none;
        }
        
        .evidence-row.visible {
            display: table-row;
        }
        
        .evidence-row td {
            background: #111;
            padding: 15px 20px;
        }
        
        .evidence-content {
            font-size: 0.8rem;
            line-height: 1.6;
            color: var(--cyan-bright);
        }
        
        /* Analysis Details */
        .analysis-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }
        
        .detail-card {
            background: rgba(48, 25, 52, 0.5);
            border: 1px solid var(--purple-mid);
            padding: 15px;
        }
        
        .detail-card h4 {
            color: var(--magenta);
            font-size: 0.8rem;
            margin-bottom: 10px;
            letter-spacing: 1px;
        }
        
        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            font-size: 0.8rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        
        .detail-label { color: rgba(255,255,255,0.6); }
        .detail-value { color: var(--text-main); }
        
        /* Dark Mode Toggle */
        .dark-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--purple-mid);
            border: 1px solid var(--magenta);
            color: var(--text-main);
            padding: 10px 15px;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.8rem;
            z-index: 1000;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: rgba(232, 232, 240, 0.4);
            font-size: 0.7rem;
            letter-spacing: 2px;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-void); }
        ::-webkit-scrollbar-thumb { background: var(--purple-mid); }
        ::-webkit-scrollbar-thumb:hover { background: var(--magenta); }
    </style>
</head>
<body>
    <button class="dark-toggle" onclick="toggleTheme()">☀ / ☾</button>
    
    <div class="container">
        <header>
            <div class="logo">NETSENTINEL v5.0</div>
            <div class="subtitle">// MINORITY REPORT // COGNITIVE TRUTH ENGINE //</div>
            <div class="philosophy">"The Truth is in the Context, not the Ports."</div>
        </header>
        
        <div class="input-section">
            <label class="input-label">&gt; ENTER TARGET URLs (one per line)</label>
            <textarea id="url-input" class="url-textarea" 
                      placeholder="https://suspicious-site.example.com&#10;https://fake-paypal.xyz&#10;https://legitimate-site.com"></textarea>
            <div class="btn-group">
                <button class="btn btn-analyze" id="analyze-btn" onclick="analyzeUrls()">
                    ANALYZE TRUTH
                </button>
                <button class="btn btn-export" onclick="exportJSON()">EXPORT JSON</button>
                <button class="btn btn-export" onclick="exportCSV()">EXPORT CSV</button>
            </div>
        </div>
        
        <div class="meter-section" id="meter-section">
            <div class="meter-container">
                <div class="meter-wrapper">
                    <div class="meter-title">REALITY DISTORTION FIELD</div>
                    <canvas id="gauge-canvas" width="250" height="150"></canvas>
                    <div class="gauge-label" id="gauge-label">Analyzing...</div>
                </div>
            </div>
        </div>
        
        <div class="evidence-section">
            <div class="evidence-header">
                <span class="evidence-title">EVIDENCE STREAM</span>
                <button class="btn btn-export" onclick="clearLogs()" style="padding: 5px 10px; font-size: 0.7rem;">CLEAR</button>
            </div>
            <div class="evidence-terminal" id="evidence-terminal">
                <div class="log-line info">&gt;&gt; COGNITIVE ENGINE READY</div>
                <div class="log-line info">&gt;&gt; Awaiting targets for truth analysis...</div>
            </div>
        </div>
        
        <div class="results-section">
            <table class="results-table">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">URL ↕</th>
                        <th onclick="sortTable(1)">TRUTH SCORE ↕</th>
                        <th onclick="sortTable(2)">VERDICT ↕</th>
                        <th onclick="sortTable(3)">IMPERSONATION ↕</th>
                        <th onclick="sortTable(4)">MANIP INDEX ↕</th>
                        <th>EVIDENCE</th>
                    </tr>
                </thead>
                <tbody id="results-body"></tbody>
            </table>
        </div>
        
        <footer>
            NETSENTINEL v5.0 // COGNITIVE TRUTH ENGINE // ETHICAL USE ONLY
        </footer>
    </div>
    
    <script>
        let analysisResults = [];
        let sortDirection = {};
        
        // Gauge drawing
        function drawGauge(score, verdict) {
            const canvas = document.getElementById('gauge-canvas');
            const ctx = canvas.getContext('2d');
            const width = canvas.width;
            const height = canvas.height;
            const centerX = width / 2;
            const centerY = height - 10;
            const radius = height - 30;
            
            ctx.clearRect(0, 0, width, height);
            
            // Draw arc background
            const colors = [
                { stop: 0, color: '#ff0044' },
                { stop: 0.25, color: '#ff6600' },
                { stop: 0.5, color: '#ffcc00' },
                { stop: 0.75, color: '#88ff00' },
                { stop: 1, color: '#00ff88' }
            ];
            
            const gradient = ctx.createLinearGradient(0, 0, width, 0);
            colors.forEach(c => gradient.addColorStop(c.stop, c.color));
            
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, Math.PI, 0, false);
            ctx.lineWidth = 15;
            ctx.strokeStyle = '#222';
            ctx.stroke();
            
            // Draw filled arc based on score
            const endAngle = Math.PI + (Math.PI * (100 - score) / 100);
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, Math.PI, endAngle, false);
            ctx.strokeStyle = gradient;
            ctx.lineWidth = 15;
            ctx.stroke();
            
            // Draw score
            ctx.font = 'bold 36px Orbitron';
            ctx.textAlign = 'center';
            ctx.fillStyle = score >= 75 ? '#00ff88' : score >= 50 ? '#ffcc00' : score >= 25 ? '#ff6600' : '#ff0044';
            ctx.fillText(score.toFixed(0), centerX, centerY - 20);
            
            ctx.font = '12px JetBrains Mono';
            ctx.fillStyle = '#888';
            ctx.fillText('TRUTH SCORE', centerX, centerY + 5);
            
            // Update label
            const label = document.getElementById('gauge-label');
            label.textContent = verdict;
            label.className = 'gauge-label ' + verdict.toLowerCase().replace('_', '');
        }
        
        // Log to terminal with typing effect
        async function logToTerminal(message, type = 'info') {
            const terminal = document.getElementById('evidence-terminal');
            const line = document.createElement('div');
            line.className = 'log-line ' + type;
            
            // Check for lie detection
            if (message.includes('LIE DETECTED') || message.includes('IDENTITY MISMATCH')) {
                type = 'lie';
                line.className = 'log-line lie';
            } else if (message.includes('ERROR')) {
                line.className = 'log-line error';
            } else if (message.includes('VERDICT') && message.includes('TRUTHFUL')) {
                line.className = 'log-line success';
            } else if (message.includes('⚠️') || message.includes('ANOMALY')) {
                line.className = 'log-line warn';
            }
            
            line.textContent = message;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
            
            await new Promise(r => setTimeout(r, 50));
        }
        
        function clearLogs() {
            document.getElementById('evidence-terminal').innerHTML = 
                '<div class="log-line info">>> EVIDENCE LOG CLEARED</div>';
        }
        
        async function analyzeUrls() {
            const textarea = document.getElementById('url-input');
            const urls = textarea.value.split('\\n').map(u => u.trim()).filter(u => u.length > 0);
            
            if (urls.length === 0) {
                alert('Please enter at least one URL');
                return;
            }
            
            if (urls.length > 100) {
                alert('Maximum 100 URLs per batch');
                return;
            }
            
            const btn = document.getElementById('analyze-btn');
            btn.disabled = true;
            btn.textContent = 'ANALYZING...';
            
            document.getElementById('meter-section').classList.add('active');
            await logToTerminal('>> INITIATING COGNITIVE TRUTH ENGINE', 'info');
            await logToTerminal(`>> ${urls.length} target(s) queued for analysis`, 'info');
            
            analysisResults = [];
            
            for (const url of urls) {
                try {
                    await logToTerminal(`>> SCANNING: ${url}`, 'info');
                    
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({urls: [url]})
                    });
                    
                    const results = await response.json();
                    
                    if (results.length > 0) {
                        const result = results[0];
                        analysisResults.push(result);
                        
                        // Stream evidence logs
                        for (const log of result.evidence_log || []) {
                            await logToTerminal(log);
                        }
                        
                        drawGauge(result.truth_score, result.verdict);
                        addResultToTable(result);
                    }
                } catch (e) {
                    await logToTerminal(`>> ERROR: ${e.message}`, 'error');
                }
            }
            
            await logToTerminal('>> ANALYSIS COMPLETE', 'success');
            btn.disabled = false;
            btn.textContent = 'ANALYZE TRUTH';
        }
        
        function addResultToTable(result) {
            const tbody = document.getElementById('results-body');
            const rowId = 'row-' + Date.now();
            
            const row = document.createElement('tr');
            row.innerHTML = `
                <td title="${result.url}">${result.url.substring(0, 40)}${result.url.length > 40 ? '...' : ''}</td>
                <td><strong>${result.truth_score}</strong>/100</td>
                <td><span class="truth-badge ${result.verdict.toLowerCase().replace('_', '')}">${result.verdict}</span></td>
                <td>${result.semantic_analysis?.claimed_brands?.join(', ') || 'None'}</td>
                <td>${result.psychological_analysis?.manipulative_index?.toFixed(1) || 0}</td>
                <td><button class="expand-btn" onclick="toggleEvidence('${rowId}')">DETAILS</button></td>
            `;
            tbody.appendChild(row);
            
            // Evidence row
            const evidenceRow = document.createElement('tr');
            evidenceRow.className = 'evidence-row';
            evidenceRow.id = rowId;
            evidenceRow.innerHTML = `
                <td colspan="6">
                    <div class="evidence-content">
                        <div class="analysis-details">
                            <div class="detail-card">
                                <h4>SEMANTIC ANALYSIS</h4>
                                <div class="detail-item">
                                    <span class="detail-label">Title:</span>
                                    <span class="detail-value">${result.semantic_analysis?.extracted_title || 'N/A'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Domain:</span>
                                    <span class="detail-value">${result.semantic_analysis?.domain || 'N/A'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Registrant:</span>
                                    <span class="detail-value">${result.semantic_analysis?.registrant || 'Unknown'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Impersonation:</span>
                                    <span class="detail-value">${result.semantic_analysis?.impersonation_check || 'None'}</span>
                                </div>
                            </div>
                            <div class="detail-card">
                                <h4>PSYCHOLOGICAL ANALYSIS</h4>
                                <div class="detail-item">
                                    <span class="detail-label">Fear Triggers:</span>
                                    <span class="detail-value">${result.psychological_analysis?.triggers?.fear || 0}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Greed Triggers:</span>
                                    <span class="detail-value">${result.psychological_analysis?.triggers?.greed || 0}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Urgency Triggers:</span>
                                    <span class="detail-value">${result.psychological_analysis?.triggers?.urgency || 0}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Verdict:</span>
                                    <span class="detail-value">${result.psychological_analysis?.verdict || 'N/A'}</span>
                                </div>
                            </div>
                            <div class="detail-card">
                                <h4>DOMAIN CONSISTENCY</h4>
                                <div class="detail-item">
                                    <span class="detail-label">Created:</span>
                                    <span class="detail-value">${result.domain_consistency?.creation_date || 'Unknown'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Age (days):</span>
                                    <span class="detail-value">${result.domain_consistency?.age_days || 'Unknown'}</span>
                                </div>
                                <div class="detail-item">
                                    <span class="detail-label">Anomaly:</span>
                                    <span class="detail-value">${result.domain_consistency?.anomaly || 'None'}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </td>
            `;
            tbody.appendChild(evidenceRow);
        }
        
        function toggleEvidence(rowId) {
            const row = document.getElementById(rowId);
            row.classList.toggle('visible');
        }
        
        function sortTable(colIndex) {
            const tbody = document.getElementById('results-body');
            const rows = Array.from(tbody.querySelectorAll('tr:not(.evidence-row)'));
            
            sortDirection[colIndex] = !sortDirection[colIndex];
            const dir = sortDirection[colIndex] ? 1 : -1;
            
            rows.sort((a, b) => {
                let aVal = a.cells[colIndex].textContent;
                let bVal = b.cells[colIndex].textContent;
                
                if (colIndex === 1 || colIndex === 4) {
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                    return (aVal - bVal) * dir;
                }
                return aVal.localeCompare(bVal) * dir;
            });
            
            rows.forEach(row => {
                const evidenceRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (evidenceRow?.classList.contains('evidence-row')) {
                    tbody.appendChild(evidenceRow);
                }
            });
        }
        
        function exportJSON() {
            if (analysisResults.length === 0) {
                alert('No results to export');
                return;
            }
            const blob = new Blob([JSON.stringify(analysisResults, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'netsentinel_analysis.json';
            a.click();
        }
        
        function exportCSV() {
            if (analysisResults.length === 0) {
                alert('No results to export');
                return;
            }
            let csv = 'URL,Truth Score,Verdict,Claimed Brands,Manipulation Index,Domain Age,Anomaly\\n';
            analysisResults.forEach(r => {
                csv += `"${r.url}",${r.truth_score},"${r.verdict}","${r.semantic_analysis?.claimed_brands?.join(';') || ''}",${r.psychological_analysis?.manipulative_index || 0},${r.domain_consistency?.age_days || ''},${r.domain_consistency?.anomaly || ''}\\n`;
            });
            const blob = new Blob([csv], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'netsentinel_analysis.csv';
            a.click();
        }
        
        function toggleTheme() {
            document.body.classList.toggle('light-mode');
        }
        
        // Load history on start
        fetch('/history')
            .then(r => r.json())
            .then(history => {
                history.slice(-5).forEach(r => addResultToTable(r));
            });
    </script>
</body>
</html>
'''


@app.route('/')
@app.route('/dashboard')
def dashboard():
    """Render the Minority Report dashboard."""
    return render_template_string(DASHBOARD_HTML)


@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze URLs and return results."""
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not urls:
        return jsonify({'error': 'No URLs provided'}), 400
    
    if len(urls) > 100:
        urls = urls[:100]
    
    results = []
    
    if ANALYZER_AVAILABLE:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            async def run_analysis():
                analyzer = NetSentinelAnalyzer()
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
                'truth_score': 0,
                'verdict': 'ERROR',
                'error': 'Analyzer not available',
                'evidence_log': ['>> ERROR: Analyzer module not loaded']
            })
    
    return jsonify(results)


@app.route('/history')
def history():
    """Return analysis history."""
    return jsonify(get_history())


if __name__ == '__main__':
    print(f"\n{Fore.MAGENTA}{'='*60}")
    print(f"{Fore.CYAN}NetSentinel v5.0{Fore.MAGENTA} // Minority Report Dashboard")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Philosophy: The Truth is in the Context, not the Ports.")
    print(f"\nDashboard: {Fore.GREEN}http://localhost:5000{Style.RESET_ALL}")
    print(f"Analyzer: {Fore.GREEN if ANALYZER_AVAILABLE else Fore.RED}{'ONLINE' if ANALYZER_AVAILABLE else 'OFFLINE'}{Style.RESET_ALL}")
    print(f"\nPress Ctrl+C to terminate\n")
    
    app.run(host='0.0.0.0', port=8080, debug=False, threaded=True)
