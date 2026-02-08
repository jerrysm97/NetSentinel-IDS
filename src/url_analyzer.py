"""
url_analyzer.py
NetSentinel Forensic URL Analysis Engine

ARCHITECTURE: Pure asyncio + aiohttp for non-blocking I/O
FEATURES:
- SSL Forensics: Certificate chain analysis, issuer classification
- Content Heuristics: FOMO patterns, crypto/bank keywords, login form detection
- Tech Stack Detection: CMS fingerprinting via meta tags and headers
- Risk Assessment: Detailed threat explanations
"""

import asyncio
import aiohttp
import ssl
import socket
import re
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
import hashlib

# Blocking library imports (run in executor)
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from bs4 import BeautifulSoup


@dataclass
class AnalysisResult:
    """Strict JSON schema for analysis output."""
    target: str
    domain: str
    score: int
    verdict: str
    risk_summary: str
    logs: List[Dict[str, Any]]
    tech_stack: Dict[str, Any]
    ssl_forensics: Dict[str, Any]
    content_analysis: Dict[str, Any]
    domain_intel: Dict[str, Any]
    threat_indicators: List[str]
    recommendations: List[str]
    google_dorks: Dict[str, str]
    timestamp: str
    analysis_duration_ms: int


class ForensicURLAnalyzer:
    """
    Production-grade asynchronous URL analysis engine.
    
    Uses ThreadPoolExecutor for blocking operations (WHOIS, SSL).
    All network I/O is non-blocking via aiohttp.
    """
    
    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
        '.click', '.link', '.loan', '.online', '.site', '.website',
        '.buzz', '.rest', '.fit', '.life', '.live', '.bid'
    }
    
    # Commercial SSL issuers (higher trust)
    COMMERCIAL_CAS = {
        'digicert', 'comodo', 'sectigo', 'verisign', 'entrust', 
        'globalsign', 'godaddy', 'thawte', 'geotrust', 'symantec',
        'trustwave', 'starfield', 'amazon', 'microsoft', 'apple'
    }
    
    # Urgency/FOMO patterns (scam indicators)
    URGENCY_PATTERNS = [
        r'act\s*now', r'limited\s*time', r'expires?\s*(soon|today|in\s*\d+)',
        r'hurry', r"don'?t\s*miss", r'last\s*chance', r'urgent',
        r'immediately', r'only\s*\d+\s*(left|remaining)', r'exclusive\s*offer',
        r'winner', r'congratulations', r'claim\s*(your|now)', r'free\s*gift',
        r'risk[- ]?free', r'guaranteed', r'no\s*obligation', r'special\s*offer',
        r'limited\s*availability', r'today\s*only', r'once\s*in\s*a\s*lifetime',
        r'now\s*or\s*never', r'instant\s*(access|approval)', r'act\s*fast'
    ]
    
    # Financial/Crypto keywords (high-risk context)
    FINANCIAL_KEYWORDS = [
        r'bitcoin', r'crypto', r'wallet', r'ethereum', r'binance',
        r'coinbase', r'blockchain', r'nft', r'invest(ment)?', r'trading',
        r'forex', r'bank\s*account', r'credit\s*card', r'paypal',
        r'wire\s*transfer', r'western\s*union', r'moneygram', r'seed\s*phrase',
        r'private\s*key', r'recovery\s*phrase', r'verify\s*(your\s*)?(account|identity)',
        r'update\s*(your\s*)?(payment|billing)', r'suspended', r'locked\s*account'
    ]
    
    # CMS detection signatures
    CMS_SIGNATURES = {
        'WordPress': [
            ('meta', {'name': 'generator', 'content': re.compile(r'wordpress', re.I)}),
            ('link', {'href': re.compile(r'wp-content|wp-includes', re.I)}),
        ],
        'Shopify': [
            ('meta', {'name': 'generator', 'content': re.compile(r'shopify', re.I)}),
            ('link', {'href': re.compile(r'cdn\.shopify\.com', re.I)}),
        ],
        'Wix': [
            ('meta', {'name': 'generator', 'content': re.compile(r'wix', re.I)}),
            ('script', {'src': re.compile(r'static\.wixstatic\.com', re.I)}),
        ],
        'Squarespace': [
            ('meta', {'name': 'generator', 'content': re.compile(r'squarespace', re.I)}),
        ],
        'Drupal': [
            ('meta', {'name': 'generator', 'content': re.compile(r'drupal', re.I)}),
        ],
        'Joomla': [
            ('meta', {'name': 'generator', 'content': re.compile(r'joomla', re.I)}),
        ],
        'Webflow': [
            ('meta', {'name': 'generator', 'content': re.compile(r'webflow', re.I)}),
        ],
    }
    
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.compiled_urgency = [re.compile(p, re.I) for p in self.URGENCY_PATTERNS]
        self.compiled_financial = [re.compile(p, re.I) for p in self.FINANCIAL_KEYWORDS]
        
    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive forensic analysis of a URL.
        
        Args:
            url: Target URL to analyze
            
        Returns:
            AnalysisResult as dictionary with strict JSON schema
        """
        start_time = datetime.now()
        logs = []
        threat_indicators = []
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        if not domain:
            return self._error_result(url, "Invalid URL format", start_time)
        
        logs.append(self._log("INIT", f"Target acquired: {domain}", "info"))
        
        # Run all analyses concurrently
        ssl_task = asyncio.create_task(self._analyze_ssl(domain, logs))
        content_task = asyncio.create_task(self._analyze_content(url, logs))
        domain_task = asyncio.create_task(self._analyze_domain(domain, logs))
        
        ssl_result, content_result, domain_result = await asyncio.gather(
            ssl_task, content_task, domain_task,
            return_exceptions=True
        )
        
        # Handle exceptions (fail open)
        if isinstance(ssl_result, Exception):
            logs.append(self._log("SSL", f"Analysis failed: {str(ssl_result)}", "error"))
            ssl_result = {"error": str(ssl_result), "score": 40}
            
        if isinstance(content_result, Exception):
            logs.append(self._log("CONTENT", f"Analysis failed: {str(content_result)}", "error"))
            content_result = {"error": str(content_result), "score": 30, "tech_stack": {}}
            
        if isinstance(domain_result, Exception):
            logs.append(self._log("DOMAIN", f"Analysis failed: {str(domain_result)}", "error"))
            domain_result = {"error": str(domain_result), "score": 30}
        
        # Collect threat indicators
        threat_indicators.extend(ssl_result.get("threats", []))
        threat_indicators.extend(content_result.get("threats", []))
        threat_indicators.extend(domain_result.get("threats", []))
        
        # Calculate composite risk score
        ssl_score = ssl_result.get("score", 30)
        content_score = content_result.get("score", 30)
        domain_score = domain_result.get("score", 30)
        
        # Weighted scoring: Domain 35%, SSL 25%, Content 40%
        composite_score = int(
            (domain_score * 0.35) +
            (ssl_score * 0.25) +
            (content_score * 0.40)
        )
        
        # Apply threat indicator multipliers
        if len(threat_indicators) >= 5:
            composite_score = min(100, composite_score + 20)
        elif len(threat_indicators) >= 3:
            composite_score = min(100, composite_score + 10)
        
        # Determine verdict
        if composite_score >= 70:
            verdict = "MALICIOUS"
        elif composite_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
            
        logs.append(self._log("VERDICT", f"Risk Score: {composite_score}/100 - {verdict}", 
                             "critical" if verdict == "MALICIOUS" else ("warning" if verdict == "SUSPICIOUS" else "success")))
        
        # Generate risk summary
        risk_summary = self._generate_risk_summary(
            composite_score, verdict, threat_indicators, 
            ssl_result, content_result, domain_result
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            verdict, threat_indicators, ssl_result, content_result, domain_result
        )
        
        # Generate Google Dorks
        google_dorks = self._generate_dorks(domain)
        
        # Calculate duration
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        result = AnalysisResult(
            target=url,
            domain=domain,
            score=composite_score,
            verdict=verdict,
            risk_summary=risk_summary,
            logs=logs,
            tech_stack=content_result.get("tech_stack", {}),
            ssl_forensics=ssl_result,
            content_analysis=content_result,
            domain_intel=domain_result,
            threat_indicators=threat_indicators,
            recommendations=recommendations,
            google_dorks=google_dorks,
            timestamp=datetime.now(timezone.utc).isoformat(),
            analysis_duration_ms=duration_ms
        )
        
        return asdict(result)
    
    async def _analyze_ssl(self, domain: str, logs: List) -> Dict[str, Any]:
        """Forensic SSL certificate analysis."""
        logs.append(self._log("SSL", "Initiating TLS handshake...", "info"))
        
        result = {
            "score": 0,
            "threats": [],
            "certificate": {},
            "issuer_trust": "UNKNOWN"
        }
        
        try:
            # Run blocking SSL operation in executor
            loop = asyncio.get_event_loop()
            cert_data = await loop.run_in_executor(
                self.executor,
                self._get_ssl_certificate,
                domain
            )
            
            if cert_data is None:
                logs.append(self._log("SSL", "No HTTPS available - HIGH RISK", "critical"))
                result["score"] = 80
                result["threats"].append("No SSL/TLS encryption")
                result["issuer_trust"] = "NONE"
                return result
            
            result["certificate"] = cert_data
            
            # Analyze issuer
            issuer = cert_data.get("issuer", "").lower()
            subject = cert_data.get("subject", "")
            
            # Check for self-signed
            if issuer == subject or "self-signed" in issuer:
                logs.append(self._log("SSL", "⚠ SELF-SIGNED CERTIFICATE DETECTED", "critical"))
                result["score"] = 70
                result["threats"].append("Self-signed certificate (no third-party validation)")
                result["issuer_trust"] = "SELF-SIGNED"
            # Check for Let's Encrypt
            elif "let's encrypt" in issuer or "letsencrypt" in issuer:
                logs.append(self._log("SSL", "Let's Encrypt certificate (free, basic validation)", "warning"))
                result["score"] = 25
                result["issuer_trust"] = "FREE_DV"
            # Check for commercial CAs
            elif any(ca in issuer for ca in self.COMMERCIAL_CAS):
                logs.append(self._log("SSL", f"Commercial CA: {issuer.title()}", "success"))
                result["score"] = 5
                result["issuer_trust"] = "COMMERCIAL_EV"
            else:
                logs.append(self._log("SSL", f"Unknown CA: {issuer}", "info"))
                result["score"] = 20
                result["issuer_trust"] = "UNKNOWN_CA"
            
            # Check expiry
            expiry = cert_data.get("expiry_days")
            if expiry is not None:
                if expiry < 0:
                    logs.append(self._log("SSL", f"⚠ CERTIFICATE EXPIRED {abs(expiry)} days ago!", "critical"))
                    result["score"] = min(result["score"] + 40, 100)
                    result["threats"].append(f"Expired SSL certificate ({abs(expiry)} days)")
                elif expiry < 7:
                    logs.append(self._log("SSL", f"Certificate expires in {expiry} days", "warning"))
                    result["score"] = min(result["score"] + 10, 100)
                elif expiry < 30:
                    logs.append(self._log("SSL", f"Certificate expires in {expiry} days", "info"))
                else:
                    logs.append(self._log("SSL", f"Certificate valid for {expiry} days", "success"))
            
            # Check for domain mismatch
            cert_domains = cert_data.get("san_domains", [])
            if domain not in cert_domains and not any(
                d.replace("*.", "") in domain for d in cert_domains if d.startswith("*.")
            ):
                logs.append(self._log("SSL", "⚠ Domain not in certificate SAN", "warning"))
                result["score"] = min(result["score"] + 15, 100)
                result["threats"].append("Domain mismatch in certificate")
                
        except Exception as e:
            logs.append(self._log("SSL", f"Handshake failed: {str(e)}", "error"))
            result["score"] = 50
            result["threats"].append(f"SSL verification failed: {str(e)}")
            
        return result
    
    def _get_ssl_certificate(self, domain: str) -> Optional[Dict]:
        """Blocking SSL certificate extraction (runs in executor)."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract issuer
                    issuer_parts = []
                    for rdn in cert.get('issuer', []):
                        for key, value in rdn:
                            if key in ('organizationName', 'commonName'):
                                issuer_parts.append(value)
                    
                    # Extract subject
                    subject_parts = []
                    for rdn in cert.get('subject', []):
                        for key, value in rdn:
                            if key == 'commonName':
                                subject_parts.append(value)
                    
                    # Extract SAN domains
                    san_domains = []
                    for san_type, san_value in cert.get('subjectAltName', []):
                        if san_type == 'DNS':
                            san_domains.append(san_value)
                    
                    # Calculate expiry
                    not_after = cert.get('notAfter')
                    expiry_days = None
                    if not_after:
                        try:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            expiry_days = (expiry_date - datetime.utcnow()).days
                        except:
                            pass
                    
                    return {
                        "issuer": " ".join(issuer_parts),
                        "subject": " ".join(subject_parts),
                        "san_domains": san_domains,
                        "valid_from": cert.get('notBefore'),
                        "valid_until": cert.get('notAfter'),
                        "expiry_days": expiry_days,
                        "serial": cert.get('serialNumber'),
                        "version": cert.get('version')
                    }
        except ssl.SSLCertVerificationError as e:
            return {"error": "Certificate verification failed", "details": str(e)}
        except socket.timeout:
            return None
        except Exception as e:
            return None
    
    async def _analyze_content(self, url: str, logs: List) -> Dict[str, Any]:
        """Async content and tech stack analysis."""
        logs.append(self._log("CONTENT", "Fetching page content...", "info"))
        
        result = {
            "score": 0,
            "threats": [],
            "tech_stack": {"detected": "Unknown", "confidence": 0},
            "forms": {"count": 0, "login_forms": 0, "suspicious": False},
            "urgency_score": 0,
            "financial_score": 0
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, ssl=False) as response:
                    html = await response.text()
                    server = response.headers.get('Server', 'Unknown')
                    x_powered = response.headers.get('X-Powered-By', '')
                    
                    logs.append(self._log("CONTENT", f"Response: {response.status} | Server: {server}", "info"))
                    
            soup = BeautifulSoup(html, 'html.parser')
            text = soup.get_text().lower()
            
            # Tech stack detection
            tech_stack = self._detect_tech_stack(soup, server, x_powered)
            result["tech_stack"] = tech_stack
            logs.append(self._log("TECH", f"Detected: {tech_stack['detected']} (confidence: {tech_stack['confidence']}%)", "info"))
            
            # Urgency pattern analysis
            urgency_count = sum(1 for pattern in self.compiled_urgency if pattern.search(text))
            result["urgency_score"] = min(urgency_count * 8, 100)
            
            if urgency_count > 0:
                logs.append(self._log("CONTENT", f"⚠ {urgency_count} urgency/FOMO patterns detected", "warning"))
                if urgency_count >= 5:
                    result["threats"].append(f"High urgency manipulation ({urgency_count} patterns)")
                    result["score"] += 30
                elif urgency_count >= 2:
                    result["threats"].append(f"Urgency tactics detected ({urgency_count} patterns)")
                    result["score"] += 15
            
            # Financial keyword analysis
            financial_count = sum(1 for pattern in self.compiled_financial if pattern.search(text))
            result["financial_score"] = min(financial_count * 10, 100)
            
            if financial_count > 0:
                logs.append(self._log("CONTENT", f"⚠ {financial_count} financial/crypto keywords found", "warning"))
                if financial_count >= 5:
                    result["threats"].append(f"Heavy financial focus ({financial_count} keywords)")
                    result["score"] += 25
                elif financial_count >= 2:
                    result["threats"].append(f"Financial content detected ({financial_count} keywords)")
                    result["score"] += 10
            
            # Form analysis
            forms = soup.find_all('form')
            password_fields = soup.find_all('input', {'type': 'password'})
            result["forms"]["count"] = len(forms)
            result["forms"]["login_forms"] = len(password_fields)
            
            if password_fields:
                # Check if login form on suspicious page
                parsed = urlparse(url)
                is_http = parsed.scheme == 'http'
                is_suspicious_tld = any(parsed.netloc.endswith(tld) for tld in self.SUSPICIOUS_TLDS)
                
                if is_http:
                    logs.append(self._log("CONTENT", "⚠ LOGIN FORM ON UNENCRYPTED PAGE", "critical"))
                    result["threats"].append("Password field on HTTP (no encryption)")
                    result["score"] += 40
                    result["forms"]["suspicious"] = True
                elif is_suspicious_tld:
                    logs.append(self._log("CONTENT", "⚠ Login form on suspicious TLD", "warning"))
                    result["threats"].append(f"Login form on suspicious domain")
                    result["score"] += 20
                    result["forms"]["suspicious"] = True
                else:
                    logs.append(self._log("CONTENT", f"Login form detected ({len(password_fields)} password fields)", "info"))
            
            # Check for obfuscated/minified content (potential phishing kit)
            if len(html) > 1000 and text.strip() == "":
                logs.append(self._log("CONTENT", "⚠ Page content appears obfuscated", "warning"))
                result["threats"].append("Obfuscated or dynamically loaded content")
                result["score"] += 15
                
        except aiohttp.ClientError as e:
            logs.append(self._log("CONTENT", f"Connection failed: {str(e)}", "error"))
            result["score"] = 40
            result["threats"].append(f"Unable to fetch content: {str(e)}")
        except Exception as e:
            logs.append(self._log("CONTENT", f"Analysis error: {str(e)}", "error"))
            result["score"] = 30
            
        return result
    
    def _detect_tech_stack(self, soup: BeautifulSoup, server: str, x_powered: str) -> Dict:
        """Detect CMS and technology stack."""
        result = {"detected": "Custom/Unknown", "confidence": 0, "details": []}
        
        # Check header-based detection
        server_lower = server.lower()
        if 'nginx' in server_lower:
            result["details"].append("Nginx")
        elif 'apache' in server_lower:
            result["details"].append("Apache")
        elif 'cloudflare' in server_lower:
            result["details"].append("Cloudflare")
            
        if x_powered:
            result["details"].append(f"Powered by: {x_powered}")
        
        # Check CMS signatures
        for cms, signatures in self.CMS_SIGNATURES.items():
            for tag, attrs in signatures:
                elements = soup.find_all(tag)
                for el in elements:
                    for attr_name, attr_pattern in attrs.items():
                        attr_value = el.get(attr_name, '')
                        if isinstance(attr_pattern, re.Pattern):
                            if attr_pattern.search(str(attr_value)):
                                result["detected"] = cms
                                result["confidence"] = 95
                                return result
                        elif attr_pattern in str(attr_value):
                            result["detected"] = cms
                            result["confidence"] = 90
                            return result
        
        # Check for common frameworks
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '').lower()
            if 'react' in src or 'reactdom' in src:
                result["details"].append("React")
            elif 'vue' in src or 'vuejs' in src:
                result["details"].append("Vue.js")
            elif 'angular' in src:
                result["details"].append("Angular")
            elif 'jquery' in src:
                result["details"].append("jQuery")
        
        # If no CMS detected but has obfuscated JS, flag as potential phishing kit
        if result["detected"] == "Custom/Unknown":
            all_scripts = soup.find_all('script')
            obfuscated_count = sum(1 for s in all_scripts if s.string and len(s.string) > 1000 and s.string.count('\\x') > 10)
            if obfuscated_count > 0:
                result["detected"] = "Potential Phishing Kit"
                result["confidence"] = 60
                result["details"].append("Heavily obfuscated JavaScript detected")
            else:
                result["confidence"] = 30
                
        return result
    
    async def _analyze_domain(self, domain: str, logs: List) -> Dict[str, Any]:
        """Domain intelligence analysis via WHOIS."""
        logs.append(self._log("DOMAIN", "Querying domain intelligence...", "info"))
        
        result = {
            "score": 0,
            "threats": [],
            "age_days": None,
            "registrar": None,
            "creation_date": None,
            "privacy_protected": False
        }
        
        # Check TLD
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                logs.append(self._log("DOMAIN", f"⚠ Suspicious TLD: {tld}", "warning"))
                result["threats"].append(f"High-risk TLD: {tld}")
                result["score"] += 25
                break
        
        if not WHOIS_AVAILABLE:
            logs.append(self._log("DOMAIN", "WHOIS not available (install python-whois)", "warning"))
            return result
        
        try:
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(
                self.executor,
                lambda: whois.whois(domain)
            )
            
            # Extract creation date
            creation_date = whois_data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                    age_days = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days
                else:
                    age_days = (datetime.now() - creation_date).days
                    
                result["age_days"] = age_days
                result["creation_date"] = str(creation_date)
                
                if age_days < 7:
                    logs.append(self._log("DOMAIN", f"⚠ DOMAIN CREATED {age_days} DAYS AGO - EXTREMELY SUSPICIOUS", "critical"))
                    result["threats"].append(f"Brand new domain ({age_days} days old)")
                    result["score"] += 50
                elif age_days < 30:
                    logs.append(self._log("DOMAIN", f"⚠ Domain only {age_days} days old", "warning"))
                    result["threats"].append(f"Very new domain ({age_days} days)")
                    result["score"] += 35
                elif age_days < 90:
                    logs.append(self._log("DOMAIN", f"Domain {age_days} days old", "info"))
                    result["score"] += 15
                elif age_days < 365:
                    logs.append(self._log("DOMAIN", f"Domain {age_days} days old", "info"))
                    result["score"] += 5
                else:
                    years = age_days // 365
                    logs.append(self._log("DOMAIN", f"Established domain ({years}+ years)", "success"))
            else:
                logs.append(self._log("DOMAIN", "Could not determine domain age", "warning"))
                result["score"] += 20
            
            # Check registrar
            registrar = whois_data.registrar
            if registrar:
                result["registrar"] = registrar
                # Some registrars are commonly used for spam domains
                suspicious_registrars = ['namecheap', 'namesilo', 'porkbun']
                if any(sr in registrar.lower() for sr in suspicious_registrars):
                    logs.append(self._log("DOMAIN", f"Registrar: {registrar} (commonly used for disposable domains)", "info"))
            
            # Check for privacy protection
            if whois_data.org and 'privacy' in str(whois_data.org).lower():
                result["privacy_protected"] = True
                logs.append(self._log("DOMAIN", "WHOIS privacy protection enabled", "info"))
                
        except Exception as e:
            logs.append(self._log("DOMAIN", f"WHOIS lookup failed: {str(e)}", "error"))
            result["score"] += 15
            
        return result
    
    def _generate_risk_summary(self, score: int, verdict: str, threats: List[str],
                                ssl: Dict, content: Dict, domain: Dict) -> str:
        """Generate human-readable risk summary."""
        if verdict == "SAFE":
            return (f"This URL appears to be legitimate with a risk score of {score}/100. "
                   "No significant threats were detected during analysis.")
        
        summary_parts = [f"This URL has a risk score of {score}/100 and is classified as {verdict}."]
        
        if threats:
            summary_parts.append(f"\n\n⚠ KEY THREATS IDENTIFIED:\n")
            for i, threat in enumerate(threats[:5], 1):
                summary_parts.append(f"  {i}. {threat}")
        
        if verdict == "MALICIOUS":
            summary_parts.append("\n\n🚫 RECOMMENDATION: DO NOT VISIT THIS SITE. "
                               "It exhibits multiple characteristics of phishing, scam, or malware distribution.")
        elif verdict == "SUSPICIOUS":
            summary_parts.append("\n\n⚠ RECOMMENDATION: Exercise extreme caution. "
                               "Verify the legitimacy of this site through official channels before interacting.")
        
        return "\n".join(summary_parts)
    
    def _generate_recommendations(self, verdict: str, threats: List[str],
                                   ssl: Dict, content: Dict, domain: Dict) -> List[str]:
        """Generate actionable security recommendations."""
        recs = []
        
        if verdict == "MALICIOUS":
            recs.append("🚫 DO NOT enter any personal information on this site")
            recs.append("🚫 DO NOT download any files from this site")
            recs.append("🚫 DO NOT click any links or buttons")
            recs.append("✓ Report this URL to Google Safe Browsing")
            recs.append("✓ If you've already interacted, monitor accounts for fraud")
        elif verdict == "SUSPICIOUS":
            recs.append("⚠ Verify site legitimacy through official channels")
            recs.append("⚠ Do not enter sensitive information without verification")
            recs.append("⚠ Check URL carefully for typosquatting")
            recs.append("✓ Use a password manager to avoid phishing")
        else:
            recs.append("✓ Site appears legitimate")
            recs.append("✓ Always verify URLs before entering credentials")
            recs.append("✓ Keep browser and security software updated")
        
        if ssl.get("issuer_trust") == "SELF-SIGNED":
            recs.append("⚠ Self-signed certificate - connection may not be secure")
        
        if content.get("forms", {}).get("suspicious"):
            recs.append("⚠ Suspicious login form detected - verify site before entering credentials")
            
        return recs
    
    def _generate_dorks(self, domain: str) -> Dict[str, str]:
        """Generate Google Dork links for additional intelligence."""
        base_domain = domain.replace("www.", "")
        return {
            "site_search": f"https://www.google.com/search?q=site:{base_domain}",
            "reputation": f"https://www.google.com/search?q=\"{base_domain}\"+scam+OR+fraud+OR+fake",
            "whois_lookup": f"https://who.is/whois/{base_domain}",
            "virustotal": f"https://www.virustotal.com/gui/domain/{base_domain}",
            "urlscan": f"https://urlscan.io/search/#domain:{base_domain}",
            "wayback": f"https://web.archive.org/web/*/{base_domain}",
            "shodan": f"https://www.shodan.io/search?query=hostname:{base_domain}",
            "abuse_report": f"https://safebrowsing.google.com/safebrowsing/report_phish/?url=https://{base_domain}"
        }
    
    def _log(self, module: str, message: str, level: str) -> Dict:
        """Create a structured log entry."""
        return {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "module": module,
            "message": message,
            "level": level
        }
    
    def _error_result(self, url: str, error: str, start_time: datetime) -> Dict:
        """Generate error result."""
        return {
            "target": url,
            "domain": "",
            "score": 100,
            "verdict": "ERROR",
            "risk_summary": f"Analysis failed: {error}",
            "logs": [self._log("ERROR", error, "critical")],
            "tech_stack": {},
            "ssl_forensics": {},
            "content_analysis": {},
            "domain_intel": {},
            "threat_indicators": [error],
            "recommendations": ["Unable to analyze URL"],
            "google_dorks": {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analysis_duration_ms": int((datetime.now() - start_time).total_seconds() * 1000)
        }


# Singleton instance
_analyzer = None

def get_analyzer() -> ForensicURLAnalyzer:
    """Get or create the analyzer singleton."""
    global _analyzer
    if _analyzer is None:
        _analyzer = ForensicURLAnalyzer()
    return _analyzer


async def analyze_url_async(url: str) -> Dict[str, Any]:
    """Async convenience function for URL analysis."""
    analyzer = get_analyzer()
    return await analyzer.analyze(url)


def analyze_url(url: str) -> Dict[str, Any]:
    """Synchronous wrapper for URL analysis."""
    return asyncio.run(analyze_url_async(url))
