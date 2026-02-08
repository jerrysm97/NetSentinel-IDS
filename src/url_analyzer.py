"""
url_analyzer.py
NetSentinel v6.0 - THE OMNISCIENT EDITION

Ultimate URL Intelligence Platform combining:
- MODULE A: Deep Network Recon (IP, Geo, ISP, ASN, Port Scan, Cloud Detection)
- MODULE B: Temporal Forensics (Wayback Machine integration)
- MODULE C: Content Classification (Phishing + Piracy/Warez Detection)
- MODULE D: Cognitive Truth Engine (Brand Impersonation)

Architecture: AsyncIO + Aiohttp (Non-blocking, Massively Concurrent)
"""

from __future__ import annotations

import asyncio
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import (
    Dict, Any, List, Optional, Set, Tuple, AsyncIterator, TypedDict
)
from urllib.parse import urlparse, urljoin

import aiohttp
from bs4 import BeautifulSoup, Comment

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# TYPE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkIntel(TypedDict):
    ip_address: Optional[str]
    geolocation: Dict[str, str]
    isp: Optional[str]
    asn: Optional[str]
    org: Optional[str]
    open_ports: List[int]
    cloud_provider: Optional[str]
    is_bulletproof_host: bool
    reverse_dns: Optional[str]


class TemporalAnalysis(TypedDict):
    wayback_first_seen: Optional[str]
    wayback_last_seen: Optional[str]
    wayback_snapshot_count: int
    wayback_snapshots: List[str]
    domain_age_days: Optional[int]
    domain_created: Optional[str]
    temporal_anomaly: Optional[str]
    history_fabrication: bool


class ContentClassification(TypedDict):
    category: str
    phishing_score: int
    piracy_score: int
    malware_score: int
    ad_fraud_score: int
    piracy_indicators: List[str]
    phishing_indicators: List[str]
    suspicious_scripts: List[str]
    shady_ad_networks: List[str]


class CognitiveAnalysis(TypedDict):
    extracted_title: str
    h1_tags: List[str]
    claimed_brands: List[str]
    domain: str
    registrant: Optional[str]
    impersonation_check: str
    identity_mismatch: bool


class PsychologicalAnalysis(TypedDict):
    manipulative_index: float
    triggers: Dict[str, int]
    body_word_count: int
    verdict: str


class OmniscientResult(TypedDict):
    url: str
    domain: str
    risk_score: int
    category: str
    verdict: str
    threat_badges: List[str]
    network_intel: NetworkIntel
    temporal_analysis: TemporalAnalysis
    content_classification: ContentClassification
    cognitive_analysis: CognitiveAnalysis
    psychological_analysis: PsychologicalAnalysis
    evidence_log: List[str]
    timestamp: str
    analysis_duration_ms: int


# ═══════════════════════════════════════════════════════════════════════════════
# OMNISCIENT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class OmniscientAnalyzer:
    """
    NetSentinel v6.0 - The Omniscient Edition
    
    Ultimate URL intelligence platform combining network recon,
    temporal forensics, content classification, and cognitive analysis.
    """
    
    # Known brands for impersonation detection
    known_brands: Set[str] = field(default_factory=lambda: {
        'Apple', 'PayPal', 'Binance', 'Microsoft', 'Amazon', 'Google',
        'Facebook', 'Meta', 'Netflix', 'Spotify', 'Disney', 'HBO',
        'Prime Video', 'Hulu', 'YouTube', 'Chase', 'Bank of America',
        'Wells Fargo', 'Coinbase', 'OpenAI', 'Instagram', 'WhatsApp',
        'Twitter', 'LinkedIn', 'Adobe', 'Steam', 'Epic Games', 'Sony'
    })
    
    # Bulletproof hosting providers
    bulletproof_hosts: Set[str] = field(default_factory=lambda: {
        'njalla', 'shinjiru', 'hostinger', '1984', 'bahnhof', 'flokinet',
        'privatelayer', 'cyberbunker', 'ecatel', 'santrex', 'mccolo',
        'bulletproof', 'offshore', 'anonymous'
    })
    
    # Cloud providers (legitimate)
    cloud_providers: Dict[str, List[str]] = field(default_factory=lambda: {
        'AWS': ['amazon', 'aws', 'ec2', 'cloudfront', 'amazonaws'],
        'Google Cloud': ['google', 'gcp', 'googlecloud', '1e100'],
        'Azure': ['azure', 'microsoft', 'windowsazure', 'msedge'],
        'Cloudflare': ['cloudflare', 'cf-'],
        'DigitalOcean': ['digitalocean'],
        'Linode': ['linode', 'akamai'],
        'Vultr': ['vultr'],
        'OVH': ['ovh', 'kimsufi'],
        'Hetzner': ['hetzner']
    })
    
    # Piracy/Warez detection patterns
    piracy_keywords: List[str] = field(default_factory=lambda: [
        r'\b1080p\b', r'\b720p\b', r'\b4k\b', r'\b2160p\b', r'\bhdtv\b',
        r'\bcamrip\b', r'\bdvdrip\b', r'\bbrrip\b', r'\bbluray\b', r'\bwebrip\b',
        r'\bhdcam\b', r'\byify\b', r'\byts\b', r'\brarbg\b', r'\btorrent\b',
        r'\bmagnet\b', r'\bstream\s*free\b', r'\bwatch\s*free\b', r'\bfree\s*download\b',
        r'\bcracked?\b', r'\bkeygen\b', r'\bserial\s*key\b', r'\bactivator\b',
        r'\bpatch(ed)?\b', r'\bfull\s*version\b', r'\bunlocked\b', r'\bmod\s*apk\b',
        r'\b(movie|film)s?\s*(download|watch)\b', r'\bsubtitles?\b', r'\bsrt\b',
        r'\bepisodes?\s*\d+\b', r'\bseason\s*\d+\b', r'\bs\d+e\d+\b',
        r'\bpirate(d|bay)?\b', r'\bwarez\b', r'\bnulledd?\b', r'\bleaked?\b'
    ])
    
    # Magnet link pattern
    magnet_pattern: str = r'magnet:\?xt=urn:[a-z0-9]+:[a-zA-Z0-9]+'
    
    # Shady ad networks (common on piracy sites)
    shady_ad_networks: Set[str] = field(default_factory=lambda: {
        'popads', 'popcash', 'propellerads', 'adsterra', 'exoclick',
        'trafficjunky', 'juicyads', 'adskeeper', 'mgid', 'revcontent',
        'taboola', 'outbrain', 'adcash', 'clickadu', 'hilltopads',
        'evadav', 'pushhouse', 'richpush', 'megapush', 'pushengage',
        'push.house', 'pushground', 'daocloud', 'admaven', 'adspyglass'
    })
    
    # Psychological manipulation patterns
    fear_patterns: List[str] = field(default_factory=lambda: [
        r'\bsuspended\b', r'\bhacked\b', r'\bblocked\b', r'\burgent\b',
        r'\baccount\s*(closed|terminated|deleted)\b', r'\bunauthorized\b',
        r'\bsecurity\s*alert\b', r'\bwarning\b', r'\bviolation\b',
        r'\bcompromised\b', r'\bfraudulent\b', r'\billegal\b'
    ])
    
    greed_patterns: List[str] = field(default_factory=lambda: [
        r'\bfree\s*money\b', r'\bdouble\s*your\b', r'\bwinner\b',
        r'\bcongratulations\b', r'\bprize\b', r'\bjackpot\b', r'\blottery\b',
        r'\bguaranteed\s*(profit|return)\b', r'\beasy\s*money\b', r'\b100%\s*bonus\b'
    ])
    
    urgency_patterns: List[str] = field(default_factory=lambda: [
        r'\b24\s*h(our)?s?\s*left\b', r'\blimited\s*time\b', r'\bact\s*now\b',
        r'\bexpires?\s*(soon|today)\b', r'\blast\s*chance\b', r'\bhurry\b',
        r'\bimmediately\b', r'\btoday\s*only\b', r'\bfinal\s*notice\b'
    ])
    
    # Ports to scan
    scan_ports: List[int] = field(default_factory=lambda: [21, 22, 53, 80, 443, 8080, 3389])
    
    # Networking config
    max_concurrent: int = 10
    timeout_seconds: int = 10
    max_retries: int = 3
    
    def __post_init__(self) -> None:
        self.executor = ThreadPoolExecutor(max_workers=6)
        self._compiled_piracy = [re.compile(p, re.I) for p in self.piracy_keywords]
        self._compiled_fear = [re.compile(p, re.I) for p in self.fear_patterns]
        self._compiled_greed = [re.compile(p, re.I) for p in self.greed_patterns]
        self._compiled_urgency = [re.compile(p, re.I) for p in self.urgency_patterns]
        self._magnet_regex = re.compile(self.magnet_pattern, re.I)
        self._brand_pattern = re.compile(
            r'\b(' + '|'.join(re.escape(b) for b in self.known_brands) + r')\b', re.I
        )
    
    async def analyze_urls(self, urls: List[str]) -> AsyncIterator[OmniscientResult]:
        """Analyze multiple URLs concurrently."""
        if len(urls) > 100:
            urls = urls[:100]
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def analyze_with_semaphore(url: str) -> OmniscientResult:
            async with semaphore:
                return await self.analyze_url(url)
        
        tasks = [analyze_with_semaphore(url) for url in urls]
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result
    
    async def analyze_url(self, url: str) -> OmniscientResult:
        """Perform omniscient analysis on a single URL."""
        start_time = datetime.now()
        evidence_log: List[str] = []
        threat_badges: List[str] = []
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        if not domain:
            return self._error_result(url, "Invalid URL format", start_time)
        
        evidence_log.append(f">> OMNISCIENT SCAN INITIATED: {domain}")
        evidence_log.append(f">> Target URL: {url}")
        
        # Run all analysis modules concurrently
        network_task = asyncio.create_task(self._module_a_network_recon(domain, evidence_log))
        temporal_task = asyncio.create_task(self._module_b_temporal_forensics(domain, evidence_log))
        
        # Fetch content first for other modules
        html_content, fetch_status = await self._fetch_with_retry(url, evidence_log)
        
        if html_content is None:
            # Continue with partial analysis
            evidence_log.append(f">> CONTENT FETCH FAILED: {fetch_status}")
            soup = None
        else:
            soup = BeautifulSoup(html_content, 'html.parser')
            for element in soup(['script', 'style', 'noscript']):
                element.decompose()
        
        # Wait for async tasks
        network_result = await network_task
        temporal_result = await temporal_task
        
        # Run content-dependent modules
        if soup:
            content_result = await self._module_c_content_classification(
                soup, html_content, url, evidence_log
            )
            cognitive_result = await self._module_d_cognitive_engine(
                soup, domain, evidence_log
            )
            psychological_result = self._analyze_psychology(soup, evidence_log)
        else:
            content_result = self._empty_content_classification()
            cognitive_result = self._empty_cognitive_analysis(domain)
            psychological_result = self._empty_psychological_analysis()
        
        # Determine threat badges
        if content_result['piracy_score'] >= 50:
            threat_badges.append("WAREZ")
            evidence_log.append(">> 🏴‍☠️ THREAT BADGE: [WAREZ] Piracy/Copyright Infringement Detected")
        if content_result['phishing_score'] >= 50:
            threat_badges.append("PHISHING")
            evidence_log.append(">> 🎣 THREAT BADGE: [PHISHING] Credential Harvesting Detected")
        if content_result['malware_score'] >= 50:
            threat_badges.append("MALWARE")
            evidence_log.append(">> 🦠 THREAT BADGE: [MALWARE] Suspicious Payload Detected")
        if content_result['ad_fraud_score'] >= 50:
            threat_badges.append("AD-FRAUD")
            evidence_log.append(">> 💰 THREAT BADGE: [AD-FRAUD] Shady Advertising Detected")
        if cognitive_result['identity_mismatch']:
            threat_badges.append("IMPERSONATION")
            evidence_log.append(">> 🎭 THREAT BADGE: [IMPERSONATION] Brand Spoofing Detected")
        if temporal_result['history_fabrication']:
            threat_badges.append("HISTORY-FAKE")
            evidence_log.append(">> 📅 THREAT BADGE: [HISTORY-FAKE] Temporal Anomaly Detected")
        if network_result['is_bulletproof_host']:
            threat_badges.append("BULLETPROOF")
            evidence_log.append(">> 🛡️ THREAT BADGE: [BULLETPROOF] Abuse-Resistant Hosting")
        
        # Calculate composite risk score
        risk_score = self._calculate_risk_score(
            network_result, temporal_result, content_result,
            cognitive_result, psychological_result
        )
        
        # Determine primary category
        category = self._determine_category(content_result, cognitive_result, threat_badges)
        
        # Final verdict
        if risk_score >= 80:
            verdict = "MALICIOUS"
        elif risk_score >= 60:
            verdict = "HIGH_RISK"
        elif risk_score >= 40:
            verdict = "SUSPICIOUS"
        elif risk_score >= 20:
            verdict = "LOW_RISK"
        else:
            verdict = "SAFE"
        
        evidence_log.append(f">> {'='*50}")
        evidence_log.append(f">> VERDICT: {verdict} | Risk Score: {risk_score}/100")
        evidence_log.append(f">> Category: {category}")
        evidence_log.append(f">> Threat Badges: {threat_badges or ['NONE']}")
        
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return OmniscientResult(
            url=url,
            domain=domain,
            risk_score=risk_score,
            category=category,
            verdict=verdict,
            threat_badges=threat_badges,
            network_intel=network_result,
            temporal_analysis=temporal_result,
            content_classification=content_result,
            cognitive_analysis=cognitive_result,
            psychological_analysis=psychological_result,
            evidence_log=evidence_log,
            timestamp=datetime.now(timezone.utc).isoformat(),
            analysis_duration_ms=duration_ms
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE A: DEEP NETWORK RECON
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _module_a_network_recon(
        self, 
        domain: str, 
        evidence_log: List[str]
    ) -> NetworkIntel:
        """Deep network reconnaissance: IP, Geo, ISP, ASN, Ports, Cloud Detection."""
        evidence_log.append(">> [MODULE A] NETWORK RECON: Initiating...")
        
        result: NetworkIntel = {
            'ip_address': None,
            'geolocation': {},
            'isp': None,
            'asn': None,
            'org': None,
            'open_ports': [],
            'cloud_provider': None,
            'is_bulletproof_host': False,
            'reverse_dns': None
        }
        
        # Resolve IP
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(self.executor, socket.gethostbyname, domain)
            result['ip_address'] = ip
            evidence_log.append(f">> [NETWORK] IP Resolved: {ip}")
        except socket.gaierror:
            evidence_log.append(f">> [NETWORK] DNS Resolution Failed")
            return result
        
        # Get IP info from free API (ip-api.com)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,city,isp,org,as,hosting',
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('status') == 'success':
                            result['geolocation'] = {
                                'country': data.get('country', ''),
                                'country_code': data.get('countryCode', ''),
                                'region': data.get('region', ''),
                                'city': data.get('city', '')
                            }
                            result['isp'] = data.get('isp')
                            result['org'] = data.get('org')
                            result['asn'] = data.get('as')
                            
                            evidence_log.append(f">> [NETWORK] Location: {data.get('city')}, {data.get('country')}")
                            evidence_log.append(f">> [NETWORK] ISP: {data.get('isp')}")
                            evidence_log.append(f">> [NETWORK] ASN: {data.get('as')}")
                            
                            # Check for bulletproof hosting
                            org_lower = (data.get('org', '') + data.get('isp', '')).lower()
                            if any(bp in org_lower for bp in self.bulletproof_hosts):
                                result['is_bulletproof_host'] = True
                                evidence_log.append(">> [NETWORK] ⚠️ BULLETPROOF HOSTING DETECTED")
                            
                            # Check for cloud provider
                            for provider, keywords in self.cloud_providers.items():
                                if any(kw in org_lower for kw in keywords):
                                    result['cloud_provider'] = provider
                                    evidence_log.append(f">> [NETWORK] Cloud Provider: {provider}")
                                    break
        except Exception as e:
            evidence_log.append(f">> [NETWORK] IP-API Error: {str(e)}")
        
        # Async port scan
        open_ports = await self._async_port_scan(ip, evidence_log)
        result['open_ports'] = open_ports
        
        # Reverse DNS
        try:
            loop = asyncio.get_event_loop()
            rdns = await loop.run_in_executor(
                self.executor,
                lambda: socket.gethostbyaddr(ip)[0]
            )
            result['reverse_dns'] = rdns
            evidence_log.append(f">> [NETWORK] Reverse DNS: {rdns}")
        except:
            pass
        
        return result
    
    async def _async_port_scan(
        self, 
        ip: str, 
        evidence_log: List[str]
    ) -> List[int]:
        """Async port scan for common ports."""
        evidence_log.append(f">> [PORTSCAN] Scanning ports: {self.scan_ports}")
        open_ports = []
        
        async def check_port(port: int) -> Optional[int]:
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=2)
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        tasks = [check_port(port) for port in self.scan_ports]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result is not None:
                open_ports.append(result)
        
        if open_ports:
            evidence_log.append(f">> [PORTSCAN] Open ports: {open_ports}")
        else:
            evidence_log.append(">> [PORTSCAN] No common ports open (filtered/stealth)")
        
        return open_ports
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE B: TEMPORAL FORENSICS
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _module_b_temporal_forensics(
        self, 
        domain: str, 
        evidence_log: List[str]
    ) -> TemporalAnalysis:
        """Query Wayback Machine and detect temporal anomalies."""
        evidence_log.append(">> [MODULE B] TEMPORAL FORENSICS: Querying Time Machine...")
        
        result: TemporalAnalysis = {
            'wayback_first_seen': None,
            'wayback_last_seen': None,
            'wayback_snapshot_count': 0,
            'wayback_snapshots': [],
            'domain_age_days': None,
            'domain_created': None,
            'temporal_anomaly': None,
            'history_fabrication': False
        }
        
        # Get domain WHOIS info
        if WHOIS_AVAILABLE:
            try:
                loop = asyncio.get_event_loop()
                whois_data = await loop.run_in_executor(
                    self.executor, self._get_whois_info, domain
                )
                if whois_data.get('creation_date'):
                    result['domain_created'] = whois_data['creation_date']
                    result['domain_age_days'] = whois_data.get('age_days')
                    evidence_log.append(f">> [TEMPORAL] Domain Created: {whois_data['creation_date']}")
                    evidence_log.append(f">> [TEMPORAL] Domain Age: {whois_data.get('age_days')} days")
            except Exception as e:
                evidence_log.append(f">> [TEMPORAL] WHOIS Error: {str(e)}")
        
        # Query Wayback Machine CDX API
        try:
            async with aiohttp.ClientSession() as session:
                cdx_url = (
                    f'https://web.archive.org/cdx/search/cdx?url={domain}'
                    f'&output=json&limit=100&fl=timestamp,statuscode'
                )
                async with session.get(cdx_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        if len(data) > 1:  # First row is header
                            snapshots = data[1:]  # Skip header
                            result['wayback_snapshot_count'] = len(snapshots)
                            
                            # Get first and last seen
                            if snapshots:
                                first_ts = snapshots[0][0]
                                last_ts = snapshots[-1][0]
                                
                                result['wayback_first_seen'] = self._parse_wayback_timestamp(first_ts)
                                result['wayback_last_seen'] = self._parse_wayback_timestamp(last_ts)
                                
                                # Sample some snapshots for timeline
                                step = max(1, len(snapshots) // 10)
                                result['wayback_snapshots'] = [
                                    self._parse_wayback_timestamp(s[0]) 
                                    for s in snapshots[::step]
                                ][:10]
                                
                                evidence_log.append(f">> [WAYBACK] First Seen: {result['wayback_first_seen']}")
                                evidence_log.append(f">> [WAYBACK] Last Seen: {result['wayback_last_seen']}")
                                evidence_log.append(f">> [WAYBACK] Snapshots: {len(snapshots)}")
                                
                                # Check for temporal anomalies
                                if result['domain_age_days'] is not None:
                                    domain_age_years = result['domain_age_days'] / 365
                                    first_seen_year = int(first_ts[:4])
                                    current_year = datetime.now().year
                                    
                                    # If domain is "old" but Wayback has recent first snapshot
                                    if domain_age_years > 5 and first_seen_year > current_year - 1:
                                        result['temporal_anomaly'] = (
                                            f"DROP-CATCH DOMAIN: Claims {domain_age_years:.0f} years old "
                                            f"but Wayback first saw it in {first_seen_year}"
                                        )
                                        result['history_fabrication'] = True
                                        evidence_log.append(f">> [WAYBACK] ⚠️ TEMPORAL ANOMALY: {result['temporal_anomaly']}")
                        else:
                            evidence_log.append(">> [WAYBACK] No archive history found (never archived)")
                            
                            # New domain with no history is suspicious
                            if result['domain_age_days'] and result['domain_age_days'] < 30:
                                result['temporal_anomaly'] = "GHOST DOMAIN: New domain with zero web presence"
                                evidence_log.append(f">> [WAYBACK] ⚠️ {result['temporal_anomaly']}")
                                
        except Exception as e:
            evidence_log.append(f">> [WAYBACK] API Error: {str(e)}")
        
        return result
    
    def _parse_wayback_timestamp(self, ts: str) -> str:
        """Parse Wayback Machine timestamp to readable date."""
        try:
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        except:
            return ts
    
    def _get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Blocking WHOIS lookup."""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age_days = None
            creation_str = None
            if creation_date:
                if hasattr(creation_date, 'date'):
                    creation_str = str(creation_date.date())
                    age_days = (datetime.now() - creation_date.replace(tzinfo=None)).days
                else:
                    creation_str = str(creation_date)
            
            registrant = None
            if w.org:
                registrant = w.org if isinstance(w.org, str) else w.org[0]
            
            return {
                'creation_date': creation_str,
                'age_days': age_days,
                'registrant': registrant
            }
        except:
            return {}
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE C: CONTENT CLASSIFICATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _module_c_content_classification(
        self, 
        soup: BeautifulSoup,
        html_raw: str,
        url: str,
        evidence_log: List[str]
    ) -> ContentClassification:
        """Classify content: Phishing, Piracy, Malware, Ad-Fraud."""
        evidence_log.append(">> [MODULE C] CONTENT CLASSIFICATION: Analyzing...")
        
        result: ContentClassification = {
            'category': 'UNKNOWN',
            'phishing_score': 0,
            'piracy_score': 0,
            'malware_score': 0,
            'ad_fraud_score': 0,
            'piracy_indicators': [],
            'phishing_indicators': [],
            'suspicious_scripts': [],
            'shady_ad_networks': []
        }
        
        body = soup.find('body')
        text = body.get_text(separator=' ', strip=True).lower() if body else ""
        
        # ─── PIRACY DETECTION ───
        piracy_count = 0
        for pattern in self._compiled_piracy:
            matches = pattern.findall(text)
            if matches:
                piracy_count += len(matches)
                indicator = matches[0] if isinstance(matches[0], str) else matches[0][0]
                if indicator not in result['piracy_indicators']:
                    result['piracy_indicators'].append(indicator)
        
        # Check for magnet links
        magnet_matches = self._magnet_regex.findall(html_raw)
        if magnet_matches:
            piracy_count += len(magnet_matches) * 5  # Heavy weight
            result['piracy_indicators'].append(f"magnet links ({len(magnet_matches)})")
            evidence_log.append(f">> [PIRACY] ⚠️ {len(magnet_matches)} MAGNET LINKS DETECTED")
        
        # Check for streaming/download buttons
        download_btns = soup.find_all(['a', 'button'], string=re.compile(r'download|stream|watch|play', re.I))
        if len(download_btns) > 5:
            piracy_count += len(download_btns)
            result['piracy_indicators'].append(f"download buttons ({len(download_btns)})")
        
        result['piracy_score'] = min(100, piracy_count * 5)
        
        if result['piracy_indicators']:
            evidence_log.append(f">> [PIRACY] Indicators: {result['piracy_indicators'][:5]}")
            evidence_log.append(f">> [PIRACY] Score: {result['piracy_score']}/100")
        
        # ─── PHISHING DETECTION ───
        phishing_count = 0
        
        # Login forms
        login_forms = soup.find_all('form')
        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            phishing_count += len(password_fields) * 10
            result['phishing_indicators'].append(f"password fields ({len(password_fields)})")
        
        # Brand mentions without ownership
        parsed = urlparse(url)
        for brand in self.known_brands:
            if brand.lower() in text and brand.lower() not in parsed.netloc.lower():
                phishing_count += 15
                result['phishing_indicators'].append(f"brand mention: {brand}")
                break
        
        result['phishing_score'] = min(100, phishing_count)
        
        if result['phishing_indicators']:
            evidence_log.append(f">> [PHISHING] Indicators: {result['phishing_indicators'][:5]}")
        
        # ─── AD-FRAUD / SHADY NETWORKS ───
        scripts = soup.find_all('script', src=True)
        iframes = soup.find_all('iframe')
        
        for script in scripts:
            src = script.get('src', '').lower()
            for ad_net in self.shady_ad_networks:
                if ad_net in src:
                    result['shady_ad_networks'].append(ad_net)
                    result['ad_fraud_score'] += 15
        
        # Excessive iframes (popup/popunder indicator)
        if len(iframes) > 10:
            result['ad_fraud_score'] += 20
            evidence_log.append(f">> [AD-FRAUD] ⚠️ Excessive iframes: {len(iframes)}")
        
        # Onclick handlers (popunders)
        onclick_elements = soup.find_all(attrs={'onclick': True})
        if len(onclick_elements) > 20:
            result['ad_fraud_score'] += 15
            evidence_log.append(f">> [AD-FRAUD] ⚠️ Excessive onclick handlers: {len(onclick_elements)}")
        
        result['ad_fraud_score'] = min(100, result['ad_fraud_score'])
        
        if result['shady_ad_networks']:
            evidence_log.append(f">> [AD-FRAUD] Shady Networks: {result['shady_ad_networks']}")
        
        # ─── MALWARE INDICATORS ───
        suspicious_patterns = [
            r'eval\s*\(', r'document\.write\s*\(', r'unescape\s*\(',
            r'fromCharCode', r'\\x[0-9a-f]{2}', r'atob\s*\('
        ]
        
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                for pattern in suspicious_patterns:
                    if re.search(pattern, script.string, re.I):
                        result['suspicious_scripts'].append(pattern)
                        result['malware_score'] += 10
        
        result['malware_score'] = min(100, result['malware_score'])
        
        # ─── DETERMINE PRIMARY CATEGORY ───
        scores = {
            'PIRACY': result['piracy_score'],
            'PHISHING': result['phishing_score'],
            'MALWARE': result['malware_score'],
            'AD-FRAUD': result['ad_fraud_score']
        }
        
        max_score = max(scores.values())
        if max_score >= 30:
            result['category'] = max(scores, key=scores.get)
        else:
            result['category'] = 'LEGITIMATE'
        
        evidence_log.append(f">> [CONTENT] Category: {result['category']}")
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE D: COGNITIVE TRUTH ENGINE
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _module_d_cognitive_engine(
        self, 
        soup: BeautifulSoup, 
        domain: str,
        evidence_log: List[str]
    ) -> CognitiveAnalysis:
        """Compare page claims vs domain reality."""
        evidence_log.append(">> [MODULE D] COGNITIVE ENGINE: Truth Analysis...")
        
        result: CognitiveAnalysis = {
            'extracted_title': '',
            'h1_tags': [],
            'claimed_brands': [],
            'domain': domain,
            'registrant': None,
            'impersonation_check': 'No impersonation detected',
            'identity_mismatch': False
        }
        
        # Extract title
        title_tag = soup.find('title')
        result['extracted_title'] = title_tag.get_text(strip=True) if title_tag else ""
        
        # Extract H1 tags
        result['h1_tags'] = [h1.get_text(strip=True) for h1 in soup.find_all('h1')][:5]
        
        # Find claimed brands
        all_text = result['extracted_title'] + " " + " ".join(result['h1_tags'])
        brand_matches = self._brand_pattern.findall(all_text)
        result['claimed_brands'] = list(set(b.title() for b in brand_matches))
        
        if result['claimed_brands']:
            evidence_log.append(f">> [COGNITIVE] Claimed Brands: {result['claimed_brands']}")
            
            # Check for identity mismatch
            domain_lower = domain.lower()
            for brand in result['claimed_brands']:
                if brand.lower() not in domain_lower:
                    # This is a potential impersonation
                    result['impersonation_check'] = (
                        f"⚠️ IDENTITY MISMATCH: Page claims '{brand}' "
                        f"but domain is '{domain}'"
                    )
                    result['identity_mismatch'] = True
                    evidence_log.append(f">> [COGNITIVE] 🚨 LIE DETECTED: {result['impersonation_check']}")
                    break
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PSYCHOLOGICAL ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _analyze_psychology(
        self, 
        soup: BeautifulSoup,
        evidence_log: List[str]
    ) -> PsychologicalAnalysis:
        """Analyze psychological manipulation patterns."""
        body = soup.find('body')
        if not body:
            return self._empty_psychological_analysis()
        
        text = body.get_text(separator=' ', strip=True).lower()
        words = text.split()
        word_count = len(words)
        
        if word_count == 0:
            return self._empty_psychological_analysis()
        
        fear_count = sum(1 for p in self._compiled_fear if p.search(text))
        greed_count = sum(1 for p in self._compiled_greed if p.search(text))
        urgency_count = sum(1 for p in self._compiled_urgency if p.search(text))
        
        raw_score = (fear_count * 1.5) + (greed_count * 1.2) + (urgency_count * 1.3)
        manipulative_index = min(100, (raw_score / max(word_count, 100)) * 500)
        
        if manipulative_index >= 70:
            verdict = "HIGH MANIPULATION"
        elif manipulative_index >= 40:
            verdict = "MODERATE MANIPULATION"
        elif manipulative_index >= 15:
            verdict = "MILD MANIPULATION"
        else:
            verdict = "LOW MANIPULATION"
        
        if manipulative_index > 20:
            evidence_log.append(f">> [PSYCH] Manipulation Index: {manipulative_index:.1f}/100 ({verdict})")
        
        return PsychologicalAnalysis(
            manipulative_index=round(manipulative_index, 1),
            triggers={'fear': fear_count, 'greed': greed_count, 'urgency': urgency_count},
            body_word_count=word_count,
            verdict=verdict
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # HELPER METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def _fetch_with_retry(
        self, 
        url: str, 
        evidence_log: List[str]
    ) -> Tuple[Optional[str], str]:
        """Fetch URL with retries."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers=headers, ssl=False, 
                                          allow_redirects=True) as response:
                        html = await response.text()
                        evidence_log.append(f">> [FETCH] HTTP {response.status} ({len(html)} bytes)")
                        return html, "OK"
            except Exception as e:
                evidence_log.append(f">> [FETCH] Attempt {attempt + 1} failed: {type(e).__name__}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1)
        
        return None, "Max retries exceeded"
    
    def _calculate_risk_score(
        self,
        network: NetworkIntel,
        temporal: TemporalAnalysis,
        content: ContentClassification,
        cognitive: CognitiveAnalysis,
        psychological: PsychologicalAnalysis
    ) -> int:
        """Calculate composite risk score."""
        score = 0
        
        # Content-based scoring (highest weight)
        score += content['piracy_score'] * 0.3
        score += content['phishing_score'] * 0.3
        score += content['malware_score'] * 0.2
        score += content['ad_fraud_score'] * 0.15
        
        # Cognitive
        if cognitive['identity_mismatch']:
            score += 25
        
        # Temporal
        if temporal['history_fabrication']:
            score += 20
        if temporal['domain_age_days'] is not None and temporal['domain_age_days'] < 30:
            score += 15
        
        # Network
        if network['is_bulletproof_host']:
            score += 15
        
        # Psychological
        if psychological['manipulative_index'] >= 50:
            score += 10
        
        return min(100, int(score))
    
    def _determine_category(
        self,
        content: ContentClassification,
        cognitive: CognitiveAnalysis,
        badges: List[str]
    ) -> str:
        """Determine primary threat category."""
        if 'WAREZ' in badges:
            return 'PIRACY/WAREZ'
        if 'PHISHING' in badges:
            return 'PHISHING'
        if 'MALWARE' in badges:
            return 'MALWARE'
        if 'IMPERSONATION' in badges:
            return 'IMPERSONATION'
        if 'AD-FRAUD' in badges:
            return 'AD-FRAUD'
        return 'LEGITIMATE'
    
    def _empty_content_classification(self) -> ContentClassification:
        return ContentClassification(
            category='UNKNOWN',
            phishing_score=0,
            piracy_score=0,
            malware_score=0,
            ad_fraud_score=0,
            piracy_indicators=[],
            phishing_indicators=[],
            suspicious_scripts=[],
            shady_ad_networks=[]
        )
    
    def _empty_cognitive_analysis(self, domain: str) -> CognitiveAnalysis:
        return CognitiveAnalysis(
            extracted_title='',
            h1_tags=[],
            claimed_brands=[],
            domain=domain,
            registrant=None,
            impersonation_check='Unable to analyze',
            identity_mismatch=False
        )
    
    def _empty_psychological_analysis(self) -> PsychologicalAnalysis:
        return PsychologicalAnalysis(
            manipulative_index=0,
            triggers={'fear': 0, 'greed': 0, 'urgency': 0},
            body_word_count=0,
            verdict='Unable to analyze'
        )
    
    def _error_result(
        self, 
        url: str, 
        error: str, 
        start_time: datetime
    ) -> OmniscientResult:
        """Generate error result."""
        domain = urlparse(url).netloc or url
        return OmniscientResult(
            url=url,
            domain=domain,
            risk_score=0,
            category='ERROR',
            verdict='ERROR',
            threat_badges=[],
            network_intel=NetworkIntel(
                ip_address=None, geolocation={}, isp=None, asn=None, org=None,
                open_ports=[], cloud_provider=None, is_bulletproof_host=False, reverse_dns=None
            ),
            temporal_analysis=TemporalAnalysis(
                wayback_first_seen=None, wayback_last_seen=None, wayback_snapshot_count=0,
                wayback_snapshots=[], domain_age_days=None, domain_created=None,
                temporal_anomaly=None, history_fabrication=False
            ),
            content_classification=self._empty_content_classification(),
            cognitive_analysis=self._empty_cognitive_analysis(domain),
            psychological_analysis=self._empty_psychological_analysis(),
            evidence_log=[f">> ERROR: {error}"],
            timestamp=datetime.now(timezone.utc).isoformat(),
            analysis_duration_ms=int((datetime.now() - start_time).total_seconds() * 1000)
        )


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

_analyzer: Optional[OmniscientAnalyzer] = None

def get_analyzer() -> OmniscientAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = OmniscientAnalyzer()
    return _analyzer

async def analyze_url_async(url: str) -> OmniscientResult:
    return await get_analyzer().analyze_url(url)

def analyze_url(url: str) -> OmniscientResult:
    return asyncio.run(analyze_url_async(url))


async def main() -> None:
    """Demo with test URLs."""
    print("=" * 60)
    print("NetSentinel v6.0 - THE OMNISCIENT EDITION")
    print("=" * 60)
    
    analyzer = OmniscientAnalyzer()
    result = await analyzer.analyze_url("https://example.com")
    
    print(f"\nTarget: {result['url']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Category: {result['category']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Threat Badges: {result['threat_badges']}")
    print(f"\nEvidence Log:")
    for log in result['evidence_log']:
        print(f"  {log}")


if __name__ == '__main__':
    asyncio.run(main())
