"""
url_analyzer.py
NetSentinel v5.0 - Cognitive Truth Engine

Philosophy: "The Truth is in the Context, not the Ports."

This engine analyzes webpages for deception through:
1. Semantic Mismatch Detection - Brand impersonation via content analysis
2. Psychological Analysis - Fear/Greed/Urgency manipulation detection  
3. Domain Consistency - Temporal anomalies and registrant verification

Architecture: Pure AsyncIO + aiohttp for high-speed concurrent analysis.
"""

from __future__ import annotations

import asyncio
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import (
    Dict, Any, List, Optional, Set, Tuple, AsyncIterator, TypedDict
)
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup, Comment

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# Type definitions
class SemanticAnalysis(TypedDict):
    extracted_title: str
    h1_tags: List[str]
    copyright_texts: List[str]
    claimed_brands: List[str]
    domain: str
    registrant: Optional[str]
    impersonation_check: str


class PsychologicalAnalysis(TypedDict):
    manipulative_index: float
    triggers: Dict[str, int]
    body_word_count: int
    verdict: str


class DomainConsistency(TypedDict):
    creation_date: Optional[str]
    copyright_years: List[int]
    anomaly: Optional[str]
    age_days: Optional[int]


class AnalysisResult(TypedDict):
    url: str
    truth_score: float
    verdict: str
    semantic_analysis: SemanticAnalysis
    psychological_analysis: PsychologicalAnalysis
    domain_consistency: DomainConsistency
    evidence_log: List[str]
    timestamp: str
    analysis_duration_ms: int


@dataclass
class NetSentinelAnalyzer:
    """
    Cognitive Truth Engine for webpage deception detection.
    
    Analyzes content semantics, psychological manipulation patterns,
    and domain consistency to detect lies and impersonation.
    """
    
    # Known brands for impersonation detection (extensible)
    known_brands: Set[str] = field(default_factory=lambda: {
        'Apple', 'PayPal', 'Binance', 'Microsoft', 'Amazon', 'Google',
        'Facebook', 'Meta', 'Netflix', 'Spotify', 'Bank of America',
        'Chase', 'Wells Fargo', 'Coinbase', 'Kraken', 'OpenAI', 'ChatGPT',
        'Instagram', 'WhatsApp', 'Twitter', 'LinkedIn', 'Adobe', 'Dropbox',
        'Uber', 'DHL', 'FedEx', 'UPS', 'USPS', 'IRS', 'Social Security',
        'Steam', 'Epic Games', 'Blizzard', 'Sony', 'PlayStation', 'Nintendo',
        'Walmart', 'Target', 'eBay', 'Etsy', 'Shopify', 'Stripe'
    })
    
    # Psychological manipulation patterns with weights
    fear_patterns: List[str] = field(default_factory=lambda: [
        r'\bsuspended\b', r'\bhacked\b', r'\bblocked\b', r'\burgent\s*threat\b',
        r'\baccount\s*(will\s+be\s+)?(closed|terminated|deleted)\b',
        r'\bunauthorized\s*(access|activity)\b', r'\bsecurity\s*alert\b',
        r'\bimmediately\b', r'\bwarning\b', r'\bviolation\b', r'\blocked\s*out\b',
        r'\bcompromised\b', r'\bfraudulent\b', r'\billegal\s*activity\b',
        r'\bverify\s*(your\s*)?(identity|account)\b', r'\brestricted\b'
    ])
    
    greed_patterns: List[str] = field(default_factory=lambda: [
        r'\bbonus\b', r'\bfree\s*money\b', r'\bdouble\s*your\s*(deposit|investment)\b',
        r'\bexclusive\s*offer\b', r'\bwinner\b', r'\bcongratulations\b',
        r'\bprize\b', r'\bjackpot\b', r'\blottery\b', r'\binheritance\b',
        r'\bmillion(s)?\s*(dollar|usd|euro)\b', r'\brisk[- ]?free\b',
        r'\bguaranteed\s*(profit|return)\b', r'\bget\s*rich\b', r'\beasy\s*money\b',
        r'\b100%\s*(bonus|return|profit)\b', r'\bno\s*deposit\b', r'\bfree\s*gift\b'
    ])
    
    urgency_patterns: List[str] = field(default_factory=lambda: [
        r'\b24\s*h(our)?s?\s*left\b', r'\blimited\s*time\b', r'\bact\s*now\b',
        r'\bexpires?\s*(soon|today|in\s*\d+)\b', r'\blast\s*chance\b',
        r'\bhurry\b', r'\bdon\'?t\s*miss\b', r'\bonly\s*\d+\s*(left|remaining)\b',
        r'\btoday\s*only\b', r'\bonce\s*in\s*a\s*lifetime\b', r'\bnow\s*or\s*never\b',
        r'\binstant\s*(access|approval)\b', r'\bact\s*fast\b', r'\bimmediately\b',
        r'\bwithin\s*\d+\s*(hour|minute|day)\b', r'\bdeadline\b', r'\bfinal\s*notice\b'
    ])
    
    # Weights for manipulation scoring
    fear_weight: float = 1.5
    greed_weight: float = 1.2
    urgency_weight: float = 1.3
    
    # Networking config
    max_concurrent: int = 10
    timeout_seconds: int = 10
    max_retries: int = 3
    
    def __post_init__(self) -> None:
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._compiled_fear = [re.compile(p, re.I) for p in self.fear_patterns]
        self._compiled_greed = [re.compile(p, re.I) for p in self.greed_patterns]
        self._compiled_urgency = [re.compile(p, re.I) for p in self.urgency_patterns]
        self._brand_pattern = re.compile(
            r'\b(' + '|'.join(re.escape(b) for b in self.known_brands) + r')\b',
            re.I
        )
        self._copyright_pattern = re.compile(
            r'(?:copyright|©|\(c\))\s*(?:©\s*)?(\d{4})(?:\s*[-–]\s*(\d{4}))?',
            re.I
        )
        self._year_pattern = re.compile(r'\b(19|20)\d{2}\b')
    
    async def analyze_urls(
        self, 
        urls: List[str]
    ) -> AsyncIterator[AnalysisResult]:
        """
        Analyze multiple URLs concurrently.
        
        Args:
            urls: List of URLs to analyze (1-100)
            
        Yields:
            AnalysisResult for each URL
        """
        if len(urls) > 100:
            urls = urls[:100]
            
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def analyze_with_semaphore(url: str) -> AnalysisResult:
            async with semaphore:
                return await self.analyze_url(url)
        
        tasks = [analyze_with_semaphore(url) for url in urls]
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result
    
    async def analyze_url(self, url: str) -> AnalysisResult:
        """
        Perform comprehensive cognitive analysis on a single URL.
        
        Returns structured forensic evidence with truth scoring.
        """
        start_time = datetime.now()
        evidence_log: List[str] = []
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        if not domain:
            return self._error_result(url, "Invalid URL format", start_time)
        
        evidence_log.append(f">> INITIATING COGNITIVE SCAN: {domain}")
        
        # Fetch HTML content with retries
        html_content, fetch_status = await self._fetch_with_retry(url, evidence_log)
        
        if html_content is None:
            return self._error_result(
                url, f"Failed to fetch content: {fetch_status}", 
                start_time, evidence_log
            )
        
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Remove script and style elements for text analysis
        for element in soup(['script', 'style', 'noscript']):
            element.decompose()
        
        # Remove HTML comments
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            comment.extract()
        
        # 1. Semantic Analysis (Brand Impersonation Detection)
        semantic_result = await self._analyze_semantics(
            soup, domain, evidence_log
        )
        
        # 2. Psychological Analysis (Manipulation Detection)
        psychological_result = self._analyze_psychology(soup, evidence_log)
        
        # 3. Domain Consistency (Temporal Anomalies)
        domain_result = await self._analyze_domain_consistency(
            domain, soup, evidence_log
        )
        
        # Calculate Truth Score
        truth_score = self._calculate_truth_score(
            semantic_result, psychological_result, domain_result
        )
        
        # Determine verdict
        if truth_score >= 75:
            verdict = "TRUTHFUL"
        elif truth_score >= 50:
            verdict = "SUSPICIOUS"
        elif truth_score >= 25:
            verdict = "DECEPTIVE"
        else:
            verdict = "MALICIOUS_LIE"
        
        evidence_log.append(f">> VERDICT: {verdict} (Truth Score: {truth_score:.1f}/100)")
        
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return AnalysisResult(
            url=url,
            truth_score=round(truth_score, 1),
            verdict=verdict,
            semantic_analysis=semantic_result,
            psychological_analysis=psychological_result,
            domain_consistency=domain_result,
            evidence_log=evidence_log,
            timestamp=datetime.now(timezone.utc).isoformat(),
            analysis_duration_ms=duration_ms
        )
    
    async def _fetch_with_retry(
        self, 
        url: str, 
        evidence_log: List[str]
    ) -> Tuple[Optional[str], str]:
        """Fetch URL content with retries and timeout."""
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url, headers=headers, ssl=False, 
                                          allow_redirects=True) as response:
                        
                        content_type = response.headers.get('Content-Type', '')
                        
                        if 'text/html' not in content_type and 'text/plain' not in content_type:
                            evidence_log.append(f">> SKIP: Non-HTML content ({content_type})")
                            return None, f"Non-HTML content: {content_type}"
                        
                        html = await response.text()
                        evidence_log.append(f">> FETCH: HTTP {response.status} ({len(html)} bytes)")
                        return html, "OK"
                        
            except asyncio.TimeoutError:
                evidence_log.append(f">> RETRY {attempt + 1}/{self.max_retries}: Timeout")
            except aiohttp.ClientError as e:
                evidence_log.append(f">> RETRY {attempt + 1}/{self.max_retries}: {type(e).__name__}")
            except Exception as e:
                evidence_log.append(f">> ERROR: {type(e).__name__}: {str(e)}")
                return None, str(e)
            
            if attempt < self.max_retries - 1:
                await asyncio.sleep(1)
        
        return None, "Max retries exceeded"
    
    async def _analyze_semantics(
        self, 
        soup: BeautifulSoup, 
        domain: str,
        evidence_log: List[str]
    ) -> SemanticAnalysis:
        """Detect brand impersonation through semantic analysis."""
        
        # Extract title
        title_tag = soup.find('title')
        title = title_tag.get_text(strip=True) if title_tag else ""
        evidence_log.append(f">> PARSE TITLE: '{title[:60]}...' " if len(title) > 60 else f">> PARSE TITLE: '{title}'")
        
        # Extract H1 tags
        h1_tags = [h1.get_text(strip=True) for h1 in soup.find_all('h1')]
        if h1_tags:
            evidence_log.append(f">> FOUND {len(h1_tags)} H1 TAGS: {h1_tags[:3]}")
        
        # Extract copyright notices
        full_text = soup.get_text()
        copyright_matches = self._copyright_pattern.findall(full_text)
        copyright_texts = [f"© {m[0]}" + (f"-{m[1]}" if m[1] else "") for m in copyright_matches]
        
        # Find claimed brands in content
        all_text = title + " " + " ".join(h1_tags) + " " + full_text[:5000]
        brand_matches = self._brand_pattern.findall(all_text)
        claimed_brands = list(set(b.title() for b in brand_matches))
        
        if claimed_brands:
            evidence_log.append(f">> BRAND DETECTION: {claimed_brands}")
        
        # Get WHOIS registrant info
        registrant = None
        impersonation_check = "No impersonation detected"
        
        if claimed_brands and WHOIS_AVAILABLE:
            loop = asyncio.get_event_loop()
            try:
                whois_data = await loop.run_in_executor(
                    self.executor, self._get_whois_registrant, domain
                )
                registrant = whois_data.get('registrant')
                
                evidence_log.append(f">> WHOIS REGISTRANT: '{registrant or 'REDACTED/UNKNOWN'}'")
                
                # Check for impersonation
                for brand in claimed_brands:
                    if not self._is_legitimate_brand_domain(brand, domain, registrant):
                        impersonation_check = (
                            f"⚠️ IDENTITY MISMATCH: Claims '{brand}' but domain "
                            f"'{domain}' owned by '{registrant or 'Unknown'}', not {brand} Inc."
                        )
                        evidence_log.append(f">> 🚨 LIE DETECTED: {impersonation_check}")
                        break
                        
            except Exception as e:
                evidence_log.append(f">> WHOIS ERROR: {str(e)}")
        
        return SemanticAnalysis(
            extracted_title=title,
            h1_tags=h1_tags[:5],
            copyright_texts=copyright_texts[:3],
            claimed_brands=claimed_brands,
            domain=domain,
            registrant=registrant,
            impersonation_check=impersonation_check
        )
    
    def _get_whois_registrant(self, domain: str) -> Dict[str, Any]:
        """Blocking WHOIS lookup (runs in executor)."""
        try:
            # Handle punycode for international domains
            if any(ord(c) > 127 for c in domain):
                domain = domain.encode('idna').decode('ascii')
            
            w = whois.whois(domain)
            
            registrant = None
            if w.org:
                registrant = w.org if isinstance(w.org, str) else w.org[0]
            elif w.name:
                registrant = w.name if isinstance(w.name, str) else w.name[0]
            elif w.registrant_name:
                registrant = w.registrant_name
                
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            return {
                'registrant': registrant,
                'creation_date': creation_date,
                'registrar': w.registrar
            }
        except Exception:
            return {'registrant': None, 'creation_date': None, 'registrar': None}
    
    def _is_legitimate_brand_domain(
        self, 
        brand: str, 
        domain: str, 
        registrant: Optional[str]
    ) -> bool:
        """Check if domain legitimately represents the brand."""
        brand_lower = brand.lower()
        domain_lower = domain.lower()
        
        # Check if brand is in domain (legitimate patterns)
        if brand_lower in domain_lower:
            # But watch for typosquatting like "paypa1" vs "paypal"
            # Simple check: brand should match exactly, not with letter substitutions
            patterns = [
                brand_lower,
                brand_lower.replace(' ', ''),
                brand_lower.replace(' ', '-'),
            ]
            if any(p in domain_lower for p in patterns):
                return True
        
        # Check registrant matches brand
        if registrant:
            registrant_lower = registrant.lower()
            similarity = SequenceMatcher(None, brand_lower, registrant_lower).ratio()
            if similarity > 0.6:
                return True
            if brand_lower in registrant_lower:
                return True
        
        # Levenshtein distance for typosquatting detection
        domain_base = domain_lower.split('.')[0].replace('www', '').replace('-', '')
        if self._levenshtein_distance(brand_lower.replace(' ', ''), domain_base) <= 2:
            # Close match could be typosquatting
            return False
        
        return False
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Simple Levenshtein distance implementation."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _analyze_psychology(
        self, 
        soup: BeautifulSoup,
        evidence_log: List[str]
    ) -> PsychologicalAnalysis:
        """Analyze psychological manipulation patterns."""
        body = soup.find('body')
        if not body:
            return PsychologicalAnalysis(
                manipulative_index=0,
                triggers={'fear': 0, 'greed': 0, 'urgency': 0},
                body_word_count=0,
                verdict="Unable to analyze (no body)"
            )
        
        text = body.get_text(separator=' ', strip=True).lower()
        words = text.split()
        word_count = len(words)
        
        if word_count == 0:
            return PsychologicalAnalysis(
                manipulative_index=0,
                triggers={'fear': 0, 'greed': 0, 'urgency': 0},
                body_word_count=0,
                verdict="Empty page content"
            )
        
        # Count pattern matches
        fear_count = sum(1 for p in self._compiled_fear if p.search(text))
        greed_count = sum(1 for p in self._compiled_greed if p.search(text))
        urgency_count = sum(1 for p in self._compiled_urgency if p.search(text))
        
        # Calculate weighted manipulation index
        raw_score = (
            (fear_count * self.fear_weight) +
            (greed_count * self.greed_weight) +
            (urgency_count * self.urgency_weight)
        )
        
        # Normalize by word count, scale to 0-100
        manipulative_index = min(100, (raw_score / max(word_count, 100)) * 500)
        
        # Log significant findings
        if fear_count > 0:
            evidence_log.append(f">> FEAR TRIGGERS: {fear_count} patterns detected")
        if greed_count > 0:
            evidence_log.append(f">> GREED TRIGGERS: {greed_count} patterns detected")
        if urgency_count > 0:
            evidence_log.append(f">> URGENCY TRIGGERS: {urgency_count} patterns detected")
        
        # Determine verdict
        if manipulative_index >= 70:
            verdict = "HIGH MANIPULATION - Likely scam"
        elif manipulative_index >= 40:
            verdict = "MODERATE MANIPULATION - Exercise caution"
        elif manipulative_index >= 15:
            verdict = "MILD MANIPULATION - Normal marketing"
        else:
            verdict = "LOW MANIPULATION - Appears genuine"
        
        evidence_log.append(f">> MANIPULATION INDEX: {manipulative_index:.1f}/100 ({verdict})")
        
        return PsychologicalAnalysis(
            manipulative_index=round(manipulative_index, 1),
            triggers={'fear': fear_count, 'greed': greed_count, 'urgency': urgency_count},
            body_word_count=word_count,
            verdict=verdict
        )
    
    async def _analyze_domain_consistency(
        self, 
        domain: str,
        soup: BeautifulSoup,
        evidence_log: List[str]
    ) -> DomainConsistency:
        """Check for temporal anomalies between domain age and copyright claims."""
        result = DomainConsistency(
            creation_date=None,
            copyright_years=[],
            anomaly=None,
            age_days=None
        )
        
        # Extract copyright years from page
        full_text = soup.get_text()
        year_matches = self._year_pattern.findall(full_text)
        copyright_years = [int(f"{match[0]}{match[1] if isinstance(match, tuple) else match}") 
                         for match in year_matches if isinstance(match, str) or len(match) == 2]
        
        # Get unique years, filter to valid range
        current_year = datetime.now().year
        valid_years = sorted(set(y for y in copyright_years if 1990 <= y <= current_year + 1))
        result['copyright_years'] = valid_years[:5]
        
        # Get domain creation date via WHOIS
        if WHOIS_AVAILABLE:
            loop = asyncio.get_event_loop()
            try:
                await asyncio.sleep(1)  # Rate limiting
                whois_data = await loop.run_in_executor(
                    self.executor, self._get_whois_registrant, domain
                )
                creation_date = whois_data.get('creation_date')
                
                if creation_date:
                    result['creation_date'] = str(creation_date.date()) if hasattr(creation_date, 'date') else str(creation_date)
                    
                    if hasattr(creation_date, 'year'):
                        creation_year = creation_date.year
                        age_days = (datetime.now() - creation_date.replace(tzinfo=None)).days
                        result['age_days'] = age_days
                        
                        evidence_log.append(f">> DOMAIN AGE: {age_days} days (created {creation_year})")
                        
                        # Check for temporal anomalies
                        if valid_years:
                            min_copyright = min(valid_years)
                            if min_copyright < creation_year - 1:
                                anomaly = (
                                    f"⚠️ TEMPORAL ANOMALY: Copyright claims {min_copyright} "
                                    f"but domain created in {creation_year} "
                                    f"({creation_year - min_copyright} year discrepancy)"
                                )
                                result['anomaly'] = anomaly
                                evidence_log.append(f">> 🚨 {anomaly}")
                            elif min_copyright > current_year + 1:
                                anomaly = f"⚠️ TEMPORAL ANOMALY: Future copyright year {min_copyright}"
                                result['anomaly'] = anomaly
                                evidence_log.append(f">> 🚨 {anomaly}")
                                
            except Exception as e:
                evidence_log.append(f">> DOMAIN WHOIS ERROR: {str(e)}")
        
        return result
    
    def _calculate_truth_score(
        self,
        semantic: SemanticAnalysis,
        psychological: PsychologicalAnalysis,
        domain: DomainConsistency
    ) -> float:
        """
        Calculate overall truth score (0-100).
        
        Higher = more truthful, Lower = more deceptive.
        """
        score = 100.0
        
        # Deductions for impersonation
        if "IDENTITY MISMATCH" in semantic['impersonation_check']:
            score -= 40
        elif "⚠️" in semantic['impersonation_check']:
            score -= 25
        
        # Deductions for manipulation
        manip_index = psychological['manipulative_index']
        if manip_index >= 70:
            score -= 35
        elif manip_index >= 40:
            score -= 20
        elif manip_index >= 15:
            score -= 10
        
        # Deductions for temporal anomalies
        if domain['anomaly']:
            score -= 15
        
        # Deductions for very new domains (<30 days)
        if domain['age_days'] is not None:
            if domain['age_days'] < 7:
                score -= 20
            elif domain['age_days'] < 30:
                score -= 10
        
        return max(0, min(100, score))
    
    def _error_result(
        self, 
        url: str, 
        error: str, 
        start_time: datetime,
        evidence_log: Optional[List[str]] = None
    ) -> AnalysisResult:
        """Generate error result for failed analysis."""
        if evidence_log is None:
            evidence_log = []
        
        evidence_log.append(f">> ERROR: {error}")
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return AnalysisResult(
            url=url,
            truth_score=0,
            verdict="ERROR",
            semantic_analysis=SemanticAnalysis(
                extracted_title="",
                h1_tags=[],
                copyright_texts=[],
                claimed_brands=[],
                domain=urlparse(url).netloc or url,
                registrant=None,
                impersonation_check=f"Error: {error}"
            ),
            psychological_analysis=PsychologicalAnalysis(
                manipulative_index=0,
                triggers={'fear': 0, 'greed': 0, 'urgency': 0},
                body_word_count=0,
                verdict="Unable to analyze"
            ),
            domain_consistency=DomainConsistency(
                creation_date=None,
                copyright_years=[],
                anomaly=None,
                age_days=None
            ),
            evidence_log=evidence_log,
            timestamp=datetime.now(timezone.utc).isoformat(),
            analysis_duration_ms=duration_ms
        )


# Singleton analyzer instance
_analyzer: Optional[NetSentinelAnalyzer] = None


def get_analyzer() -> NetSentinelAnalyzer:
    """Get or create the singleton analyzer."""
    global _analyzer
    if _analyzer is None:
        _analyzer = NetSentinelAnalyzer()
    return _analyzer


async def analyze_url_async(url: str) -> AnalysisResult:
    """Convenience function for single URL analysis."""
    analyzer = get_analyzer()
    return await analyzer.analyze_url(url)


async def analyze_batch_async(urls: List[str]) -> List[AnalysisResult]:
    """Analyze multiple URLs concurrently."""
    analyzer = get_analyzer()
    results = []
    async for result in analyzer.analyze_urls(urls):
        results.append(result)
    return results


def analyze_url(url: str) -> AnalysisResult:
    """Synchronous wrapper for URL analysis."""
    return asyncio.run(analyze_url_async(url))


async def main() -> None:
    """Demo with sample URLs."""
    test_urls = [
        "https://www.google.com",
        "https://www.paypal.com",
        "https://example.com",
    ]
    
    print("=" * 60)
    print("NetSentinel v5.0 - Cognitive Truth Engine")
    print("Philosophy: The Truth is in the Context, not the Ports.")
    print("=" * 60)
    
    analyzer = NetSentinelAnalyzer()
    
    async for result in analyzer.analyze_urls(test_urls):
        print(f"\n{'─' * 50}")
        print(f"URL: {result['url']}")
        print(f"Truth Score: {result['truth_score']}/100")
        print(f"Verdict: {result['verdict']}")
        print(f"Duration: {result['analysis_duration_ms']}ms")
        print(f"\nEvidence Log:")
        for log in result['evidence_log']:
            print(f"  {log}")


if __name__ == '__main__':
    asyncio.run(main())
