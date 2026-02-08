"""
url_analyzer.py
Scam Sentinel - URL Risk Analysis Engine

Analyzes URLs for scam indicators using multiple signals:
- Domain age (WHOIS)
- SSL certificate analysis
- Content analysis (urgency keywords, fake trust badges)
- DNS configuration
"""

import ssl
import socket
import re
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# Try to import whois
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# Try to import dns
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class URLAnalyzer:
    """
    Comprehensive URL risk analyzer for scam detection.
    Uses multiple signals to calculate risk score.
    """
    
    def __init__(self):
        # Urgency keywords that scammers use
        self.urgency_keywords = [
            "act now", "limited time", "expires", "hurry", "don't miss",
            "last chance", "urgent", "immediately", "only today",
            "exclusive offer", "winner", "congratulations", "claim your",
            "free gift", "risk-free", "guaranteed", "no obligation"
        ]
        
        # Suspicious patterns in URLs
        self.suspicious_patterns = [
            r'\d{5,}',  # Long number sequences
            r'login.*\.',  # login in subdomain
            r'secure.*\.',  # fake secure subdomain
            r'account.*\.',  # fake account subdomain
            r'-{2,}',  # Multiple hyphens
            r'\.tk$|\.ml$|\.ga$|\.cf$|\.gq$',  # Free TLDs often used for scams
        ]
        
        # Known legitimate domains for comparison
        self.safe_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'github.com', 'twitter.com', 'linkedin.com'
        }
        
    def analyze(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with risk score and detailed analysis
        """
        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "signals": [],
            "domain_info": {},
            "ssl_info": {},
            "content_info": {},
            "dns_info": {},
            "recommendations": []
        }
        
        try:
            # Parse URL
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
            
            if not domain:
                result["error"] = "Invalid URL format"
                result["risk_score"] = 100
                result["risk_level"] = "CRITICAL"
                return result
            
            result["domain"] = domain
            
            # Run all analyzers
            scores = []
            
            # 1. Domain Age Analysis (weight: 30%)
            domain_score = self._analyze_domain_age(domain, result)
            scores.append(("domain_age", domain_score, 0.30))
            
            # 2. SSL Certificate Analysis (weight: 20%)
            ssl_score = self._analyze_ssl(domain, result)
            scores.append(("ssl", ssl_score, 0.20))
            
            # 3. URL Pattern Analysis (weight: 15%)
            pattern_score = self._analyze_url_patterns(url, domain, result)
            scores.append(("url_patterns", pattern_score, 0.15))
            
            # 4. Content Analysis (weight: 25%)
            content_score = self._analyze_content(url, result)
            scores.append(("content", content_score, 0.25))
            
            # 5. DNS Analysis (weight: 10%)
            dns_score = self._analyze_dns(domain, result)
            scores.append(("dns", dns_score, 0.10))
            
            # Calculate weighted risk score
            total_weight = 0
            weighted_score = 0
            for name, score, weight in scores:
                if score is not None:
                    weighted_score += score * weight
                    total_weight += weight
            
            if total_weight > 0:
                result["risk_score"] = round(weighted_score / total_weight)
            
            # Set risk level
            if result["risk_score"] >= 80:
                result["risk_level"] = "CRITICAL"
                result["recommendations"].append("DO NOT proceed - High probability of scam")
            elif result["risk_score"] >= 60:
                result["risk_level"] = "HIGH"
                result["recommendations"].append("Exercise extreme caution")
            elif result["risk_score"] >= 40:
                result["risk_level"] = "MEDIUM"
                result["recommendations"].append("Verify legitimacy before proceeding")
            elif result["risk_score"] >= 20:
                result["risk_level"] = "LOW"
                result["recommendations"].append("Appears relatively safe")
            else:
                result["risk_level"] = "SAFE"
                result["recommendations"].append("No significant risks detected")
                
        except Exception as e:
            result["error"] = str(e)
            result["risk_score"] = 50
            result["risk_level"] = "UNKNOWN"
            
        return result
    
    def _analyze_domain_age(self, domain: str, result: Dict) -> Optional[int]:
        """Analyze domain registration age using WHOIS."""
        if not WHOIS_AVAILABLE:
            result["signals"].append({
                "type": "domain_age",
                "status": "SKIPPED",
                "reason": "WHOIS library not available"
            })
            return None
            
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                result["domain_info"]["creation_date"] = creation_date.isoformat()
                result["domain_info"]["age_days"] = age_days
                result["domain_info"]["registrar"] = w.registrar
                
                # Score based on age
                if age_days < 30:
                    score = 100
                    result["signals"].append({
                        "type": "domain_age",
                        "status": "CRITICAL",
                        "message": f"Domain only {age_days} days old - Very suspicious!"
                    })
                elif age_days < 90:
                    score = 75
                    result["signals"].append({
                        "type": "domain_age",
                        "status": "WARNING",
                        "message": f"Domain {age_days} days old - Relatively new"
                    })
                elif age_days < 365:
                    score = 40
                    result["signals"].append({
                        "type": "domain_age",
                        "status": "INFO",
                        "message": f"Domain {age_days} days old"
                    })
                else:
                    score = 10
                    years = age_days // 365
                    result["signals"].append({
                        "type": "domain_age",
                        "status": "OK",
                        "message": f"Established domain ({years} years old)"
                    })
                return score
            else:
                result["signals"].append({
                    "type": "domain_age",
                    "status": "WARNING",
                    "message": "Could not determine domain age"
                })
                return 50
                
        except Exception as e:
            result["signals"].append({
                "type": "domain_age",
                "status": "ERROR",
                "message": str(e)
            })
            return None
    
    def _analyze_ssl(self, domain: str, result: Dict) -> Optional[int]:
        """Analyze SSL certificate."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate info
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    result["ssl_info"]["issuer"] = issuer.get('organizationName', 'Unknown')
                    result["ssl_info"]["subject"] = subject.get('commonName', domain)
                    result["ssl_info"]["valid_from"] = cert.get('notBefore')
                    result["ssl_info"]["valid_until"] = cert.get('notAfter')
                    
                    # Score based on certificate quality
                    issuer_org = issuer.get('organizationName', '').lower()
                    
                    if 'let\'s encrypt' in issuer_org:
                        score = 40  # Free cert, minimal validation
                        result["signals"].append({
                            "type": "ssl",
                            "status": "INFO",
                            "message": "Free SSL certificate (Let's Encrypt)"
                        })
                    elif any(ca in issuer_org for ca in ['digicert', 'comodo', 'verisign', 'entrust']):
                        score = 10  # Premium CA
                        result["signals"].append({
                            "type": "ssl",
                            "status": "OK",
                            "message": f"Premium SSL certificate from {issuer_org}"
                        })
                    else:
                        score = 30
                        result["signals"].append({
                            "type": "ssl",
                            "status": "INFO",
                            "message": f"SSL certificate from {issuer_org}"
                        })
                    
                    return score
                    
        except ssl.SSLCertVerificationError:
            result["signals"].append({
                "type": "ssl",
                "status": "CRITICAL",
                "message": "Invalid SSL certificate!"
            })
            result["ssl_info"]["valid"] = False
            return 100
        except socket.timeout:
            result["signals"].append({
                "type": "ssl",
                "status": "WARNING",
                "message": "SSL connection timeout"
            })
            return 50
        except Exception as e:
            result["signals"].append({
                "type": "ssl",
                "status": "WARNING",
                "message": f"Could not verify SSL: {str(e)}"
            })
            return 60
    
    def _analyze_url_patterns(self, url: str, domain: str, result: Dict) -> int:
        """Analyze URL for suspicious patterns."""
        score = 0
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                score += 20
                result["signals"].append({
                    "type": "url_pattern",
                    "status": "WARNING",
                    "message": f"Suspicious URL pattern detected"
                })
                break
        
        # Check for IP address instead of domain
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, domain):
            score += 50
            result["signals"].append({
                "type": "url_pattern",
                "status": "CRITICAL",
                "message": "URL uses IP address instead of domain"
            })
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 2:
            score += 30
            result["signals"].append({
                "type": "url_pattern",
                "status": "WARNING",
                "message": f"Excessive subdomains ({subdomain_count})"
            })
        
        # Check URL length
        if len(url) > 100:
            score += 15
            result["signals"].append({
                "type": "url_pattern",
                "status": "INFO",
                "message": "Unusually long URL"
            })
        
        if score == 0:
            result["signals"].append({
                "type": "url_pattern",
                "status": "OK",
                "message": "URL structure appears normal"
            })
        
        return min(score, 100)
    
    def _analyze_content(self, url: str, result: Dict) -> Optional[int]:
        """Analyze page content for scam indicators."""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(
                url if url.startswith('http') else f'https://{url}', 
                headers=headers, 
                timeout=10,
                verify=True
            )
            
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            
            # Count urgency keywords
            urgency_count = sum(1 for kw in self.urgency_keywords if kw in text)
            result["content_info"]["urgency_keywords_found"] = urgency_count
            
            # Check for forms (potential phishing)
            forms = soup.find_all('form')
            password_fields = soup.find_all('input', {'type': 'password'})
            result["content_info"]["forms_count"] = len(forms)
            result["content_info"]["password_fields"] = len(password_fields)
            
            # Check for external scripts (potential malware)
            scripts = soup.find_all('script', src=True)
            external_scripts = [s for s in scripts if s.get('src', '').startswith('http')]
            result["content_info"]["external_scripts"] = len(external_scripts)
            
            # Calculate score
            score = 0
            
            if urgency_count > 5:
                score += 40
                result["signals"].append({
                    "type": "content",
                    "status": "WARNING",
                    "message": f"High urgency language detected ({urgency_count} phrases)"
                })
            elif urgency_count > 2:
                score += 20
                result["signals"].append({
                    "type": "content",
                    "status": "INFO",
                    "message": f"Some urgency language detected ({urgency_count} phrases)"
                })
            
            if len(password_fields) > 0 and len(forms) > 0:
                score += 20
                result["signals"].append({
                    "type": "content",
                    "status": "INFO",
                    "message": "Login form detected - verify site authenticity"
                })
            
            if score == 0:
                result["signals"].append({
                    "type": "content",
                    "status": "OK",
                    "message": "Content appears normal"
                })
            
            return score
            
        except requests.exceptions.SSLError:
            result["signals"].append({
                "type": "content",
                "status": "CRITICAL",
                "message": "SSL verification failed when fetching content"
            })
            return 80
        except requests.exceptions.Timeout:
            result["signals"].append({
                "type": "content",
                "status": "WARNING",
                "message": "Page load timeout"
            })
            return 40
        except Exception as e:
            result["signals"].append({
                "type": "content",
                "status": "ERROR",
                "message": f"Could not analyze content: {str(e)}"
            })
            return None
    
    def _analyze_dns(self, domain: str, result: Dict) -> Optional[int]:
        """Analyze DNS configuration."""
        if not DNS_AVAILABLE:
            return None
            
        try:
            # Check for MX records (legitimate sites usually have email)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                result["dns_info"]["mx_records"] = len(list(mx_records))
                has_mx = True
            except:
                has_mx = False
                result["dns_info"]["mx_records"] = 0
            
            # Check for SPF records (email authentication)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                spf = any('spf' in str(r).lower() for r in txt_records)
                result["dns_info"]["has_spf"] = spf
            except:
                spf = False
            
            score = 0
            
            if not has_mx:
                score += 30
                result["signals"].append({
                    "type": "dns",
                    "status": "INFO",
                    "message": "No email configuration (may be normal for some sites)"
                })
            else:
                result["signals"].append({
                    "type": "dns",
                    "status": "OK",
                    "message": "Email configuration present"
                })
            
            return score
            
        except Exception as e:
            result["signals"].append({
                "type": "dns",
                "status": "ERROR",
                "message": str(e)
            })
            return None


# Singleton instance
analyzer = URLAnalyzer()


def analyze_url(url: str) -> Dict[str, Any]:
    """Convenience function for URL analysis."""
    return analyzer.analyze(url)
