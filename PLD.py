import re
import tldextract
from urllib.parse import urlparse, unquote
from dataclasses import dataclass
from typing import List, Dict, Tuple
import ssl
import socket
from datetime import datetime
import whois
import requests
from collections import Counter

@dataclass
class URLAnalysisResult:
    """Data class to store URL analysis results"""
    url: str 
    risk_score: int
    risk_level: str
    findings: List[Dict[str, str]]
    recommendations: List[str]
    domain_info: Dict
    timestamp: str

class PhishingLinkdetector:
    #phishing link detector tool

    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'banking', 'password', 'credential', 'billing',
            'authenticate', 'validation', 'recovery', 'unlock', 'suspend',
            'limited', 'expired', 'urgent', 'alert', 'warning', 'security', 
            'unusual', 'activity', 'suspended', 'verify-account', 'webscr',
            'authorize', 'recover', 'unlock', 'reactivate','restore'
        ]

        #knonw legitimate domains
        self.legitimate_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook,com', 'x.com', 'linkedin.com', 'github.com', 
            'paypal.com', 'dropbox.com', 'adobe.com', 'netflix.com',
            'spotify.com', 'instagram.com', 'whatsapp.com', 'zoom.us'
        }

        #patterns for brand impersonation
        self.brand_keywords = [
        'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
        'netflix', 'dropbox', 'adobe', 'linkedin', 'twitter', 'instagram',
        'whatsapp', 'bank', 'chase', 'wellsfargo', 'citi', 'amex'
        ]

        #URL shortener services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'buff.ly', 'is.gd', 'cli.gs', 'tr.im', 'short.link',
            'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc'
        ]

    def analyze_url(self, url: str) -> URLAnalysisResult:
        """
        Analyze a URL for phishing indicators
        Args:
            url:the URL to analyze

        returns:
            URLAnalysisresult object containing analysis results
        """
        findings = []
        recommendations = []
        risk_score = 0

        #Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed_url = urlparse(unquote(url))
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        full_url = url.lower()

        #1. check for suspicious keywords in URL
        keyword_findings = self._check_suspicious_keywords(full_url)
        if keyword_findings:
            findings.extend(keyword_findings)
            risk_score += len(keyword_findings) * 10

        #2. check for IP address instead of domain
        if self._is_ip_address(domain):
            findings.append({
                'type': 'IP_ADDRESS'
                'severity': 'HIGH'
                'description': 'URL uses IP address instead of domain name'
            })
            risk_score += 30

        #3. Check for URL length (phishing URLs tend to be longer)
        if len(url) > 75:
            findings.append({
                'type': 'LONG_URL',
                'severity': 'LOW',
                'description': f'URL is unusually long ({len(url)} characters)'
            })
            risk_score += 5

        #4. check for @ symbol in URL
        if "@" in parsed_url.netloc:
            findings.append({
                'type':'AT_SYMBOL',
                'severity':'HIGH',
                'description': 'URL contains @ symbol, possibly to mislead users'
            })
            risk_score += 30

        #5. check for multiple subdomains
        subdomain_count = self._count_subdomains(domain)
        if subdomain_count > 3:
            findings.append({
                'type': 'EXCESSIVE_SUBDOMAINS',
                'severity': 'MEDIUM',
                'description': f" URL has { subdomain_count} subdomains"

            })
            risk_score += 15

        #6 check for brand impersonation
        brand_issues = self._check_brand_impersonation(domain, path)
        if brand_issues:
            findings.extend(brand_issues)
            risk_score += len(brand_issues) * 15

        #7 Check for suspicious TLDs
        tld = self._extract_tld(domain)
        if tld in self.suspicious_tlds:
            findings.append({
                'type': 'SUSPICIOUS_TLD',
                'severity': 'MEDIUM',
                'description': f'Suspicious top-level domain: {tld}'
            })
            risk_score += 20

        #8 Check for URL shorteners
        if any (shortener in domain for shortener in self.url_shorteners):
            findings.append({
                'type': 'URL_SHORTENERS',
                'severity': 'MEDIUM',
                'description': 'URL uses a link shortening service'
            })
            risk_score += 15
        
        #9. Check for special characters and encoding
        encoding_issues = self._check_encoding_issues(url)
        if encoding_issues:
            findings.extend(encoding_issues)
            risk_score += len(encoding_issues) * 10

        #10. check for https in domain name (common phishibg trick)
        if 'https' in domain and not url.startswith('https://'):
            findings.append({
                'type': 'HTTPS_IN_DOMAIN',
                'severity': 'HIGH',
                'description': 'URL contains "HTTPS" in domain name to appear legitimate'

            })
            risk_score += 25

        #11. check for character substitution
        substitution_issues = self._check_character_substitution(domain)
        if substitution_issues:
            findings.extend(substitution_issues)
            risk_score += 20

        #12 Check for data URIs
        if url.startswith('data:'):
            findings.append({
                'type': 'DATA_URI',
                'severity': 'CRITICAL',
                'decsription': 'URL uses data URI scheme, potentially hiding malicious content'

            })
            risk_score += 40

        # Calculate risk level
        risk_level = self._calculate_risk_level(risk_score)

        #Generate recommendations
        recommendations = self._generate_recommendations(findings, risk_level)

        #get domain information
        domain_info = self._get_domain_info(domain)

        return URLAnalysisResult(
            url=url,
            risk_score = min(risk_score, 100),
            risk_level = risk_level,
            findings = findings,
            recommendations = recommendations,
            domain_info = domain_info,
            timestamp = datetime.now().isoformat()
        )

    def _check_suspicious_keywords(self, url: str) -> List[Dict[str, str]]:
        """check for suspicious keywords in the URL"""
        findings = []
        found_keyword = []

        for keyword in self.suspicious_keywords:
            if keyword in url:
                found_keywords.append(keyword)

        if found_keywords:
            findings.append({
                'type': 'SUSPICIOUS_KEYWORDS',
                'severity':'MEDIUM',
                'description': f'Contains suspicious keywords: {", ".join(found_keywords)}'
            }
            )
        return findings

    def _is_ip_address(self, domain: str) -> bool:
        """Check if the domain is an IP address"""
        #Remove port if present
        domain = domain.split(':')[0]

        #IPv4 pattern
        ipv4_pattern = r'^\{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, domain):
            return True

        #IPv6 pattern
        ipv6_pattern = r'^\[?[0-9a-fA-F:]+\]?$'
        if re.match(ipv6_pattern, domain):
            return True
        
        return False
        