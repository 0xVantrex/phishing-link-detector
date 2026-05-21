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
    
    def _count_subdomains(self, domain: str) -> int:
        #count the number of subdomains
        extracted = tldextract.extract(domain)
        subdomain = extracted.subdomain

        if subdomain:
            return len(subdomain.split('.'))
        return 0

    def _extract_tld(self, domain: str) -> str:
        #Extract the TLD from a domain
        extracted = tldextract.extract(domain)
        return f".{extracted.suffix}"
    
    def _check_brand_impersonation(self, domain: str, path: str) -> List[Dict[str, str]]:
        #Check for brand impersonation
        findings = []

        for brand in self.brand_keywords:
            #Check if brand is in domain but not the legitimate domain
            if brand in domain:
                legitimate_domain = f"{brand}.com"
                if domain != legitimate_domain and legitimate_domain not in domain:
                    findings.append({
                        'type': 'BRAND_IMPERSONATION',
                        'severity': 'HIGH',
                        'description': f'Possible brand impersonation of {brand.capitalize()}'
                    })
                    break
            
            #Check if brand name appears in subdirectory
            if brand in path and brand not in domain:
                findings.append({
                        'type': 'SUSPICIOUS BRAND IN PATH',
                        'severity': 'MEDIUM',
                        'description': f'Brand name "{brand}" found in url path'
                    })
        return findings

    def _check_encoding_issues(self, url: str) -> List[Dict[str, str]]:
        #check for suspicious URL encoding
        findings = []

        #Check for percent encoding
        if % in url:
            percent_count = url.count('%')
            if percent_count > 3:
                findings.append({
                    'type': 'EXCESSIVE_ENCODING',
                    'severity': 'MEDIUM',
                    'decsription': f'URL contains excessive percent encoding ({percent_count} instances)'
                })

        #check for unicode encoding
        if any(ord(char) > 127 for char in url):
            findings.append({
                'type': 'UNICODE_CHARACTERS',
                'severity': 'HIGH',
                'description': 'URL contains non-ASCII characters, potential homograph attack'
            })       

        return findings

    def _check_character_substitution(self, domain: str) -> List[Dict[str, str]]:
        #Check for common character substitution
        findings = []

        substitutions = {
            '0': 'o',
            '1': 'l',
            '5': 's',
            '8': 'b',
            'rn': 'm',
            'vv': 'w'
        }

        for fake_char, real_char in substitutions.items():
            #Check if substitution is used in a brand-like context
            for brand in self.brand_keywords:
                modified_brand = brand.replace(real_char, fake_char)
                if modified_brand in domain and modified_brand != brand:
                    findings.append({
                        'type': 'CHARACTER_SUBSTITUION',
                        'severity': 'HIGH',
                        'decsription': f'Possible character substitution: "{fake_char}" for "{real_char}" mimicking "{brand}"'
                    })
        return findings

    def _calculate_risk_level(self, score: int) -> str:
        #Calculate risk level based on score
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        elif score >= 15:
            return 'LOW'
        else:
            return 'SAFE'
    
    def _generate_recommendations(self, findings: List[Dict], risk_level: str ) -> List[str]:
        #Generate security recommendations based on findings
        recommendations = []

        if risk_level in ['CRITICAL', 'HIGH']:
            recommendations.append('DO NOT click on this link')
            recommendations.append('Report this URL to your IT security team')
            recommendations.append('If you must visit, manually type the known legitimate URL')

        if any(f['type'] == 'BRAND_IMPERSONATION' for f in findings):
            recommendations.append('verify the sender\'s identity through a different channel')
            recommendations.append('Contact the company directly usign their office website')        

        if any(f['type'] == 'IP_ADDRESS' for f in findings):
            recommendations.append('legitimate services rarely use IP addresses directly')
            recommendations.append('This is highly suspicious - avoid this link')

        if any(f['type'] == 'DATA_URI' for f in findings):
            recommendations.append('Data URIs can execute code - never click unless you fully trust the source')

        if risk_level == 'LOW':
            recommendations.append('Exercise caution when visiting this link')
            recommendations.append('Verify the website\'s legitmacy before entering any information')
        
        if not recommendations:
            recommendations.append('URL appears safe, but always practice good security habits')
        
        return recommendations
    
    def _get_domain_info(self, domain: str) -> Dict:
        #Get basic domain information
        info = {
            'domain': domain,
            'is_legitimate': domain in self.legitimate_domains,
            'suspicious_tld': self._extract_tld(domain) in self.suspicious_tlds
        }

        #Check if it's an IP address
        info['is_ip'] = self._is_ip_address(domain)

        return info

    def batch_analyze(*self, urls: List[str]) -> List[URLAnalysisResult]:
        #Analyze multiple URLs
        results = []
        for url in urls:
            results.append(slef.analyze_url(url))
        return results

    def generate_reports(self, result: URLAnalysisResult) -> str:
        #Generate a formatted report
        report = f """
        ╔══════════════════════════════════════════════════════════════╗
        ║                 PHISHING LINK ANALYSIS REPORT                 ║
        ╚══════════════════════════════════════════════════════════════╝

        URL: {result.url}
        Timestamp: {result.timestamp}
        Risk Score: {result.risk_score}/100
        Risk Level: {result.risk_level}
        """

        if result.findings:
            report += "\n!!! SUSPICIOUS FINDINGS:\n"
            report += "-" * 60 + "\n"
            for i, finding in enumerate(result.findings, 1):
                severity_icon = {
                    'CRITICAL':'🔴',
                    'HIGH':'🟠',
                    'MEDIUM':'🟡',
                    'LOW':'🟢'
                }.get(finding['severity'], '⚪')
                report += f"{i}. {severity_icon} [{finding['severity']}] {finding['type']}\n"
                report += f" {finding['description']}\n\n"

        if result.recommendations:
            report += "\n RECOMMENDATIONS: \n"
            report += "_" * 60 + "\n"
            for i, rec in enumerate(result.recommendations, 1):
                report += f"{i}. {rec}\n"

        report += "\n"+ "=" * 60 + "\n"
        return report

    def main():
        """Main function to demonmstrate the phishing link detector"""
        detector = PhishingLinkdetector()

        print("=" * 60)
        print("PHISHING LINK DETCTOR - Social Engineering Analysis")
        print("=" * 60)

        #Example URLs to analyze
        test_urls = [
            "https://www.google.com", # legit
            "http://192.168.1.1/login", #IP-based
            "https://secure-paypal.com.verify-account.tk/login", #suspicious
            "https://bit.ly/3xK9mN2", #URL shortener
            "https://paypa1.com/login", #legit
            "https://accounts.google.com.security-alert.xyz/verify", #brand impersonation
            "https://www.amazon.com/gp/css/homepage.html", #legit
            "data:text/html,<script>alert('test')</script>", #Data URI
            "https://security-alert-urgent.ga/update-password", #multiple red flags
        ]

        while True:
            print("\nOptions:")
            print("1. Run demo analysis")
            print("2. Analyze custom URL")
            print("3. Batch analyze URLs")
            print("4. Exit")

            choice = input("\nSelect option (1-4): ").strip()

            if choice == '1':
                print("\n RUNNING DEMO ANALYSIS...")
                print("=" * 60)

                for urls in test_urls:
                    result = detector.analyze_url(url)
                    print(detector.generate_report(result))
                    input("Press Enter to continue...")

            elif choice == '2':
                url = input("\nEnter URL to analyze: ").strip()
                if url:
                    print("\n ANALYZING URL...")
                    result = detector.analyze_url(url)
                    print(detector.generate_report(result))
                else:
                    print("No URL entered")

            elif choice == '3':
                print ("Enter multiple URLs (one per line, empty line to finish):")
                urls = []
                while True:
                    url = input().strip()
                    if not url:
                        break
                    urls.append(url)

                if urls:
                    print(f"ANALYZING {len(urls)} URLs...")
                    results = detector.batch_analyze(urls)

                    #summary
                    risk_counts = Counter(r.risk_level for r in results)
                    print("\n BATCH ANALYSIS SUMMARY:")
                    PRINT("-" * 40) 
                    for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE']:
                        count = risk_counts.get(level, 0)
                        if count > 0:
                            print(f"{level}: {count} URLs")

                    #Detailed results
                    print("\nDETAILED RESULTS:")
                    for results in results:
                        print(f"\nURL: {result.url}")
                        print(f"Risk Level: {result.risk_level} (Score: {result.risk_score}/100)")
                        print("-" * 40)

                elif choice == '4':
                    print("\nExiting Phishing Link Detector. Stay safe online!!!!!")
                    break
                else:
                    print("Invalid option! Please try again.")

if __name__=="__main__":
    #check for required packages
    required_packages = ['tldextract', 'whois', 'requests']
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("Missing required packages. Install them using:")
        print(f"pip install {' '.join(missing_packages)}")
        print("\nBasic functionality will still work without these packages.\n")

        main()



