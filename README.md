# phishing-link-detector
Key Features:
1. Suspicious Keyword detection
  Identifies common phisnhing keywords (login, verify, secure, account, etc)
  Checks for urgency-inducing words (alert, warning, limited)

2. Technical Indicators
  IP address detection
  URL length analysis
  @ symbol detection
  Excessive subdomains
  URL shortener detection
  
3. Brand impersonation Detection
  Identifies when legitimate brands are spoofed
  Detects character substitution (paypa1.com vs paypal.com)
  Unicode/homograph attack detection

4. Risk Scoring ssystem
  Calculates risk score (0-100)
  categorizes risk: SAFE,LOW,MEDIUM,HIGH,CRITICAL
  provides actionable recommendations

5. Advanced pattern recognition
  Suspicious TLD detection (,tk, .ml, etc.)
  Data URI detection
  HTTPS-in-domain trick detection
  Percentage encoding analysis

Installation Requirements:
pip install tldextract pythoin-whois requests

##The tool provides a comprehensive social engineering detection system that identifies common phishing tactics and helps user make informed decisions about link safety
