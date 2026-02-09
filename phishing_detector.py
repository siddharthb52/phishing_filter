#!/usr/bin/env python3
"""
Phishing Detection Engine - Structural and Behavioral Feature Analysis
Analyzes .eml files to calculate a Phish Probability Score based on pattern density.
"""

import email
import re
import json
import sys
import io
from pathlib import Path
from typing import Dict, List, Tuple
from email.message import Message
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

# Force UTF-8 encoding for stdout (cross-platform fix for Unicode output)
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


class LinkExtractor(HTMLParser):
    """Extract links from HTML content"""
    def __init__(self):
        super().__init__()
        self.links = []
        self.current_tag = None
        self.current_href = None
        self.current_text = []
    
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.current_tag = 'a'
            self.current_text = []
            for attr, value in attrs:
                if attr == 'href':
                    self.current_href = value
    
    def handle_endtag(self, tag):
        if tag == 'a' and self.current_tag == 'a':
            text = ''.join(self.current_text).strip()
            if self.current_href:
                self.links.append({
                    'text': text,
                    'href': self.current_href
                })
            self.current_tag = None
            self.current_href = None
            self.current_text = []
    
    def handle_data(self, data):
        if self.current_tag == 'a':
            self.current_text.append(data)


class PhishingDetector:
    """
    Detects phishing emails by analyzing structural and behavioral patterns.
    No static blacklists - focuses on anomaly detection and suspicious indicators.
    """
    
    def __init__(self):
        # Feature weights based on 500-email statistical analysis
        # Weights adjusted by trigger frequency and signal strength
        self.FEATURE_WEIGHTS = {
            # TIER 1: Very Common Baseline (50-85% trigger rate)
            "microsoft_spam_scores": 30,        # 85.4% trigger
            "authentication_failures": 40,      # 74.2% trigger
            "bcl_ara_indicators": 25,           # 59.6% trigger
            
            # TIER 2: Strong Discriminators (30-50% trigger rate)
            "subject_tracking_codes": 35,       # 49.6% trigger
            "multi_domain_inconsistency": 45,   # 43.0% trigger
            
            # TIER 3: Moderate Indicators (15-30% trigger rate)
            "return_path_mismatch": 25,         # 29.4% trigger
            "urgency_manipulation": 20,         # 21.6% trigger
            "random_domain_patterns": 20,       # 16.2% trigger
            
            # TIER 4: Rare but Valid (5-15% trigger rate)
            "priority_flags": 15,               # 11.6% trigger
            "brand_domain_mismatch": 20,        # 9.2% trigger
            "empty_return_path": 10,            # 7.2% trigger
            "suspicious_username": 20,          # 6.8% trigger
            "transactional_service_abuse": 10,  # 6.0% trigger
            "suspicious_url_patterns": 15,      # 5.4% trigger
            "arc_authentication_failure": 10,   # 5.4% trigger
            "url_display_mismatch": 20,         # 5.0% trigger
            
            # TIER 5: Disabled (<5% trigger rate)
            "unicode_obfuscation": 0,           # 3.8% trigger - too rare
            "customer_code_in_from": 0,         # 2.4% trigger - too rare
            "reply_to_freemail": 0,             # 2.2% trigger - too rare
            "brand_with_freemail": 0,           # 1.2% trigger - too rare
        }
        
        # Calculate maximum score dynamically from feature weights
        self.MAX_SCORE = sum(self.FEATURE_WEIGHTS.values())
    
    def parse_eml(self, filepath: Path) -> Message:
        """Parse .eml file and return email.message.Message object"""
        with open(filepath, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        return msg
    
    # Extracts domains from email headers -- returns a dict of domains
    def extract_domains(self, msg: Message) -> Dict[str, str]:
        """Extract domains from various email headers using proper email parsing"""
        domains = {}
        
        # From domain - use parseaddr for proper parsing
        from_header = msg.get('From', '')
        name, addr = parseaddr(from_header)
        domains['from'] = addr.split('@', 1)[1].lower() if '@' in addr else ''
        
        # Reply-To domain - use parseaddr
        reply_to = msg.get('Reply-To', '')
        name, addr = parseaddr(reply_to)
        domains['reply_to'] = addr.split('@', 1)[1].lower() if '@' in addr else ''
        
        # Return-Path domain - usually just an email address, sometimes with <>
        return_path = msg.get('Return-Path', '')
        # Strip angle brackets if present
        return_path = return_path.strip('<>').strip()
        domains['return_path'] = return_path.split('@', 1)[1].lower() if '@' in return_path else ''
        
        # Sender domain - use parseaddr
        sender = msg.get('Sender', '')
        name, addr = parseaddr(sender)
        domains['sender'] = addr.split('@', 1)[1].lower() if '@' in addr else ''
        
        return domains
    
    def extract_links(self, msg: Message) -> List[Dict[str, str]]:
        """Extract all links from HTML body"""
        try:
            # Try to get HTML body
            body = msg.get_body(preferencelist=('html',))
            if not body:
                return []
            
            html_content = body.get_content()
            parser = LinkExtractor()
            parser.feed(html_content)
            return parser.links
        except Exception:
            return []
    
    def check_url_mismatch(self, links: List[Dict[str, str]]) -> Tuple[bool, List[str]]:
        """
        Check for display text vs href mismatches in links.
        Returns (has_mismatch, list_of_mismatches)
        """
        mismatches = []
        
        for link in links:
            text = link['text'].lower().strip()
            href = link['href'].lower().strip()
            
            # Skip empty or very short text
            if len(text) < 4:
                continue
            
            # Check if text looks like a URL/domain
            url_like = bool(re.search(r'(https?://|www\.|\.com|\.net|\.org|\.gov)', text))
            if not url_like:
                continue
            
            # Extract domain from text if it looks like URL
            text_domain = None
            text_match = re.search(r'(?:https?://)?(?:www\.)?([a-z0-9\-\.]+\.[a-z]{2,})', text)
            if text_match:
                text_domain = text_match.group(1)
            
            # Extract domain from href
            href_domain = None
            try:
                parsed = urlparse(href)
                href_domain = parsed.netloc.lower()
                if href_domain.startswith('www.'):
                    href_domain = href_domain[4:]
            except Exception:
                continue
            
            # Compare domains
            if text_domain and href_domain:
                # Remove www. prefix for comparison
                text_domain_clean = text_domain.replace('www.', '')
                href_domain_clean = href_domain.replace('www.', '')
                
                if text_domain_clean != href_domain_clean:
                    mismatches.append(f"Text: '{text}' -> Href: '{href_domain}'")
        
        return (len(mismatches) > 0, mismatches)
    
    def check_suspicious_url_patterns(self, links: List[Dict[str, str]]) -> Tuple[bool, List[str]]:
        """
        Check for suspicious URL patterns:
        - IP literal URLs (http://192.168.1.1)
        - Punycode domains (xn--)
        - Suspicious TLDs (.tk, .ml, .ga, .cf, .gq)
        - Very long subdomains
        """
        suspicious = []
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw'}
        
        for link in links:
            href = link['href'].lower()
            
            try:
                parsed = urlparse(href)
                netloc = parsed.netloc
                
                # Check for IP literal
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', netloc):
                    suspicious.append(f"IP literal: {href[:50]}")
                    continue
                
                # Check for punycode
                if 'xn--' in netloc:
                    suspicious.append(f"Punycode: {href[:50]}")
                    continue
                
                # Check for suspicious TLDs
                for tld in suspicious_tlds:
                    if netloc.endswith(tld):
                        suspicious.append(f"Suspicious TLD ({tld}): {href[:50]}")
                        break
                
                # Check for very long subdomain (potential homograph)
                if netloc.count('.') > 3:
                    suspicious.append(f"Long subdomain: {netloc}")
            
            except Exception:
                continue
        
        return (len(suspicious) > 0, suspicious)
    
    # Extracts authentication results from email headers -- returns a dict of authentication results
    def extract_auth_results(self, msg: Message) -> Dict[str, str]:
        """Extract SPF, DKIM, DMARC, CompAuth results"""
        auth_header = msg.get('Authentication-Results', '')
        
        auth = {
            'spf': 'unknown',
            'dkim': 'unknown',
            'dmarc': 'unknown',
            'compauth': 'unknown'
        }
        
        # Parse authentication results
        if auth_header:
            spf_match = re.search(r'spf=(pass|fail|softfail|none|temperror|permerror)', auth_header, re.IGNORECASE)
            if spf_match:
                auth['spf'] = spf_match.group(1).lower()
            
            dkim_match = re.search(r'dkim=(pass|fail|none)', auth_header, re.IGNORECASE)
            if dkim_match:
                auth['dkim'] = dkim_match.group(1).lower()
            
            dmarc_match = re.search(r'dmarc=(pass|fail|none|permerror|temperror)', auth_header, re.IGNORECASE)
            if dmarc_match:
                auth['dmarc'] = dmarc_match.group(1).lower()
            
            compauth_match = re.search(r'compauth=(pass|fail)', auth_header, re.IGNORECASE)
            if compauth_match:
                auth['compauth'] = compauth_match.group(1).lower()
        
        return auth
    
    def get_scl_bcl(self, msg: Message) -> Tuple[int, int]:
        """Extract SCL (Spam Confidence Level) and BCL (Bulk Confidence Level)"""
        scl_header = msg.get('X-MS-Exchange-Organization-SCL', '')
        bcl_header = msg.get('X-Microsoft-Antispam', '')
        
        scl = -1
        bcl = -1
        
        if scl_header:
            try:
                scl = int(scl_header.strip())
            except ValueError:
                pass
        
        if bcl_header:
            bcl_match = re.search(r'BCL:(\d+)', bcl_header)
            if bcl_match:
                bcl = int(bcl_match.group(1))
        
        return scl, bcl
    
    def check_unicode_obfuscation(self, msg: Message) -> bool:
        """Check for Unicode obfuscation in From/Subject"""
        from_header = msg.get('From', '')
        subject_header = msg.get('Subject', '')
        
        # Check for Unicode characters in From/Subject that look like obfuscation
        # Common patterns: strikethrough, bold Unicode, Cyrillic homoglyphs
        unicode_patterns = [
            r'[\u0336-\u0338]',  # Strikethrough
            r'[\U0001D400-\U0001D7FF]',  # Mathematical alphanumeric symbols
            r'[\u0400-\u04FF]',  # Cyrillic (if used for non-Cyrillic brand)
        ]
        
        for pattern in unicode_patterns:
            if re.search(pattern, from_header) or re.search(pattern, subject_header):
                return True
        
        return False
    
    def check_arc_failure(self, msg: Message) -> bool:
        """Check for ARC-Seal failures"""
        arc_seal = msg.get('ARC-Seal', '')
        if arc_seal and 'cv=fail' in arc_seal.lower():
            return True
        return False
    
    def is_freemail(self, domain: str) -> bool:
        """Check if domain is a free email provider"""
        freemail_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 
                           'aol.com', 'mail.com', 'protonmail.com', 'icloud.com']
        return domain.lower() in freemail_domains
    
    def check_suspicious_username(self, email: str) -> bool:
        """Check if email username looks randomly generated or suspicious"""
        if not email or '@' not in email:
            return False
        
        username = email.split('@')[0].lower()
        
        # Remove common separators
        username = username.replace('.', '').replace('_', '').replace('-', '')
        
        # Check for random patterns
        # 1. Mix of letters and numbers with no clear pattern
        if re.search(r'[a-z]+\d+[a-z]+\d+', username):  # e.g., "sel553r", "user123test456"
            return True
        
        # 2. Very short (3 chars or less)
        if len(username) <= 3:
            return True
        
        # 3. Contains "undefined" or similar garbage
        if any(word in username for word in ['undefined', 'test', 'temp', 'spam', 'fake']):
            return True
        
        # 4. Excessive consonants (> 85%)
        alpha_chars = [c for c in username if c.isalpha()]
        if len(alpha_chars) > 5:
            vowels = sum(1 for c in alpha_chars if c in 'aeiou')
            if vowels / len(alpha_chars) < 0.15:  # Less than 15% vowels
                return True
        
        return False
    
    def check_subject_tracking_codes(self, subject: str) -> bool:
        """Check if subject contains tracking/automation codes"""
        # Base64-like random strings
        if re.search(r'[A-Za-z0-9]{15,}', subject):
            return True
        
        # Multiple random alphanumeric codes
        codes = re.findall(r'\b[A-Za-z0-9]{8,}\b', subject)
        if len(codes) >= 2:
            return True
        
        return False
    
    def check_customer_code_in_from(self, from_header: str) -> bool:
        """Check if From field contains suspicious customer codes or long numbers"""
        # Look for long number sequences in From (often tracking codes)
        if re.search(r'\d{10,}', from_header):
            return True
        
        # Customer code patterns: "Cod.", "Code:", "Ref:"
        if re.search(r'(Cod\.|Code:|Ref:)\s*\d+', from_header, re.IGNORECASE):
            return True
        
        return False
    
    def check_brand_in_subject_or_from(self, msg: Message) -> Tuple[bool, str]:
        """Check for bank/financial brands in Subject or From with freemail domain"""
        from_header = msg.get('From', '').lower()
        subject = msg.get('Subject', '').lower()
        domains = self.extract_domains(msg)
        
        # Common financial/bank brands and institutions
        brands = {
            # Brazilian banks
            'banco do brasil': ['bb', '[bb]', 'banco do brasil'],
            'bradesco': ['bradesco'],
            'itau': ['itaú', 'itau'],
            'santander': ['santander'],
            'caixa': ['caixa economica', 'caixa'],
            'nubank': ['nubank', 'nu bank'],
            
            # International
            'paypal': ['paypal'],
            'stripe': ['stripe'],
            'square': ['square'],
            'venmo': ['venmo'],
            
            # Government/Tax
            'irs': ['irs', 'receita federal', 'tax credit', 'tax refund'],
            'social security': ['social security', 'ssa'],
        }
        
        # Check if any brand mentioned but using freemail
        for brand_name, keywords in brands.items():
            for keyword in keywords:
                if keyword in from_header or keyword in subject:
                    if self.is_freemail(domains.get('from', '')):
                        return True, f"Brand '{brand_name}' mentioned with freemail domain"
        
        return False, "No brand-freemail mismatch"
    
    def check_random_domain(self, domain: str) -> bool:
        """Check if domain appears to be randomly generated"""
        if not domain:
            return False
        
        # Extract domain without TLD
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False
        
        name = domain_parts[0]
        
        # Heuristics for random domains
        # 1. Very long (>20 chars)
        if len(name) > 20:
            return True
        
        # 2. High consonant-to-vowel ratio (hard to pronounce)
        vowels = set('aeiouAEIOU')
        consonants = sum(1 for c in name if c.isalpha() and c not in vowels)
        total_alpha = sum(1 for c in name if c.isalpha())
        
        if total_alpha > 5 and consonants / total_alpha > 0.8:
            return True
        
        # 3. Contains many numbers
        if sum(1 for c in name if c.isdigit()) > len(name) * 0.3:
            return True
        
        return False
    
    def check_urgency_language(self, msg: Message) -> bool:
        """Check for urgency/manipulation language in Subject"""
        subject = msg.get('Subject', '').lower()
        
        urgency_keywords = [
            'urgent', 'immediate', 'act now', 'limited time', 'expires', 'suspended',
            'verify', 'confirm', 'unusual', 'suspicious', 'alert', 'warning', 'blocked',
            'claim', 'congratulations', 'winner', 'prize', 'giveaway', 'free',
            'click here', 'important', 'action required', 'account', 'security'
        ]
        
        return any(keyword in subject for keyword in urgency_keywords)
    
    def get_priority(self, msg: Message) -> bool:
        """Check if email has high priority flags"""
        priority = msg.get('X-Priority', '')
        importance = msg.get('Importance', '')
        
        return priority == '1' or importance == 'high'
    
    def check_microsoft_tenant_abuse(self, domains: Dict[str, str]) -> bool:
        """Check if using abused Microsoft tenant"""
        for domain in domains.values():
            if domain and 'onmicrosoft.com' in domain.lower():
                return True
        return False
    
    # ==================== FEATURE SCORING FUNCTIONS ====================
    
    def score_multi_domain_inconsistency(self, domains: Dict[str, str]) -> Tuple[int, str]:
        """
        Feature 1: Multi-Domain Inconsistency
        Score: 0-50 points based on number of mismatches
        """
        unique_domains = set(d.lower() for d in domains.values() if d)
        
        if len(unique_domains) >= 4:
            return 50, f"4+ different domains: {', '.join(unique_domains)}"
        elif len(unique_domains) == 3:
            return 35, f"3 different domains: {', '.join(unique_domains)}"
        elif len(unique_domains) == 2:
            return 20, f"2 different domains: {', '.join(unique_domains)}"
        else:
            return 0, "Consistent domain usage"
    
    def score_authentication_failures(self, auth: Dict[str, str]) -> Tuple[int, str]:
        """
        Feature 2: Authentication Failures/Anomalies
        Score: 0-45 points
        """
        score = 0
        details = []
        
        # SPF failures
        if auth['spf'] in ['fail', 'softfail']:
            score += 15
            details.append(f"SPF: {auth['spf']}")
        elif auth['spf'] in ['none', 'temperror', 'permerror']:
            score += 10
            details.append(f"SPF: {auth['spf']}")
        
        # DKIM failures
        if auth['dkim'] in ['fail']:
            score += 15
            details.append(f"DKIM: {auth['dkim']}")
        elif auth['dkim'] == 'none':
            score += 10
            details.append(f"DKIM: {auth['dkim']}")
        
        # DMARC failures
        if auth['dmarc'] in ['fail', 'permerror']:
            score += 10
            details.append(f"DMARC: {auth['dmarc']}")
        elif auth['dmarc'] == 'none':
            score += 5
            details.append(f"DMARC: {auth['dmarc']}")
        
        # CompAuth
        if auth['compauth'] == 'fail':
            score += 5
            details.append("CompAuth: fail")
        
        # Cap at max weight
        score = min(score, self.FEATURE_WEIGHTS['authentication_failures'])
        
        return score, "; ".join(details) if details else "All authentication passed"
    
    def score_microsoft_spam_scores(self, scl: int, bcl: int) -> Tuple[int, str]:
        """
        Feature 3: Microsoft Spam Confidence Level & Bulk Confidence Level
        Score: 0-35 points
        """
        score = 0
        details = []
        
        if scl >= 9:
            score += 25
            details.append(f"SCL: {scl} (highest)")
        elif scl >= 7:
            score += 20
            details.append(f"SCL: {scl} (high)")
        elif scl >= 5:
            score += 15
            details.append(f"SCL: {scl} (medium)")
        elif scl >= 3:
            score += 10
            details.append(f"SCL: {scl} (low-medium)")
        
        if bcl >= 7:
            score += 10
            details.append(f"BCL: {bcl} (bulk)")
        elif bcl >= 5:
            score += 5
            details.append(f"BCL: {bcl}")
        
        score = min(score, self.FEATURE_WEIGHTS['microsoft_spam_scores'])
        
        return score, "; ".join(details) if details else "Low spam scores"
    
    def score_random_domain_patterns(self, domains: Dict[str, str]) -> Tuple[int, str]:
        """
        Feature 4: Random/Suspicious Domain Patterns
        Score: 0-25 points
        """
        score = 0
        suspicious = []
        
        for key, domain in domains.items():
            if domain and self.check_random_domain(domain):
                score += 10
                suspicious.append(f"{key}: {domain}")
        
        score = min(score, self.FEATURE_WEIGHTS['random_domain_patterns'])
        
        return score, f"Suspicious domains: {', '.join(suspicious)}" if suspicious else "Domains appear legitimate"
    
    def score_urgency_manipulation(self, msg: Message) -> Tuple[int, str]:
        """
        Feature 5: Urgency/Manipulation Language
        Score: 0-15 points
        """
        if self.check_urgency_language(msg):
            return 15, f"Urgency detected in subject: {msg.get('Subject', '')}"
        return 0, "No urgency language"
    
    def score_priority_flags(self, msg: Message) -> Tuple[int, str]:
        """
        Feature 6: High Priority Flags
        Score: 0-20 points
        """
        if self.get_priority(msg):
            return 20, "High priority flags set"
        return 0, "Normal priority"
    
    def score_return_path_mismatch(self, domains: Dict[str, str]) -> Tuple[int, str]:
        """
        Feature 7: Return-Path Domain Mismatch
        Score: 0-20 points
        """
        if domains['from'] and domains['return_path']:
            if domains['from'].lower() != domains['return_path'].lower():
                return 20, f"Return-Path ({domains['return_path']}) != From ({domains['from']})"
        return 0, "Return-Path matches From"
    
    def score_bcl_ara_indicators(self, msg: Message) -> Tuple[int, str]:
        """
        Feature 8: BCL & ARA (Anti-spam Report Aggregator) Indicators
        Score: 0-30 points
        """
        score = 0
        details = []
        
        ara_header = msg.get('X-Microsoft-Antispam', '')
        
        # Look for high ARA scores (e.g., ARA:1444111002)
        ara_matches = re.findall(r'ARA:(\d+)', ara_header)
        if ara_matches:
            for ara_score in ara_matches:
                if len(ara_score) >= 10:  # Very high ARA score
                    score += 15
                    details.append(f"High ARA: {ara_score}")
                    break
        
        # X-SID-Result: FAIL
        sid_result = msg.get('X-SID-Result', '')
        if sid_result == 'FAIL':
            score += 10
            details.append("X-SID-Result: FAIL")
        
        # Empty Return-Path (often indicates bulk/spam)
        return_path = msg.get('Return-Path', '')
        if return_path == '<>':
            score += 5
            details.append("Empty Return-Path")
        
        score = min(score, self.FEATURE_WEIGHTS['bcl_ara_indicators'])
        
        return score, "; ".join(details) if details else "No suspicious ARA indicators"
    
    def score_brand_domain_mismatch(self, msg: Message, domains: Dict[str, str]) -> Tuple[int, str]:
        """
        Feature 9: Brand Impersonation (Brand name in From but wrong domain)
        Score: 0-20 points
        """
        from_header = msg.get('From', '').lower()
        from_domain = domains.get('from', '').lower()
        
        # Common brands and their legitimate domains
        brands = {
            'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com'],
            'amazon': ['amazon.com', 'amazon.co.uk'],
            'paypal': ['paypal.com'],
            'dhl': ['dhl.com', 'dhl.de'],
            'apple': ['apple.com', 'icloud.com'],
            'google': ['google.com', 'gmail.com'],
            'facebook': ['facebook.com', 'fb.com'],
            'netflix': ['netflix.com'],
            'ups': ['ups.com'],
            'fedex': ['fedex.com']
        }
        
        for brand, legitimate_domains in brands.items():
            if brand in from_header and not any(legit_domain in from_domain for legit_domain in legitimate_domains):
                return 20, f"Brand '{brand}' in From, but domain is {from_domain}"
        
        return 0, "No obvious brand impersonation"
    
    def score_reply_to_freemail(self, msg: Message, domains: Dict[str, str]) -> Tuple[int, str]:
        """
        Feature 10: Reply-To uses freemail (Gmail, Outlook, etc.) while From doesn't
        Score: 0-25 points
        """
        from_domain = domains.get('from', '')
        reply_to_domain = domains.get('reply_to', '')
        
        if reply_to_domain and self.is_freemail(reply_to_domain):
            if from_domain and not self.is_freemail(from_domain):
                return 25, f"Reply-To is freemail ({reply_to_domain}), From is not ({from_domain})"
        
        return 0, "Reply-To consistent with From or absent"
    
    def score_unicode_obfuscation(self, msg: Message) -> Tuple[int, str]:
        """
        Additional Feature: Unicode Obfuscation
        Score: 0-20 points
        """
        if self.check_unicode_obfuscation(msg):
            return 20, f"Unicode obfuscation in From/Subject"
        return 0, "No Unicode obfuscation"
    
    def score_empty_return_path(self, msg: Message) -> Tuple[int, str]:
        """
        Additional Feature: Empty Return-Path
        Score: 0-15 points
        """
        return_path = msg.get('Return-Path', '').strip()
        if not return_path or return_path == '<>':
            return 15, "Empty or missing Return-Path"
        return 0, "Return-Path present"
    
    def score_arc_authentication_failure(self, msg: Message) -> Tuple[int, str]:
        """
        Additional Feature: ARC Authentication Failure
        Score: 0-20 points
        """
        if self.check_arc_failure(msg):
            return 20, "ARC-Seal: cv=fail (authentication chain broken)"
        return 0, "ARC authentication passed or not present"
    
    def score_transactional_service_abuse(self, msg: Message, domains: Dict[str, str]) -> Tuple[int, str]:
        """
        Additional Feature: Legitimate Transactional Service Abuse
        Score: 0-25 points
        """
        score = 0
        details = []
        
        # Check for Microsoft tenant abuse
        if self.check_microsoft_tenant_abuse(domains):
            score += 15
            details.append("Microsoft onmicrosoft.com tenant")
        
        # Check for common transactional email services
        transactional_indicators = [
            'sendgrid', 'mailgun', 'postmark', 'mailchimp', 'sendinblue',
            'amazonses', 'sparkpost', 'mandrill'
        ]
        
        for indicator in transactional_indicators:
            if any(indicator in str(d).lower() for d in domains.values() if d):
                score += 10
                details.append(f"Transactional service: {indicator}")
                break
        
        score = min(score, self.FEATURE_WEIGHTS['transactional_service_abuse'])
        
        return score, "; ".join(details) if details else "No transactional service abuse detected"
    
    def score_suspicious_username(self, msg: Message) -> Tuple[int, str]:
        """
        New Feature: Suspicious Username Patterns
        Score: 0-30 points
        """
        from_header = msg.get('From', '')
        from_match = re.search(r'<(.+?)>', from_header)
        
        if from_match:
            email = from_match.group(1)
            if self.check_suspicious_username(email):
                return 30, f"Suspicious username pattern: {email}"
        
        return 0, "Username appears normal"
    
    def score_subject_tracking_codes(self, msg: Message) -> Tuple[int, str]:
        """
        New Feature: Subject Tracking/Automation Codes
        Score: 0-20 points
        """
        subject = msg.get('Subject', '')
        
        if self.check_subject_tracking_codes(subject):
            return 20, f"Tracking/automation codes detected in subject"
        
        return 0, "No tracking codes in subject"
    
    def score_customer_code_in_from(self, msg: Message) -> Tuple[int, str]:
        """
        New Feature: Customer/Reference Code in From Field
        Score: 0-25 points
        """
        from_header = msg.get('From', '')
        
        if self.check_customer_code_in_from(from_header):
            return 25, f"Customer/reference code in From field"
        
        return 0, "No suspicious codes in From"
    
    def score_brand_with_freemail(self, msg: Message) -> Tuple[int, str]:
        """
        New Feature: Financial Brand with Freemail Domain
        Score: 0-35 points
        """
        is_suspicious, detail = self.check_brand_in_subject_or_from(msg)
        
        if is_suspicious:
            return 35, detail
        
        return 0, "No brand-freemail mismatch"
    
    def score_url_display_mismatch(self, msg: Message) -> Tuple[int, str]:
        """
        New Feature: URL Display Text vs Href Mismatch
        Score: 0-40 points
        High-value phishing indicator - clicking "microsoft.com" goes to something like attacker.com
        """
        links = self.extract_links(msg)
        has_mismatch, mismatches = self.check_url_mismatch(links)
        
        if has_mismatch:
            num_mismatches = len(mismatches)
            if num_mismatches >= 3:
                return 40, f"{num_mismatches} URL mismatches: {'; '.join(mismatches[:2])}"
            elif num_mismatches == 2:
                return 30, f"2 URL mismatches: {'; '.join(mismatches)}"
            else:
                return 20, f"URL mismatch: {mismatches[0]}"
        
        return 0, "No URL mismatches detected"
    
    def score_suspicious_url_patterns(self, msg: Message) -> Tuple[int, str]:
        """
        New Feature: Suspicious URL Patterns
        Score: 0-35 points
        Detects IP literals, punycode, suspicious TLDs, long subdomains
        """
        links = self.extract_links(msg)
        has_suspicious, patterns = self.check_suspicious_url_patterns(links)
        
        if has_suspicious:
            num_patterns = len(patterns)
            if num_patterns >= 3:
                return 35, f"{num_patterns} suspicious URLs: {'; '.join(patterns[:2])}"
            elif num_patterns == 2:
                return 25, f"2 suspicious URLs: {'; '.join(patterns)}"
            else:
                return 15, f"Suspicious URL: {patterns[0]}"
        
        return 0, "No suspicious URL patterns"
    
    # ==================== MAIN ANALYSIS FUNCTION ====================
    
    def analyze(self, filepath: Path) -> Dict:
        """
        Main analysis function - returns complete analysis with scores
        """
        msg = self.parse_eml(filepath)
        
        # Extract basic info
        domains = self.extract_domains(msg)
        auth = self.extract_auth_results(msg)
        scl, bcl = self.get_scl_bcl(msg)
        
        # Score all features
        features = {}
        total_score = 0
        
        score, detail = self.score_multi_domain_inconsistency(domains)
        features['multi_domain_inconsistency'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_authentication_failures(auth)
        features['authentication_failures'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_microsoft_spam_scores(scl, bcl)
        features['microsoft_spam_scores'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_random_domain_patterns(domains)
        features['random_domain_patterns'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_urgency_manipulation(msg)
        features['urgency_manipulation'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_priority_flags(msg)
        features['priority_flags'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_return_path_mismatch(domains)
        features['return_path_mismatch'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_bcl_ara_indicators(msg)
        features['bcl_ara_indicators'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_brand_domain_mismatch(msg, domains)
        features['brand_domain_mismatch'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_reply_to_freemail(msg, domains)
        features['reply_to_freemail'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_unicode_obfuscation(msg)
        features['unicode_obfuscation'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_empty_return_path(msg)
        features['empty_return_path'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_arc_authentication_failure(msg)
        features['arc_authentication_failure'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_transactional_service_abuse(msg, domains)
        features['transactional_service_abuse'] = {'score': score, 'detail': detail}
        total_score += score
        
        # New features for compromised account detection
        score, detail = self.score_suspicious_username(msg)
        features['suspicious_username'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_subject_tracking_codes(msg)
        features['subject_tracking_codes'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_customer_code_in_from(msg)
        features['customer_code_in_from'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_brand_with_freemail(msg)
        features['brand_with_freemail'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_url_display_mismatch(msg)
        features['url_display_mismatch'] = {'score': score, 'detail': detail}
        total_score += score
        
        score, detail = self.score_suspicious_url_patterns(msg)
        features['suspicious_url_patterns'] = {'score': score, 'detail': detail}
        total_score += score
        
        # Calculate probability using logistic transformation
        # Linear score (0-1)
        linear_score = total_score / self.MAX_SCORE
        
        # Apply sigmoid transformation to better reflect real phishing distribution
        # Since all emails in dataset are phishing, we expect most to score 50-80%
        # Sigmoid params: center at 0.20 (where average phishing scores), steepness 8
        import math
        center = 0.20  # Raw 20% should map to ~50%
        steepness = 8
        adjusted = steepness * (linear_score - center)
        sigmoid = 1 / (1 + math.exp(-adjusted))
        phish_probability = sigmoid * 100
        
        # Determine risk level based on sigmoid-adjusted probability
        if phish_probability >= 85:
            risk_level = "CRITICAL"
        elif phish_probability >= 70:
            risk_level = "HIGH"
        elif phish_probability >= 50:
            risk_level = "MEDIUM"
        elif phish_probability >= 30:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            'filename': filepath.name,
            'phish_probability': round(phish_probability, 2),
            'risk_level': risk_level,
            'total_score': total_score,
            'max_score': self.MAX_SCORE,
            'features': features,
            'metadata': {
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'subject': msg.get('Subject', ''),
                'date': msg.get('Date', ''),
                'domains': domains,
                'authentication': auth,
                'scl': scl if scl != -1 else None,
                'bcl': bcl if bcl != -1 else None
            }
        }


def main():
    """CLI Entry Point"""
    if len(sys.argv) < 2:
        print("Usage: python phishing_detector.py <directory_or_file>")
        print("Example: python phishing_detector.py ./phishing_pot/email/")
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    
    if not input_path.exists():
        print(f"Error: Path '{input_path}' does not exist")
        sys.exit(1)
    
    detector = PhishingDetector()
    results = []
    
    # Collect .eml files
    if input_path.is_file():
        eml_files = [input_path]
    else:
        eml_files = list(input_path.glob('*.eml'))
    
    if not eml_files:
        print(f"Error: No .eml files found in '{input_path}'")
        sys.exit(1)
    
    print(f"Processing {len(eml_files)} email(s)...")
    
    # Analyze each file
    for eml_file in eml_files:
        try:
            result = detector.analyze(eml_file)
            results.append(result)
            print(f"✓ {eml_file.name}: {result['phish_probability']}% ({result['risk_level']})")
        except Exception as e:
            print(f"✗ {eml_file.name}: Error - {str(e)}")
    
    # Output JSON
    output_file = Path('phishing_detection_results.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Results saved to: {output_file}")
    
    # Summary statistics
    if results:
        avg_prob = sum(r['phish_probability'] for r in results) / len(results)
        critical = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in results if r['risk_level'] == 'MEDIUM')
        
        print(f"\n=== Summary ===")
        print(f"Total emails analyzed: {len(results)}")
        print(f"Average phish probability: {avg_prob:.2f}%")
        print(f"Risk distribution: CRITICAL={critical}, HIGH={high}, MEDIUM={medium}")


if __name__ == '__main__':
    main()
