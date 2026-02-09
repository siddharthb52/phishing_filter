"""
Test suite for URL analysis features
Demonstrates URL mismatch detection and suspicious pattern detection
"""

import sys
import io
from pathlib import Path
from typing import Dict, List

# Force UTF-8 encoding for stdout (cross-platform fix for Unicode)
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Import the detector
from phishing_detector import PhishingDetector, LinkExtractor


def print_section(title: str):
    """Pretty print section headers"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def test_link_extractor():
    """Test HTML link extraction"""
    print_section("TEST 1: HTML Link Extraction")
    
    test_cases = [
        {
            'name': 'Simple link',
            'html': '<a href="https://example.com">Click here</a>',
            'expected': [{'text': 'Click here', 'href': 'https://example.com'}]
        },
        {
            'name': 'Link with domain in text',
            'html': '<a href="https://attacker.com">Visit microsoft.com</a>',
            'expected': [{'text': 'Visit microsoft.com', 'href': 'https://attacker.com'}]
        },
        {
            'name': 'Multiple links',
            'html': '''
                <a href="https://google.com">Google</a>
                <a href="https://evil.com">Click www.paypal.com</a>
            ''',
            'expected': [
                {'text': 'Google', 'href': 'https://google.com'},
                {'text': 'Click www.paypal.com', 'href': 'https://evil.com'}
            ]
        },
        {
            'name': 'Nested HTML',
            'html': '<div><p>Text</p><a href="http://192.168.1.1">IP link</a></div>',
            'expected': [{'text': 'IP link', 'href': 'http://192.168.1.1'}]
        }
    ]
    
    for test in test_cases:
        print(f"\n{test['name']}:")
        print(f"  HTML: {test['html'][:60]}...")
        
        parser = LinkExtractor()
        parser.feed(test['html'])
        
        print(f"  Extracted: {parser.links}")
        print(f"  Expected:  {test['expected']}")
        print(f"  ✓ PASS" if parser.links == test['expected'] else "  ✗ FAIL")


def test_url_mismatch_detection():
    """Test URL display text vs href mismatch detection"""
    print_section("TEST 2: URL Display vs Href Mismatch Detection")
    
    detector = PhishingDetector()
    
    test_cases = [
        {
            'name': 'BENIGN: Text matches href',
            'links': [
                {'text': 'Visit microsoft.com', 'href': 'https://microsoft.com/login'}
            ],
            'should_flag': False,
            'reason': 'Domain in text matches domain in href'
        },
        {
            'name': 'BENIGN: Generic text (no domain)',
            'links': [
                {'text': 'Click here to login', 'href': 'https://example.com/login'}
            ],
            'should_flag': False,
            'reason': 'Text has no domain, so no mismatch possible'
        },
        {
            'name': 'PHISHING: Domain mismatch',
            'links': [
                {'text': 'Visit microsoft.com for updates', 'href': 'https://evil-site.com/phish'}
            ],
            'should_flag': True,
            'reason': 'Text says microsoft.com but href goes to evil-site.com'
        },
        {
            'name': 'PHISHING: Multiple mismatches',
            'links': [
                {'text': 'PayPal Security', 'href': 'https://paypal-secure.tk'},
                {'text': 'Visit www.paypal.com', 'href': 'https://attacker.com'},
                {'text': 'https://paypal.com/login', 'href': 'http://192.168.1.1/phish'}
            ],
            'should_flag': True,
            'reason': 'Multiple domain mismatches'
        },
        {
            'name': 'BENIGN: www prefix handled correctly',
            'links': [
                {'text': 'www.github.com', 'href': 'https://github.com/repo'}
            ],
            'should_flag': False,
            'reason': 'www. prefix is normalized (github.com == www.github.com)'
        },
        {
            'name': 'EDGE CASE: Short text ignored',
            'links': [
                {'text': 'Go', 'href': 'https://evil.com'}
            ],
            'should_flag': False,
            'reason': 'Text < 4 chars is ignored (too short to be meaningful)'
        }
    ]
    
    for test in test_cases:
        print(f"\n{test['name']}")
        print(f"  Links: {test['links']}")
        
        has_mismatch, mismatches = detector.check_url_mismatch(test['links'])
        
        print(f"  Expected: {'FLAGGED' if test['should_flag'] else 'CLEAN'}")
        print(f"  Result:   {'FLAGGED' if has_mismatch else 'CLEAN'}")
        
        if mismatches:
            print(f"  Mismatches found:")
            for m in mismatches:
                print(f"    - {m}")
        
        print(f"  Reason: {test['reason']}")
        
        status = "✓ PASS" if has_mismatch == test['should_flag'] else "✗ FAIL"
        print(f"  {status}")


def test_suspicious_url_patterns():
    """Test suspicious URL pattern detection"""
    print_section("TEST 3: Suspicious URL Pattern Detection")
    
    detector = PhishingDetector()
    
    test_cases = [
        {
            'name': 'IP Literal URL',
            'links': [{'text': 'Login', 'href': 'http://192.168.1.1/phishing'}],
            'expected_patterns': ['IP literal'],
            'reason': 'Legitimate sites use domain names, not raw IPs'
        },
        {
            'name': 'Punycode Domain (Homograph Attack)',
            'links': [{'text': 'Apple', 'href': 'https://xn--pple-43d.com/login'}],
            'expected_patterns': ['Punycode'],
            'reason': 'xn-- indicates internationalized domain (often used for lookalike attacks)'
        },
        {
            'name': 'Suspicious TLD (.tk)',
            'links': [{'text': 'Secure login', 'href': 'https://paypal-verify.tk/login'}],
            'expected_patterns': ['Suspicious TLD'],
            'reason': '.tk domains are free and frequently abused by phishers'
        },
        {
            'name': 'Long Subdomain (Typosquatting)',
            'links': [{'text': 'Microsoft', 'href': 'https://login.microsoft.account.verify.evil.com/'}],
            'expected_patterns': ['Long subdomain'],
            'reason': '4+ dots suggests brand impersonation via long subdomain'
        },
        {
            'name': 'Multiple Suspicious Patterns',
            'links': [
                {'text': 'Link 1', 'href': 'http://203.0.113.5/phish'},
                {'text': 'Link 2', 'href': 'https://fake-site.ml/login'},
                {'text': 'Link 3', 'href': 'https://xn--e1afmkfd.xn--p1ai/'}
            ],
            'expected_patterns': ['IP literal', 'Suspicious TLD', 'Punycode'],
            'reason': 'Multiple red flags in different links'
        },
        {
            'name': 'CLEAN: Normal legitimate URL',
            'links': [{'text': 'GitHub', 'href': 'https://github.com/repo'}],
            'expected_patterns': [],
            'reason': 'Standard domain with legitimate TLD'
        }
    ]
    
    for test in test_cases:
        print(f"\n{test['name']}")
        print(f"  Links: {test['links']}")
        
        has_suspicious, patterns = detector.check_suspicious_url_patterns(test['links'])
        
        print(f"  Expected patterns: {test['expected_patterns']}")
        print(f"  Detected patterns: {patterns}")
        print(f"  Reason: {test['reason']}")
        
        # Check if we detected any of the expected patterns
        detected_all = all(
            any(expected in pattern for pattern in patterns) 
            for expected in test['expected_patterns']
        ) if test['expected_patterns'] else (len(patterns) == 0)
        
        status = "✓ PASS" if detected_all else "✗ FAIL"
        print(f"  {status}")


def test_scoring_logic():
    """Test the scoring logic for URL features"""
    print_section("TEST 4: URL Feature Scoring Logic")
    
    detector = PhishingDetector()
    
    print("\nURL Display Mismatch Scoring:")
    print("  - 3+ mismatches: 40 points")
    print("  - 2 mismatches:  30 points")
    print("  - 1 mismatch:    20 points")
    print("  - 0 mismatches:   0 points")
    
    print("\nSuspicious URL Pattern Scoring:")
    print("  - 3+ patterns: 35 points")
    print("  - 2 patterns:  25 points")
    print("  - 1 pattern:   15 points")
    print("  - 0 patterns:   0 points")
    
    print("\nExample: High-risk phishing email")
    print("  Scenario: Email claims to be from PayPal")
    example_links = [
        {'text': 'Click here to verify: www.paypal.com', 'href': 'http://192.168.1.1/phish'},
        {'text': 'Support at paypal.com', 'href': 'https://paypal-secure.tk/login'},
        {'text': 'Visit https://paypal.com', 'href': 'https://account.verify.paypal.phishing.com/'}
    ]
    
    has_mismatch, mismatches = detector.check_url_mismatch(example_links)
    has_suspicious, patterns = detector.check_suspicious_url_patterns(example_links)
    
    print(f"\n  Link 1: Text mentions 'www.paypal.com' → href goes to IP address")
    print(f"  Link 2: Text mentions 'paypal.com' → href is .tk domain")
    print(f"  Link 3: Text shows 'https://paypal.com' → href has long subdomain")
    
    print(f"\n  URL Mismatches: {len(mismatches)} detected")
    for m in mismatches:
        print(f"    - {m}")
    
    print(f"\n  Suspicious Patterns: {len(patterns)} detected")
    for p in patterns:
        print(f"    - {p}")
    
    # Calculate score
    mismatch_score = 40 if len(mismatches) >= 3 else (30 if len(mismatches) == 2 else (20 if len(mismatches) == 1 else 0))
    pattern_score = 35 if len(patterns) >= 3 else (25 if len(patterns) == 2 else (15 if len(patterns) == 1 else 0))
    
    total_url_score = mismatch_score + pattern_score
    
    print(f"\n  URL Mismatch Score:    {mismatch_score}/40")
    print(f"  Suspicious Pattern Score: {pattern_score}/35")
    print(f"  Total URL Score:       {total_url_score}/75")
    print(f"  Percentage of MAX:     {(total_url_score / detector.MAX_SCORE) * 100:.1f}%")


def test_real_email_sample():
    """Test with actual email file"""
    print_section("TEST 5: Real Email Analysis")
    
    detector = PhishingDetector()
    
    # Test with sample-10.eml (Microsoft phishing)
    sample_path = Path('phishing_pot/email/sample-10.eml')
    
    if not sample_path.exists():
        print(f"\n  ⚠ Sample file not found: {sample_path}")
        print("  Skipping real email test")
        return
    
    print(f"\n  Analyzing: {sample_path.name}")
    
    try:
        msg = detector.parse_eml(sample_path)
        links = detector.extract_links(msg)
        
        print(f"\n  Total links found: {len(links)}")
        
        if links:
            print(f"\n  First 3 links:")
            for i, link in enumerate(links[:3], 1):
                print(f"    {i}. Text: '{link['text'][:50]}...' if len(link['text']) > 50 else link['text']")
                print(f"       Href: {link['href'][:60]}...")
        
        has_mismatch, mismatches = detector.check_url_mismatch(links)
        has_suspicious, patterns = detector.check_suspicious_url_patterns(links)
        
        print(f"\n  URL Mismatches: {'Yes' if has_mismatch else 'No'}")
        if mismatches:
            for m in mismatches[:3]:
                print(f"    - {m}")
        
        print(f"\n  Suspicious Patterns: {'Yes' if has_suspicious else 'No'}")
        if patterns:
            for p in patterns[:3]:
                print(f"    - {p}")
        
        # Get scores
        mismatch_score, mismatch_detail = detector.score_url_display_mismatch(msg)
        pattern_score, pattern_detail = detector.score_suspicious_url_patterns(msg)
        
        print(f"\n  URL Mismatch Score: {mismatch_score}/40")
        print(f"    Detail: {mismatch_detail}")
        print(f"\n  Suspicious Pattern Score: {pattern_score}/35")
        print(f"    Detail: {pattern_detail}")
        
        print(f"\n  ✓ Real email test completed")
        
    except Exception as e:
        print(f"\n  ✗ Error analyzing email: {e}")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("  URL FEATURE TEST SUITE")
    print("  Testing URL mismatch detection and suspicious pattern analysis")
    print("="*70)
    
    try:
        test_link_extractor()
        test_url_mismatch_detection()
        test_suspicious_url_patterns()
        test_scoring_logic()
        test_real_email_sample()
        
        print_section("TEST SUITE COMPLETE")
        print("\n  All tests executed successfully!")
        print("  Review output above to verify expected behavior")
        
    except Exception as e:
        print(f"\n\n✗ TEST SUITE FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
