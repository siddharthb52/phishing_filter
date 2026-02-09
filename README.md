# Phishing Detection Engine

A behavioral phishing detection engine that analyzes email structural patterns to calculate a "Phish Probability Score" based on pattern density rather than static blacklists.

## Overview

This detection engine was built and validated against the `rf_peixoto/phishing_pot` dataset containing **7,068 real phishing emails**. Through systematic analysis of 42 diverse samples for feature discovery, followed by comprehensive validation across the entire corpus, we identified **20 structural and behavioral features** (16 active, 4 disabled).

### Key Finding: The Authentication Paradox

**~26% of phishing emails in the dataset pass all authentication checks** (SPF, DKIM, DMARC) due to:
- Compromised legitimate accounts (Gmail, Outlook, AOL)
- Abused Microsoft 365 tenants (onmicrosoft.com)
- Legitimate transactional email services (SendGrid, Mailgun)
- Email forwarding chains

Authentication tells you WHO sent the email, not WHETHER it's malicious. Further research online shows that an even greater portion of real phishing attacks are able to circumvent these basic authentication protocols.

## Features

The engine employs a tiered feature architecture based on trigger frequency analysis across all 7,068 emails:

### TIER 1: Baseline Indicators (50-85% prevalence) - 95 points
1. **Microsoft Spam Scores** (30 pts, 85.4%) - SCL and BCL from Exchange headers
2. **Authentication Failures** (40 pts, 74.3%) - SPF, DKIM, DMARC, CompAuth results
3. **BCL/ARA Indicators** (25 pts, 60.9%) - Advanced anti-spam aggregator scores

### TIER 2: Strong Discriminators (30-50% prevalence) - 80 points
4. **Subject Tracking Codes** (35 pts, 47.3%) - Random alphanumeric sequences, timestamps
5. **Multi-Domain Inconsistency** (45 pts, 43.7%) - Mismatched From/Reply-To/Return-Path domains

### TIER 3: Moderate Indicators (15-30% prevalence) - 65 points
6. **Return-Path Mismatch** (25 pts, 30.1%) - Different bounce-handling domain
7. **Urgency Manipulation** (20 pts, 21.4%) - Psychological pressure keywords
8. **Random Domain Patterns** (20 pts, 15.0%) - Algorithmically generated domains

### TIER 4: Rare but Valid (5-15% prevalence) - 120 points
9. **Priority Flags** (15 pts, 10.8%) - Abuse of importance headers
10. **Brand-Domain Mismatch** (20 pts, 7.9%) - Brand impersonation detection
11. **Empty Return-Path** (10 pts, 6.7%) - Missing bounce address
12. **ARC Authentication Failure** (10 pts, 6.7%) - Broken authentication chain
13. **Transactional Service Abuse** (10 pts, 6.3%) - Legitimate services being exploited
14. **Suspicious URL Patterns** (15 pts, 6.2%) - IP addresses, URL shorteners, non-standard ports
15. **URL Display Mismatch** (20 pts, 5.4%) - Link text vs. actual destination mismatch
16. **Suspicious Username** (20 pts, 5.2%) - Random-looking sender addresses

### TIER 5: Disabled Features (<5% prevalence) - 0 points
17. **Unicode Obfuscation** (0 pts, 3.8%) - Too rare to be meaningful
18. **Customer Code in From** (0 pts, 1.6%) - Too rare to be meaningful
19. **Reply-To Freemail** (0 pts, 2.6%) - Redundant with multi-domain inconsistency
20. **Brand with Freemail** (0 pts, 1.1%) - Too rare to be meaningful

**Total Maximum Score**: 360 points (dynamically calculated)

## Scoring Algorithm

The engine uses a **logistic (sigmoid) transformation** to calibrate raw feature scores into realistic phishing probabilities:

```
1. Raw Score = Sum of triggered feature weights (0-360)
2. Linear Score = Raw Score / 360 (0.0-1.0)
3. Sigmoid Transform: probability = 1 / (1 + exp(-8 * (linear_score - 0.20)))
4. Phish Probability (%) = probability × 100
```

### Why Sigmoid Calibration?

Since 100% of the training data is confirmed phishing, simple linear scoring produced unrealistically low probabilities (10-30%). The sigmoid transformation maps scores to reflect real-world phishing distribution, with most emails scoring 50-80%.

## Risk Thresholds

| Probability | Risk Level | Action |
|------------|------------|--------|
| 85-100% | **CRITICAL** | Block automatically |
| 70-84% | **HIGH** | Quarantine |
| 50-69% | **MEDIUM** | Flag for review |
| 30-49% | **LOW** | Enhanced monitoring |
| 0-29% | **MINIMAL** | Very sophisticated or edge case |

## Installation

**Requirements**: Python 3.x (standard library only)

```bash
# Clone this repository
git clone https://github.com/siddharthb52/phishing_filter.git
cd phishing_filter

```

### Dataset Setup

This project analyzes emails from the `rf_peixoto/phishing_pot` dataset. You'll need to clone it separately:

```bash
# Clone the dataset into the project directory
git clone https://github.com/rf_peixoto/phishing_pot.git
```

**Expected structure**:
```
phishing_filter/
├── phishing_detector.py
├── phishing_pot/          # Cloned dataset
│   └── email/
│       ├── sample-1.eml
│       ├── sample-2.eml
│       └── ... (7,068 .eml files)
└── ...
```

**Note**: The dataset is ~50MB and contains 7,068 phishing email samples. See attribution below.

## Usage

### Analyze a single email

```bash
python phishing_detector.py path/to/email.eml
```

### Analyze a directory of emails

```bash
python phishing_detector.py phishing_pot/email/
```

### Output

CLI shows basic terminal output with a list of .eml files paired with their phishing score.

<img width="518" height="524" alt="image" src="https://github.com/user-attachments/assets/4d7a9fcc-4aca-4ae5-96b0-69b6a5fa6a7d" />


More comprehensive results for each email are saved to `phishing_detection_results.json`:

```json
{
  "filename": "sample-10.eml",
  "phish_probability": 73.2,
  "risk_level": "HIGH",
  "total_score": 135,
  "max_score": 360,
  "features": {
    "microsoft_spam_scores": {
      "score": 15,
      "detail": "SCL: 5 (Medium Confidence)"
    },
    "authentication_failures": {
      "score": 20,
      "detail": "spf=softfail, dmarc=none"
    },
    "subject_tracking_codes": {
      "score": 35,
      "detail": "Tracking pattern detected in subject"
    },
    ...
  },
  "metadata": {
    "from": "Microsoft account team <no-reply@access-accsecurity.com>",
    "subject": "Microsoft account unusual signin activity",
    "authentication": {
      "spf": "softfail",
      "dkim": "none",
      "dmarc": "none",
      "compauth": "fail"
    },
    "scl": 5,
    "bcl": null
  }
}
```

## Validation Results

### Full Dataset Analysis (7,068 Emails)

**Average Phish Probability**: 57.98%

**Distribution by Risk Level**:
- **CRITICAL (≥85%)**: 3.76% (266 emails)
- **HIGH (70-84%)**: 22.59% (1,597 emails)
- **MEDIUM (50-69%)**: 40.39% (2,855 emails)
- **LOW (30-49%)**: 26.33% (1,861 emails)
- **MINIMAL (<30%)**: 6.92% (489 emails)

**High-Confidence Detection**: 26.36% of emails score HIGH or CRITICAL (≥70%)

**Score Distribution**:
- Minimum: 16.80%
- Q1 (25th percentile): 46.12%
- Median: 57.17%
- Q3 (75th percentile): 72.22%
- Maximum: 96.00%

### Representative Test Cases

**Sample-5 (Blatant PayPal Phish) - CRITICAL 87.4%**
- Microsoft spam scores: 15 pts
- Authentication failures: 25 pts
- Multi-domain inconsistency: 30 pts
- BCL/ARA indicators: 15 pts
- Subject tracking codes: 35 pts
- Return-Path mismatch: 25 pts
- Random domain patterns: 20 pts
- **Raw Score**: 165/360 → **87.4% (CRITICAL)** ✓

**Sample-10 (Microsoft Account Phish) - HIGH 73.2%**
- Microsoft spam scores: 15 pts
- Authentication failures: 20 pts
- Multi-domain inconsistency: 15 pts
- BCL/ARA indicators: 15 pts
- Subject tracking codes: 35 pts
- Urgency manipulation: 20 pts
- Priority flags: 15 pts
- **Raw Score**: 135/360 → **73.2% (HIGH)** ✓

**Sample-1009 (Compromised AOL Account) - LOW 46.3%**
- All authentication: PASS
- Subject tracking codes: 35 pts only
- **Raw Score**: 35/360 → **46.3% (LOW)** ⚠️
- **Analysis**: Demonstrates the authentication paradox - legitimate infrastructure abuse is hardest to detect

## Performance

- **Processing Speed**: ~2 minutes for 7,068 emails (~0.02 seconds per email)
- **High-Confidence Detection**: 26.36% at HIGH+ (≥70%)
- **Actionable Detection**: 66.74% at MEDIUM+ (≥50%)
- **False Negatives**: ~26% compromised legitimate accounts score LOW

## Limitations

1. **Compromised Accounts**: ~26% of phishing passing all authentication (score LOW 30-49%)
2. **Dataset Bias**: All training data is phishing; cannot measure false positive rate on legitimate emails
3. **Language Bias**: Urgency detection tuned for English (60% of dataset is non-English)
4. **Content Depth**: While URL analysis is implemented, more sophisticated obfuscation may evade detection
5. **No ML Training**: Rule-based system with data-driven weights, not trained classifier

## Future Enhancements

1. **Advanced Content Analysis**:
   - Base64 decoding and hidden text detection
   - HTML/CSS junk detection for filter evasion
   - Image OCR for embedded phishing URLs
   - Attachment analysis (macro detection, executable scanning)

2. **Machine Learning**:
   - Train binary classifier on benign + phishing samples to measure false positive rate
   - Feature importance ranking via XGBoost/Random Forest
   - Automated sigmoid parameter tuning

3. **Multi-Language Support**:
   - Urgency keyword expansion (German, Dutch, Portuguese, Spanish, French)
   - Character set analysis for language detection
   - Region-specific brand domain validation

## Documentation

- **DESIGN_DOC.md** - Comprehensive technical documentation of all 20 features with validation methodology
- **BLOG_POST.md** - One-page announcement for CISOs
- **feature_analysis_notes.md** - Raw analysis notes from 42-sample discovery phase

## Project Structure

```
phishing_filter/
├── phishing_detector.py          # Main detection engine (CLI)
├── test_batch/                    # 16 curated test samples
│   ├── README.md                  # Test batch documentation
│   ├── BASELINE_SCORES.md         # Expected scores reference
│   └── *.eml                      # Sample emails
├── phishing_pot/                  # Dataset (7,068 .eml files)
│   └── email/
│       ├── sample-1.eml
│       └── ...
├── analyze_features.py            # Feature trigger frequency analyzer
├── analyze_distribution.py        # Probability distribution analyzer
├── create_large_sample.py         # Random sampling utility
├── test_url_features.py           # URL feature validation tests
├── DESIGN_DOC.md                  # Detailed feature documentation
├── BLOG_POST.md                   # CISO announcement
├── feature_analysis_notes.md      # Discovery phase notes
├── phishing_detection_results.json # Latest analysis output
└── README.md                      # This file
```

## Dataset

**Source**: `rf_peixoto/phishing_pot` (clone separately - see Installation)  
**Size**: 7,068 phishing email samples (`.eml` format)  
**Years**: 2022-2026  
**Languages**: English, German, Dutch, Portuguese, Spanish, French, Russian  
**Note**: All samples are phishing emails (no benign samples)

To obtain the dataset:
```bash
git clone https://github.com/rf_peixoto/phishing_pot.git
```

## Deployment Scenarios

### 1. Pre-Delivery Scanning
- Integrate with email gateway via API
- Score incoming emails in real-time
- Block CRITICAL (≥85%), quarantine HIGH (≥70%)

### 2. Post-Delivery Analysis
- Scan inbox folders periodically
- Retroactive detection of sophisticated phishing
- Move flagged emails to quarantine

### 3. SOC Enrichment
- Add behavioral scores to security alerts
- Prioritize incident response based on risk level
- Reduce authentication-only false negatives

### 4. Security Training
- Demonstrate phishing indicators to employees
- Show real attacker techniques and patterns
- Build organizational pattern recognition skills

## Feature Validation Methodology

To ensure robust feature weighting, we employed a systematic validation approach:

1. **Feature Discovery Phase**: Manually analyzed 42 diverse samples to identify potential indicators
2. **Implementation**: Built 20 feature detectors in Python
3. **Full Corpus Analysis**: Processed all 7,068 emails through the detection engine
4. **Frequency Analysis**: For each email, recorded which features triggered (contributed to score)
5. **Statistical Validation**: Aggregated results to determine discriminative value
6. **Weight Calibration**: Assigned weights proportional to predictive power (not just frequency)

This data-driven approach ensures weights reflect real-world phishing patterns, not assumptions.

## Dataset Attribution

This project uses the **phishing_pot** dataset:

- **Source**: [rf_peixoto/phishing_pot](https://github.com/rf_peixoto/phishing_pot)
- **Author**: Ricardo Ferreira Peixoto
- **License**: MIT License (see `phishing_pot/LICENSE` after cloning)
- **Size**: 7,068 phishing email samples (`.eml` format)
- **Years**: 2022-2026

**Citation**: If you use this detection engine or methodology, please also credit the original phishing_pot dataset.

## License

This detection engine is a prototype/educational tool built for a phishing detection challenge. Not intended for production use without further hardening and testing.

The dataset (`phishing_pot/`) has its own license - see the dataset repository for details.

## Contributing

This was a one-day design and prototyping challenge. Future enhancements welcome:
- Content analysis features (attachment scanning, image OCR)
- Multi-language support and international brand databases
- ML classifier training on benign + phishing corpus
- Integration with email gateways and SIEM platforms

## Contact

Built as part of a security engineering assessment demonstrating:
- Dataset analysis and systematic feature discovery
- Behavioral detection vs. static blacklists
- Python development and email parsing expertise
- Technical documentation and communication skills

---
