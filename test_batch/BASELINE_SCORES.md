# Quick Reference: Test Batch Scores (Logistic Scoring)

Run this after making changes to verify scores:

```bash
python phishing_detector.py test_batch/
```

## Expected Scores (Baseline - After Logistic Transformation)

| Filename | Score | Risk | Key Features Triggered |
|----------|-------|------|------------------------|
| sample-3.eml | **21.98%** | MINIMAL | SCL:5 only |
| sample-188.eml | **21.98%** | MINIMAL | SCL:5 only |
| sample-250.eml | **30.53%** | LOW | Urgency, tracking codes |
| sample-11.eml | **32.94%** | LOW | Auth fail, BCL/ARA |
| sample-20.eml | **38.02%** | LOW | Multi-domain, SCL, return-path |
| sample-25.eml | **40.67%** | LOW | Auth fail, unicode |
| sample-150.eml | **40.67%** | LOW | Auth fail |
| sample-75.eml | **51.67%** | MEDIUM | Auth fail, BCL, tracking |
| sample-1009.eml | **54.43%** | MEDIUM | Tracking, suspicious username |
| sample-1005.eml | **57.17%** | MEDIUM | Multi-domain, SCL:9, return-path |
| sample-125.eml | **57.17%** | MEDIUM | Multi-domain, SCL:9, return-path |
| sample-40.eml | **62.51%** | MEDIUM | BCL/ARA, tracking, urgency |
| sample-99.eml | **65.07%** | MEDIUM | Multi-domain, return-path, BCL |
| sample-175.eml | **67.55%** | MEDIUM | Auth fail, BCL, tracking |
| sample-1008.eml | **69.94%** | MEDIUM | Suspicious username, tracking |
| sample-10.eml | **83.51%** | HIGH | Auth fail, urgency, priority, brand mismatch |

**Average:** 49.74%  
**Distribution:** HIGH=1, MEDIUM=8, LOW=5, MINIMAL=2

---

## Scoring System

**Method:** Logistic (Sigmoid) Transformation
- Raw score normalized: `linear = raw_score / 360`
- Sigmoid applied: `sigmoid = 1 / (1 + exp(-8 * (linear - 0.20)))`
- Center: 0.20 (raw 20% → 50% after transform)
- Steepness: 8

**Risk Thresholds (Post-Logit):**
- CRITICAL: ≥85%
- HIGH: 70-85%
- MEDIUM: 50-70%
- LOW: 30-50%
- MINIMAL: <30%

---

## Active Features: 16 (out of 20 total)

**Disabled (weight = 0):**
- unicode_obfuscation (3.8% trigger rate)
- customer_code_in_from (1.6% trigger rate)
- reply_to_freemail (2.6% trigger rate)
- brand_with_freemail (1.1% trigger rate)

---

**Last Updated:** Feb 9, 2026  
**MAX_SCORE:** 360 (dynamically calculated)  
**Total Features:** 20 (16 active, 4 disabled)  
**Scoring:** Logistic transformation (sigmoid)
