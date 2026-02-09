# Test Batch - Curated Sample Emails

This directory contains **16 diverse phishing email samples** for quick testing and validation.

## Quick Test Command

```bash
python phishing_detector.py test_batch/
```

## Sample Overview

**Total Samples**: 16  
**Average Score**: 49.74%  
**Risk Distribution**: HIGH=1, MEDIUM=8, LOW=5, MINIMAL=2

## Individual Sample Descriptions

### High Risk (≥70%)

**sample-10.eml - HIGH 83.51%**
- **From:** Microsoft impersonation
- **Auth:** Failed (SPF/DKIM none, DMARC permerror)
- **Features:** Auth failures, urgency, priority flags, brand mismatch
- **Use case:** Classic brand impersonation with multiple red flags

---

### Medium Risk (50-69%)

**sample-1008.eml - MEDIUM 69.94%**
- **From:** Compromised Gmail (sonyundefinedralph@gmail.com)
- **Auth:** All passing (SPF/DKIM/DMARC)
- **Features:** Suspicious username, tracking codes
- **Use case:** Authentication paradox - passes all checks but clearly phishing

**sample-175.eml - MEDIUM 67.55%**
- **From:** Various indicators
- **Auth:** Failed authentication
- **Features:** Auth failures, BCL/ARA, tracking codes
- **Use case:** Multiple behavioral indicators

**sample-99.eml - MEDIUM 65.07%**
- **From:** Multi-domain patterns
- **Auth:** Mixed
- **Features:** Multi-domain inconsistency, return-path mismatch, BCL/ARA
- **Use case:** Domain-based detection

**sample-40.eml - MEDIUM 62.51%**
- **From:** Behavioral patterns
- **Auth:** Mixed
- **Features:** BCL/ARA indicators, tracking codes, urgency
- **Use case:** Behavioral pattern detection

**sample-1005.eml - MEDIUM 57.17%**
- **From:** Brazilian phishing attempt
- **Auth:** DMARC none, CompAuth fail
- **Features:** Multi-domain inconsistency, SCL:9, return-path mismatch
- **Use case:** Regional phishing with high spam score

**sample-125.eml - MEDIUM 57.17%**
- **From:** Similar to sample-1005
- **Auth:** Mixed authentication
- **Features:** Multi-domain, SCL:9, return-path mismatch
- **Use case:** Duplicate pattern validation

**sample-1009.eml - MEDIUM 54.43%**
- **From:** Compromised Gmail (sel553r@gmail.com)
- **Auth:** All passing (SPF/DKIM/DMARC)
- **Features:** Tracking codes, suspicious username
- **Use case:** Low SCL (1) phishing that bypasses traditional filters

**sample-75.eml - MEDIUM 51.67%**
- **From:** Multiple indicators
- **Auth:** Failed authentication
- **Features:** Auth failures, BCL/ARA, tracking codes
- **Use case:** Mid-range detection threshold

---

### Low Risk (30-49%)

**sample-150.eml - LOW 40.67%**
- **From:** Basic authentication failures
- **Auth:** Failed
- **Features:** Authentication failures only
- **Use case:** Minimal feature triggering

**sample-25.eml - LOW 40.67%**
- **From:** Mixed indicators
- **Auth:** Failed
- **Features:** Auth failures, unicode obfuscation
- **Use case:** Borderline case testing

**sample-20.eml - LOW 38.02%**
- **From:** Domain patterns
- **Auth:** Mixed
- **Features:** Multi-domain, SCL, return-path mismatch
- **Use case:** Low-confidence domain inconsistency

**sample-11.eml - LOW 32.94%**
- **From:** Basic patterns
- **Auth:** Failed
- **Features:** Auth failures, BCL/ARA indicators
- **Use case:** Low feature density

**sample-250.eml - LOW 30.53%**
- **From:** Minimal indicators
- **Auth:** Mixed
- **Features:** Urgency manipulation, tracking codes
- **Use case:** Threshold testing (LOW/MINIMAL boundary)

---

### Minimal Risk (<30%)

**sample-3.eml - MINIMAL 21.98%**
- **From:** Compromised Gmail account (noraalex01@gmail.com)
- **Auth:** All passing (SPF/DKIM/DMARC)
- **Features:** Only SCL:5 triggered
- **Use case:** Baseline for legitimate-looking compromised accounts

**sample-188.eml - MINIMAL 21.98%**
- **From:** Clean authentication
- **Auth:** All passing
- **Features:** Only SCL:5 triggered
- **Use case:** Duplicate baseline test

---

## Feature Coverage

This test batch exercises:

✅ **Authentication features:**
- Passing SPF/DKIM/DMARC (samples 3, 188, 1008, 1009)
- Failing authentication (samples 10, 25, 75, 150, 175, 11)
- Mixed authentication (samples 1005, 125, 20, 40, 99, 250)

✅ **Domain features:**
- Multi-domain inconsistency (samples 10, 1005, 125, 20, 99)
- Brand-domain mismatch (sample 10)
- Return-path mismatch (samples 1005, 125, 20, 99)

✅ **Behavioral features:**
- Urgency language (samples 10, 40, 250)
- Priority flags (sample 10)
- Suspicious usernames (samples 1008, 1009)
- Tracking codes (samples 1008, 1009, 75, 175, 40, 250)
- Unicode obfuscation (sample 25)

✅ **Microsoft spam scores:**
- SCL: 1 (sample 1009) - Very low
- SCL: 5 (samples 3, 188, 10) - Medium
- SCL: 9 (samples 1005, 125) - High
- BCL variations across samples

✅ **Risk level distribution:**
- HIGH: 1 sample (6.25%)
- MEDIUM: 8 samples (50%)
- LOW: 5 samples (31.25%)
- MINIMAL: 2 samples (12.5%)

---

## Use Cases

### 1. Quick Validation After Code Changes
```bash
python phishing_detector.py test_batch/
```
Run this after any feature modifications to ensure scores stay consistent.

### 2. Feature Testing
Add a new feature? Check how it affects these 16 diverse samples across all risk levels.

### 3. Regression Testing
Track score changes over time:
```bash
# Before changes
python phishing_detector.py test_batch/ > before.txt

# After changes
python phishing_detector.py test_batch/ > after.txt

# Compare
diff before.txt after.txt
```

### 4. Performance Benchmarking
Small enough to run quickly (~5 seconds), diverse enough to be meaningful.

### 5. Threshold Testing
- Verify risk level boundaries (85%, 70%, 50%, 30%)
- Test edge cases near thresholds
- Validate sigmoid calibration

---

## Sample Characteristics Matrix

| Sample | Score | Auth Pass | SCL | Multi-Domain | Tracking | Urgency | Username |
|--------|-------|-----------|-----|--------------|----------|---------|----------|
| 10     | 83.51 | ✗         | 5   | ✓            | ✗        | ✓       | ✗        |
| 1008   | 69.94 | ✓         | 1   | ✗            | ✓        | ✗       | ✓        |
| 175    | 67.55 | ✗         | ?   | ✗            | ✓        | ✗       | ✗        |
| 99     | 65.07 | Mixed     | ?   | ✓            | ✗        | ✗       | ✗        |
| 40     | 62.51 | Mixed     | ?   | ✗            | ✓        | ✓       | ✗        |
| 1005   | 57.17 | Mixed     | 9   | ✓            | ✗        | ✗       | ✗        |
| 125    | 57.17 | Mixed     | 9   | ✓            | ✗        | ✗       | ✗        |
| 1009   | 54.43 | ✓         | 1   | ✗            | ✓        | ✗       | ✓        |
| 75     | 51.67 | ✗         | ?   | ✗            | ✓        | ✗       | ✗        |
| 150    | 40.67 | ✗         | ?   | ✗            | ✗        | ✗       | ✗        |
| 25     | 40.67 | ✗         | ?   | ✗            | ✗        | ✗       | ✗        |
| 20     | 38.02 | Mixed     | ?   | ✓            | ✗        | ✗       | ✗        |
| 11     | 32.94 | ✗         | ?   | ✗            | ✗        | ✗       | ✗        |
| 250    | 30.53 | Mixed     | ?   | ✗            | ✓        | ✓       | ✗        |
| 3      | 21.98 | ✓         | 5   | ✗            | ✗        | ✗       | ✗        |
| 188    | 21.98 | ✓         | 5   | ✗            | ✗        | ✗       | ✗        |

---

## Expected Results

See `BASELINE_SCORES.md` for detailed expected scores and feature breakdowns.

**Quick Summary:**
```
Processing 16 email(s)...
✓ sample-10.eml: 83.51% (HIGH)
✓ sample-1008.eml: 69.94% (MEDIUM)
✓ sample-175.eml: 67.55% (MEDIUM)
✓ sample-99.eml: 65.07% (MEDIUM)
✓ sample-40.eml: 62.51% (MEDIUM)
✓ sample-1005.eml: 57.17% (MEDIUM)
✓ sample-125.eml: 57.17% (MEDIUM)
✓ sample-1009.eml: 54.43% (MEDIUM)
✓ sample-75.eml: 51.67% (MEDIUM)
✓ sample-150.eml: 40.67% (LOW)
✓ sample-25.eml: 40.67% (LOW)
✓ sample-20.eml: 38.02% (LOW)
✓ sample-11.eml: 32.94% (LOW)
✓ sample-250.eml: 30.53% (LOW)
✓ sample-3.eml: 21.98% (MINIMAL)
✓ sample-188.eml: 21.98% (MINIMAL)

=== Summary ===
Total emails analyzed: 16
Average phish probability: 49.74%
Risk distribution: CRITICAL=0, HIGH=1, MEDIUM=8, LOW=5, MINIMAL=2
```

---

## Adding More Samples

To add more test samples:

```bash
# Copy from main dataset
Copy-Item phishing_pot/email/sample-XXXX.eml test_batch/

# Re-run test
python phishing_detector.py test_batch/

# Update BASELINE_SCORES.md with new results
```

**Recommendation:** Keep test batch under 20-25 samples for quick iteration cycles.

---

## Notes

- These samples represent diverse attack vectors:
  - **Authentication Paradox** (samples 3, 188, 1008, 1009) - passing all checks but still phishing
  - **Brand Impersonation** (sample 10) - classic Microsoft phish
  - **Regional Phishing** (samples 1005, 125) - Portuguese/Brazilian attacks
  - **Behavioral Detection** (samples 40, 250) - urgency and tracking patterns
  - **Domain Abuse** (samples 20, 99) - multi-domain inconsistencies

- Covers all risk levels: MINIMAL → HIGH (no CRITICAL in test batch)
- Small enough for fast testing (~5 seconds)
- Diverse enough to catch regressions
- Representative of full dataset distribution

---

**Created:** Feb 9, 2026  
**Purpose:** Quick regression testing during development  
**Maintained:** Keep updated as engine evolves  
**Last Updated:** Feb 9, 2026 (Logistic scoring implementation)
