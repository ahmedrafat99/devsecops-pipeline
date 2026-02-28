# OWASP ZAP Scan Consistency Guide

## Why ZAP Results Vary Between Runs

### Normal Variations
1. **Spider Discovery**: Different URLs found each time due to:
   - JavaScript timing variations
   - Network latency
   - Application state changes
   - Random session tokens

2. **Active Scan Coverage**: With time limits, different endpoints get tested:
   - Scan might timeout before completing all tests
   - Thread scheduling varies
   - Some tests take longer on different runs

3. **Application Behavior**:
   - Database content changes
   - Different error messages
   - Session state variations
   - Dynamic content

### Your Results Analysis

**Run 1:**
- Alert types: 17
- Instances: 83
- Scan completed in time limit

**Run 2:**
- Alert types: 39 (+129% increase)
- Instances: 145 (+75% increase)
- Found more issues because:
  - Discovered more endpoints
  - Different spider path
  - More time on certain tests

## Solutions for Consistent Results

### Solution 1: Remove Time Limit (Simplest)

**Pros:**
- Ensures complete scan every time
- No configuration needed
- Most thorough

**Cons:**
- Takes longer (30-45 minutes)
- May timeout in CI/CD

**Implementation:**
```yaml
# In workflow file, remove -m flag:
zap-full-scan.py \
  -t http://pygoat-app:8000 \
  -a \
  -l INFO \
  # No -m 20 = unlimited time
```

### Solution 2: Use ZAP Automation Framework (Recommended)

**Pros:**
- Consistent test execution
- Reproducible results
- Better control over scan phases
- Can version control configuration

**Cons:**
- Requires configuration file
- More complex setup

**Implementation:**
```yaml
# Use automation framework instead of zap-full-scan.py
docker run --rm --network zap-net \
  --user root \
  -v "${GITHUB_WORKSPACE}/python:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd \
  -autorun /zap/wrk/zap-automation.yaml
```

### Solution 3: Increase Time Limit

**Pros:**
- Simple change
- More thorough than current
- Still has safety timeout

**Cons:**
- Still may not complete
- Results still vary slightly

**Implementation:**
```yaml
# Increase from 20 to 30 or 45 minutes
-m 45
```

### Solution 4: Use Context File for Scope

**Pros:**
- Limits scan to specific areas
- Faster and more consistent
- Focuses on important endpoints

**Cons:**
- May miss some vulnerabilities
- Requires maintenance

**Implementation:**
Create context file defining exact scope:
```xml
<!-- .zap/context.xml -->
<context>
  <name>PyGoat</name>
  <includedUrls>
    <url>http://pygoat-app:8000/.*</url>
  </includedUrls>
  <excludedUrls>
    <url>http://pygoat-app:8000/static/.*</url>
    <url>http://pygoat-app:8000/media/.*</url>
  </excludedUrls>
</context>
```

## Recommended Approach

### For Development/PR Checks:
Use baseline scan (fast, consistent enough):
```yaml
zap-baseline.py -t http://app:8000 -I
```

### For Staging/Pre-Production:
Use full scan with longer timeout:
```yaml
zap-full-scan.py -t http://app:8000 -m 45 -a -l INFO
```

### For Production Validation:
Use automation framework (most consistent):
```yaml
zap.sh -cmd -autorun /zap/wrk/zap-automation.yaml
```

## Monitoring Scan Consistency

### Track These Metrics:
1. **Scan Duration**: Should be similar each run
2. **URLs Discovered**: Track spider coverage
3. **Alert Types**: Should stabilize over time
4. **High/Critical Findings**: Most important to track

### Example Tracking:
```bash
# In workflow, log key metrics
echo "Scan Duration: $(cat zap-report.json | jq '.duration')"
echo "URLs Found: $(cat zap-report.json | jq '.site[].alerts | length')"
echo "High Risk: $(cat zap-report.json | jq '[.site[].alerts[] | select(.riskcode=="3")] | length')"
```

## Understanding Acceptable Variation

### Expected Variations (Normal):
- ±10-20% in total findings
- ±5-10 alert types
- Different instance counts for same alert

### Concerning Variations (Investigate):
- >50% change in findings
- New high/critical alerts appearing randomly
- Scan duration varying by >30%
- Spider finding vastly different URL counts

## Debugging Inconsistent Scans

### Check These:
1. **Application State**:
   ```bash
   # Verify app is in consistent state
   docker logs pygoat-app | grep ERROR
   ```

2. **Spider Coverage**:
   ```bash
   # Check URLs discovered
   grep "Total of" zap-warnings.md
   ```

3. **Scan Completion**:
   ```bash
   # Check if scan timed out
   grep "Scan incomplete" zap-warnings.md
   ```

4. **Network Issues**:
   ```bash
   # Test connectivity
   docker run --rm --network zap-net curlimages/curl:latest \
     curl -v http://pygoat-app:8000
   ```

## Best Practices

### 1. Stabilize Application State
```yaml
# Wait for app to be fully ready
- name: Wait for app stability
  run: |
    sleep 10  # Let app fully initialize
    for i in {1..5}; do
      curl -f http://pygoat-app:8000/health || sleep 2
    done
```

### 2. Use Consistent Spider Settings
```yaml
-z "-config spider.maxDuration=10 -config spider.maxDepth=5"
```

### 3. Exclude Dynamic Content
```yaml
# Exclude URLs that change frequently
-z "-config spider.excludeUrl=.*timestamp.*"
-z "-config spider.excludeUrl=.*random.*"
```

### 4. Set Deterministic Seeds (if possible)
```yaml
# For applications with random behavior
env:
  RANDOM_SEED: "12345"
  DISABLE_CSRF_ROTATION: "true"
```

### 5. Run Multiple Times and Average
```yaml
# Run scan 3 times and compare
- name: ZAP Scan 1
  run: [scan command]
- name: ZAP Scan 2
  run: [scan command]
- name: ZAP Scan 3
  run: [scan command]
- name: Compare Results
  run: python compare_zap_results.py
```

## Quick Fix for Your Current Issue

The simplest fix to get more consistent results:

```yaml
# Option A: Remove time limit (let it complete)
-m 0  # or remove -m flag entirely

# Option B: Increase time significantly
-m 45  # 45 minutes

# Option C: Add deterministic spider config
-z "-config spider.maxDuration=10 -config spider.maxDepth=5 -config spider.maxChildren=10"
```

## Summary

**Current Issue**: Scan results vary because 20-minute timeout causes incomplete scans

**Quick Fix**: Increase timeout to 45 minutes or remove it

**Best Fix**: Use ZAP Automation Framework with defined configuration

**Acceptable Variation**: ±10-20% in findings is normal for dynamic testing

**Monitor**: Track high/critical findings - these should be consistent
