[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![OWASP API Security](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010%202023-red)](https://owasp.org/www-project-api-security/)

### Unified Reconnaissance & Vulnerability Assessment for APIs

<p align="center">
  <img src="https://img.shields.io/badge/Recon-🔍-blue" alt="Reconnaissance">
  <img src="https://img.shields.io/badge/VA-🛡️-red" alt="Vulnerability Assessment">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-orange" alt="OWASP Top 10">
</p>

**[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Documentation](#documentation) • [Contributing](#contributing)**

</div>

---

## 🌟 Overview

API Security Toolkit is a comprehensive, single-tool solution for API penetration testing that combines **automated reconnaissance** with **vulnerability assessment** against the [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/).

Unlike other tools that require multiple utilities, this toolkit provides a seamless workflow from discovery to vulnerability confirmation in one unified interface.

### Why This Toolkit?

- 🎯 **All-in-One**: No need to switch between recon and VA tools
- ⚡ **Fast**: Automated pipeline from discovery to vulnerability detection  
- 🔗 **Integrable**: JSON output perfect for CI/CD pipelines
- 🛡️ **Comprehensive**: Covers all OWASP API Top 10 vulnerabilities
- 📊 **Actionable**: Clear severity ratings with remediation guidance

---

## ✨ Features

### 🔍 Reconnaissance Mode
- Auto-discovers API documentation (Swagger/OpenAPI)
- Fuzzes 40+ common API endpoints
- Technology stack fingerprinting (Express, Django, Laravel, Spring)
- CORS misconfiguration detection
- GraphQL endpoint discovery

### 🛡️ Vulnerability Assessment Mode
Tests for **OWASP API Top 10 2023**:

| Category | Vulnerability | Severity |
|----------|--------------|----------|
| API1:2023 | **BOLA/IDOR** - Broken Object Level Authorization | 🔴 Critical |
| API2:2023 | **Broken Authentication** - JWT weaknesses, no expiration | 🔴 Critical |
| API3:2023 | **Excessive Data Exposure** - Sensitive data in responses | 🟠 High |
| API4:2023 | **Resource Consumption** - Missing rate limiting | 🟡 Medium |
| API5:2023 | **Broken Function Auth** - Admin bypass, method switching | 🔴 Critical |
| API6:2023 | **Mass Assignment** - Privileged field injection | 🔴 Critical |
| API7:2023 | **Security Misconfiguration** - Missing headers, verbose errors | 🟡 Medium |
| API8:2023 | **Injection** - SQL Injection detection | 🔴 Critical |
| API9:2023 | **Improper Assets Management** - Old API versions | 🟠 High |

### 🚀 Full Pipeline Mode
Combines both modes: **Reconnaissance → Vulnerability Assessment** automatically

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- `pip` package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/KishanKhetia/API-Security-Toolkit.git
cd API-Recon-VA-Scanner-

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
python api_security_toolkit.py --help
```

---

## 📖 Usage

### Three Operating Modes

#### 1. 🔍 Reconnaissance Mode (`--mode recon`)

Discover API surface without active vulnerability testing.

```bash
python api_security_toolkit.py -t https://api.example.com --mode recon
```

**What it finds:**
- API documentation endpoints
- Common REST endpoints
- Technology stack
- CORS policies

**Output:** `recon_report_YYYYMMDD_HHMMSS.json`

---

#### 2. 🛡️ Vulnerability Assessment Mode (`--mode va`)

Test for security vulnerabilities using discovered endpoints or specific targets.

**From recon report:**
```bash
python api_security_toolkit.py -t https://api.example.com \\
    --mode va \\
    -r recon_report_20240315_143022.json \\
    -k "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Specific endpoint:**
```bash
python api_security_toolkit.py -t https://api.example.com \\
    --mode va \\
    -e "POST:/api/v1/users" \\
    -k "Bearer YOUR_TOKEN_HERE"
```

**Output:** `va_report_YYYYMMDD_HHMMSS.json`

---

#### 3. 🚀 Full Pipeline Mode (`--mode full`) [Default]

Complete automated assessment: **Reconnaissance → Vulnerability Assessment**

```bash
python api_security_toolkit.py -t https://api.example.com --mode full
```

**Output:** `full_assessment_YYYYMMDD_HHMMSS.json`

---

### Command Reference

```
Required Arguments:
  -t, --target          Target API base URL (e.g., https://api.example.com)

Mode Selection:
  -m, --mode            Choose: recon, va, full (default: full)

Input Options:
  -r, --recon-file      Path to recon report JSON (for VA mode)
  -e, --endpoint        Test specific endpoint (format: METHOD:/path)

Authentication:
  -k, --token           Authorization token or JWT

Output Options:
  -o, --output          Output directory for reports (default: current dir)
```

---

## 📊 Output Examples

### Recon Report

```json
{
  "scan_type": "reconnaissance",
  "target": "https://api.example.com",
  "timestamp": "2024-03-15T14:30:22",
  "summary": {
    "total_endpoints": 15,
    "has_docs": true,
    "cors_issues": 1
  },
  "endpoints": [
    {
      "path": "/api/v1/users",
      "method": "GET",
      "status_code": 200,
      "size": 1847,
      "source": "fuzz"
    }
  ],
  "tech_stack": {
    "server": "nginx/1.18.0",
    "framework": "Express.js"
  }
}
```

### VA Report

```json
{
  "scan_type": "vulnerability_assessment",
  "target": "https://api.example.com",
  "summary": {
    "endpoints_tested": 15,
    "vulnerabilities_found": 7,
    "severity_counts": {
      "CRITICAL": 2,
      "HIGH": 2,
      "MEDIUM": 3
    }
  },
  "vulnerabilities": [
    {
      "type": "BOLA/IDOR",
      "severity": "CRITICAL",
      "endpoint": "GET /api/v1/users/123",
      "description": "IDOR: /api/v1/users/124 accessible without authorization",
      "evidence": "Status 200, 1847 bytes returned",
      "remediation": "Implement object-level authorization checks"
    }
  ]
}
```

---

## 🎯 Real-World Workflows

### Workflow 1: CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: API Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install requests urllib3
      
      - name: Run Security Scan
        run: |
          python api_security_toolkit.py \\
            -t ${{ secrets.API_TARGET_URL }} \\
            --mode full \\
            -k ${{ secrets.API_AUTH_TOKEN }} \\
            -o ./security-reports
      
      - name: Check Critical Vulnerabilities
        run: |
          CRITICAL=$(jq -r '.va.summary.severity_counts.CRITICAL // 0' \\
            security-reports/full_assessment_*.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ $CRITICAL Critical vulnerabilities found!"
            exit 1
          fi
```

### Workflow 2: Penetration Testing

```bash
# Step 1: Reconnaissance
python api_security_toolkit.py -t https://api.target.com --mode recon

# Step 2: Review endpoints, identify high-value targets
cat recon_report_*.json | jq '.endpoints[] | select(.status_code == 200)'

# Step 3: Targeted testing on sensitive endpoints
python api_security_toolkit.py -t https://api.target.com \\
    --mode va \\
    -e "GET:/api/admin/users" \\
    -k "$ADMIN_TOKEN"

# Step 4: Import to Burp Suite for manual verification
# Use recon_report.json to populate Target tab
```

### Workflow 3: Multi-Environment Testing

```bash
#!/bin/bash
# test-all-environments.sh

ENVIRONMENTS=("dev" "staging" "prod")

for env in "${ENVIRONMENTS[@]}"; do
    echo "Testing $env environment..."
    python api_security_toolkit.py \\
        -t "https://api-$env.company.com" \\
        --mode full \\
        -o "./reports/$env-$(date +%Y%m%d)"
done

# Generate summary report
echo "=== Security Scan Summary ==="
for report in ./reports/*/full_assessment_*.json; do
    env=$(echo $report | cut -d'/' -f3)
    critical=$(jq -r '.va.summary.severity_counts.CRITICAL // 0' "$report")
    echo "$env: $critical critical issues"
done
```

---

## 🔧 Integration Guide

### Burp Suite Professional

1. **Run reconnaissance**:
   ```bash
   python api_security_toolkit.py -t target.com --mode recon
   ```

2. **Import to Burp**:
   - Open Burp Suite → Target → Site Map
   - Right-click → "Add to scope"
   - Import endpoints from `recon_report.json`

3. **Run VA and verify**:
   ```bash
   python api_security_toolkit.py -t target.com --mode va -r recon.json
   ```
   
4. **Manual verification**: Use Burp Repeater to confirm findings

### Postman

1. **Discover endpoints**:
   ```bash
   python api_security_toolkit.py -t api.example.com --mode recon
   ```

2. **Import to Postman**:
   - File → Import → Select `recon_report.json`
   - Create collection from discovered endpoints

3. **Manual testing**: Test business logic flows identified by VA

---

## 🛡️ Security Considerations

### ⚠️ Legal & Ethical Use

**IMPORTANT**: This tool is intended for authorized security testing only.

- ✅ **DO** test APIs you own
- ✅ **DO** test APIs with explicit written authorization
- ✅ **DO** follow responsible disclosure practices
- ❌ **DON'T** test APIs without permission
- ❌ **DON'T** use for malicious purposes

Unauthorized testing may violate:
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- Local computer crime laws

### Rate Limiting & Ethics

- Tool includes built-in delays between requests
- Add `time.sleep()` for slower, stealthier testing
- Respect rate limits to avoid service disruption
- Consider whitelisting your IP with target organization

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| **SSL Certificate Errors** | Tool uses `verify=False` for testing. For production, use valid certificates. |
| **Rate Limited** | Increase delays in `_request()` method or use `--mode recon` with longer intervals. |
| **No Endpoints Found** | Check if API requires authentication (`-k` flag) or specific headers. |
| **False Positives** | Always manually verify CRITICAL findings with Burp Suite. |
| **Import Errors** | Run `pip install requests urllib3` to install dependencies. |
| **JSON Parse Errors** | Ensure API returns valid JSON (check Content-Type headers). |

---

## 🙏 Acknowledgments

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [PortSwigger Burp Suite](https://portswigger.net/burp) for manual testing workflows
