# API-Recon-VA-Scanner-

readme_content = """# 🔍 API Security Toolkit v3.0

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP API Security](https://img.shields.io/badge/OWASP-API%20Security%20Top%2010%202023-red)](https://owasp.org/www-project-api-security/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Unified Reconnaissance & Vulnerability Assessment for APIs**

A comprehensive, single-tool solution for API penetration testing that combines **automated reconnaissance** with **vulnerability assessment** against the [OWASP API Security Top 10 2023](https://owasp.org/www-project-api-security/).

---

## ✨ Features

- 🎯 **Three Operating Modes**: Reconnaissance, Vulnerability Assessment, or Full Pipeline
- 🔍 **Smart Recon**: Auto-discovers API docs (Swagger/OpenAPI), endpoints, tech stack
- 🛡️ **OWASP Coverage**: Tests for all API Security Top 10 vulnerabilities
- 🔗 **Seamless Workflow**: Recon feeds directly into VA or run standalone
- 📊 **Structured Output**: JSON reports for CI/CD integration
- 🔐 **Auth Support**: JWT/API key authentication for authenticated testing
- ⚡ **Fast & Efficient**: Concurrent testing with intelligent rate limiting

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/api-security-toolkit.git
cd api-security-toolkit

# Install dependencies
pip install requests urllib3
```

### Basic Usage

```bash
# Full assessment (recon + vulnerability scan)
python api_security_toolkit.py -t https://api.example.com

# Reconnaissance only
python api_security_toolkit.py -t https://api.example.com --mode recon

# Vulnerability assessment from recon report
python api_security_toolkit.py -t https://api.example.com --mode va -r recon_report.json

# Test specific endpoint
python api_security_toolkit.py -t https://api.example.com --mode va -e "GET:/api/users/123"
```

---

## 📖 Usage Guide

### Command Line Options

```
Required:
  -t, --target          Target API base URL (e.g., https://api.example.com)

Mode Selection:
  -m, --mode            Choose: recon, va, full (default: full)

Input Options:
  -r, --recon-file      Path to recon report JSON (for VA mode)
  -e, --endpoint        Test specific endpoint (format: METHOD:/path)

Authentication:
  -k, --token           Authorization token or JWT

Output:
  -o, --output          Output directory for reports (default: current dir)
```

### Operating Modes

#### 🔍 Mode: `recon` (Reconnaissance)

Discovers API surface without active vulnerability testing.

**What it finds:**
- API documentation (Swagger/OpenAPI specs)
- Common endpoints (/api/v1/users, /admin, /graphql, etc.)
- Technology stack (framework fingerprinting)
- CORS misconfigurations

**Example:**
```bash
python api_security_toolkit.py -t https://api.target.com --mode recon -o ./reports
```

**Output:** `recon_report_YYYYMMDD_HHMMSS.json`

---

#### 🛡️ Mode: `va` (Vulnerability Assessment)

Tests for security vulnerabilities. Requires endpoints from recon or manual specification.

**What it tests:**
| OWASP Category | Vulnerability | Severity |
|----------------|---------------|----------|
| API1:2023 | BOLA/IDOR (Insecure Direct Object Reference) | 🔴 Critical |
| API2:2023 | Broken Authentication (JWT issues) | 🔴 Critical |
| API3:2023 | Excessive Data Exposure | 🟠 High |
| API4:2023 | Lack of Resources & Rate Limiting | 🟡 Medium |
| API5:2023 | Broken Function Level Authorization | 🔴 Critical |
| API6:2023 | Mass Assignment | 🔴 Critical |
| API7:2023 | Security Misconfiguration | 🟡 Medium |
| API8:2023 | Injection (SQLi) | 🔴 Critical |
| API9:2023 | Improper Assets Management | 🟠 High |

**Example - From Recon Report:**
```bash
python api_security_toolkit.py -t https://api.target.com \\
    --mode va \\
    -r recon_report_20240315_143022.json \\
    -k "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Example - Single Endpoint:**
```bash
python api_security_toolkit.py -t https://api.target.com \\
    --mode va \\
    -e "POST:/api/v1/users" \\
    -k "Bearer YOUR_TOKEN_HERE"
```

**Output:** `va_report_YYYYMMDD_HHMMSS.json`

---

#### 🚀 Mode: `full` (Full Pipeline) **[Default]**

Complete automated assessment: **Reconnaissance → Vulnerability Assessment**

Automatically discovers endpoints and tests each for vulnerabilities.

**Example:**
```bash
python api_security_toolkit.py -t https://api.target.com --mode full
```

**Output:** `full_assessment_YYYYMMDD_HHMMSS.json`

---

## 📊 Output Format

### Recon Report Structure
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
    },
    {
      "path": "/api/v1/admin",
      "method": "GET", 
      "status_code": 401,
      "source": "fuzz"
    }
  ],
  "tech_stack": {
    "server": "nginx/1.18.0",
    "framework": "Express.js"
  }
}
```

### VA Report Structure
```json
{
  "scan_type": "vulnerability_assessment",
  "target": "https://api.example.com",
  "timestamp": "2024-03-15T14:35:10",
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
      "remediation": "Implement object-level authorization checks for every resource access"
    }
  ]
}
```

---

## 🎯 Workflow Examples

### 1. Quick Security Assessment
Perfect for initial security audits or CI/CD pipelines.

```bash
# Run full assessment
python api_security_toolkit.py -t https://api.staging.company.com --mode full

# Check results
cat full_assessment_*.json | jq '.va.summary'
```

### 2. Stealthy Reconnaissance First
When you want to review endpoints before active testing.

```bash
# Step 1: Passive reconnaissance
python api_security_toolkit.py -t https://api.target.com --mode recon

# Step 2: Review discovered endpoints
cat recon_report_*.json | jq '.endpoints[] | select(.status_code == 200)'

# Step 3: Targeted testing on sensitive endpoints
python api_security_toolkit.py -t https://api.target.com \\
    --mode va \\
    -e "GET:/api/admin/users" \\
    -k "$ADMIN_TOKEN"
```

### 3. Authenticated Testing
Test with different privilege levels.

```bash
# Test as regular user
python api_security_toolkit.py -t https://api.target.com \\
    --mode va \\
    -r recon_report.json \\
    -k "$USER_JWT"

# Test as admin
python api_security_toolkit.py -t https://api.target.com \\
    --mode va \\
    -r recon_report.json \\
    -k "$ADMIN_JWT"
```

### 4. CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: API Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run API Security Toolkit
        run: |
          pip install requests urllib3
          python api_security_toolkit.py \\
            -t https://api.staging.company.com \\
            --mode full \\
            -o ./security-reports
      
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICAL_COUNT=$(cat security-reports/full_assessment_*.json | \\
            jq '.va.summary.severity_counts.CRITICAL // 0')
          if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "❌ $CRITICAL_COUNT CRITICAL vulnerabilities found!"
            exit 1
          fi
```

---

## 🔧 Integration with Security Tools

### Burp Suite Workflow
1. **Run recon**: `python api_security_toolkit.py -t target.com --mode recon`
2. **Import to Burp**: Import discovered endpoints into Target → Site Map
3. **Run VA**: `python api_security_toolkit.py -t target.com --mode va -r recon.json`
4. **Manual verification**: Use Burp Repeater to verify findings
5. **Deep testing**: Use Burp Intruder on identified vulnerable parameters

### Postman Workflow
1. **Run recon** to discover endpoints
2. **Import** `recon_report.json` into Postman
3. **Create collection** from discovered paths
4. **Manual testing** of business logic flows
5. **Use VA results** to prioritize testing focus

---

## 🛡️ OWASP API Top 10 Coverage

| # | Category | Detection Capability | Status |
|---|----------|---------------------|--------|
| API1 | Broken Object Level Authorization | IDOR, UUID bypass, path traversal | ✅ Full |
| API2 | Broken Authentication | JWT analysis, weak secrets, expiration | ✅ Full |
| API3 | Excessive Data Exposure | Sensitive field detection, PII exposure | ✅ Full |
| API4 | Lack of Resources & Rate Limiting | Burst testing, header validation | ✅ Full |
| API5 | Broken Function Level Authorization | Admin bypass, method switching | ✅ Full |
| API6 | Mass Assignment | Privileged field injection | ✅ Full |
| API7 | Security Misconfiguration | Headers, CORS, verbose errors | ✅ Full |
| API8 | Injection | SQL Injection detection | ✅ Full |
| API9 | Improper Assets Management | Old API versions, debug endpoints | ✅ Full |
| API10 | Insufficient Logging & Monitoring | Limited testing (requires log access) | ⚠️ Partial |

---

## ⚠️ Important Notes

### Legal & Authorization
- **Only test systems you own or have explicit written permission to test**
- Unauthorized testing is illegal under computer fraud laws (CFAA, etc.)
- Always obtain proper authorization before scanning

### Rate Limiting & Ethics
- Tool includes basic delays between requests
- Add `time.sleep()` in code for slower, stealthier testing
- Respect rate limits to avoid service disruption
- Consider whitelisting your IP with the target organization

### False Positives
- Automated tools produce false positives
- Always manually verify **CRITICAL** findings with Burp Suite
- Review evidence in JSON reports before reporting

---

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| SSL Certificate Errors | Tool uses `verify=False` for testing environments. For production, use valid certificates. |
| Rate Limited by Target | Increase delays in `_request()` method or use `--mode recon` with longer intervals. |
| No Endpoints Found | Check if API requires authentication (`-k` flag) or specific headers. |
| False Positives | Manually verify in Burp Suite. Check context and evidence in JSON report. |
| Import Errors | Run `pip install requests urllib3` to install dependencies. |

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/
```

## 🙏 Acknowledgments

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [Burp Suite](https://portswigger.net/burp) for manual verification workflows

<p align="center">
  <b>🔒 Secure APIs. Automated. Simplified.</b>
</p>
"""

