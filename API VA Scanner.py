import argparse
import json
import re
import time
import urllib3
import base64
import sys
import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APISecurityToolkit:
    """
    Unified API Security Toolkit
    Modes: recon, va (vulnerability assessment), full (recon + va)
    """
    
    def __init__(self, target, auth_token=None, headers=None, output_dir=None):
        self.target = target.rstrip('/')
        self.auth_token = auth_token
        self.headers = headers or {'User-Agent': 'API-Security-Toolkit/3.0', 'Accept': 'application/json'}
        if auth_token:
            self.headers['Authorization'] = f"Bearer {auth_token}"
        
        self.output_dir = output_dir or '.'
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Shared state
        self.discovered_endpoints = []
        self.api_spec = None
        self.vulnerabilities = []
        self.tested_endpoints = set()
        self.recon_data = {}
        
    # ═══════════════════════════════════════════════════════════════════
    # MODE: RECONNAISSANCE
    # ═══════════════════════════════════════════════════════════════════
    
    def run_recon(self, save_file=None):
        """
        Run full reconnaissance mode
        """
        print(f"\n{'='*70}")
        print(f"🔍 API RECONNAISSANCE MODE")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # 1. Check for API documentation
        self._check_api_docs()
        
        # 2. Fuzz common endpoints
        self._fuzz_common_endpoints()
        
        # 3. Analyze technology stack
        self._analyze_tech_stack()
        
        # 4. Check CORS policy
        self._check_cors()
        
        # 5. Generate and save report
        report = self._generate_recon_report()
        
        output_file = save_file or f"{self.output_dir}/recon_report_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"✅ RECON COMPLETE")
        print(f"   Endpoints discovered: {len(self.discovered_endpoints)}")
        print(f"   Report saved: {output_file}")
        print(f"{'='*70}\n")
        
        return report
    
    def _check_api_docs(self):
        """Discover API documentation"""
        doc_paths = [
            '/swagger.json', '/swagger-ui.html', '/api-docs', '/openapi.json',
            '/v2/api-docs', '/v3/api-docs', '/api/swagger.json', '/docs',
            '/redoc', '/api.html', '/openapi.yaml', '/.well-known/openapi.json'
        ]
        
        print("[*] Searching for API documentation...")
        for path in doc_paths:
            try:
                url = urljoin(self.target, path)
                resp = requests.get(url, headers=self.headers, timeout=10, verify=False)
                if resp.status_code == 200:
                    print(f"  [+] Found: {url}")
                    if 'json' in resp.headers.get('Content-Type', ''):
                        try:
                            self.api_spec = resp.json()
                            # Parse spec endpoints
                            for path_key, methods in self.api_spec.get('paths', {}).items():
                                for method, details in methods.items():
                                    if method in ['get', 'post', 'put', 'delete', 'patch']:
                                        self.discovered_endpoints.append({
                                            'path': path_key,
                                            'method': method.upper(),
                                            'source': 'openapi_spec',
                                            'details': details
                                        })
                            print(f"  [+] Parsed {len(self.discovered_endpoints)} endpoints from spec")
                            return
                        except:
                            pass
            except:
                continue
        print("  [-] No API documentation found")
    
    def _fuzz_common_endpoints(self):
        """Fuzz common API endpoints"""
        common_paths = [
            '/api/v1/users', '/api/v1/admin', '/api/v1/login', '/api/v1/register',
            '/api/v2/users', '/api/users', '/api/admin', '/api/login',
            '/api/health', '/api/status', '/api/config', '/api/settings',
            '/api/v1/orders', '/api/v1/products', '/api/v1/items',
            '/graphql', '/api/graphql', '/gql',
            '/api/v1/profile', '/api/v1/account', '/api/v1/me',
            '/api/v1/search', '/api/v1/export', '/api/v1/import',
            '/api/v1/files', '/api/v1/upload', '/api/v1/download',
            '/actuator/health', '/actuator/info', '/actuator/env',
            '/api/v1/dashboard', '/api/v1/reports', '/api/v1/analytics'
        ]
        
        print(f"\n[*] Fuzzing {len(common_paths)} common endpoints...")
        found_count = 0
        
        for path in common_paths:
            try:
                url = urljoin(self.target, path)
                resp = requests.get(url, headers=self.headers, timeout=5, verify=False, allow_redirects=False)
                
                if resp.status_code != 404:
                    self.discovered_endpoints.append({
                        'path': path,
                        'method': 'GET',
                        'status_code': resp.status_code,
                        'content_type': resp.headers.get('Content-Type', 'unknown'),
                        'size': len(resp.content),
                        'source': 'fuzzing'
                    })
                    found_count += 1
                    status_icon = "✅" if resp.status_code == 200 else "⚠️ " if resp.status_code in [401, 403] else "❓"
                    print(f"  {status_icon} [{resp.status_code}] {path} ({len(resp.content)} bytes)")
            except:
                continue
        
        print(f"  Found {found_count} active endpoints")
    
    def _analyze_tech_stack(self):
        """Fingerprint technology stack"""
        print(f"\n[*] Analyzing technology stack...")
        try:
            resp = requests.get(self.target, headers=self.headers, timeout=10, verify=False)
            
            stack_info = {
                'server': resp.headers.get('Server', 'Unknown'),
                'powered_by': resp.headers.get('X-Powered-By', 'Unknown'),
                'framework': 'Unknown'
            }
            
            # Framework detection
            body = resp.text.lower()
            cookies = resp.headers.get('Set-Cookie', '').lower()
            
            if 'laravel' in body or 'laravel_session' in cookies:
                stack_info['framework'] = 'Laravel/PHP'
            elif 'express' in body:
                stack_info['framework'] = 'Express.js/Node'
            elif 'django' in body or 'csrftoken' in cookies:
                stack_info['framework'] = 'Django/Python'
            elif 'spring' in body:
                stack_info['framework'] = 'Spring Boot/Java'
            elif 'rails' in body:
                stack_info['framework'] = 'Ruby on Rails'
            
            self.recon_data['tech_stack'] = stack_info
            print(f"  Server: {stack_info['server']}")
            print(f"  Framework: {stack_info['framework']}")
            
        except Exception as e:
            self.recon_data['tech_stack'] = {'error': str(e)}
            print(f"  Error: {e}")
    
    def _check_cors(self):
        """Check CORS configuration"""
        print(f"\n[*] Testing CORS policy...")
        test_origins = ['https://evil.com', 'null', self.target]
        cors_issues = []
        
        for origin in test_origins:
            try:
                test_headers = self.headers.copy()
                test_headers['Origin'] = origin
                resp = requests.options(self.target, headers=test_headers, timeout=5, verify=False)
                
                allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
                allow_creds = resp.headers.get('Access-Control-Allow-Credentials', '')
                
                if allow_origin == origin:
                    severity = 'HIGH' if allow_creds.lower() == 'true' else 'MEDIUM'
                    cors_issues.append({
                        'origin': origin,
                        'allow_origin': allow_origin,
                        'allow_credentials': allow_creds,
                        'severity': severity
                    })
            except:
                continue
        
        self.recon_data['cors_issues'] = cors_issues
        if cors_issues:
            print(f"  ⚠️  Found {len(cors_issues)} CORS configuration issues")
        else:
            print("  ✅ CORS looks properly configured")
    
    def _generate_recon_report(self):
        """Generate recon report"""
        return {
            'scan_type': 'reconnaissance',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_endpoints': len(self.discovered_endpoints),
                'documentation_found': self.api_spec is not None,
                'cors_issues': len(self.recon_data.get('cors_issues', []))
            },
            'endpoints': self.discovered_endpoints,
            'tech_stack': self.recon_data.get('tech_stack', {}),
            'cors_analysis': self.recon_data.get('cors_issues', []),
            'api_spec': self.api_spec is not None
        }

    # ═══════════════════════════════════════════════════════════════════
    # MODE: VULNERABILITY ASSESSMENT
    # ═══════════════════════════════════════════════════════════════════
    
    def run_va(self, recon_file=None, endpoints=None, save_file=None):
        """
        Run vulnerability assessment mode
        Can load from recon file or use provided endpoints
        """
        print(f"\n{'='*70}")
        print(f"🛡️  VULNERABILITY ASSESSMENT MODE")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Load endpoints to test
        if recon_file:
            self._load_from_recon(recon_file)
        elif endpoints:
            self.discovered_endpoints = endpoints
        else:
            print("[!] No endpoints provided. Use --recon-file or run in 'full' mode")
            return None
        
        print(f"[*] Loaded {len(self.discovered_endpoints)} endpoints for testing\n")
        
        # Run VA tests on each endpoint
        for i, endpoint in enumerate(self.discovered_endpoints, 1):
            print(f"[{i}/{len(self.discovered_endpoints)}] Testing {endpoint.get('method', 'GET')} {endpoint.get('path', '/')}")
            self._scan_endpoint_for_vulnerabilities(endpoint)
        
        # Generate report
        report = self._generate_va_report()
        
        output_file = save_file or f"{self.output_dir}/va_report_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._print_va_summary()
        print(f"\n✅ Report saved: {output_file}\n")
        
        return report
    
    def _load_from_recon(self, recon_file):
        """Load endpoints from recon report"""
        try:
            with open(recon_file, 'r') as f:
                data = json.load(f)
                self.discovered_endpoints = data.get('endpoints', [])
                print(f"[+] Loaded {len(self.discovered_endpoints)} endpoints from {recon_file}")
        except Exception as e:
            print(f"[!] Error loading recon file: {e}")
            self.discovered_endpoints = []
    
    def _scan_endpoint_for_vulnerabilities(self, endpoint):
        """Run all VA tests on a single endpoint"""
        method = endpoint.get('method', 'GET')
        path = endpoint.get('path', '/')
        
        endpoint_key = f"{method}:{path}"
        if endpoint_key in self.tested_endpoints:
            return
        self.tested_endpoints.add(endpoint_key)
        
        findings = []
        
        # Run all security tests
        findings.extend(self._test_bola(method, path))
        findings.extend(self._test_broken_auth(method, path))
        findings.extend(self._test_data_exposure(method, path))
        findings.extend(self._test_rate_limiting(method, path))
        findings.extend(self._test_function_auth(method, path))
        findings.extend(self._test_mass_assignment(method, path))
        findings.extend(self._test_security_config(method, path))
        findings.extend(self._test_injection(method, path))
        findings.extend(self._test_assets_mgmt(path))
        
        if findings:
            self.vulnerabilities.extend(findings)
            for f in findings:
                icon = "🔴" if f['severity'] == 'CRITICAL' else "🟠" if f['severity'] == 'HIGH' else "🟡"
                print(f"    {icon} {f['type']}")
        else:
            print(f"    ✅ No issues detected")
    
    # [Include all the VA test methods from previous scanner]
    def _test_bola(self, method, path):
        """Test for Broken Object Level Authorization (IDOR)"""
        findings = []
        
        if any(ind in path.lower() for ind in ['user', 'order', 'account', 'profile', 'item']):
            # Test ID by incrementing
            test_path = re.sub(r'/(\d+)(/|$)', lambda m: f'/{int(m.group(1))+1}{m.group(2)}', path)
            if test_path != path:
                try:
                    resp = self._make_request(method, test_path)
                    if resp.status_code == 200 and len(resp.content) > 100:
                        findings.append({
                            'type': 'BOLA/IDOR',
                            'severity': 'CRITICAL',
                            'endpoint': f"{method} {path}",
                            'description': f'IDOR: {test_path} accessible without authorization',
                            'evidence': f'Status 200, {len(resp.content)} bytes',
                            'remediation': 'Implement object-level authorization checks'
                        })
                except:
                    pass
        
        # UUID bypass test
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        if re.search(uuid_pattern, path):
            test_path = re.sub(uuid_pattern, '00000000-0000-0000-0000-000000000000', path)
            try:
                resp = self._make_request(method, test_path)
                if resp.status_code not in [404, 403]:
                    findings.append({
                        'type': 'BOLA/UUID Bypass',
                        'severity': 'HIGH',
                        'endpoint': f"{method} {path}",
                        'description': 'UUID validation bypass possible',
                        'remediation': 'Validate UUIDs and authorization server-side'
                    })
            except:
                pass
        
        return findings
    
    def _test_broken_auth(self, method, path):
        """Test for Broken Authentication"""
        findings = []
        
        if self.auth_token and self.auth_token.startswith('eyJ'):
            try:
                # Check JWT structure
                header = json.loads(base64.b64decode(self.auth_token.split('.')[0] + '=='))
                payload = json.loads(base64.b64decode(self.auth_token.split('.')[1] + '=='))
                
                if header.get('alg') == 'none':
                    findings.append({
                        'type': 'Broken Auth - JWT None',
                        'severity': 'CRITICAL',
                        'endpoint': f"{method} {path}",
                        'description': 'JWT accepts "none" algorithm',
                        'remediation': 'Explicitly specify allowed algorithms'
                    })
                
                if 'exp' not in payload:
                    findings.append({
                        'type': 'Broken Auth - JWT No Expiration',
                        'severity': 'HIGH',
                        'endpoint': f"{method} {path}",
                        'description': 'JWT token has no expiration',
                        'remediation': 'Add exp claim with short validity'
                    })
            except:
                pass
        
        return findings
    
    def _test_data_exposure(self, method, path):
        """Test for Excessive Data Exposure"""
        findings = []
        try:
            resp = self._make_request(method, path)
            if resp.status_code == 200:
                text = resp.text.lower()
                sensitive = ['password', 'secret', 'private_key', 'credit_card', 'ssn']
                found = [s for s in sensitive if s in text]
                if found:
                    findings.append({
                        'type': 'Excessive Data Exposure',
                        'severity': 'HIGH',
                        'endpoint': f"{method} {path}",
                        'description': f'Sensitive fields exposed: {", ".join(found)}',
                        'remediation': 'Filter sensitive data from API responses'
                    })
        except:
            pass
        return findings
    
    def _test_rate_limiting(self, method, path):
        """Test for Rate Limiting"""
        findings = []
        responses = []
        
        for _ in range(5):
            try:
                resp = self._make_request(method, path, timeout=3)
                responses.append(resp.status_code)
            except:
                responses.append(0)
            time.sleep(0.2)
        
        if all(r == 200 for r in responses):
            findings.append({
                'type': 'Missing Rate Limiting',
                'severity': 'MEDIUM',
                'endpoint': f"{method} {path}",
                'description': 'No rate limiting detected (5 rapid requests succeeded)',
                'remediation': 'Implement rate limiting per IP/user'
            })
        
        return findings
    
    def _test_function_auth(self, method, path):
        """Test for Broken Function Level Authorization"""
        findings = []
        
        if any(ind in path.lower() for ind in ['/admin/', '/manage/', '/config/']):
            try:
                resp = self._make_request(method, path)
                if resp.status_code == 200:
                    findings.append({
                        'type': 'Broken Function Level Auth',
                        'severity': 'CRITICAL',
                        'endpoint': f"{method} {path}",
                        'description': 'Admin endpoint accessible without proper authorization',
                        'remediation': 'Implement RBAC for administrative functions'
                    })
            except:
                pass
        
        # HTTP method switching
        if method == 'GET':
            try:
                resp = self._make_request('POST', path, data={'test': 'value'})
                if resp.status_code not in [405, 404, 401, 403]:
                    findings.append({
                        'type': 'HTTP Method Override',
                        'severity': 'HIGH',
                        'endpoint': f"{method} {path}",
                        'description': f'Endpoint accepts POST (returned {resp.status_code})',
                        'remediation': 'Explicitly define allowed HTTP methods'
                    })
            except:
                pass
        
        return findings
    
    def _test_mass_assignment(self, method, path):
        """Test for Mass Assignment"""
        findings = []
        
        if method in ['POST', 'PUT', 'PATCH']:
            dangerous = [{'is_admin': True}, {'role': 'admin'}, {'admin': True}]
            for payload in dangerous:
                try:
                    resp = self._make_request(method, path, data=payload)
                    if resp.status_code in [200, 201]:
                        findings.append({
                            'type': 'Mass Assignment',
                            'severity': 'CRITICAL',
                            'endpoint': f"{method} {path}",
                            'description': f'Accepts privileged field: {list(payload.keys())[0]}',
                            'remediation': 'Use property allowlists for input binding'
                        })
                        break
                except:
                    continue
        
        return findings
    
    def _test_security_config(self, method, path):
        """Test for Security Misconfiguration"""
        findings = []
        try:
            resp = self._make_request(method, path)
            
            # Security headers
            required_headers = ['X-Content-Type-Options', 'X-Frame-Options']
            for header in required_headers:
                if header not in resp.headers:
                    findings.append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'endpoint': f"{method} {path}",
                        'description': f'Missing {header}',
                        'remediation': f'Add {header} header to responses'
                    })
            
            # Verbose errors
            if resp.status_code >= 400:
                error_indicators = ['stack trace', 'exception', 'sql', 'syntax error']
                if any(ind in resp.text.lower() for ind in error_indicators):
                    findings.append({
                        'type': 'Verbose Error Messages',
                        'severity': 'MEDIUM',
                        'endpoint': f"{method} {path}",
                        'description': 'Error response leaks internal details',
                        'remediation': 'Use generic error messages for clients'
                    })
        except:
            pass
        return findings
    
    def _test_injection(self, method, path):
        """Test for Injection vulnerabilities"""
        findings = []
        
        # SQL Injection
        sqli_payloads = ["' OR '1'='1", "' UNION SELECT null--"]
        for payload in sqli_payloads:
            try:
                test_path = f"{path}?q={payload}"
                resp = self._make_request(method, test_path)
                if any(err in resp.text.lower() for err in ['sql', 'mysql', 'syntax error']):
                    findings.append({
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'endpoint': f"{method} {path}",
                        'description': f'SQL error triggered with payload',
                        'remediation': 'Use parameterized queries'
                    })
                    break
            except:
                continue
        
        return findings
    
    def _test_assets_mgmt(self, path):
        """Test for Improper Assets Management"""
        findings = []
        
        version_tests = [
            path.replace('/v2/', '/v1/'),
            path.replace('/api/v1/', '/api/beta/'),
            path.replace('/api/v1/', '/api/dev/')
        ]
        
        for test_path in set(version_tests):
            if test_path != path:
                try:
                    resp = self._make_request('GET', test_path)
                    if resp.status_code == 200:
                        findings.append({
                            'type': 'Old API Version',
                            'severity': 'HIGH',
                            'endpoint': f"GET {path}",
                            'description': f'Old version accessible: {test_path}',
                            'remediation': 'Retire deprecated API versions'
                        })
                        break
                except:
                    pass
        
        return findings
    
    def _make_request(self, method, path, data=None, timeout=10):
        """Make HTTP request"""
        import requests
        url = urljoin(self.target, path)
        kwargs = {
            'headers': self.headers,
            'timeout': timeout,
            'verify': False
        }
        if data:
            kwargs['json'] = data
        return requests.request(method, url, **kwargs)
    
    def _generate_va_report(self):
        """Generate VA report"""
        severity_counts = defaultdict(int)
        for v in self.vulnerabilities:
            severity_counts[v['severity']] += 1
        
        return {
            'scan_type': 'vulnerability_assessment',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'endpoints_tested': len(self.tested_endpoints),
                'vulnerabilities_found': len(self.vulnerabilities),
                'severity_breakdown': dict(severity_counts)
            },
            'vulnerabilities': self.vulnerabilities
        }
    
    def _print_va_summary(self):
        """Print VA summary"""
        print(f"\n{'='*70}")
        print("🛡️  VULNERABILITY ASSESSMENT SUMMARY")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Endpoints Tested: {len(self.tested_endpoints)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            counts = defaultdict(int)
            for v in self.vulnerabilities:
                counts[v['severity']] += 1
            
            print("\nSeverity Breakdown:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if counts[sev] > 0:
                    icon = "🔴" if sev == 'CRITICAL' else "🟠" if sev == 'HIGH' else "🟡" if sev == 'MEDIUM' else "🟢"
                    print(f"  {icon} {sev}: {counts[sev]}")
            
            print("\n🔥 Critical/High Priority:")
            critical_high = [v for v in self.vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']]
            for i, vuln in enumerate(critical_high[:5], 1):
                print(f"  {i}. [{vuln['severity']}] {vuln['type']} - {vuln['endpoint']}")
        else:
            print("\n✅ No vulnerabilities detected!")
        
        print(f"{'='*70}")

    # ═══════════════════════════════════════════════════════════════════
    # MODE: FULL PIPELINE (RECON + VA)
    # ═══════════════════════════════════════════════════════════════════
    
    def run_full_pipeline(self):
        """
        Run complete pipeline: Reconnaissance → Vulnerability Assessment
        """
        print(f"\n{'='*70}")
        print(f"🚀 FULL SECURITY ASSESSMENT PIPELINE")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"This will run RECON → VA automatically\n")
        
        # Step 1: Reconnaissance
        recon_report = self.run_recon()
        
        if not self.discovered_endpoints:
            print("[!] No endpoints discovered. Cannot proceed with VA.")
            return None
        
        # Step 2: Vulnerability Assessment
        print("\n" + "="*70)
        print("AUTO-PROCEEDING TO VULNERABILITY ASSESSMENT")
        print("="*70)
        
        va_report = self.run_va(endpoints=self.discovered_endpoints)
        
        # Combined report
        combined = {
            'scan_type': 'full_assessment',
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'recon': recon_report,
            'vulnerability_assessment': va_report
        }
        
        output_file = f"{self.output_dir}/full_assessment_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(combined, f, indent=2)
        
        print(f"\n{'='*70}")
        print(f"🎯 FULL ASSESSMENT COMPLETE")
        print(f"   Combined report: {output_file}")
        print(f"{'='*70}\n")
        
        return combined


# ═══════════════════════════════════════════════════════════════════
# COMMAND LINE INTERFACE
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='🔍 API Security Toolkit - Reconnaissance & Vulnerability Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reconnaissance mode
  python api_toolkit.py -t https://api.example.com --mode recon
  
  # VA mode with existing recon report
  python api_toolkit.py -t https://api.example.com --mode va --recon-file recon_report.json
  
  # Full pipeline (recon + va)
  python api_toolkit.py -t https://api.example.com --mode full
  
  # VA on specific endpoint
  python api_toolkit.py -t https://api.example.com --mode va --endpoint "GET:/api/users/123"
  
  # With authentication
  python api_toolkit.py -t https://api.example.com --mode full --token "eyJ..."
        """
    )
    
    # Required arguments
    parser.add_argument('-t', '--target', required=True, 
                       help='Target API base URL (e.g., https://api.example.com)')
    
    # Mode selection
    parser.add_argument('-m', '--mode', choices=['recon', 'va', 'full'], default='full',
                       help='Scanning mode: recon (discovery), va (vulnerability assessment), full (both)')
    
    # Input options
    parser.add_argument('-r', '--recon-file', 
                       help='Load endpoints from recon report (for VA mode)')
    parser.add_argument('-e', '--endpoint', 
                       help='Test specific endpoint in format METHOD:/path (e.g., GET:/api/users)')
    
    # Authentication
    parser.add_argument('-k', '--token', 
                       help='Authorization token/JWT for authenticated testing')
    parser.add_argument('--header', action='append', 
                       help='Custom headers (format: "Key: Value")')
    
    # Output options
    parser.add_argument('-o', '--output', 
                       help='Output directory for reports')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    # Process custom headers
    headers = {'User-Agent': 'API-Security-Toolkit/3.0', 'Accept': 'application/json'}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Initialize toolkit
    toolkit = APISecurityToolkit(
        target=args.target,
        auth_token=args.token,
        headers=headers,
        output_dir=args.output
    )
    
    # Execute based on mode
    try:
        if args.mode == 'recon':
            toolkit.run_recon()
            
        elif args.mode == 'va':
            if args.endpoint:
                # Parse endpoint string
                try:
                    method, path = args.endpoint.split(':', 1)
                    endpoints = [{'method': method.upper(), 'path': path}]
                    toolkit.run_va(endpoints=endpoints)
                except ValueError:
                    print("[!] Invalid endpoint format. Use: METHOD:/path (e.g., GET:/api/users)")
                    sys.exit(1)
            else:
                toolkit.run_va(recon_file=args.recon_file)
                
        elif args.mode == 'full':
            toolkit.run_full_pipeline()
            
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()