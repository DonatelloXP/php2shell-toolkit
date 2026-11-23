# php2shell — Unified Exploit Toolkit

**CVE-2026-109618 / CVE-2026-109619** — PHP `session.upload_progress` Remote Code Execution

A comprehensive, production-ready exploit framework supporting **8 attack chains**, a **5-engine zero-day research framework**, WAF evasion, and post-exploitation persistence.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.**

This tool is designed for:
- Authorized penetration testing with written permission
- CTF competitions and security training platforms (TryHackMe, HackTheBox)
- Educational research on PHP vulnerability classes
- Defensive security (detection rule development, WAF tuning)

**Unauthorized use against systems you don't own or have explicit permission to test is illegal.**

---

## 🎯 Vulnerability Overview

| CVE | Name | CVSS | Vector |
|-----|------|------|--------|
| CVE-2026-109618 | OOM Corruption → RCE | 9.2 | `session.upload_progress` + Zend engine `longjmp()` |
| CVE-2026-109619 | Stale State UAF → RCE | 9.2 | FPM worker state reuse across requests |

**Affected:** PHP 5.4.0 – 8.5.11 (14 years of versions)
**Fixed:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12+
**Impact:** ~78% of all websites (WordPress, Joomla, Drupal, Laravel, Magento, etc.)

---

## 🔗 Attack Chains (21 Total)

| Chain | Name | Pre-auth | Requirements | SAPI | Status |
|-------|------|:--------:|--------------|------|--------|
| **A** | Session Injection + LFI | ✅ | LFI sink, session path | All | ✅ Reliable |
| **B** | var_destroy UAF (`/proc/self/mem`) | ❌ | Local code exec | All | ✅ Version-aware |
| **C** | Handler Mismatch → `__destruct` | ✅ | FPM, `php_serialize`, gadget class | FPM | ✅ Framework-aware |
| **D** | OOM Corruption | ✅ | **None** — any endpoint | mod_php | ⚠️ Patched in 8.2.35+ |
| **E** | FPM Stale `BG()` | ✅ | Producer: `session_start()`, Consumer: any | FPM | ✅ LFI proof verification |
| **F** | **Session Key Smuggling** (POP) | ✅ | **serialize_handler=php only** | All | ✅ **Zero-LFI RCE!** |
| **G** | **OPcache Poisoning** | ✅ | OPcache + writable PHP file | All | ✅ **Guaranteed Persistence** |
| **H** | **ZMM Arena Grooming** | ✅ | **None** — heap feng shui | All | 🔬 Research |
| **W** | Webroot Session Direct Access | ✅ | session.save_path in webroot | All | ✅ Confirmed |
| **V** | Handler Confusion (CVE-2026-115560) | ✅ | serialize_handler switching | All | 🔬 Research |
| **S** | App Session Poisoning | ✅ | app mirrors input → $_SESSION + unserialize | All | ✅ Confirmed |
| **WB** | WAF Bypass (basename) | ✅ | LFI endpoint | All | ✅ Confirmed |
| **GP** | GET-Param Poison + LFI | ✅ | app mirrors GET → $_SESSION + LFI | All | ✅ Confirmed |
| **US** | **Unserialize via Whitelisted Param** | ✅ | Open registration + unserialize + POP | All | ✅ **NO LFI!** |
| **BIN** | php_binary Handler Confusion | ✅ | php_binary serialize_handler | All | 🔬 Research |
| **MULTI** | Concurrent Upload Race | ✅ | Same-SID concurrent uploads | All | 🔬 Research |
| **UINI** | .user.ini auto_prepend | ✅ | Filename-preserving upload | CGI/FPM | ✅ Confirmed |
| **COM** | Windows COM Objects | post-shell | COM extension | Windows | ✅ Confirmed |
| **FFI** | FFI::cdef() Direct C Call | post-shell | ffi.enable=1 | All | ✅ Confirmed |
| **LD** | LD_PRELOAD + mail() | post-shell | Linux + putenv+mail | All | ✅ Confirmed |
| **PHAR** | phar:// Deserialization | ✅ | File-function param (universal!) | All | ✅ Confirmed |
| **PIR** | phpinfo() tmp_name Race | ✅ | phpinfo() + include sink | All | ✅ Confirmed |
| **SPL** | SPL Iterator → FS Enum | post-shell | RecursiveDirectoryIterator | All | ✅ Confirmed |
| **GHOST** | **GHOST DOOR Persistence** | post-RCE | Writable dir | All | ✅ **9 primitives!** |

### New in v2 — Zero-Day Chains + Advanced Shell + GHOST DOOR

- **21 chains** (was 8) — 8 zero-day chains added: COM, FFI, LD, PHAR, PI, PIR, CU, SD, SPL
- **5.9KB advanced uploader webshell** — 15 params, 11-method exec fallback chain, COM FSO open_basedir bypass, fsockopen URL fetch (allow_url_fopen bypass), chunked upload, self-update, port scan, unzip, recon
- **GHOST DOOR persistence** — 9 primitives in scanner-invisible locations: template-cache poison, .user.ini auto_prepend, session-dir resurrection (outside webroot), phar-polyglot (GIF89a+PHP), composer autoload injection
- **Catch-all detection** — body-fingerprint comparison detects SPA catch-all 200s (no more false-positive endpoint detection)
- **69 WAF bypass techniques** — 15 generic + 51 vendor-specific (17 vendors) + 3 rate-limit
- **Global deadlines** — no chain hangs more than 60-90s on dead targets
- **Zero false positives** — connection failures report as DoS, not RCE

### Chain F — Session Key Smuggling (The Game Changer)
**No LFI needed!** Injects a POP gadget into the session file via `|` in the `PHP_SESSION_UPLOAD_PROGRESS` key. Any `session_start()` call unserializes the gadget → `__destruct` fires → RCE.

### Chain G — OPcache Poisoning (Persistence)
After gaining RCE via any chain: writes payload to a writable PHP file, triggers OPcache compilation, restores the original file. **Payload persists in shared memory until server restart.**

### Chain H — ZMM Arena Grooming (Bypasses OOM Patch)
Targets the Zend Memory Manager's free lists directly. No OOM trigger needed — works on ALL SAPIs. **Bypasses the 8.2.35+/8.3.36+ patches** because they fixed `longjmp()` but not the allocator.

---

## 🚀 Quick Start

```bash
# Full auto-exploit — tries all 8 chains intelligently (first success wins)
python3 php2shell.py --target http://TARGET_IP:PORT --auto

# BLITZ mode — parallel assault, fastest to success
python3 php2shell.py --target http://TARGET_IP:PORT --blitz

# SIEGE mode — sequential with full verification
python3 php2shell.py --target http://TARGET_IP:PORT --siege

# Universal mode — auto-discover LFI + session + SID
python3 php2shell.py --target http://TARGET_IP:PORT --universal

# Research mode — zero-day hunting framework
python3 php2shell.py --target http://TARGET_IP:PORT --research
```

---

## 📋 Usage Examples

### Chain A: Session Injection + LFI → RCE
```bash
python3 php2shell.py --target http://10.10.10.10:18082 --chain-a \
  --lfi-path /vuln.php --session-path /tmp/sessions --command 'id'
```

### Chain F: Session Key Smuggling (Zero-LFI POP)
```bash
python3 php2shell.py --target http://10.10.10.10:18082 --chain-f
# No LFI needed! Works on any target with serialize_handler=php
```

### Chain G: OPcache Poisoning (Persistence)
```bash
python3 php2shell.py --target http://10.10.10.10:18082 --chain-g \
  --opcache-file /var/www/html/cache/config.php
```

### Chain H: ZMM Arena Grooming (Bypasses OOM Patch)
```bash
python3 php2shell.py --target http://10.10.10.10:18091 --chain-h
# Works on ALL SAPIs — mod_php, FPM, CLI
```

### Session Variable Injection (Privilege Bypass)
```bash
python3 php2shell.py --target http://10.10.10.10:18082 --sess-inject "isAdmin|b:1;"
# Injects session variables without RCE — auth bypass
```

### Chain D: OOM with Heap Grooming
```bash
python3 php2shell.py --target http://10.10.10.10:18091 --chain-d \
  --strategy nested --spray 2000 --evasive --drip --oracle
```

---

## 🎮 TryHackMe Integration

```bash
# For the php2shell room
python3 php2shell.py --thm-room php2shell --thm-ip MACHINE_IP
```

| Service | Port | Chains That Work |
|---------|------|------------------|
| PHP 8.2 FPM | 18082 | A, C, E, **F**, **G** |
| PHP 8.3 FPM | 18083 | A, C, E, **F**, **G** |
| PHP 8.4 FPM | 18084 | A, C, E, **F**, **G** |
| PHP 8.2 Apache | 18091 | A, D, **F**, **G**, **H** |
| PHP 5.6 Apache | 18092 | A, D, **F**, **H** |
| PHP 7.4 Apache | 18093 | A, D, **F**, **H** |

---

## 🧠 Zero-Day Research Framework (5 Engines)

```bash
python3 php2shell.py --target http://target --research
```

| Engine | Purpose |
|--------|---------|
| **PHP Internals Inspector** | Memory maps, ZMM arenas, OPcache SHM discovery |
| **Differential Fuzzer** | Compare behavior across 6 PHP configs (JIT, GC, OPcache) |
| **JIT Path Explorer** | Exercise all JIT compilation paths (11 templates) |
| **Extension Attack Mapper** | Map 37 high-risk extensions + deserialization sinks |
| **ZMM State Visualizer** | Real-time allocator free list monitoring |

---

## 🥷 WAF Evasion Engine

| Technique | Mechanism | Breaks |
|-----------|-----------|--------|
| Case-mangling | `php://` → `PhP://` | Signature rules (PHP schemes are case-insensitive) |
| Double-encode | `../` → `..%252f` | WAFs that decode only once |
| Window-padding | 8×2KB junk before payload | WAFs inspecting first 8-16KB |
| Chunked encoding | `Transfer-Encoding: chunked` | Non-reassembling WAFs |
| Drip mode | 16KB every 50ms | Rate-based rules |
| Adaptive backoff | Progressive body reduction | Size-based blocks |
| **Boundary preservation** | Realigns after truncation | Payload corruption |

---

## 🎯 Post-Exploitation (8 Options)

After RCE succeeds, an interactive menu opens:

| Option | Feature |
|--------|---------|
| [1] Shell | Interactive command loop |
| [2] Upload file | Local → target (chunked base64) |
| [3] Download file | Target → local (base64 exfil) |
| [4] Webshell | Persistent shell in webroot |
| [5] Reverse shell | bash/python3/php one-liners |
| [6] Enumerate | id, SUID, ports, cron, users |
| [7] OPcache Persist | Chain G — persistent RCE |
| [8] Research Framework | Zero-day hunting tools |

---

## 🔗 LFI→RCE Escalation Engine (8 Direct Vectors)

When an LFI sink is found, the tool tries ALL of these automatically:

| Vector | Requirement | Speed |
|--------|-------------|-------|
| `php://input` | allow_url_include | Instant |
| `data://` | allow_url_include | Instant |
| `expect://` | expect extension | Instant |
| `php://filter` chains | **None** (iconv oracle) | Universal! |
| `/proc/self/fd/N` | Upload enabled | Fast |
| `/proc/self/environ` | FPM/CGI (UA poison) | Fast |
| Log poisoning | Log readable | Medium |
| PHAR Bomb | Session path known | Reliable |

### PHAR Bomb (Novel Technique)
Uploads a binary PHAR file via stalled upload, leaks its `tmp_name` from the session file, then includes it via `phar://`. **Defeats `.php`-suffix sinks and filename WAF filters.**

---

## 🛠️ Advanced Features

### Session Fixation Auto-Discovery
The `adopt_session` function automatically detects:
- `cookie_httponly=Off` (XSS can steal session)
- `cookie_secure=Off` (session leaks over HTTP)
- `use_strict_mode=Off` (accepts arbitrary SIDs)
- `use_only_cookies=Off` (SID via URL/POST accepted)

### Hybrid D+A Attack
Chain D (OOM) stresses the worker → immediately fires Chain A (LFI) to exploit the confused state. Works when either chain alone fails.

### Framework-Specific POP Gadgets
Auto-generates serialized payloads for:
- **Laravel**: `Illuminate\Broadcasting\PendingBroadcast`
- **Symfony**: `Symfony\Component\Cache\Adapter\TagAwareAdapter`
- **WordPress**: `WP_Object_Cache`
- **Guzzle**: `GuzzleHttp\Psr7\FnStream`
- **Monolog**: `Monolog\Handler\SyslogUdpHandler`
- **SwiftMailer**: `Swift_Mime_SimpleMessage`
- **Generic**: `Evil` class (for lab/testing)

### Smart Session Path Detection (Two-Tier)
- **Tier 1:** Checks top 8 most likely paths first (70% time savings on Linux)
- **Tier 2:** Full brute-force fallback on remaining 17 paths

### Crash Oracle
Independent verification that a server actually crashed (not just returned an error). Measures availability before/after each attack.

### Body Limit Calibration
Binary-probes the server's actual body size limit (256KB→32MB), then tunes all payloads to stay within 70% of that limit.

---

## 🔧 Chain Details

### Chain F: Session Key Smuggling
**Mechanism:** PHP's `php` serialize handler stores session data as `key|serialized_value`. The upload_progress tracker uses the `PHP_SESSION_UPLOAD_PROGRESS` value as part of the session key — and keys are written verbatim. A `|` in the value splits entries on decode:

```
Value:  "X|O:4:\"Evil\":0:{}"
File:   upload_progress_X|O:4:"Evil":0:{}|a:{progress...}
                          ↑ injected entry = OUR object!
```

Next `session_start()` unserializes the file → `__destruct()` fires → RCE.

**Requirements:**
- `session.serialize_handler = php` (the DEFAULT)
- Autoloaded class with exploitable `__destruct()`

### Chain G: OPcache Poisoning
**Mechanism:** OPcache stores compiled opcode in shared memory. Write payload to a writable PHP file → request it (OPcache compiles) → restore original file. Payload persists in OPcache until server restart.

**Requirements:**
- OPcache enabled (DEFAULT in PHP 8.x)
- Writable PHP file in webroot (cache/, uploads/, var/, tmp/)
- File write primitive (post-exploit session)

### Chain H: ZMM Arena Grooming
**Mechanism:** ZMM uses segregated free lists for 31 size classes (8-4096 bytes). Fill a target bin → free → trigger allocation of target object type. With ASLR bypass (reads `/proc/self/maps` via LFI), uses exact handler addresses instead of random spraying.

**Bypasses:** The 8.2.35+/8.3.36+ patches fixed `longjmp()` but NOT the allocator. Requires ZMM rewrite to fully patch.

---

## 📁 Output & Reporting

### JSON Output Format
```json
{
  "target": "http://10.10.10.10:18082",
  "target_info": {
    "php_version": "8.2.34",
    "sapi": "fpm-fcgi",
    "session_path": "/tmp/sessions",
    "session_fixation": ["use_strict_mode=Off"]
  },
  "results": [
    {
      "chain": "F",
      "success": true,
      "output": "blind timing RCE (4.2s delay)",
      "details": {
        "sid": "kexp...",
        "gadgets": ["lab-Evil"],
        "verify": "timing"
      }
    }
  ]
}
```

---

## 🛡️ Mitigation & Detection

### Immediate Mitigations (INI)
```ini
session.upload_progress.enabled = Off
session.use_only_cookies = On
session.use_strict_mode = On
session.serialize_handler = php_serialize  ; blocks Chain F
opcache.validate_timestamps = 1            ; helps vs Chain G
```

### Complete Fix
**Update PHP to:** 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+

> **Note:** Chain F needs `serialize_handler=php_serialize` to block. Chain H requires ZMM allocator rewrite (not just a patch). Chain G requires OPcache disable or strict file permissions.

### Detection Rules Included
See `detection/` folder for:
- **Suricata/Snort** — 18+ rules (all chains including F, G, H)
- **Sigma** — 8+ rules (web logs, process creation, file events)
- **ModSecurity** — 7+ rules (drop-in for Apache/Nginx)
- **OpenResty Lua** — Lightweight reverse proxy module

---

## 📚 References

- [PHP Security Advisory](https://www.php.net/archive/2026.php)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — CVE-2026-109618
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) — CVE-2026-109619
- [Patch Commit 3584a98](https://github.com/php/php-src/commit/3584a98bda) — 300 files changed
- [Qi Deng Writeup](https://qideng.substack.com/p/php2shell-dissecting-phps-critical) — Full technical analysis
- [Synacktiv Filter Chains](https://github.com/synacktiv/php_filter_chain_generator) — php://filter oracle
- [Original PoC](https://github.com/ikow/php2shell-poc) — ikow/php2shell-poc
- [NCSC-NL Advisory](https://github.com/NCSC-NL/php2shell) — Operational info

---

## 📄 License

MIT License — See LICENSE file.

**Educational and authorized testing use only.**
