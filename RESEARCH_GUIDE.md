# PHP Security Research Guide — Complete Reference

## Downloaded Research Materials

| Source | File | Key Intelligence |
|--------|------|-----------------|
| php2shell-poc (Qi Deng) | `research/original-poc/` | Original exploits + analysis + scanner |
| JFrog Analysis | `research/docs/jfrog-analysis.html` | 3 arms of 109619 + exploit flow |
| hubertf Deep-Dive | `research/docs/hubertf-deep-dive.html` | Step-by-step exploit rebuild |
| Dev.to Patch Analysis | `research/docs/devto-patch-analysis.html` | Independent verification |
| PHP Core Dev | `research/docs/php-core-dev-analysis.html` | The actual fix from PHP team |
| tuxz Dissected | `research/docs/tuxz-dissected.html` | Exploitability + threat intel |
| PHP 8.4 Source | `php-src/php/` | Vulnerable source code |
| PHP 8.5 Source | `php-src/php85/` | Latest — check for new bugs |

---

## 1. How Qi Deng Found the Vulnerability

He identified **6 root causes** — not just one bug, but a system of interacting flaws:

```
1. Session Fixation    → PHPSESSID from POST body (ignores use_only_cookies)
2. Filename Injection   → add_assoc_string_ex stores raw filename
3. Serializer Leak      → PS(serializer) not reset in RSHUTDOWN  
4. var_destroy UAF      → __destruct fires without BG(serialize_lock)
5. OOM longjmp          → zend_bailout() skips cleanup during multipart
6. Stale BG             → BG(unserialize) not reset before rfc1867
```

**Key insight:** `__destruct` fires on BOTH success AND failure of `var_destroy`. The decode FAILURE does NOT prevent exploitation — it actually HELPS by triggering the destructor chain.

---

## 2. The Complete Exploit Flow (from JFrog + hubertf)

```
Step 1: A/B pair — same worker, sequential requests
  Request A: 12MB form field → OOM during session init → longjmp
             → PS(id) and PS(http_session_vars) left dangling
  Request B: Same worker → re-occupy freed block with controlled bytes

Step 2: Three exploitations from one primitive
  Leak 1: PS(id) read back → Set-Cookie header → heap base leak
  Leak 2: fake HashTable pDestructor → libphp.so base leak  
  Execute: PS(http_session_vars) → zval_ptr_dtor → system()

Step 3: Worker rotation (between stages)
  Apache prefork → abort child → fresh worker with same mappings
  HTTP-only rotation: send malformed request → child dies → new worker
```

---

## 3. What the Patch ACTUALLY Fixes (from PHP Core Dev + JFrog)

### Commit 3584a98 — "Avoid state corruption via bailout" (300 files)

**Before:**
```c
zend_mm_safe_error() {
    zend_error_noreturn(E_ERROR, format, limit, size);
    zend_bailout();   // longjmp() — skips ALL cleanup
}
```

**After:**
```c
zend_mm_check_limit() {
    if (UNEXPECTED(heap->limit < heap->real_size)) {
        if (!ZEND_HAS_OOM()) {
            zend_mm_delayed_error(...);   // soft OOM
        }
        return heap->fallible ? FAILURE : SUCCESS;
    }
}
```

**Additional changes:**
- `php_basic_early_rinit()` — resets BG() before rfc1867
- `php_rinit_session_globals()` — at MULTIPART_EVENT_START (pre-RINIT)
- `PS(in_rfc1867_update)` — forces __PHP_IncompleteClass (no autoload, no __destruct)
- `php_session_initialize()` FAILURE → return immediately (don't set session_status)
- `request_parse_body()` — NEW in 8.4, parses multipart on GET/PUT/DELETE
- Multipart parser checks ZEND_HAS_OOM between parts
- Hard limit `_exit(137)` at memory_hard_limit_percent (default 200%)

---

## 4. What's NOT Fixed (Attack Surface Remaining)

| Gap | Status | Exploitability |
|-----|--------|----------------|
| Chain A (LFI + filename injection) | **UNPATCHED** | Works on fully patched PHP |
| `upload_progress.enabled=Off` | **INSUFFICIENT** | CVE-2026-109618 doesn't need it |
| `PS(serializer)` leak | **NEEDS PR #22113** | Chain C still works without it |
| Session fixation via POST body | **NEEDS PR #22113** | Without PR, POST body SID still works |
| `var_destroy` Phase 1/2 ordering | **UNCHANGED** | User-code unserialize still UAFs |
| `zend_bailout()` fallback | **STILL EXISTS** | When execute_data=NULL → old path |
| `fatal_error_backtraces` (8.5) | **3rd ARM** | `fatal_error_backtraces=0` needed |
| OPcache shared memory | **NO INI FIX** | Cross-worker corruption possible |
| `request_parse_body()` (8.4) | **WIDENS SURFACE** | Parses multipart on GET/PUT/DELETE |
| `memory_limit=-1` defense | **DOUBLE-EDGED** | Removes predictable OOM trigger |

---

## 5. OUR Discoveries (Beyond Original CVE)

### Chain Z: Session Key Collision (session.c:3236)
```c
zend_hash_update(Z_ARRVAL_P(sess_var), progress->key.s, &progress->data);
// progress->key.s = USER-CONTROLLED, NO validation
// Overwrites session keys: is_admin, role, user_level, logged_in
```

### Chain W2: Decode Failure Double-Free (session.c:265)
```c
php_session_cancel_decode() {
    php_session_destroy();       // frees PS(http_session_vars)
    php_session_track_init();    // zval_ptr_dtor on SAME pointer → DOUBLE FREE
}
```

### Universal POP Spray (Chain Y)
10+ gadgets in ONE injection: Monolog, Guzzle, Laravel, Symfony, WP, SwiftMailer, PHPExcel, Carbon, Doctrine, PHPUnit

### DTOR-Delta Sweep
```
zif_system = leaked_pDestructor + DELTA
PHP 5.x:-0x1B0000 | 7.x:-0x1C0000 | 8.0-8.2:-0x1DE000 | 8.3:-0x1D93E0 | 8.4:-0x1F97F0
```

---

## 6. New Research Directions (10 Unexplored Areas)

```
1. request_parse_body() on GET/PUT/DELETE  → WAF bypass + new attack surface
2. fatal_error_backtraces (8.5.x)          → 3rd arm, no INI fix except =0
3. OPcache shared memory                   → cross-worker corruption
4. Session fixation via POST body           → still works pre-PR#22113
5. Filename injection                       → UNPATCHABLE (feature, not bug)
6. var_destroy UAF on user code             → core bug remains
7. upload_progress.prefix                  → arbitrary key overwrite possible?
8. Concurrent uploads                       → race on session file between workers
9. register_argc_argv                      → CLI injection in web context
10. session.lazy_write                      → delayed write → race window
```

---

## 7. Scanner Intelligence (from check.py)

4-tier progressive detection:
- **Tier 1**: Version fingerprint (X-Powered-By / Server header)
- **Tier 2**: upload_progress reachability (POST multipart → PHPSESSID cookie)
- **Tier 3**: Session write verification (inject marker via filename)
- **Tier 4**: OOM differential (send oversized multipart → compare responses)

Key signals:
- `HTTP 502` + no recovery = unpatched FPM crash
- `HTTP 500` empty body = unpatched worker crash  
- `HTTP 500` + "Allowed memory size" = could be patched
- Connection reset = mod_php crash (unpatched)
- `post_max_size` bypass: chunked transfer (no Content-Length)

---

## 8. POP Gadget Targets (for Chain C/F/Y)

| Framework | Class | Type |
|-----------|-------|------|
| Laravel | `Illuminate\Broadcasting\PendingBroadcast` | __destruct |
| Symfony | `Symfony\Component\Cache\Adapter\TagAwareAdapter` | __destruct |
| WordPress | `WP_Object_Cache` | __destruct |
| Monolog | `Monolog\Handler\SyslogUdpHandler` | __destruct |
| Guzzle | `GuzzleHttp\Psr7\FnStream` | __destruct |
| SwiftMailer | `Swift_Message` | __destruct |
| Doctrine | `Doctrine\Common\Cache\FilesystemCache` | __destruct |
| PHPExcel | `PHPExcel_Reader` | __destruct |
| Carbon | `Carbon\Laravel\ServiceProvider` | __destruct |
| PHPUnit | `PHPUnit\Framework\MockObject\Generator` | __destruct |

---

## 9. Key Source Files for Future Research

```
ext/session/session.c          ← upload_progress handler (main attack surface)
ext/session/php_session.h      ← Progress struct, in_rfc1867_update flag
main/rfc1867.c                  ← Multipart parser, ZEND_HAS_OOM checks
main/rfc1867.h                  ← Event types, multipart_event structs
main/main.c                     ← php_request_startup/shutdown, bailout path
Zend/zend.c                     ← OOM handler, zend_bailout() fallback
Zend/zend_alloc.c               ← ZMM allocator, memory_limit check
ext/standard/var_unserializer.re ← unserialize(), var_destroy UAF
ext/standard/var.c              ← serialize(), PHP_VAR_UNSERIALIZE_INIT
Zend/zend_hash.c                ← HashTable ops, double-free potential
Zend/zend_objects.c             ← Object handlers, __destruct dispatch
ext/opcache/                    ← Shared memory, 3rd arm of 109619
```

---

## 10. How to Report a 0-Day

```
Email: security@php.net
Include: affected versions, root cause (file:line), minimal PoC, 
         impact, suggested fix, your name for credit
Wait: 90 days for coordinated disclosure
```

---

## 11. Version Matrix (Patched vs Vulnerable)

| Version | Vulnerable | Fix Version | Status |
|---------|-----------|-------------|--------|
| 5.4-5.6 | YES | NONE | EOL — no fix ever |
| 7.0-7.4 | YES | NONE | EOL — no fix ever |
| 8.0-8.1 | YES | NONE | EOL — community backports only |
| 8.2.x | YES | 8.2.35 | PATCHED |
| 8.3.x | YES | 8.3.36 | PATCHED |
| 8.4.x | YES | 8.4.27 | PATCHED |
| 8.5.x | YES | 8.5.12 | PATCHED |

Vulnerable code identical across ALL versions since PHP 5.4.0 (2012).
