-- ============================================================================
-- php2shell — OpenResty / Nginx Lua WAF Rules
-- CVE-2026-109618 / CVE-2026-109619
--
-- Drop this into your OpenResty access_by_lua_block or reference it via
-- access_by_lua_file. Blocks the primary php2shell attack vector at the
-- reverse proxy layer before requests reach PHP.
--
-- Author: Qi Deng (@ikow)
-- Reference: https://github.com/ikow/php2shell-poc
-- ============================================================================

local _M = {}

-- Check if request is a multipart POST
local function is_multipart_post()
    if ngx.req.get_method() ~= "POST" then
        return false
    end
    local ct = ngx.req.get_headers()["content-type"]
    if not ct then
        return false
    end
    return ct:find("multipart/form%-data", 1, false) ~= nil
end

-- Read request body (up to limit)
local function get_body(max_size)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        -- body might be in a temp file if too large
        local file = ngx.req.get_body_file()
        if file then
            local fh = io.open(file, "r")
            if fh then
                body = fh:read(max_size or 65536)
                fh:close()
            end
        end
    end
    return body
end

function _M.check(opts)
    opts = opts or {}
    local max_body_read = opts.max_body_read or 65536  -- 64KB default
    local log_only = opts.log_only or false

    if not is_multipart_post() then
        return  -- not a multipart POST, skip
    end

    local body = get_body(max_body_read)
    if not body then
        return  -- no body to inspect
    end

    -- Rule 1: Block PHP_SESSION_UPLOAD_PROGRESS
    -- Primary trigger for both CVEs. Near-zero legitimate use.
    if body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) then
        ngx.log(ngx.WARN,
            "php2shell: blocked PHP_SESSION_UPLOAD_PROGRESS from ",
            ngx.var.remote_addr, " uri=", ngx.var.request_uri)

        if not log_only then
            ngx.status = 403
            ngx.header["X-Blocked-By"] = "php2shell-detection"
            ngx.say("Forbidden")
            return ngx.exit(403)
        end
    end

    -- Rule 2: Detect PHPSESSID in POST body (session fixation)
    -- Normal browsers send this as a Cookie, never as a form field.
    if body:find('name="PHPSESSID"', 1, true) or
       body:find("name=PHPSESSID", 1, true) then
        ngx.log(ngx.WARN,
            "php2shell: PHPSESSID in POST body from ",
            ngx.var.remote_addr, " uri=", ngx.var.request_uri)

        -- Alert only — some legacy apps may do this legitimately
    end

    -- Rule 3: Detect PHP code in multipart body (session injection)
    if body:find("<?php", 1, true) or body:find("<?=", 1, true) then
        local has_filename = body:find('filename="', 1, true)
        if has_filename then
            ngx.log(ngx.WARN,
                "php2shell: PHP code in upload filename from ",
                ngx.var.remote_addr, " uri=", ngx.var.request_uri)

            if not log_only then
                ngx.status = 403
                ngx.header["X-Blocked-By"] = "php2shell-detection"
                ngx.say("Forbidden")
                return ngx.exit(403)
            end
        end
    end
end

return _M

-- ============================================================================
-- Usage in nginx.conf:
--
--   # Option A: Inline
--   access_by_lua_block {
--       require("php2shell").check()
--   }
--
--   # Option B: Log-only mode (detect without blocking)
--   access_by_lua_block {
--       require("php2shell").check({ log_only = true })
--   }
--
--   # Option C: Custom body inspection size
--   access_by_lua_block {
--       require("php2shell").check({ max_body_read = 131072 })  -- 128KB
--   }
-- ============================================================================
-- ═══════════════════════════════════════════════════════════════════════
-- NEW CHAIN DETECTION (F, G, H, PHAR, filter chains)
-- ═══════════════════════════════════════════════════════════════════════

-- Chain F: Session Key Smuggling (pipe + object in upload_progress)
local function detect_chain_f(body)
    if body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) then
        -- Look for | followed by O: (serialized object)
        local pattern = "PHP_SESSION_UPLOAD_PROGRESS"
        local start = body:find(pattern, 1, true)
        if start then
            local segment = body:sub(start, start + 200)
            if segment:find("|", 1, true) and segment:find("O:", 1, true) then
                return true, "Chain F: session key smuggling (pipe+object)"
            end
        end
    end
    return false, nil
end

-- Chain G: OPcache poisoning (file_put_contents to .php)
local function detect_chain_g(body)
    if body:find("file_put_contents", 1, true) and
       body:find(".php", 1, true) and
       body:find("___START___", 1, true) then
        return true, "Chain G: OPcache poisoning (write+cache+restore)"
    end
    return false, nil
end

-- Chain H: ZMM grooming (sequential form fields g0, g1, g2...)
local function detect_chain_h(body)
    if body:find('name="g0"', 1, true) and
       body:find('name="g1"', 1, true) and
       body:find('name="g2"', 1, true) then
        return true, "Chain H: ZMM arena grooming (allocation spray)"
    end
    if body:find("ZMM_TRIGGER_OK", 1, true) then
        return true, "Chain H: ZMM trigger code"
    end
    return false, nil
end

-- PHAR Bomb: phar:// wrapper in URI
local function detect_phar_bomb(uri)
    if uri:lower():find("phar://", 1, true) then
        return true, "PHAR Bomb: phar:// wrapper in URI"
    end
    return false, nil
end

-- php://filter chain (iconv oracle)
local function detect_filter_chain(uri)
    if uri:lower():find("php://filter/convert.iconv.", 1, true) then
        return true, "LFI escalation: php://filter iconv chain"
    end
    return false, nil
end

-- data:// wrapper
local function detect_data_wrapper(uri)
    if uri:lower():find("data://text/plain;base64,", 1, true) then
        return true, "LFI escalation: data:// wrapper"
    end
    return false, nil
end

-- Session Fixation probe
local function detect_session_fixation(cookie_header)
    if cookie_header and cookie_header:find("PHPSESSID=fixtest", 1, true) then
        return true, "Session Fixation: probe SID detected"
    end
    return false, nil
end

-- Extended check function (overrides the main check if present)
function _M.check_extended(opts)
    local uri = opts.uri or ngx.var.request_uri or ""
    local method = opts.method or ngx.var.request_method or "GET"
    local cookie = ngx.var.http_cookie or ""

    -- URI-based checks (fast, no body read needed)
    local uri_checks = {
        detect_phar_bomb,
        detect_filter_chain,
        detect_data_wrapper,
    }
    for _, check in ipairs(uri_checks) do
        local detected, reason = check(uri)
        if detected then
            return true, reason
        end
    end

    -- Cookie checks
    local fixed, fix_reason = detect_session_fixation(cookie)
    if fixed then
        return true, fix_reason
    end

    -- Body checks (only for POST)
    if method == "POST" then
        local body = get_body(opts.max_size or 1048576)
        if body then
            local body_checks = {
                detect_chain_f,
                detect_chain_g,
                detect_chain_h,
            }
            for _, check in ipairs(body_checks) do
                local detected, reason = check(body)
                if detected then
                    return true, reason
                end
            end
        end
    end

    return false, nil
end

-- GHOST DOOR persistence detection (2026-10-24)
local function detect_ghost_door(uri, body)
    if uri:match("%.tpl_[0-9a-f]+%.php") then
        return true, "GHOST: template-cache poison file"
    end
    if uri:match("%.ghost_inc%.php") or uri:match("%.user%.ini") then
        return true, "GHOST: .user.ini/ghost_inc access"
    end
    if uri:match("%?g=[A-Za-z0-9+/=]+") then
        return true, "GHOST: ?g= eval request"
    end
    if uri:match("autoload_files%.php") then
        return true, "GHOST: composer autoload injection"
    end
    if body and body:match("GIF89a.-%<%?php") then
        return true, "GHOST: GIF89a+PHP polyglot"
    end
    return false, nil
end
