#!/usr/bin/env python3
"""
哈吉米网页版高性能自托管网关 (V6 - 规范分块流与零挂死版)
更新日志：
1. P0 彻底根治：修复 StreamGenerate / chunked 流式帧协议缺陷
   - 补齐规范 HTTP/1.1 分块传输帧 (<hex_len>\\r\\n<data>\\r\\n) 与终结帧 (0\\r\\n\\r\\n)
   - 确保非流式 RPC 显式声明 Content-Length，剥除上游 Connection/Transfer-Encoding，彻底消除无限 pending 挂死
2. 消除 Google 孤岛域名阻断：
   - 前端 Shim 与 HTML 彻底屏蔽 accounts.google.com/RotateCookiesPage 与 ogs.google.com (about:blank 秒级降级)
   - 解决 Chrome/Firefox 6个并发连接槽被占满问题
3. 补齐 /favicon.ico 204 秒回，消灭控制台报错
"""

import threading
import os
import sys
import time
import json
import sqlite3
import shutil
import hmac
import hashlib
import ipaddress
import re
import urllib.parse
import traceback
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import httpx

# 端口/域名/缓存支持环境变量覆盖：默认与阿里云中转一致；
# 直连实例由 systemd 传入 MIRROR_PORT/MIRROR_DOMAIN/MIRROR_CACHE。
PORT = int(os.environ.get("MIRROR_PORT", "8324"))
DIRECT_TLS_PORT = int(os.environ.get("DIRECT_TLS_PORT", "8322"))   # 直连 HTTPS（可选）
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY", "http://127.0.0.1:7890")
# 专用浏览器 profile（cookie 来源）；可选 MIRROR_ALT_PROFILE 配合 HAJIMI_ALT_PWD 支持双账号口令分流
FIREFOX_PROFILE = os.environ.get("FIREFOX_PROFILE", "/home/admin/.mozilla/firefox-gemini")
FIREFOX_PROFILE_ALT = os.environ.get("MIRROR_ALT_PROFILE", "")
# ⚠️ 口令务必通过环境变量 HAJIMI_PWD（可选 HAJIMI_ALT_PWD）提供，不要写死在代码里；留空则不启用鉴权
PASSWORD = os.environ.get("HAJIMI_PWD", "")
ALT_PASSWORD = os.environ.get("HAJIMI_ALT_PWD", "")
SECRET_KEY = os.environ.get(
    "HAJIMI_SECRET", "Hajimi_2026_HJM_SecretKey_Salt_7f3a"
).encode("utf-8")
DOMAIN = os.environ.get("MIRROR_DOMAIN", "hajimi.example.com")

# 多账号路由：不同口令决定使用哪套浏览器 profile / Cookie，互不回落。
ACCOUNTS = {
    "owner": {"password": PASSWORD, "profile": FIREFOX_PROFILE, "label": "主账号"},
}
if ALT_PASSWORD and FIREFOX_PROFILE_ALT:
    ACCOUNTS["alt"] = {"password": ALT_PASSWORD, "profile": FIREFOX_PROFILE_ALT, "label": "备用账号"}

# 安全：登录失败限速（按真实客户端 IP，Caddy 的 X-Forwarded-For 末项）。
LOGIN_FAIL_WINDOW = 600
LOGIN_FAIL_MAX = 10
LOGIN_LOCK_SECONDS = 600
_LOGIN_FAIL = {}
_LOGIN_LOCK = threading.Lock()

CACHE_DIR = os.environ.get("MIRROR_CACHE", "./cache")
os.makedirs(CACHE_DIR, exist_ok=True)

# ── 1. 全局 HTTP 客户端（长连接池）────────────────────────────
GLOBAL_CLIENT = httpx.Client(
    proxy=UPSTREAM_PROXY,
    http2=False,  # 必须关闭：httpcore 同步 HTTP/2 在多线程下共用连接会 ReadError(EAGAIN)
    # 2026-10-29: read 120s 会掐断深度思考（Pro 思考常 >2min），表现为「卡在思考中」后整包失败
    timeout=httpx.Timeout(600.0, connect=15.0, read=600.0, write=120.0, pool=60.0),
    limits=httpx.Limits(max_keepalive_connections=100, max_connections=200, keepalive_expiry=120.0),
    follow_redirects=False
)

class _BoundedLRU:
    """线程安全内存缓存：总字节/条目双上限，LRU 淘汰；单条超限直接不入缓存。"""

    def __init__(self, max_bytes, max_entries, max_entry_bytes):
        self._max_bytes = max_bytes
        self._max_entries = max_entries
        self._max_entry_bytes = max_entry_bytes
        self._data = OrderedDict()
        self._bytes = 0
        self._evictions = 0
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            self._data.move_to_end(key)
            return item

    def put(self, key, value):
        size = len(value[1])
        if size > self._max_entry_bytes:
            return False
        with self._lock:
            old = self._data.pop(key, None)
            if old is not None:
                self._bytes -= len(old[1])
            while self._data and (
                self._bytes + size > self._max_bytes
                or len(self._data) >= self._max_entries
            ):
                _, evicted = self._data.popitem(last=False)
                self._bytes -= len(evicted[1])
                self._evictions += 1
            self._data[key] = value
            self._bytes += size
            return True

    def snapshot(self):
        with self._lock:
            return len(self._data), self._bytes, self._evictions


MEM_CACHE = _BoundedLRU(
    max_bytes=int(os.environ.get("MIRROR_MEM_CACHE_MB", "64")) * 1024 * 1024,
    max_entries=int(os.environ.get("MIRROR_MEM_CACHE_ENTRIES", "2048")),
    max_entry_bytes=int(os.environ.get("MIRROR_MEM_CACHE_ENTRY_KB", "4096")) * 1024,
)

_STATS_LOCK = threading.Lock()
_STATS = {k: 0 for k in ("mem_hits", "disk_hits", "misses", "upstream_ok", "upstream_err", "slow_2s")}


def _stat_inc(name, n=1):
    with _STATS_LOCK:
        _STATS[name] = _STATS.get(name, 0) + n


def _stat_snapshot():
    with _STATS_LOCK:
        return dict(_STATS)


def _rss_mb():
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0


def _stats_reporter(interval):
    while True:
        time.sleep(interval)
        s = _stat_snapshot()
        entries, mem_bytes, evictions = MEM_CACHE.snapshot()
        sys.stderr.write(
            f"[STATS] rss={_rss_mb():.0f}MB mem_entries={entries} mem={mem_bytes / 1024 / 1024:.1f}MB "
            f"evict={evictions} mem_hits={s['mem_hits']} disk_hits={s['disk_hits']} "
            f"miss={s['misses']} upstream={s['upstream_ok']} err={s['upstream_err']} "
            f"slow={s['slow_2s']}\n"
        )

# ── 2. Cookie 智能内存缓存（按账号隔离，基于 mtime 检查）────────────
_COOKIE_LOCKS = {k: threading.Lock() for k in ACCOUNTS}
_COOKIE_STATE = {k: {"data": {}, "mtime": 0, "checked": 0.0} for k in ACCOUNTS}


def _account_profile(account):
    return (ACCOUNTS.get(account) or {}).get("profile", FIREFOX_PROFILE)


def _load_cookies(account):
    """从该账号的 Firefox profile 读取全部 google 域 Cookie，按 host 建索引。

    2026-11-02: 双账号 —— owner/friend 各自独立 profile，缓存与临时库也按账号隔离。
    2026-10-29: 原实现先更新时间戳再读库，并发首调时另一线程会读到「已更新时间戳但缓存仍空」
    → NameError: CACHED_COOKIES（变量名与定义不符）→ 请求中断 → Caddy 502。
    这里统一变量名并加锁 + 双重检查，彻底消除竞态。
    """
    st = _COOKIE_STATE.get(account)
    lock = _COOKIE_LOCKS.get(account)
    if st is None or lock is None:
        return {}
    now = time.time()
    if now - st["checked"] < 5.0 and st["data"]:
        return st["data"]

    with lock:
        now = time.time()
        if now - st["checked"] < 5.0 and st["data"]:
            return st["data"]
        st["checked"] = now
        return _load_cookies_locked(account)


def _load_cookies_locked(account):
    st = _COOKIE_STATE[account]
    db_path = os.path.join(_account_profile(account), "cookies.sqlite")
    if not os.path.exists(db_path):
        return st["data"]

    try:
        mtime = os.path.getmtime(db_path)
        # Firefox 用 WAL 模式，新 cookie 先落 -wal、主库 mtime 不变。
        # 只看主库 mtime 会让缓存永不刷新，读到过期 1PSIDTS → 上游判未登录。
        try:
            wal_m = os.path.getmtime(db_path + "-wal")
            if wal_m > mtime:
                mtime = wal_m
        except OSError:
            pass
        if mtime == st["mtime"] and st["data"]:
            return st["data"]

        tmp_path = f"/tmp/gemini_cookie_sync_{account}.db"
        # 必须连 -wal/-shm 一起拷，否则读到的是未合并的旧值
        for _ext in ("", "-wal", "-shm"):
            try:
                os.remove(tmp_path + _ext)
            except Exception:
                pass
        for _ext in ("", "-wal", "-shm"):
            _src = db_path + _ext
            if os.path.exists(_src):
                shutil.copy2(_src, tmp_path + _ext)
        conn = sqlite3.connect(tmp_path, timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT name, value, host FROM moz_cookies WHERE host LIKE ?", ("%google.com%",))
        data = {}
        for n, v, h in cur.fetchall():
            data.setdefault(h, []).append((n, v))
        conn.close()
        for _ext in ("", "-wal", "-shm"):
            try:
                os.remove(tmp_path + _ext)
            except Exception:
                pass
        st["data"] = data
        st["mtime"] = mtime
        return data
    except Exception as e:
        sys.stderr.write(f"[COOKIE] account={account} 读取失败: {e}\n")
        return st["data"]


def get_cookies_str(target_host="", account="owner"):
    """按目标域名组装该账号的 Cookie 头。host 匹配规则与浏览器一致。"""
    data = _load_cookies(account) or {}
    out = []
    for h, items in data.items():
        hl = h.lstrip(".")
        if not target_host or target_host == hl or target_host.endswith("." + hl) or hl.endswith("." + target_host):
            for n, v in items:
                out.append(f"{n}={v}")
    return "; ".join(dict.fromkeys(out))


def has_login_cookies(account):
    """该账号的 profile 是否具备可用的 Google 登录态（不能退化为匿名）。"""
    names = set()
    for items in (_load_cookies(account) or {}).values():
        for n, _v in items:
            names.add(n)
    return bool(names & {"__Secure-1PSID"}) and bool(
        names & {"SAPISID", "__Secure-1PAPISID", "__Secure-3PAPISID", "APISID"}
    )


def make_sapisidhash(sapisid, origin="https://gemini.google.com"):
    """Google 的客户端签名：SAPISIDHASH {ts}_{sha1(f'{ts} {sapisid} {origin}')}。
    缺了它，写请求会被服务端当成「不可信客户端」→ 临时会话（能回复但不落库）。"""
    import hashlib
    ts = int(time.time())
    raw = f"{ts} {sapisid} {origin}"
    return "SAPISIDHASH %d_%s" % (ts, hashlib.sha1(raw.encode("utf-8")).hexdigest())



def redact_pwd(text):
    """日志脱敏：绝不把访问口令写进 journal。"""
    return re.sub(r"pwd=[^&\s\"]+", "pwd=***", text or "")


def _client_ip(handler):
    """取真实客户端 IP。Caddy 会写 X-Forwarded-For；取最后一跳，防客户端伪造。"""
    xff = handler.headers.get("X-Forwarded-For", "") or ""
    if xff:
        candidate = xff.split(",")[-1].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return handler.client_address[0]


def _login_is_blocked(ip):
    now = time.monotonic()
    with _LOGIN_LOCK:
        rec = _LOGIN_FAIL.get(ip)
        if not rec:
            return False, 0
        count, first, until = rec
        if until and now < until:
            return True, max(1, int(until - now))
        if now - first > LOGIN_FAIL_WINDOW:
            _LOGIN_FAIL.pop(ip, None)
        return False, 0


def _login_record_failure(ip):
    now = time.monotonic()
    with _LOGIN_LOCK:
        count, first, until = _LOGIN_FAIL.get(ip, (0, now, 0))
        if now - first > LOGIN_FAIL_WINDOW:
            count, first, until = 0, now, 0
        count += 1
        if count >= LOGIN_FAIL_MAX:
            until = now + LOGIN_LOCK_SECONDS
        _LOGIN_FAIL[ip] = (count, first, until)
        if len(_LOGIN_FAIL) > 1000:
            for key, (_c, _f, _u) in list(_LOGIN_FAIL.items()):
                if now - _f > LOGIN_FAIL_WINDOW and (not _u or now > _u):
                    _LOGIN_FAIL.pop(key, None)


def _login_clear(ip):
    with _LOGIN_LOCK:
        _LOGIN_FAIL.pop(ip, None)


def _is_private_host(host):
    """用户内容类上游：未登录不得读，即使命中静态缓存。"""
    h = (host or "").lower()
    return h.endswith(".googleusercontent.com") or h.endswith(".usercontent.goog")


def account_for_password(pwd):
    """口令 → 账号 key；不匹配返回 None。"""
    if not pwd:
        return None
    for key, acc in ACCOUNTS.items():
        if hmac.compare_digest(pwd, acc["password"]):
            return key
    return None


def make_auth_token(account):
    ts = int(time.time())
    password = ACCOUNTS[account]["password"]
    sig = hmac.new(
        SECRET_KEY, f"{account}:{password}:{ts}".encode(), hashlib.sha256
    ).hexdigest()
    return f"{account}.{ts}.{sig}"


def verify_auth_token(token):
    """校验并返回账号 key；兼容 2026-11-02 之前签发的旧 token。"""
    if not token or "." not in token:
        return None
    parts = token.split(".")
    try:
        if len(parts) == 3:
            account, ts_s, sig = parts
            if account not in ACCOUNTS:
                return None
            ts = int(ts_s)
            if abs(time.time() - ts) > 30 * 86400:
                return None
            password = ACCOUNTS[account]["password"]
            expected = hmac.new(
                SECRET_KEY, f"{account}:{password}:{ts}".encode(), hashlib.sha256
            ).hexdigest()
            return account if hmac.compare_digest(sig, expected) else None
        if len(parts) == 2:
            # 旧格式：ts.sig，签名只绑定口令；按口令反查账号。
            ts_s, sig = parts
            ts = int(ts_s)
            if abs(time.time() - ts) > 30 * 86400:
                return None
            for account, acc in ACCOUNTS.items():
                expected = hmac.new(
                    SECRET_KEY, f"{acc['password']}:{ts}".encode(), hashlib.sha256
                ).hexdigest()
                if hmac.compare_digest(sig, expected):
                    return account
            return None
    except Exception:
        return None
    return None

# ── 3. 客户端防卡顿加速脚本（注入在 HTML <head> 最前）──────────
SHIELD_SCRIPT = f"""<script>
(function() {{
    window.dataLayer = window.dataLayer || [];
    window.__hajimiShield = 1;
    // 模拟 Google Chrome on Linux Desktop，与账号服务端环境 100% 保持一致
    try {{
        Object.defineProperty(navigator, 'userAgent', {{
            get: function() {{ return 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'; }},
            configurable: true
        }});
        Object.defineProperty(navigator, 'appVersion', {{
            get: function() {{ return '5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'; }},
            configurable: true
        }});
        Object.defineProperty(navigator, 'platform', {{
            get: function() {{ return 'Linux x86_64'; }},
            configurable: true
        }});
        if (navigator.userAgentData) {{
            Object.defineProperty(navigator, 'userAgentData', {{
                get: function() {{
                    return {{
                        brands: [
                            {{brand: 'Google Chrome', version: '131'}},
                            {{brand: 'Chromium', version: '131'}},
                            {{brand: 'Not_A Brand', version: '24'}}
                        ],
                        mobile: false,
                        platform: 'Linux',
                        getHighEntropyValues: function() {{
                            return Promise.resolve({{
                                architecture: 'x86',
                                bitness: '64',
                                mobile: false,
                                model: '',
                                platform: 'Linux',
                                platformVersion: '6.6.0',
                                uaFullVersion: '131.0.0.0'
                            }});
                        }}
                    }};
                }},
                configurable: true
            }});
        }}
    }} catch(e) {{}}
    var origin = window.location.origin;
    var blockedList = [
        "play.google.com",
        "google.com/ccm",
        "ogads-pa.clients6.google.com",
        "googletagmanager.com",
        "google-analytics.com",
        "stats.g.doubleclick.net",
        "doubleclick.net",
        "accounts.google.com",
        "apis.google.com",
        "www.google.com",
        "ogs.google.com"
    ];

    function isBlocked(u) {{
        if (!u) return false;
        try {{
            var s = String(u);
            for (var i = 0; i < blockedList.length; i++) {{
                if (s.indexOf(blockedList[i]) !== -1) return true;
            }}
        }} catch(e) {{}}
        return false;
    }}

    function mapUrl(u) {{
        if (!u) return u;
        try {{
            var s = String(u);
            if (s.indexOf("lh3.googleusercontent.com") !== -1) {{
                return s.replace(/https?:\\/\\/lh3\\.googleusercontent\\.com/g, origin + "/_lh3_usercontent_")
                        .replace(/\\/\\/lh3\\.googleusercontent\\.com/g, origin + "/_lh3_usercontent_");
            }}
            if (s.indexOf("lh3.google.com") !== -1) {{
                return s.replace(/https?:\\/\\/lh3\\.google\\.com/g, origin + "/_lh3_")
                        .replace(/\\/\\/lh3\\.google\\.com/g, origin + "/_lh3_");
            }}
            if (s.indexOf("geminiweb-pa.clients6.google.com") !== -1) {{
                return s.replace(/https?:\\/\\/geminiweb-pa\\.clients6\\.google\\.com/g, origin + "/_geminiweb_pa_");
            }}
            if (s.indexOf("waa-pa.clients6.google.com") !== -1) {{
                return s.replace(/https?:\\/\\/waa-pa\\.clients6\\.google\\.com/g, origin + "/_waa_pa_");
            }}
            if (s.indexOf("signaler-pa.clients6.google.com") !== -1) {{
                return s.replace(/https?:\\/\\/signaler-pa\\.clients6\\.google\\.com/g, origin + "/_signaler_pa_");
            }}
            if (s.indexOf("push.clients6.google.com") !== -1) {{
                return s.replace(/https?:\\/\\/push\\.clients6\\.google\\.com/g, origin + "/_push_clients6_");
            }}
            if (s.indexOf("ssl.gstatic.com") !== -1) {{
                return s.replace(/https?:\\/\\/ssl\\.gstatic\\.com/g, origin + "/_ssl_gstatic_")
                        .replace(/\\/\\/ssl\\.gstatic\\.com/g, origin + "/_ssl_gstatic_");
            }}
            if (s.indexOf("gemini.gstatic.com") !== -1) {{
                return s.replace(/https?:\\/\\/gemini\\.gstatic\\.com/g, origin + "/_gstatic_");
            }}
            if (s.indexOf("www.gstatic.com") !== -1) {{
                return s.replace(/https?:\\/\\/www\\.gstatic\\.com/g, origin + "/_www_gstatic_");
            }}
            // 2026-10-29: AI Studio Applet 宿主页（*.usercontent.goog）必须每次用新 URL。
            //   之前该路径被当作静态资源，发出了 Cache-Control: immutable(1y)，浏览器一直复用
            //   旧副本 -> 服务端注入/改写全被跳过 -> applet 永远转圈。这里加个一次性参数强制回源。
            if (s.indexOf(".usercontent.goog") !== -1 && s.indexOf("/download") === -1) {{
                var _ap = s.replace(/^(?:https?:)?\/\/([a-z0-9.-]+\.usercontent\.goog)(.*)$/i,
                                    origin + "/_gg_/$1$2");
                if (_ap !== s) {{
                    if (!window.__hajT) window.__hajT = String(Date.now());
                    return _ap + (_ap.indexOf("?") === -1 ? "?__t=" : "&__t=") + window.__hajT;
                }}
            }}
            // 通用兜底：任意 *.clients6.google.com / googleusercontent / googleapis / google.com / gstatic 子域
            var gm = s.match(/^(?:https?:)?\\/\\/([a-z0-9.-]+\\.(?:clients6\\.google\\.com|googleusercontent\\.com|usercontent\\.goog|googleapis\\.com|google\\.co\\.[a-z]{2}|google\\.com\\.[a-z]{2}|google\\.com|gstatic\\.com))(.*)$/i);
            if (gm) {{
                return origin + "/_gg_/" + gm[1] + (gm[2] || "");
            }}
            return s;
        }} catch(e) {{
            return u;
        }}
    }}

    // 1. Mock navigator.sendBeacon
    if (navigator.sendBeacon) {{
        var _sb = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(u, d) {{
            if (isBlocked(u)) return true;
            try {{ return _sb(mapUrl(u), d); }} catch(e) {{ return true; }}
        }};
    }}

    // 2. Intercept window.fetch
    var _fetch = window.fetch;
    window.fetch = function(input, init) {{
        // 2026-10-29: 原实现只认 string 和 Request；fetch(new URL(...)) 时 .url 为空 → 不改写 → 直连上游超时。
        var u = "";
        try {{
            if (typeof input === "string") u = input;
            else if (input && typeof input === "object") u = input.url || input.href || String(input);
        }} catch(e) {{ u = ""; }}
        if (isBlocked(u)) {{
            try {{ (window.__shieldLog = window.__shieldLog || []).push("FETCH-BLOCK " + u); }} catch(e) {{}}
            return Promise.resolve(new Response(JSON.stringify({{
                status: "ok",
                code: 200,
                nextRequestWaitMillis: "86400000",
                response: {{}}
            }}), {{
                status: 200,
                statusText: "OK",
                headers: {{ "Content-Type": "application/json" }}
            }}));
        }}
        var mapped = mapUrl(u);
        if (mapped && u && mapped !== u) {{
            try {{ (window.__shieldLog = window.__shieldLog || []).push("FETCH-REWRITE " + String(u).slice(0, 80)); }} catch(e) {{}}
            var _done = false;
            if (typeof input === "string") {{
                input = mapped; _done = true;
            }} else if (input && typeof input === "object") {{
                try {{ input = new Request(mapped, init); _done = true; }} catch(e) {{ _done = false; }}
            }}
            if (!_done) {{
                // Request 构造失败（URL 对象 / signal 异常等）→ 退化成字符串 URL，绝不回落到上游绝对地址
                try {{ input = mapped; }} catch(e) {{}}
            }}
        }}
        return _fetch.call(this, input, init);
    }};

    // 3. Intercept XMLHttpRequest
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {{
        var rest = Array.prototype.slice.call(arguments, 2);
        try {{ url = (typeof url === "string") ? url : String(url); }} catch(e) {{}}
        if (isBlocked(url)) {{
            try {{ (window.__shieldLog = window.__shieldLog || []).push("XHR-BLOCK " + url); }} catch(e) {{}}
            url = "/__mock_ok__?src=" + encodeURIComponent(url);
        }} else {{
            url = mapUrl(url);
        }}
        return _open.apply(this, [method, url].concat(rest));
    }};

    // 3.5 原生下载改写（2026-10-29）：<a download> 不经过 fetch/XHR，
    //     上游媒体域名（contribution.usercontent / lh3.googleusercontent）会直连超时。
    //     这里在捕获阶段把 href 换成本站 /_gg_/ 前缀，同源下载即可走镜像。
    function rewriteAnchor(a) {{
        try {{
            var raw = a.getAttribute("href") || a.href || "";
            if (!raw || raw.indexOf(origin) === 0) return false;
            var mapped = mapUrl(raw);
            if (mapped && mapped !== raw) {{
                a.setAttribute("href", mapped);
                try {{ (window.__shieldLog = window.__shieldLog || []).push("DL-REWRITE " + mapped.slice(0, 90)); }} catch(e) {{}}
                return true;
            }}
        }} catch(e) {{}}
        return false;
    }}
    // ⚠️ Google 新 UI 大量使用 Shadow DOM：e.target 是 shadow host，closest() 拿不到里面的 <a>。
    //    必须走 composedPath() 穿透 shadow 边界，否则「下载」按钮永远改写不到。
    function findAnchor(e) {{
        try {{
            var path = (e.composedPath && e.composedPath()) || [];
            for (var i = 0; i < path.length; i++) {{
                var n = path[i];
                if (n && n.tagName === "A" && n.getAttribute) return n;
            }}
        }} catch(x) {{}}
        var t = e.target;
        try {{ return t && t.closest ? t.closest("a[href]") : null; }} catch(x) {{ return null; }}
    }}
    ["click", "pointerdown", "mousedown", "auxclick"].forEach(function(ev) {{
        document.addEventListener(ev, function(e) {{
            var a = findAnchor(e);
            if (a) rewriteAnchor(a);
        }}, true);
    }});
    // shadow root 也需要单独观察 + 改写（document 的 observer 进不去 shadow 树）
    function scanShadow(root) {{
        try {{
            var as = root.querySelectorAll ? root.querySelectorAll("a[href]") : [];
            for (var i = 0; i < as.length; i++) rewriteAnchor(as[i]);
            var all = root.querySelectorAll ? root.querySelectorAll("*") : [];
            for (var j = 0; j < all.length; j++) {{
                var sr = all[j].shadowRoot;
                if (sr && !sr.__hajimiObs) {{
                    sr.__hajimiObs = true;
                    scanShadow(sr);
                    try {{
                        new MutationObserver(function(muts, obs) {{
                            scanShadow(obs.__root || sr);
                        }}).observe(sr, {{childList: true, subtree: true}});
                    }} catch(x) {{}}
                }}
            }}
        }} catch(x) {{}}
    }}
    setInterval(function() {{ scanShadow(document); }}, 1200);
    try {{
        new MutationObserver(function(muts) {{
            for (var i = 0; i < muts.length; i++) {{
                var nodes = muts[i].addedNodes || [];
                for (var j = 0; j < nodes.length; j++) {{
                    var n = nodes[j];
                    if (!n || n.nodeType !== 1) continue;
                    if (n.tagName === "A") rewriteAnchor(n);
                    if (n.querySelectorAll) {{
                        var as = n.querySelectorAll("a[href]");
                        for (var k = 0; k < as.length; k++) rewriteAnchor(as[k]);
                    }}
                }}
            }}
        }}).observe(document.documentElement, {{childList: true, subtree: true}});
    }} catch(e) {{}}
    var _winOpen = window.open;
    window.open = function(u) {{
        var args = Array.prototype.slice.call(arguments);
        if (u) args[0] = mapUrl(u);
        return _winOpen.apply(window, args);
    }};

    // 3.6 postMessage targetOrigin 重写（2026-10-29）
    //     Google 的 Applet「宿主页」要求父页面 postMessage 的 targetOrigin 必须是 applet 原始域名
    //     （*.scf.usercontent.goog）。经镜像后接收方实际 origin 是我们自己，浏览器会直接拒绝投递
    //     （target origin ... does not match the recipient window's origin），正文永远送不进 iframe，
    //     表现为 applet 永远转圈。postMessage 不在 Window.prototype 上，只能给目标窗口装包装。
    (function () {{
        function patchWin(w) {{
            try {{
                if (!w || typeof w.postMessage !== "function" || w.__hajimiPM) return;
                var _orig = w.postMessage;
                var wrapper = function (msg, targetOrigin, transfer) {{
                    try {{
                        var t = String(targetOrigin || "");
                        if (t.indexOf(".usercontent.goog") !== -1) {{
                            targetOrigin = window.location.origin;
                            try {{ (window.__shieldLog = window.__shieldLog || []).push("PM-REWRITE " + t.slice(0, 60)); }} catch (e2) {{}}
                        }}
                    }} catch (e) {{}}
                    return _orig.apply(w, [msg, targetOrigin, transfer]);
                }};
                var ok = false;
                try {{
                    Object.defineProperty(w, "postMessage", {{ configurable: true, writable: true, value: wrapper }});
                    ok = (w.postMessage === wrapper);
                }} catch (e) {{}}
                if (!ok) {{
                    try {{ w.postMessage = wrapper; ok = (w.postMessage === wrapper); }} catch (e) {{}}
                }}
                if (ok) {{ try {{ w.__hajimiPM = 1; }} catch (e) {{}} }}
            }} catch (e) {{}}
        }}
        try {{
            patchWin(window);
            var _d = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "contentWindow");
            if (_d && _d.get) {{
                Object.defineProperty(HTMLIFrameElement.prototype, "contentWindow", {{
                    configurable: true,
                    get: function () {{
                        var w = _d.get.call(this);
                        patchWin(w);
                        return w;
                    }}
                }});
            }}
            // iframe 一创建就包装（父页面可能创建后立刻 postMessage，轮询来不及）
            try {{
                var _ce = Document.prototype.createElement;
                Document.prototype.createElement = function (tag) {{
                    var el = _ce.apply(this, arguments);
                    try {{
                        if (String(tag).toLowerCase() === "iframe") {{
                            setTimeout(function () {{ try {{ patchWin(el.contentWindow); }} catch (e) {{}} }}, 0);
                        }}
                    }} catch (e) {{}}
                    return el;
                }};
            }} catch (e) {{}}
            // 兜底：100ms 轮询 + iframe load 事件，尽量在父页面首次 postMessage 之前完成包装
            document.addEventListener("load", function (ev) {{
                try {{
                    if (ev.target && ev.target.tagName === "IFRAME") patchWin(ev.target.contentWindow);
                }} catch (e) {{}}
            }}, true);
            // ⚠️ applet 的 iframe 在 Shadow DOM 里，document.querySelectorAll 扫不到 —— 必须递归 shadowRoot
            function scanFix(root, depth) {{
                if (!root || depth > 6) return;
                try {{
                    var fs = root.querySelectorAll ? root.querySelectorAll("iframe") : [];
                    for (var i = 0; i < fs.length; i++) {{
                        try {{ patchWin(fs[i].contentWindow); }} catch (e) {{}}
                    }}
                    var all = root.querySelectorAll ? root.querySelectorAll("*") : [];
                    for (var j = 0; j < all.length; j++) {{
                        if (all[j].shadowRoot) scanFix(all[j].shadowRoot, depth + 1);
                    }}
                }} catch (e) {{}}
            }}
            // 插入瞬间就打补丁：MutationObserver 比轮询早一个微任务，覆盖 shadow root 里的 iframe
            function onNodes(nodes) {{
                for (var i = 0; i < nodes.length; i++) {{
                    var n = nodes[i];
                    if (!n || n.nodeType !== 1) continue;
                    try {{
                        if (n.tagName === "IFRAME") patchWin(n.contentWindow);
                        if (n.shadowRoot) {{
                            obs(n.shadowRoot);
                            var fs0 = n.shadowRoot.querySelectorAll("iframe");
                            for (var k = 0; k < fs0.length; k++) patchWin(fs0[k].contentWindow);
                        }}
                    }} catch (e) {{}}
                }}
            }}
            function obs(root) {{
                try {{
                    if (!root || root.__hajObs) return;
                    root.__hajObs = 1;
                    new MutationObserver(function (ms) {{
                        for (var i = 0; i < ms.length; i++) onNodes(ms[i].addedNodes || []);
                    }}).observe(root, {{ childList: true, subtree: true }});
                }} catch (e) {{}}
            }}
            obs(document);
            try {{
                var _ar = Element.prototype.attachShadow;
                Element.prototype.attachShadow = function () {{
                    var sr = _ar.apply(this, arguments);
                    try {{ obs(sr); }} catch (e) {{}}
                    return sr;
                }};
            }} catch (e) {{}}
            setInterval(function () {{ scanFix(document, 0); }}, 100);
        }} catch (e) {{}}
    }})();

    // 4. Intercept WebSocket
    var _WS = window.WebSocket;
    if (_WS) {{
        window.WebSocket = function(url, protocols) {{
            if (isBlocked(url)) {{
                return {{
                    readyState: 3,
                    close: function() {{}},
                    send: function() {{}},
                    addEventListener: function() {{}},
                    removeEventListener: function() {{}}
                }};
            }}
            return protocols ? new _WS(url, protocols) : new _WS(url);
        }};
        window.WebSocket.prototype = _WS.prototype;
    }}

    // 5. Intercept HTMLIFrameElement src (阻断 accounts/ogs 挂死)
    var iframeDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "src");
    if (iframeDesc && iframeDesc.set) {{
        Object.defineProperty(HTMLIFrameElement.prototype, "src", {{
            set: function(val) {{
                if (isBlocked(val)) {{
                    val = "about:blank";
                }}
                iframeDesc.set.call(this, val);
            }},
            get: iframeDesc.get
        }});
    }}

    // 6. Intercept HTMLImageElement src & srcset
    var imgDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
    if (imgDesc && imgDesc.set) {{
        Object.defineProperty(HTMLImageElement.prototype, "src", {{
            set: function(val) {{
                imgDesc.set.call(this, mapUrl(val));
            }},
            get: imgDesc.get
        }});
    }}
    var srcsetDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "srcset");
    if (srcsetDesc && srcsetDesc.set) {{
        Object.defineProperty(HTMLImageElement.prototype, "srcset", {{
            set: function(val) {{
                srcsetDesc.set.call(this, mapUrl(val));
            }},
            get: srcsetDesc.get
        }});
    }}

    // 7. Intercept Element.setAttribute
    var origSetAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function(name, val) {{
        if (typeof val === "string") {{
            var n = name.toLowerCase();
            if (n === "src" || n === "href" || n === "srcset" || n === "style") {{
                if (isBlocked(val)) {{
                    // 2026-10-31: <script src> 不能塞 about:blank（会报 Failed to load resource
                    // 且 onload 不触发），改走同源空桩，见 7.5。
                    val = (this && this.tagName === "SCRIPT")
                        ? origin + "/__mock_js__"
                        : "about:blank";
                }} else {{
                    val = mapUrl(val);
                }}
            }}
        }}
        return origSetAttr.call(this, name, val);
    }};

    // 7.5 Intercept HTMLScriptElement.src (2026-10-31)
    //     Google 的 jsloader（PendingScript / _.Cja.load）是直接给 script.src 赋值，
    //     根本不经过 setAttribute，所以 7 号补丁管不到它。之前只能靠 CSP 硬拦：
    //     虽然确实没出网（CSP 违规连 DNS 都不发），但 console 一片红字，
    //     连带 GTM/viewability 组件报 "No ID or name found in config"。
    //     这里把「已被黑名单命中的」脚本换成本站空桩：同源不违反 CSP、
    //     onload 照常触发、依旧零外连。
    //     ⚠️ 非黑名单 URL 一律原样透传，不做 mapUrl —— 绝不改动现有正常加载链路。
    (function() {{
        var sd = null;
        try {{ sd = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src"); }} catch(e) {{}}
        if (!sd || !sd.set) return;
        Object.defineProperty(HTMLScriptElement.prototype, "src", {{
            configurable: true,
            set: function(val) {{
                try {{
                    if (isBlocked(val)) {{
                        try {{
                            var m = String(val).match(/[?&]id=(GTM-[A-Za-z0-9]+)/);
                            if (m) (window.__hajGtmIds = window.__hajGtmIds || []).push(m[1]);
                            (window.__shieldLog = window.__shieldLog || []).push(
                                "SCRIPT-BLOCK " + String(val).slice(0, 90));
                        }} catch(e2) {{}}
                        val = origin + "/__mock_js__";
                    }}
                }} catch(e3) {{}}
                return sd.set.call(this, val);
            }},
            get: function() {{ return sd.get.call(this); }}
        }});
    }})();

    // 8. Intercept CSSStyleDeclaration
    var origSetProp = CSSStyleDeclaration.prototype.setProperty;
    if (origSetProp) {{
        CSSStyleDeclaration.prototype.setProperty = function(prop, val, pri) {{
            if (typeof val === "string") {{
                val = mapUrl(val);
            }}
            return origSetProp.call(this, prop, val, pri);
        }};
    }}
    var bgProp = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, "backgroundImage");
    if (bgProp && bgProp.set) {{
        Object.defineProperty(CSSStyleDeclaration.prototype, "backgroundImage", {{
            set: function(val) {{
                bgProp.set.call(this, mapUrl(val));
            }},
            get: bgProp.get
        }});
    }}
    var cssTextProp = Object.getOwnPropertyDescriptor(CSSStyleDeclaration.prototype, "cssText");
    if (cssTextProp && cssTextProp.set) {{
        Object.defineProperty(CSSStyleDeclaration.prototype, "cssText", {{
            set: function(val) {{
                cssTextProp.set.call(this, mapUrl(val));
            }},
            get: cssTextProp.get
        }});
    }}

    // 8.5 MutationObserver 兜底：innerHTML 插入的图片会绕过属性补丁
    function __fixImgEl(el) {{
        try {{
            if (!el || el.nodeType !== 1) return;
            var tag = el.tagName;
            if (tag === "IMG" || tag === "SOURCE") {{
                var v = el.getAttribute("src");
                if (v && v.indexOf("google") !== -1) el.setAttribute("src", mapUrl(v));
                var ss = el.getAttribute("srcset");
                if (ss && ss.indexOf("google") !== -1) el.setAttribute("srcset", mapUrl(ss));
            }}
            if (el.querySelectorAll) {{
                var list = el.querySelectorAll("img,source");
                for (var i = 0; i < list.length; i++) {{
                    var v2 = list[i].getAttribute("src");
                    if (v2 && v2.indexOf("google") !== -1) list[i].setAttribute("src", mapUrl(v2));
                    var s2 = list[i].getAttribute("srcset");
                    if (s2 && s2.indexOf("google") !== -1) list[i].setAttribute("srcset", mapUrl(s2));
                }}
            }}
        }} catch(e) {{}}
    }}
    try {{
        new MutationObserver(function(muts) {{
            for (var i = 0; i < muts.length; i++) {{
                var ns = muts[i].addedNodes;
                for (var j = 0; j < ns.length; j++) __fixImgEl(ns[j]);
            }}
        }}).observe(document.documentElement, {{ childList: true, subtree: true }});
        document.addEventListener("DOMContentLoaded", function() {{ __fixImgEl(document.documentElement); }});

        // Shadow DOM 里的图片 MutationObserver 进不去，单独挂监听
        var __observeRoot = function(root) {{
            try {{
                new MutationObserver(function(muts) {{
                    for (var i = 0; i < muts.length; i++) {{
                        var ns = muts[i].addedNodes;
                        for (var j = 0; j < ns.length; j++) __fixImgEl(ns[j]);
                    }}
                }}).observe(root, {{ childList: true, subtree: true }});
            }} catch(e) {{}}
        }};
        var __origAttach = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function(init) {{
            var root = __origAttach.call(this, init);
            __observeRoot(root);
            return root;
        }};
        // 兜底：周期性全量扫描（含 shadow root），覆盖 worker/延迟创建等场景
        var __deepFix = function(root, depth) {{
            if (!root || depth > 8) return;
            try {{
                __fixImgEl(root);
                var kids = root.querySelectorAll ? root.querySelectorAll("*") : [];
                for (var i = 0; i < kids.length; i++) {{
                    if (kids[i].shadowRoot) __deepFix(kids[i].shadowRoot, depth + 1);
                }}
            }} catch(e) {{}}
        }};
        // 兜底 2：内联样式与 <style> 里的 Google 图片地址（CSS 背景图不走属性补丁）
        var __fixCss = function(text) {{
            if (!text || text.indexOf("google") === -1) return text;
            return text.replace(/https?:\\/\\/(lh3\.googleusercontent\.com|lh3\.google\.com|lh[0-9]\.googleusercontent\.com)/g, origin + "/_lh3_usercontent_")
                       .replace(/https?:\\/\\/fonts\.gstatic\.com/g, origin + "/_fonts_gstatic_")
                       .replace(/https?:\\/\\/fonts\.googleapis\.com/g, origin + "/_fonts_api_")
                       .replace(/https?:\\/\\/ssl\.gstatic\.com/g, origin + "/_ssl_gstatic_")
                       .replace(/https?:\\/\\/www\.gstatic\.com/g, origin + "/_www_gstatic_")
                       .replace(/https?:\\/\\/gemini\.gstatic\.com/g, origin + "/_gstatic_");
        }};
        var __sweepStyle = function() {{
            try {{
                var all = document.querySelectorAll('[style],[data-style]');
                for (var i = 0; i < all.length; i++) {{
                    var sv = all[i].getAttribute("style");
                    if (sv && sv.indexOf("google") !== -1) {{
                        var nv = __fixCss(sv);
                        if (nv !== sv) all[i].setAttribute("style", nv);
                    }}
                }}
                var st = document.querySelectorAll("style");
                for (var j = 0; j < st.length; j++) {{
                    var css = st[j].textContent;
                    if (css && css.indexOf("google") !== -1) {{
                        var nc = __fixCss(css);
                        if (nc !== css) st[j].textContent = nc;
                    }}
                }}
            }} catch(e) {{}}
        }};
        setInterval(__sweepStyle, 2500);

        // 注：不再注销 Service Worker —— PWA「安装应用」需要它；
        // 外连已由边缘 CSP + 服务端重写兜底，SW 即使发起请求也会被 CSP 在 DNS 前拦下。

        setInterval(function() {{ __deepFix(document, 0); }}, 2500);
    }} catch(e) {{}}

    // 8.55 元素 URL 属性 setter：link.href / script.src / iframe.src 等由 JS 直接赋值时也会改写
    // （CSP 默认拦住未改写的外部资源，所以这些 setter 必须补上，否则页面会大面积报错）
    try {{
        var __patchSetter = function(proto, prop) {{
            if (!proto) return;
            var d = Object.getOwnPropertyDescriptor(proto, prop);
            if (!d || !d.set) return;
            try {{
                Object.defineProperty(proto, prop, {{
                    get: d.get,
                    set: function (v) {{
                        try {{ v = mapUrl(String(v)); }} catch (e) {{}}
                        return d.set.call(this, v);
                    }},
                    configurable: true
                }});
            }} catch (e) {{}}
        }};
        __patchSetter(HTMLLinkElement && HTMLLinkElement.prototype, "href");
        __patchSetter(HTMLScriptElement && HTMLScriptElement.prototype, "src");
        __patchSetter(HTMLIFrameElement && HTMLIFrameElement.prototype, "src");
        __patchSetter(HTMLSourceElement && HTMLSourceElement.prototype, "src");
        __patchSetter(HTMLMediaElement && HTMLMediaElement.prototype, "src");
        __patchSetter(HTMLImageElement && HTMLImageElement.prototype, "src");
    }} catch (e) {{}}

    // 8.6 动态插入的 CSS 规则（insertRule/addRule/replaceSync）里的 Google 地址也要改写
    try {{
        var __fixCssText = function(t) {{
            if (!t || t.indexOf("google") === -1) return t;
            return t.replace(/https?:\\/\\/(lh3\.googleusercontent\.com|lh3\.google\.com)/g, origin + "/_lh3_usercontent_")
                    .replace(/https?:\\/\\/fonts\.gstatic\.com/g, origin + "/_fonts_gstatic_")
                    .replace(/https?:\\/\\/fonts\.googleapis\.com/g, origin + "/_fonts_api_")
                    .replace(/https?:\\/\\/ssl\.gstatic\.com/g, origin + "/_ssl_gstatic_")
                    .replace(/https?:\\/\\/www\.gstatic\.com/g, origin + "/_www_gstatic_")
                    .replace(/https?:\\/\\/gemini\.gstatic\.com/g, origin + "/_gstatic_");
        }};
        ["insertRule", "addRule"].forEach(function(fn) {{
            var _f = CSSStyleSheet.prototype[fn];
            if (!_f) return;
            CSSStyleSheet.prototype[fn] = function(rule, idx) {{
                try {{ rule = __fixCssText(rule); }} catch(e) {{}}
                return _f.call(this, rule, idx);
            }};
        }});
        if (CSSStyleSheet.prototype.replaceSync) {{
            var _rs = CSSStyleSheet.prototype.replaceSync;
            CSSStyleSheet.prototype.replaceSync = function(t) {{
                try {{ t = __fixCssText(t); }} catch(e) {{}}
                return _rs.call(this, t);
            }};
        }}
    }} catch(e) {{}}

    // 9. Storage Protection
    try {{
        var testKey = "__shield_test__";
        window.localStorage.setItem(testKey, "1");
        window.localStorage.removeItem(testKey);
    }} catch(e) {{
        var mem = {{}};
        var shim = {{
            getItem: function(k) {{ return mem[k] !== undefined ? mem[k] : null; }},
            setItem: function(k, v) {{ mem[k] = String(v); }},
            removeItem: function(k) {{ delete mem[k]; }},
            clear: function() {{ mem = {{}}; }},
            key: function(i) {{ return Object.keys(mem)[i] || null; }},
            get length() {{ return Object.keys(mem).length; }}
        }};
        try {{
            Object.defineProperty(window, "localStorage", {{ value: shim, configurable: true, writable: true }});
            Object.defineProperty(window, "sessionStorage", {{ value: shim, configurable: true, writable: true }});
        }} catch(e2) {{}}
    }}
}})();
</script>"""

SHIELD_MINIMAL = r"""<script>
(function() {
    window.dataLayer = window.dataLayer || [];
    var origin = window.location.origin;
    var blockedList = ["play.google.com","google.com/ccm","googletagmanager.com","google-analytics.com",
        "stats.g.doubleclick.net","doubleclick.net","accounts.google.com","ogs.google.com"];
    function isBlocked(u) {
        if (!u) return false;
        var s = String(u);
        for (var i = 0; i < blockedList.length; i++) if (s.indexOf(blockedList[i]) !== -1) return true;
        return false;
    }
    function mapUrl(u) {
        if (!u) return u;
        try {
            var s = String(u);
            if (s.indexOf("lh3.googleusercontent.com") !== -1) return s.replace(/https?:\/\/lh3\.googleusercontent\.com/g, origin + "/_lh3_usercontent_").replace(/\/\/lh3\.googleusercontent\.com/g, origin + "/_lh3_usercontent_");
            if (s.indexOf("lh3.google.com") !== -1) return s.replace(/https?:\/\/lh3\.google\.com/g, origin + "/_lh3_").replace(/\/\/lh3\.google\.com/g, origin + "/_lh3_");
            if (s.indexOf("geminiweb-pa.clients6.google.com") !== -1) return s.replace(/https?:\/\/geminiweb-pa\.clients6\.google\.com/g, origin + "/_geminiweb_pa_");
            if (s.indexOf("waa-pa.clients6.google.com") !== -1) return s.replace(/https?:\/\/waa-pa\.clients6\.google\.com/g, origin + "/_waa_pa_");
            if (s.indexOf("signaler-pa.clients6.google.com") !== -1) return s.replace(/https?:\/\/signaler-pa\.clients6\.google\.com/g, origin + "/_signaler_pa_");
            if (s.indexOf("push.clients6.google.com") !== -1) return s.replace(/https?:\/\/push\.clients6\.google\.com/g, origin + "/_push_clients6_");
            if (s.indexOf("ssl.gstatic.com") !== -1) return s.replace(/https?:\/\/ssl\.gstatic\.com/g, origin + "/_ssl_gstatic_").replace(/\/\/ssl\.gstatic\.com/g, origin + "/_ssl_gstatic_");
            if (s.indexOf("gemini.gstatic.com") !== -1) return s.replace(/https?:\/\/gemini\.gstatic\.com/g, origin + "/_gstatic_");
            if (s.indexOf("www.gstatic.com") !== -1) return s.replace(/https?:\/\/www\.gstatic\.com/g, origin + "/_www_gstatic_");
            var gm = s.match(/^(?:https?:)?\/\/([a-z0-9.-]+\.(?:clients6\.google\.com|googleusercontent\.com|usercontent\.goog|googleapis\.com|google\.co\.[a-z]{2}|google\.com\.[a-z]{2}|google\.com|gstatic\.com))(.*)$/i);
            if (gm) return origin + "/_gg_/" + gm[1] + (gm[2] || "");
            return s;
        } catch(e) { return u; }
    }
    if (navigator.sendBeacon) {
        var _sb = navigator.sendBeacon.bind(navigator);
        navigator.sendBeacon = function(u, d) { if (isBlocked(u)) return true; try { return _sb(mapUrl(u), d); } catch(e) { return true; } };
    }
    var _fetch = window.fetch;
    window.fetch = function(input, init) {
        var u = typeof input === "string" ? input : (input && input.url ? input.url : "");
        if (isBlocked(u)) {
            return Promise.resolve(new Response(JSON.stringify({status:"ok",code:200,nextRequestWaitMillis:"86400000",response:{}}), {status:200, statusText:"OK", headers:{"Content-Type":"application/json"}}));
        }
        var mapped = mapUrl(u);
        if (mapped !== u) {
            if (typeof input === "string") { input = mapped; }
            else if (input && typeof input === "object") { try { input = new Request(mapped, init); } catch(e) {} }
        }
        return _fetch.call(this, input, init);
    };
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        var rest = Array.prototype.slice.call(arguments, 2);
        if (isBlocked(url)) { url = "/__mock_ok__?src=" + encodeURIComponent(url); } else { url = mapUrl(url); }
        return _open.apply(this, [method, url].concat(rest));
    };
    var imgDesc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
    if (imgDesc && imgDesc.set) {
        Object.defineProperty(HTMLImageElement.prototype, "src", { set: function(v) { imgDesc.set.call(this, mapUrl(v)); }, get: imgDesc.get });
    }
})();
</script>"""

ACTIVE_SHIELD = SHIELD_MINIMAL if os.environ.get("SHIELD_MINIMAL") == "1" else SHIELD_SCRIPT




LOGIN_PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>私有访问认证</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: #131314; color: #e3e3e3; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #1e1f20; padding: 40px 32px; border-radius: 24px; width: 100%; max-width: 420px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); text-align: center; border: 1px solid #333538; }
        .logo { font-size: 32px; font-weight: 600; margin-bottom: 8px; background: linear-gradient(135deg, #7cacf8, #a8c7fa 50%, #e8eaed); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: #8e918f; font-size: 14px; margin-bottom: 28px; }
        input[type="password"] { width: 100%; padding: 14px 18px; border-radius: 12px; border: 1px solid #444746; background: #131314; color: #fff; font-size: 16px; margin-bottom: 20px; outline: none; transition: border-color 0.2s; }
        input[type="password"]:focus { border-color: #a8c7fa; }
        button { width: 100%; padding: 14px; border-radius: 12px; border: none; background: #a8c7fa; color: #040e1b; font-size: 16px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
        button:hover { opacity: 0.9; }
        .error { color: #f2b8b5; font-size: 14px; margin-top: 14px; display: none; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">Gemini</div>
        <div class="subtitle">私有专用反向代理 · 请输入访问口令</div>
        <form method="POST" action="/__login">
            <input type="password" name="pwd" placeholder="访问口令" required autofocus>
            <button type="submit">进入 Gemini</button>
            <div id="err" class="error">口令错误，请重试</div>
        </form>
    </div>
    <script>
        if (location.search.includes('err=1')) {
            document.getElementById('err').style.display = 'block';
        }
    </script>
</body>
</html>
"""

MOCK_RESPONSE_BODY = b'{"status":"ok","code":200,"nextRequestWaitMillis":"86400000","response":{}}'

# 2026-10-31: 第三方脚本（GTM / analytics / doubleclick）空桩。
# 被 CSP 拦掉的 <script> 请求改指向本端点：同源、零外连，但 onload 正常触发，
# 同时补齐 GTM/gtag 的全局对象，避免上层组件因为「脚本没加载」连带报错。
MOCK_JS_BODY = b"""/* hajimi mock: third-party analytics stub. never leaves this origin. */
(function(){
  try {
    var dl = window.dataLayer = window.dataLayer || [];
    window.gtag = window.gtag || function(){ dl.push(arguments); };
    window.ga = window.ga || function(){};
    window.gaplugins = window.gaplugins || {};
    window.google_analytics_domain_name = window.google_analytics_domain_name || "none";
    var gtm = window.google_tag_manager = window.google_tag_manager || {};
    var ids = window.__hajGtmIds || [];
    var stub = function(){
      return {
        dataLayer: { get: function(){ return undefined; }, set: function(){} },
        get: function(){ return undefined; },
        reset: function(){}
      };
    };
    for (var i = 0; i < ids.length; i++) {
      if (!gtm[ids[i]]) gtm[ids[i]] = stub();
    }
  } catch (e) {}
})();
"""

# ── 2026-10-31: HTML 解析期的外域遥测/统计资源清理 ────────────────────
# 为什么必须放在服务端：<script async src="https://www.googletagmanager.com/gtm.js?id=...">
# 是浏览器**解析 HTML 时就建元素**的，createElement / script.src 赋值 / setAttribute
# 三种 JS 侧 hook 全部绕开，只有 CSP 拦得住。拦是拦住了（违规请求连 DNS 都不发），
# 代价是 console 一片红字，GTM 组件还连带报 "No ID or name found in config"。
# 这里直接把 src 换成本站空桩：同样零外连，但页面干净、onload 也正常触发。
_TELEMETRY_SRC_RE = re.compile(
    r'(<script\b[^>]*?\bsrc\s*=\s*)(["\'])(?:https?:)?//(?:[a-z0-9.-]+\.)?'
    r'(?:googletagmanager\.com|google-analytics\.com|googlesyndication\.com|'
    r'googleadservices\.com|doubleclick\.net)(?:[^"\']*)\2',
    re.I)

# ⚠️ 真正的 DNS 泄露点（CSP 管不到）：<link rel="dns-prefetch" href="https://www.googletagmanager.com">
# CSP 只约束「取资源」，不约束 DNS 预解析 —— 浏览器会老老实实去解析这个域名。
# 凡是没被改写成同源 /_gg_/ 的外域 hint，整条删掉。
_LINK_HINT_RE = re.compile(
    r'<link\b[^>]*\brel\s*=\s*["\']?(?:dns-prefetch|preconnect)["\']?[^>]*>',
    re.I)

def _strip_telemetry_scripts(text):
    if not text:
        return text
    return _TELEMETRY_SRC_RE.sub(lambda m: f'{m.group(1)}"/__mock_js__"', text)

def _strip_ext_link_hints(text):
    if not text:
        return text
    def _f(m):
        tag = m.group(0)
        hm = re.search(r'\bhref\s*=\s*(["\'])(.*?)\1', tag, re.I)
        if not hm:
            return tag
        href = hm.group(2).strip()
        try:
            if DOMAIN and DOMAIN in href:
                return tag          # 已指向本站，保留（同源预连接是有益的）
        except Exception:
            pass
        # 外域绝对地址 / 协议相对地址 → 丢弃
        if re.match(r'^(?:https?:)?//', href, re.I):
            return ''
        return tag
    return _LINK_HINT_RE.sub(_f, text)


def remap_google_url(u):
    """把任意 Google 资源 URL 改写成本机代理路径，用于 Location 头等无法用 shim 处理的地方。"""
    if not u:
        return u
    pairs = [
        ("https://lh3.googleusercontent.com", "/_lh3_usercontent_"),
        ("http://lh3.googleusercontent.com", "/_lh3_usercontent_"),
        ("https://lh3.google.com", "/_lh3_"),
        ("http://lh3.google.com", "/_lh3_"),
        ("https://www.gstatic.com", "/_www_gstatic_"),
        ("https://ssl.gstatic.com", "/_ssl_gstatic_"),
        ("https://gemini.gstatic.com", "/_gstatic_"),
        ("https://fonts.gstatic.com", "/_fonts_gstatic_"),
        ("https://fonts.googleapis.com", "/_fonts_api_"),
    ]
    for pre, rep in pairs:
        if u.startswith(pre):
            return f"https://{DOMAIN}{rep}" + u[len(pre):]
    m = re.match(r"^https?://([a-z0-9.-]+\.(?:clients6\.google\.com|googleusercontent\.com|usercontent\.goog|googleapis\.com|google\.co\.[a-z]{2}|google\.com\.[a-z]{2}|google\.com|gstatic\.com))(.*)$", u, re.I)
    if m:
        return f"https://{DOMAIN}/_gg_/{m.group(1)}{m.group(2)}"
    return u

# 2026-10-31: 严格同源 CSP。目的不是"安全"，而是**杜绝 DNS/流量泄露**：
# 浏览器对违反 CSP 的请求连 DNS 查询都不会发出，因此任何漏改写的 Google 域名
# （apis.google.com / www.google.com / gstatic 等）都不会被解析、更不会外连。
CSP_META = ('<meta http-equiv="Content-Security-Policy" content="'
            "default-src 'self' data: blob:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data: blob:; "
            "media-src 'self' data: blob:; "
            "connect-src 'self' data: blob:; "
            "frame-src 'self' data: blob:; "
            "child-src 'self' data: blob:; "
            "worker-src 'self' blob:; "
            "manifest-src 'self'; "
            "form-action 'self'; "
            "object-src 'none'; base-uri 'self'"
            '">')

def _safe_header(k, v):
    """响应头只能是 latin-1；上游给中文文件名（Content-Disposition）时
    http.server 的 send_header 会抛 UnicodeEncodeError -> 连接中断 -> 反代侧 502。
    这里统一兜底：content-disposition 走 RFC 5987（filename*），其它非法字符转义。
    """
    try:
        v.encode("latin-1")
        return v
    except UnicodeEncodeError:
        pass
    if k.lower() == "content-disposition":
        try:
            m = re.search(r'filename="([^"]*)"', v) or re.search(r"filename=([^;]+)", v)
            name = (m.group(1).strip() if m else "download")
            ascii_name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip("_") or "download"
            base = v[:m.start()] if m else v
            quoted = urllib.parse.quote(name, safe="")
            return f'{base}filename="{ascii_name}"; filename*=UTF-8\'\'{quoted}'
        except Exception:
            pass
    return v.encode("latin-1", "backslashreplace").decode("latin-1")


_IMMUTABLE_STATIC_HOSTS = {
    "gemini.gstatic.com", "www.gstatic.com", "fonts.gstatic.com",
}


def static_cache_control(host, content_type):
    """带内容哈希的 gstatic 静态资源长期 immutable；用户内容仍用 7 天。"""
    h = (host or "").lower()
    ct = (content_type or "").lower()
    if h in _IMMUTABLE_STATIC_HOSTS and "html" not in ct:
        return "public, max-age=31536000, immutable"
    return "public, max-age=604800"


def _cache_store(cache_file, ct, body):
    """原子写磁盘缓存：先 data 后 meta，崩溃最多留下孤儿，不会出现 meta 指向缺失 data。"""
    suffix = f".tmp.{os.getpid()}.{threading.get_ident()}"
    data_tmp = cache_file + suffix
    meta_tmp = cache_file + ".meta" + suffix
    try:
        with open(data_tmp, "wb") as cf:
            cf.write(body)
        os.replace(data_tmp, cache_file)
        with open(meta_tmp, "w") as mf:
            mf.write(ct)
        os.replace(meta_tmp, cache_file + ".meta")
    except Exception as e:
        for p in (data_tmp, meta_tmp):
            try:
                os.remove(p)
            except Exception:
                pass
        sys.stderr.write(f"[CACHE] write failed {os.path.basename(cache_file)}: {e}\n")


def _cache_startup_cleanup():
    """清理半成品：*.tmp.* 与超过 1 小时的无 meta 数据文件（只扫缓存根目录）。"""
    now = time.time()
    removed_orphans = removed_tmp = 0
    freed = 0
    try:
        with os.scandir(CACHE_DIR) as it:
            entries = list(it)
    except Exception as e:
        sys.stderr.write(f"[CACHE] startup scan failed: {e}\n")
        return
    names = {e.name for e in entries if e.is_file()}
    for e in entries:
        try:
            if not e.is_file() or ".tmp." not in e.name:
                continue
            st = e.stat()
            if now - st.st_mtime < 3600:
                continue
            os.unlink(e.path)
            names.discard(e.name)
            removed_tmp += 1
            freed += st.st_size
        except Exception:
            pass
    for e in entries:
        try:
            if not e.is_file() or e.name.endswith(".meta") or ".tmp." in e.name:
                continue
            if e.name + ".meta" in names:
                continue
            st = e.stat()
            if now - st.st_mtime < 3600:
                continue
            os.unlink(e.path)
            removed_orphans += 1
            freed += st.st_size
        except Exception:
            pass
    sys.stderr.write(
        f"[CACHE] startup cleanup: orphans={removed_orphans} tmp={removed_tmp} "
        f"freed={freed / 1024 / 1024:.1f}MB\n"
    )


class FastProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # 小响应在 keep-alive 连接上会被 Nagle + 延迟 ACK 卡 40ms
    disable_nagle_algorithm = True

    def handle_one_request(self):
        """客户端中途断开（刷新/跳转/关标签）会抛 ConnectionResetError，
        默认会让 socketserver 打一整段 Traceback 污染日志。这里静默吞掉。"""
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            self.close_connection = True

    def log_message(self, fmt, *args):
        # 过滤高频静态日志
        if not any(self.path.startswith(p) for p in [
            "/_gstatic_/", "/_www_gstatic_/", "/_fonts_gstatic_/", "/_fonts_api_/",
            "/_ssl_gstatic_/", "/_static_/", "/_static/", "/_lh3_/", "/_lh3_usercontent_/", "/_gg_/",
            "/__mock_ok__", "/__mock_js__", "/favicon.ico"
        ]):
            sys.stderr.write(f"[{self.date_time_string()}] {redact_pwd(fmt % args)}\n")

    def get_account(self):
        """返回口令对应的账号 key；未设口令时默认 owner，未认证返回 None。"""
        if not any(acc["password"] for acc in ACCOUNTS.values()):
            return "owner"
        cookie_header = self.headers.get("Cookie", "")
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if pair.startswith("gemini_auth="):
                account = verify_auth_token(pair[len("gemini_auth="):])
                if account:
                    return account

        # 2026-11-02: 不再接受 URL query 里的口令（会被访问日志/Caddy 日志记录）。
        # 口令只走 POST /__login（表单 body）或 HTTP Basic。
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                _, pwd = decoded.split(":", 1)
                return account_for_password(pwd)
            except Exception:
                pass
        return None

    def _send_unauthorized(self):
        body = b'{"error":{"message":"unauthorized","code":"unauthorized"}}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_account_unavailable(self, account):
        label = (ACCOUNTS.get(account) or {}).get("label", account)
        text = f"{label}账号尚未登录，请联系管理员在专用 Firefox 中登录 Gemini。"
        if self.command == "POST":
            body = json.dumps(
                {"error": {"message": text, "code": "account_not_ready"}},
                ensure_ascii=False,
            ).encode("utf-8")
            ctype = "application/json; charset=utf-8"
        else:
            body = (
                "<!doctype html><meta charset='utf-8'><title>账号未就绪</title>"
                f"<h1>{label}账号尚未登录</h1><p>{text}</p>"
            ).encode("utf-8")
            ctype = "text/html; charset=utf-8"
        self.send_response(503)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self._body_read = False
        self._body = None
        self.do_GET()

    def _drain_body(self):
        """读取并缓存请求体。任何提前返回的路径都必须先调用，
        否则残留的 body 字节会被当成下一个 keep-alive 请求的请求行，导致 501/串请求。"""
        if getattr(self, "_body_read", False):
            return getattr(self, "_body", None)
        self._body_read = True
        self._body = None
        te = (self.headers.get("Transfer-Encoding", "") or "").lower()
        if "chunked" in te:
            # 上传大文件时浏览器用 chunked 发送请求体，必须按分块协议读完，
            # 否则 body 丢失 → 上游 400（文件传不上去）
            buf = []
            try:
                while True:
                    line = self.rfile.readline(65536)
                    if not line:
                        break
                    line = line.strip().split(b";")[0]
                    if not line:
                        continue
                    try:
                        size = int(line, 16)
                    except ValueError:
                        break
                    if size == 0:
                        self.rfile.readline(65536)
                        break
                    buf.append(self.rfile.read(size))
                    self.rfile.read(2)
            except Exception:
                pass
            self._body = b"".join(buf) if buf else None
            return self._body
        try:
            cl = int(self.headers.get("Content-Length", 0) or 0)
        except Exception:
            cl = 0
        if cl > 0:
            try:
                self._body = self.rfile.read(cl)
            except Exception:
                self._body = None
        return self._body

    def _iter_body(self):
        """真流式读取请求体（不落内存），供大文件上传/ chunked 请求使用。
        调用后视为 body 已消费；中途异常必须关闭连接，避免残留字节污染 keep-alive。"""
        self._body_read = True
        self._body = None
        te = (self.headers.get("Transfer-Encoding", "") or "").lower()
        if "chunked" in te:
            while True:
                line = self.rfile.readline(65536)
                if not line:
                    return
                line = line.strip().split(b";")[0]
                if not line:
                    continue
                try:
                    size = int(line, 16)
                except ValueError:
                    return
                if size == 0:
                    self.rfile.readline(65536)
                    return
                remaining = size
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        return
                    remaining -= len(chunk)
                    yield chunk
                self.rfile.read(2)
        else:
            try:
                cl = int(self.headers.get("Content-Length", 0) or 0)
            except Exception:
                cl = 0
            remaining = cl
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    return
                remaining -= len(chunk)
                yield chunk

    def do_POST(self):
        self._body_read = False
        self._body = None
        parsed = urllib.parse.urlparse(self.path)

        # 🔴 P2 根治：POST /__mock_ok__ 秒回 200
        if parsed.path == "/__mock_ok__":
            self._drain_body()
            _qs = urllib.parse.parse_qs(parsed.query)
            _src = (_qs.get("src", [""])[0] or "")
            # 遥测/信令类接口真实返回 protobuf，必须回空二进制，否则前端解析失败会中断发送链路
            if ("waa-pa" in _src) or ("signaler-pa" in _src) or ("pa.clients6.google.com" in _src):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(MOCK_RESPONSE_BODY)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(MOCK_RESPONSE_BODY)
            self.wfile.flush()
            return

        if self.path == "/__login":
            self._drain_body()
            login_ip = _client_ip(self)
            blocked, retry_after = _login_is_blocked(login_ip)
            if blocked:
                retry_s = max(1, int(retry_after or LOGIN_LOCK_SECONDS))
                sys.stderr.write(f"[LOGIN] blocked ip={login_ip} retry={retry_s}s\n")
                body = (
                    "<!doctype html><meta charset='utf-8'><title>尝试过多</title>"
                    f"<h1>尝试过多</h1><p>请在 {retry_s} 秒后重试。</p>"
                ).encode("utf-8")
                self.send_response(429)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Retry-After", str(retry_s))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return
            body = (getattr(self, "_body", None) or b"").decode("utf-8", "replace")
            data = urllib.parse.parse_qs(body)
            pwd = data.get("pwd", [""])[0]
            account = account_for_password(pwd)
            if account:
                _login_clear(login_ip)
                token = make_auth_token(account)
                sys.stderr.write(f"[LOGIN] account={account} ok ip={login_ip}\n")
                self.send_response(303)
                self.send_header("Location", "/app")
                self.send_header("Set-Cookie", f"gemini_auth={token}; Path=/; Max-Age=2592000; SameSite=Lax; Secure; HttpOnly")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                _login_record_failure(login_ip)
                sys.stderr.write(f"[LOGIN] failed ip={login_ip}\n")
                self.send_response(303)
                self.send_header("Location", "/__login?err=1")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return

        # 2026-11-02: 除登录/遥测桩外，所有 POST 必须有有效口令；
        # 否则未认证请求会带着 owner 的 Cookie 打到 Google。
        account = self.get_account()
        if not account:
            self._drain_body()
            self._send_unauthorized()
            return
        self.account = account
        self.handle_proxy("POST")

    def do_GET(self):
        self._body_read = False
        self._body = None
        self._drain_body()
        self.account = self.get_account()
        # 拦截 source map，秒回 404
        if self.path.endswith(".map"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        parsed = urllib.parse.urlparse(self.path)

        # 🔴 拦截 favicon.ico 秒回 204
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # 🔴 P2 根治：GET /__mock_ok__ 秒回 200
        if parsed.path == "/__mock_ok__":
            _qs = urllib.parse.parse_qs(parsed.query)
            _src = (_qs.get("src", [""])[0] or "")
            # 遥测/信令类接口真实返回 protobuf，必须回空二进制，否则前端解析失败会中断发送链路
            if ("waa-pa" in _src) or ("signaler-pa" in _src) or ("pa.clients6.google.com" in _src):
                self.send_response(200)
                self.send_header("Content-Type", "application/x-protobuf")
                self.send_header("Content-Length", "0")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(MOCK_RESPONSE_BODY)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(MOCK_RESPONSE_BODY)
            self.wfile.flush()
            return

        # 2026-10-31: 第三方脚本空桩（GTM / analytics / doubleclick）。
        # SHIELD 的 script.src 拦截面把命中的外域脚本指到这里：同源、零外连、onload 正常。
        if parsed.path == "/__mock_js__":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(MOCK_JS_BODY)))
            self.end_headers()
            self.wfile.write(MOCK_JS_BODY)
            self.wfile.flush()
            return

        if parsed.path == "/__login":
            b = LOGIN_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return

        # 静态资源免鉴权直发
        if any(self.path.startswith(p) for p in [
            "/_gstatic_/", "/_www_gstatic_/", "/_fonts_gstatic_/", "/_fonts_api_/",
            "/_ssl_gstatic_/", "/_static_/", "/_static/", "/_lh3_/", "/_lh3_usercontent_/", "/_gg_/", "/favicon.ico"
        ]):
            self.handle_proxy("GET")
            return

        if not self.account:
            if self.path == "/" or self.path.startswith("/app"):
                self.send_response(303)
                self.send_header("Location", "/__login")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "12")
                self.end_headers()
                self.wfile.write(b"Unauthorized")
            return

        if self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/app")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.handle_proxy("GET")

    def do_OPTIONS(self):
        self._body_read = False
        self._body = None
        self._drain_body()
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def handle_proxy(self, method):
        path = self.path
        _t_start = time.time()

        # 拦截残留的遥测/打点请求，秒回 200
        # 2026-11-07: waa 是 protobuf 客户端，只能回空 protobuf；回 JSON 会被当成
        # 数据帧喂给反序列化器，抛 "Error when deserializing response data"。
        if "$rpc/google.internal.waa" in path:
            if method in ("POST", "PUT", "PATCH"):
                self._drain_body()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.send_header("Content-Length", "0")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            return
        # 2026-11-07: punctual/v1/chooseServer 是 Punctual 时钟同步 RPC（protobuf）。
        # 曾把它 mock 成 JSON → 前端解析失败 → 指数退避重试 5~10 分钟（表现为
        # 长时间"思考中"后回退新对话页）。必须走真代理，不要加回 mock。
        if any(x in path for x in ["ccm/collect", "play.google.com", "google-analytics"]):
            if method in ("POST", "PUT", "PATCH"):
                self._drain_body()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(MOCK_RESPONSE_BODY)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(MOCK_RESPONSE_BODY)
            self.wfile.flush()
            return

        # 映射上游主机与路径
        target_host = "gemini.google.com"
        target_path = path

        if path.startswith("/_gstatic_/"):
            target_host = "gemini.gstatic.com"
            target_path = path[len("/_gstatic_"):]
        elif path.startswith("/_static_/"):
            target_host = "gemini.gstatic.com"
            target_path = path[len("/_static_"):]
        elif path.startswith("/_static/"):
            target_host = "gemini.gstatic.com"
            target_path = path[len("/_static"):]
        elif path.startswith("/_www_gstatic_/"):
            target_host = "www.gstatic.com"
            target_path = path[len("/_www_gstatic_"):]
        elif path.startswith("/_fonts_gstatic_/"):
            target_host = "fonts.gstatic.com"
            target_path = path[len("/_fonts_gstatic_"):]
        elif path.startswith("/_fonts_api_/"):
            target_host = "fonts.googleapis.com"
            target_path = path[len("/_fonts_api_"):]
        elif path.startswith("/_ssl_gstatic_/"):
            target_host = "ssl.gstatic.com"
            target_path = path[len("/_ssl_gstatic_"):]
        elif path.startswith("/_lh3_/"):
            # 注意：/_lh3_ 前缀对应 lh3.google.com（与前端 shim 的 lh3.google.com 分支一致），
            # 不能指向 lh3.googleusercontent.com，否则 rd-gg 等图片会 404。
            target_host = "lh3.google.com"
            target_path = path[len("/_lh3_"):]
        elif path.startswith("/_lh3_usercontent_/"):
            target_host = "lh3.googleusercontent.com"
            target_path = path[len("/_lh3_usercontent_"):]
        elif path.startswith("/_geminiweb_pa_/"):
            target_host = "geminiweb-pa.clients6.google.com"
            target_path = path[len("/_geminiweb_pa_"):]
        elif path.startswith("/_gg_/"):
            _rest = path[len("/_gg_/"):]
            _slash = _rest.find("/")
            if _slash == -1:
                _h, _rp = _rest, "/"
            else:
                _h, _rp = _rest[:_slash], _rest[_slash:]
            # 2026-11-02 安全：主机名大小写不敏感；统一小写，防止
            # /_gg_/GEMINI.GOOGLE.COM/... 绕过下面的鉴权与 Cookie 注入。
            _h = _h.lower()
            if not re.match(r"^[a-z0-9.-]+\.(clients6\.google\.com|googleusercontent\.com|usercontent\.goog|googleapis\.com|google\.co\.[a-z]{2}|google\.com\.[a-z]{2}|google\.com|gstatic\.com)$", _h, re.I):
                if method in ("POST", "PUT", "PATCH"):
                    self._drain_body()
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # 账号/组件类直连会挂 21~31s，直接秒回空
            if _h in ("ogs.google.com", "accounts.google.com", "play.google.com"):
                if method in ("POST", "PUT", "PATCH"):
                    self._drain_body()
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            target_host = _h
            target_path = _rp
        elif path.startswith("/_waa_pa_/"):
            target_host = "waa-pa.clients6.google.com"
            target_path = path[len("/_waa_pa_"):]
        elif path.startswith("/_signaler_pa_/"):
            target_host = "signaler-pa.clients6.google.com"
            target_path = path[len("/_signaler_pa_"):]
        elif path.startswith("/_push_clients6_/"):
            target_host = "push.clients6.google.com"
            target_path = path[len("/_push_clients6_"):]

        upstream_url = f"https://{target_host}{target_path}"

        # 2026-11-02 安全：用户内容（头像/生成图/Applet 宿主）即使命中静态缓存，
        # 也必须先通过镜像登录；否则知道 URL 就能匿名读取。
        if _is_private_host(target_host) and not getattr(self, "account", None):
            if method in ("POST", "PUT", "PATCH"):
                self._drain_body()
            self._send_unauthorized()
            return

        # 判定是否属于静态资源
        # 2026-10-29: 媒体下载（视频/大文件）绝不入静态缓存：体积大、要支持 Range/206
        _is_media_dl = ("/download" in target_path) or target_host.startswith("contribution.usercontent.")
        is_static = (not _is_media_dl) and any(path.startswith(p) for p in [
            "/_gstatic_/", "/_www_gstatic_/", "/_fonts_gstatic_/", "/_fonts_api_/",
            "/_ssl_gstatic_/", "/_static_/", "/_static/", "/_lh3_/", "/_lh3_usercontent_/", "/_gg_/"
        ]) or any(
            ext in target_path for ext in [".js", ".css", ".woff2", ".ttf", ".svg", ".png", ".jpg", ".webp", ".ico", ".wasm"]
        )

        cache_key = hashlib.md5(upstream_url.encode("utf-8")).hexdigest()
        cache_file = os.path.join(CACHE_DIR, cache_key)
        _cache_status = None

        # 内存 -> 磁盘缓存直接命中（0 毫秒直出）
        if method == "GET" and is_static:
            # 2026-10-29: HTML 不吃内存缓存 —— Applet shim 等页面需要每次回源走注入/改写，
            #   命中缓存会拿到「改写前」的旧副本（补丁不生效、页面永远转圈）。
            _mem = MEM_CACHE.get(upstream_url)
            if _mem is not None and "html" not in _mem[0].lower():
                ct, body = _mem
                _stat_inc("mem_hits")
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", static_cache_control(target_host, ct))
                self.send_header("X-Mirror-Cache", "mem")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                if method != "HEAD":
                    self.wfile.write(body)
                    self.wfile.flush()
                return

            if os.path.exists(cache_file):
                try:
                    with open(cache_file + ".meta", "r") as mf:
                        ct = mf.read().strip()
                    # 2026-10-29: HTML 绝不能直接吐缓存 —— Applet shim 等页面需要每次走改写流程，
                    # 否则浏览器拿到的是「改写前」的旧 HTML（表现为刷新多次仍报同样的错）。
                    if "html" in ct.lower():
                        raise RuntimeError("html bypass cache")
                    with open(cache_file, "rb") as cf:
                        body = cf.read()
                    MEM_CACHE.put(upstream_url, (ct, body))
                    _stat_inc("disk_hits")
                    self.send_response(200)
                    self.send_header("Content-Type", ct)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", static_cache_control(target_host, ct))
                    self.send_header("X-Mirror-Cache", "disk")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    if method != "HEAD":
                        self.wfile.write(body)
                        self.wfile.flush()
                    return
                except Exception:
                    pass
            _cache_status = "miss"
            _stat_inc("misses")

        if "upload" in path:
            sys.stderr.write(f"[UPLOAD] {method} {redact_pwd(path)[:120]} te={self.headers.get('Transfer-Encoding','-')} "
                             f"cl={self.headers.get('Content-Length','-')}\n")
        # 2026-11-05: 小请求体缓冲（可重试）；chunked 或 >2MB 大上传真流式，避免全量进内存。
        req_body = getattr(self, "_body", None)
        _body_is_stream = False
        _stream_cl = None
        if method in ("POST", "PUT", "PATCH") and not getattr(self, "_body_read", False):
            _te = (self.headers.get("Transfer-Encoding", "") or "").lower()
            try:
                _cl = int(self.headers.get("Content-Length", 0) or 0)
            except Exception:
                _cl = 0
            if "chunked" in _te or _cl > 2 * 1024 * 1024:
                req_body = self._iter_body()
                _body_is_stream = True
                _stream_cl = _cl if _cl > 0 else None
            else:
                req_body = self._drain_body()

        # 强制模拟 Google Chrome on Linux Desktop（与 Linux Cookie 账号环境 100% 吻合）
        _CHROME_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        _CHROME_SEC_CH_UA = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
        _CHROME_SEC_CH_UA_MOBILE = "?0"
        _CHROME_SEC_CH_UA_PLATFORM = '"Linux"'

        forward_headers = {
            "Host": target_host,
            "User-Agent": _CHROME_UA,
            "Accept": self.headers.get("Accept", "*/*"),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://gemini.google.com/",
            "Origin": "https://gemini.google.com",
            "X-Same-Domain": "1",
            "Sec-Fetch-Site": "same-origin",
            "sec-ch-ua": _CHROME_SEC_CH_UA,
            "sec-ch-ua-mobile": _CHROME_SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": _CHROME_SEC_CH_UA_PLATFORM,
        }
        if _body_is_stream and _stream_cl:
            forward_headers["Content-Length"] = str(_stream_cl)
        # 上传头已合并到上面的 x-goog-* 转发

        if target_host.lower().endswith(".google.com") or target_host.lower() == "gemini.google.com":
            # 2026-11-02: 双账号与鉴权收紧。凡是会注入 Google Cookie 的上游，
            # 必须有有效口令且对应账号已登录；否则匿名请求（包括 /_gg_/ 静态前缀）
            # 会带着 owner 的 Cookie 打到 Google。
            if not getattr(self, "account", None):
                self._send_unauthorized()
                return
            if not has_login_cookies(self.account):
                sys.stderr.write(f"[COOKIE] account={self.account} 未检测到登录 cookie\n")
                self._send_account_unavailable(self.account)
                return
            cookie_str = get_cookies_str(target_host, self.account)
            if cookie_str:
                forward_headers["Cookie"] = cookie_str
                # 客户端身份 blob（浏览器生成的 x-goog-ext-* / 账号索引）必须透传，
                # 否则服务端把写请求当成「未注册客户端」→ 临时会话（能回复但不落库）。
                # 仅转发所有 x-goog-* 头（ext 为客户端身份，upload 为上传协议，缺一不可）；sec-ch-ua 强制锁定为 Desktop Chrome
                for _k, _v in self.headers.items():
                    _kl = _k.lower()
                    if _kl.startswith("x-goog-"):
                        forward_headers[_k] = _v
                # 上传请求：额外转发所有原始头（黑名单），确保不丢任何 Google 上传协议需要的头
                if "upload" in path:
                    _skip = {"host","connection","proxy-connection","keep-alive","te","trailer",
                             "transfer-encoding","upgrade","cookie","content-length","accept-encoding"}
                    for _k, _v in self.headers.items():
                        if _k.lower() not in _skip and _k not in forward_headers:
                            forward_headers[_k] = _v
                # SAPISIDHASH：浏览器只有在 google.com 域下才会自己算；镜像域名下必须由我们算。
                # 这是 Google 区分「真实浏览器会话」与「API/临时会话」的关键凭证。
                try:
                    _ck = dict(x.split("=", 1) for x in cookie_str.split("; ") if "=" in x)
                    _sid = (_ck.get("SAPISID") or _ck.get("__Secure-1PAPISID")
                            or _ck.get("__Secure-3PAPISID") or _ck.get("APISID"))
                    if _sid and ("batchexecute" in path or "processSession" in path or method in ("POST", "PUT")):
                        forward_headers["Authorization"] = make_sapisidhash(_sid)
                        sys.stderr.write(f"[AUTH-HASH] {redact_pwd(path)[:50]} 已注入 SAPISIDHASH\n")
                except Exception as _e:
                    sys.stderr.write(f"[AUTH-HASH] 计算失败: {_e}\n")

        ct = self.headers.get("Content-Type")
        if ct:
            forward_headers["Content-Type"] = ct
        # 关键：Google 的 RPC 靠 Authorization: SAPISIDHASH（浏览器按 Cookie 实时签名）区分登录/游客。
        # 这个头必须原样转发，丢了就会「读得到历史、写是游客态」（降智 + 会话不保存）。
        _rng = self.headers.get("Range")
        if _rng:
            forward_headers["Range"] = _rng
        authz = self.headers.get("Authorization")
        # Basic 是本镜像的登录口令，绝不能转发给 Google；SAPISIDHASH 已由上面注入。
        if authz and not authz.startswith("Basic "):
            forward_headers["Authorization"] = authz
        sys.stderr.write(
            f"[AUTH] {method} {redact_pwd(path)[:60]} account={getattr(self, 'account', None) or '-'} "
            f"auth={'YES' if authz else 'NO'}\n"
        )

        # 流式原样直通：StreamGenerate 打字机 + 所有 batchexecute RPC（RPC 响应禁止重写，否则破坏前端状态）
        # 2026-11-05: 媒体下载（视频/大文件）也走流式，避免 resp.content 全量进内存。
        is_stream = _is_media_dl or any(k in path for k in [
            "StreamGenerate", "assistant.lamda", "batchexecute",
            # WebChannel 长连接（geminiweb-pa）必须逐帧透传；缓冲会让前端收不到「会话已建立」的帧，
            # 表现为：能拿到回复文本，但新会话不入列表、URL 不跳转、不落到账号里。
            "processSession", "geminiweb_pa",
        ])

        if is_stream:
            # 🔴 关键修复：流式与媒体请求强制声明 Accept-Encoding: identity，禁止上游 Google 返回 gzip。
            # 根因：Google 上游在 gzip 下对增量小帧（如“正在搜索网络”、“思考中”、搜索引用等仅几十字节的状态帧）
            # 不会触发即时 flush，导致 Python httpx GZipDecoder（zlib）在内存中积攒缓冲，
            # 前端一直处于空等状态；改用 identity 后 Google 原生 chunk 即收即推，消除打字机与思考等待卡顿。
            forward_headers["Accept-Encoding"] = "identity"

        skip_headers = {
            "set-cookie", "content-security-policy", "content-security-policy-report-only",
            "x-frame-options", "content-encoding", "transfer-encoding", "content-length",
            "connection", "server-timing", "report-to", "nel", "alt-svc", "date", "server"
        }

        _is_ps = (os.environ.get("MIRROR_DEBUG_PS") == "1") and ("processSession" in path)
        if _is_ps:
            sys.stderr.write(f"[PS-DEBUG-REQ] {method} {path}\n")
            if req_body:
                sys.stderr.write(f"[PS-DEBUG-BODY] len={len(req_body)} preview={repr(req_body[:300])}\n")

        try:
            if is_stream:
                # 建连/TLS 握手阶段（拿到响应头前）遇 ConnectError 重试 1 次；
                # 拿到响应头后再出错绝不重放，避免重复生成或破坏客户端状态。
                _stream_cm = None
                _stream_resp = None
                for _attempt in range(1 if _body_is_stream else 2):
                    _cm = GLOBAL_CLIENT.stream(method, upstream_url, headers=forward_headers, content=req_body)
                    try:
                        _stream_resp = _cm.__enter__()
                        _stream_cm = _cm
                        break
                    except httpx.ConnectError as _e:
                        try:
                            _cm.__exit__(type(_e), _e, _e.__traceback__)
                        except Exception:
                            pass
                        _stat_inc("upstream_err")
                        sys.stderr.write(f"[RETRY-STREAM] {method} {redact_pwd(path)[:70]} attempt={_attempt+1} err={type(_e).__name__}: {_e}\n")
                        if _body_is_stream or _attempt >= 1:
                            raise
                        time.sleep(0.25)
                try:
                    resp = _stream_resp
                    _stat_inc("upstream_ok")
                    _ttfb_ms = int((time.time() - _t_start) * 1000)
                    if _is_ps:
                        sys.stderr.write(f"[PS-DEBUG-RESP] status={resp.status_code} headers={dict(resp.headers)}\n")
                    self.send_response(resp.status_code)
                    for k, v in resp.headers.items():
                        if k.lower() not in skip_headers:
                            self.send_header(k, v)
                    # 2026-10-29: 媒体下载（视频/图片）走 206/Content-Length 直通，
                    # 只有真·增量流（无 CL）才用 chunked —— 否则播放器/下载器进度条会失效。
                    _cl = resp.headers.get("content-length")
                    _ce = resp.headers.get("content-encoding")
                    if _cl and resp.status_code in (200, 206) and not _ce:
                        self.send_header("Content-Length", _cl)
                        _use_chunked = False
                    else:
                        self.send_header("Transfer-Encoding", "chunked")
                        _use_chunked = True
                    self.send_header("Access-Control-Allow-Origin", f"https://{DOMAIN}")
                    self.send_header("Access-Control-Allow-Credentials", "true")
                    self.end_headers()

                    try:
                        _first_byte_ms = None
                        _t0 = time.time()
                        # 2026-10-29: 原 chunk_size=4096 会让 ByteChunker 攒满 4KB 才吐，
                        # 思考期的几百字节增量帧被压住 → 前端「一直转圈」；改成 1 即收即转。
                        for chunk in resp.iter_bytes():
                            if chunk:
                                if _first_byte_ms is None:
                                    _first_byte_ms = int((time.time() - _t0) * 1000)
                                if _is_ps:
                                    sys.stderr.write(f"[PS-DEBUG-CHUNK] len={len(chunk)} preview={repr(chunk[:200])}\n")
                                # ⚠️ 流式响应是「长度前缀 + JSON」的二进制帧（rt=c），
                                # 任何字节替换都会让长度前缀与实际不符 → 前端流解析崩溃（图片类会话白屏）。
                                # 因此这里必须原样透传，URL 重写交给前端 shim 处理。
                                # 标准 HTTP/1.1 分块：<hex_length>\r\n<data>\r\n
                                if _use_chunked:
                                    chunk_header = f"{len(chunk):X}\r\n".encode("ascii")
                                    self.wfile.write(chunk_header + chunk + b"\r\n")
                                else:
                                    self.wfile.write(chunk)
                                self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    finally:
                        if _is_ps:
                            sys.stderr.write(f"[PS-DEBUG-FIN] {method} {path} total={int((time.time()-_t0)*1000)}ms\n")
                        sys.stderr.write(f"[STREAM] {redact_pwd(path)[:40]} ttfb={_ttfb_ms}ms first_byte={_first_byte_ms}ms "
                                         f"total={int((time.time()-_t0)*1000)}ms\n")
                        try:
                            if _use_chunked:
                                # 🔴 终结分块：RFC 规范必须发送 0\r\n\r\n 结束帧，杜绝无限 pending
                                self.wfile.write(b"0\r\n\r\n")
                                self.wfile.flush()
                        except Exception:
                            pass
                except BaseException as _inner_e:
                    if not _stream_cm.__exit__(type(_inner_e), _inner_e, _inner_e.__traceback__):
                        raise
                else:
                    _stream_cm.__exit__(None, None, None)
                return

            last_err = None
            resp = None
            for attempt in range(1 if _body_is_stream else 3):
                try:
                    resp = GLOBAL_CLIENT.request(method, upstream_url, headers=forward_headers, content=req_body)
                    break
                except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout) as e:
                    last_err = e
                    _stat_inc("upstream_err")
                    sys.stderr.write(f"[RETRY] {method} {redact_pwd(path)[:70]} attempt={attempt+1} err={type(e).__name__}: {e}\n")
                    if attempt < 2:
                        time.sleep(0.25 * (attempt + 1))
            if resp is None:
                raise last_err
            _stat_inc("upstream_ok")
            _t_up = time.time()

            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                loc = loc.replace("https://gemini.google.com", f"https://{DOMAIN}")
                loc = remap_google_url(loc)
                self.send_response(resp.status_code)
                self.send_header("Location", loc)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            resp_ct = resp.headers.get("content-type", "")
            body = resp.content
            # 2026-10-31: 按内容嗅探纠正 Content-Type。
            # Google 的 /l/font 等端点偶尔会把字体二进制标成 text/html；若按 ct 走文本改写，
            # 二进制会被 decode/encode 一遍直接毁掉字形（浏览器报 OTS parsing error → 图标变文字）。
            _magic = body[:4]
            _sniff = None
            if _magic == b"wOF2":
                _sniff = "font/woff2"
            elif _magic == b"wOFF":
                _sniff = "font/woff"
            elif _magic == b"OTTO" or _magic == b"ttcf" or _magic[:4] == b"\x00\x01\x00\x00":
                _sniff = "font/ttf"
            elif _magic[:4] == b"\x89PNG":
                _sniff = "image/png"
            elif _magic[:2] == b"\xff\xd8":
                _sniff = "image/jpeg"
            elif _magic == b"GIF8":
                _sniff = "image/gif"
            elif _magic == b"RIFF":
                _sniff = "image/webp"
            if _sniff and ("html" in resp_ct.lower() or resp_ct.lower().startswith("text/")):
                sys.stderr.write(f"[SNIFF] {redact_pwd(path)[:50]} ct {resp_ct[:24]} -> {_sniff}\n")
                resp_ct = _sniff
            is_text_replace = any(t in resp_ct for t in ["text/html", "text/css", "javascript"])
            # PWA manifest 里带 www.gstatic.com 图标地址，浏览器会去取 → 也必须重写（非 RPC，安全）
            if "manifest" in path:
                is_text_replace = True

            if is_text_replace:
                text = resp.text
                is_html = "text/html" in resp_ct
                if is_html:
                    # 只改写「标签属性」里的 Google 链接，不要动 HTML 内嵌 JSON（AF_initDataCallback 等）——
                    # 里面的 URL 是前端身份/会话配置，误改会让写请求变成游客态（能回复但不保存、降智）。
                    def _remap_attr(_m):
                        attr, quote, val = _m.group(1), _m.group(2), _m.group(3)
                        def _one(mm):
                            h = mm.group(1)
                            if h == "gemini.google.com":
                                return f"https://{DOMAIN}"
                            return f"https://{DOMAIN}/_gg_/{h}"
                        val2 = re.sub(
                            r"https://([a-z0-9.-]+\.(?:google\.co\.[a-z]{2}|google\.com\.[a-z]{2}|google\.com|googleusercontent\.com|usercontent\.goog|googleapis\.com|gstatic\.com|google\.app))",
                            _one, val)
                        return f"{attr}={quote}{val2}{quote}"

                    text = re.sub(
                        r"\b(href|src|action|srcset|poster)=(['\"])([^'\"]+)\2",
                        _remap_attr, text)
                    # 2026-10-31: 上面那条通用改写按 *google.com / gstatic 白名单走，
                    # googletagmanager.com / doubleclick.net 不在名单里，会原样留下 →
                    # 交给 CSP 硬拦（console 红字）。这里显式清理一遍。
                    text = _strip_telemetry_scripts(text)
                    text = _strip_ext_link_hints(text)
                    # 2026-10-29: AI Studio Applet 的 shim 页会校验 location.hostname 必须形如
                    #   <50位hash>-h<ver>.scf.usercontent.goog，并从 pathname 首段取 product。
                    # 经镜像访问时 hostname 是我们域名、pathname 多了 /_gg_/<host> 前缀 → 直接抛错。
                    # 这里把它改成「从 pathname 里的真实 host 提取」，product 跳过前缀，并保留原始路径做基准。
                    if "Hashed domain" in text:
                        # 2026-10-29: AI Studio Applet 的 shim 是「宿主页」：父页面用 postMessage 把正文递进来，
                        #   shim 会拿 ?origin=（也就是镜像自己的域名）重算一遍 hash，与域名里的 50 位哈希比对，
                        #   不等就拒绝渲染。origin 无法伪造成 google 域名，所以让校验恒真（L=c），
                        #   并强制走 document.write 分支，让 applet 的相对资源落在 /_gg_/<host>/ 下。
                        _n = 0
                        _pairs = (
                            ("var V=a.hostname;",
                             "var V=(a.pathname.match(/^\\/_gg_\\/([^\\/]+)/)||[])[1]||a.hostname;"),
                            ("f=/^\\/([a-z0-9_-]+)\\//.exec(a.pathname)",
                             "f=/^\\/_gg_\\/[^\\/]+\\/([a-z0-9_-]+)\\//.exec(a.pathname)||{1:\"applet\"}"),
                            ("let L=await R({product:d,salt:h.salt,trustedOrigin:b,version:Number(e)});",
                             "let L=c;/*mirror:skip-hash*/"),
                            ("if(h.unsafeDocumentWrite===!0){",
                             "if(!0){/*mirror:force-docwrite*/"),
                        )
                        for _a, _b in _pairs:
                            if _a in text:
                                text = text.replace(_a, _b, 1)
                                _n += 1
                        sys.stderr.write(f"[APPLET] shim rewrite applied {_n}/4\n")

                    # 注入客户端补丁（fetch/XHR/img/srcset/CSS/CSSOM/ShadowDOM/SW 等）
                    if "<head>" in text:
                        _csp = "" if os.environ.get("MIRROR_NO_CSP") == "1" else CSP_META
                        text = text.replace("<head>", "<head>" + _csp + ACTIVE_SHIELD, 1)
                    text = text.replace("https://accounts.google.com/RotateCookiesPage",
                                        f"https://{DOMAIN}/_gg_/accounts.google.com/RotateCookiesPage")
                    text = text.replace("https://ogs.google.com", f"https://{DOMAIN}/_gg_/ogs.google.com")
                    text = text.replace("https://gemini.google.com", f"https://{DOMAIN}")
                    text = text.replace('"gemini.google.com"', f'"{DOMAIN}"')
                    text = text.replace("'gemini.google.com'", f"'{DOMAIN}'")

                # JS/CSS 正文里的资源 URL（图标/岛屿模块/字体）——单次正则改写，避免大文件多次扫描。
                # 只动资源类主机，不碰身份相关 URL。
                def _res_host(m):
                    h = m.group(1)
                    if h == "www.gstatic.com":
                        return f"https://{DOMAIN}/_www_gstatic_"
                    if h == "fonts.gstatic.com":
                        return f"https://{DOMAIN}/_fonts_gstatic_"
                    if h == "fonts.googleapis.com":
                        return f"https://{DOMAIN}/_fonts_api_"
                    return m.group(0)
                text = re.sub(
                    r"(?:https?:)?//((?:www|fonts)\.gstatic\.com|fonts\.googleapis\.com)(?=[/\"'`])",
                    _res_host, text)

                body = text.encode("utf-8")

            if method == "GET" and resp.status_code == 200 and is_static and "html" not in resp_ct.lower():
                MEM_CACHE.put(upstream_url, (resp_ct, body))
                _cache_store(cache_file, resp_ct, body)

            self.send_response(resp.status_code)
            _is_manifest = "manifest" in path
            for k, v in resp.headers.items():
                if k.lower() in skip_headers:
                    continue
                # manifest 不能沿用 Google 的「缓存一年」，否则浏览器长期持有旧图标地址
                if _is_manifest and k.lower() == "cache-control":
                    continue
                # 静态资源由我们自己声明缓存策略，避免同一响应出现两个 Cache-Control
                if is_static and k.lower() == "cache-control":
                    continue
                # 2026-10-31: 中文文件名会让 send_header 抛 UnicodeEncodeError -> 502
                self.send_header(k, _safe_header(k, v))
            if _is_manifest:
                self.send_header("Cache-Control", "no-cache, must-revalidate")

            # 🔴 P0 修复：非流式响应严格显式声明 Content-Length，绝不带 chunked 头，确保连接干净结算
            self.send_header("Content-Length", str(len(body)))
            sys.stderr.write(f"[RESP] {method} {redact_pwd(path)[:90]} -> {resp.status_code} len={len(body)} "
                             f"ct={resp_ct[:40]} ttfb={int((_t_up - _t_start) * 1000)}ms cache={_cache_status or '-'}\n")
            if is_static and not _is_manifest:
                self.send_header("Cache-Control", static_cache_control(target_host, resp_ct))
            self.send_header("Access-Control-Allow-Origin", f"https://{DOMAIN}")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("X-DNS-Prefetch-Control", "off")
            if _cache_status:
                self.send_header("X-Mirror-Cache", _cache_status)
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body)
                self.wfile.flush()
            _total_ms = int((time.time() - _t_start) * 1000)
            if _total_ms > 2000:
                _stat_inc("slow_2s")
                sys.stderr.write(f"[SLOW] {method} {redact_pwd(path)[:90]} -> {resp.status_code} "
                                 f"total={_total_ms}ms len={len(body)} cache={_cache_status or '-'}\n")

        except (BrokenPipeError, ConnectionResetError):
            if _body_is_stream:
                self.close_connection = True
        except Exception as e:
            if _body_is_stream:
                self.close_connection = True
            traceback.print_exc()
            try:
                err_body = f"Bad Gateway: {e}".encode("utf-8")
                self.send_response(502)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(err_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(err_body)
                self.wfile.flush()
                self.close_connection = True
            except Exception:
                pass

class FastHTTPServer(ThreadingHTTPServer):
    request_queue_size = 128


def start_direct_tls():
    """直连入口：0.0.0.0:<DIRECT_TLS_PORT> 走 HTTPS。
    与前置反代/隧道用的 127.0.0.1:<MIRROR_PORT>（明文）互不影响。
    必要性：登录 Cookie 带 Secure，走明文 HTTP 根本存不住。"""
    cert = os.environ.get("DIRECT_TLS_CERT", "certs/fullchain.pem")
    key = os.environ.get("DIRECT_TLS_KEY", "certs/privkey.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        print("[!] 未找到证书，跳过直连 HTTPS 监听", flush=True)
        return None
    try:
        import ssl, threading
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv = FastHTTPServer(("0.0.0.0", DIRECT_TLS_PORT), FastProxyHandler)
        srv.daemon_threads = True
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[*] 直连 HTTPS 已监听 0.0.0.0:{DIRECT_TLS_PORT}", flush=True)
        return srv
    except Exception as e:
        print(f"[!] 直连 HTTPS 启动失败: {e}", flush=True)
        return None


def main():
    print(f"[*] hajimi-web 网关 V6 已启动，监听 127.0.0.1:{PORT} ...", flush=True)
    _cache_startup_cleanup()
    _stats_interval = int(os.environ.get("MIRROR_STATS_INTERVAL", "300"))
    if _stats_interval > 0:
        threading.Thread(target=_stats_reporter, args=(_stats_interval,), daemon=True).start()
    # 直连 TLS 已关闭（2026-10-28）：Python 自带 TLS 不稳定（握手卡死无自愈），
    # 推荐前置 Caddy/Nginx 终止 TLS；如需 Python 自带 TLS，可按需开启。
    # start_direct_tls()
    server = FastHTTPServer(("127.0.0.1", PORT), FastProxyHandler)
    server.daemon_threads = True
    server.serve_forever()

if __name__ == "__main__":
    main()
