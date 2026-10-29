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
import re
import urllib.parse
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import httpx

# 端口/域名/缓存支持环境变量覆盖：默认与阿里云中转一致；
# 直连实例由 systemd 传入 MIRROR_PORT/MIRROR_DOMAIN/MIRROR_CACHE。
PORT = int(os.environ.get("MIRROR_PORT", "8324"))
DIRECT_TLS_PORT = int(os.environ.get("DIRECT_TLS_PORT", "8322"))   # 直连 HTTPS（公网映射指向这里）
UPSTREAM_PROXY = os.environ.get("UPSTREAM_PROXY", "http://127.0.0.1:7890")
FIREFOX_PROFILE = os.environ.get("FIREFOX_PROFILE", "/home/admin/.mozilla/firefox-gemini")
# ⚠️ 口令务必通过环境变量 HAJIMI_PWD 提供，不要写死在代码里
PASSWORD = os.environ.get("HAJIMI_PWD", "")
SECRET_KEY = b"Hajimi_2026_HJM_SecretKey_Salt_7f3a"
DOMAIN = os.environ.get("MIRROR_DOMAIN", "hajimi.example.com")

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

STATIC_MEM_CACHE = {}

# ── 2. Cookie 智能内存缓存（基于 mtime 检查）─────────────────────
CACHED_COOKIE_STR = ""
LAST_COOKIE_MTIME = 0
LAST_COOKIE_CHECK = 0

_COOKIE_LOCK = threading.Lock()

def _load_cookies():
    """从 Firefox profile 读取全部 google 域 Cookie，按 host 建索引。返回 {host: [(name,value)]}。

    2026-10-29: 原实现先更新时间戳再读库，并发首调时另一线程会读到「已更新时间戳但缓存仍空」
    → NameError: CACHED_COOKIES（变量名与定义不符）→ 请求中断 → Caddy 502。
    这里统一变量名并加锁 + 双重检查，彻底消除竞态。
    """
    global CACHED_COOKIE_STR, LAST_COOKIE_MTIME, LAST_COOKIE_CHECK
    now = time.time()
    if now - LAST_COOKIE_CHECK < 5.0 and CACHED_COOKIE_STR:
        return CACHED_COOKIE_STR

    with _COOKIE_LOCK:
        now = time.time()
        if now - LAST_COOKIE_CHECK < 5.0 and CACHED_COOKIE_STR:
            return CACHED_COOKIE_STR
        LAST_COOKIE_CHECK = now
        return _load_cookies_locked()


def _load_cookies_locked():
    global CACHED_COOKIE_STR, LAST_COOKIE_MTIME
    db_path = os.path.join(FIREFOX_PROFILE, "cookies.sqlite")
    if not os.path.exists(db_path):
        return CACHED_COOKIE_STR

    try:
        mtime = os.path.getmtime(db_path)
        # 2026-10-29: Firefox 用 WAL 模式，新 cookie 先落 -wal、主库 mtime 不变。
        # 只看主库 mtime 会让缓存永不刷新，读到过期 1PSIDTS → 上游判未登录。
        try:
            wal_m = os.path.getmtime(db_path + "-wal")
            if wal_m > mtime:
                mtime = wal_m
        except OSError:
            pass
        if mtime == LAST_COOKIE_MTIME and CACHED_COOKIE_STR:
            return CACHED_COOKIE_STR

        tmp_path = "/tmp/hajimi_cookie_sync.db"
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
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        CACHED_COOKIE_STR = data
        LAST_COOKIE_MTIME = mtime
        return data
    except Exception as e:
        sys.stderr.write(f"[COOKIE] 读取失败: {e}\n")
        return CACHED_COOKIE_STR


def get_cookies_str(target_host=""):
    """按目标域名组装 Cookie 头。host 匹配规则与浏览器一致：cookie host 是目标域的后缀。"""
    data = _load_cookies() or {}
    out = []
    for h, items in data.items():
        hl = h.lstrip(".")
        if not target_host or target_host == hl or target_host.endswith("." + hl) or hl.endswith("." + target_host):
            for n, v in items:
                out.append(f"{n}={v}")
    return "; ".join(dict.fromkeys(out))


def make_sapisidhash(sapisid, origin="https://gemini.google.com"):
    """Google 的客户端签名：SAPISIDHASH {ts}_{sha1(f'{ts} {sapisid} {origin}')}。
    缺了它，写请求会被服务端当成「不可信客户端」→ 临时会话（能回复但不落库）。"""
    import hashlib
    ts = int(time.time())
    raw = f"{ts} {sapisid} {origin}"
    return "SAPISIDHASH %d_%s" % (ts, hashlib.sha1(raw.encode("utf-8")).hexdigest())



def make_auth_token():
    ts = int(time.time())
    sig = hmac.new(SECRET_KEY, f"{PASSWORD}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"

def verify_auth_token(token):
    if not token or "." not in token:
        return False
    parts = token.split(".", 1)
    try:
        ts = int(parts[0])
        if abs(time.time() - ts) > 30 * 86400:
            return False
        expected = hmac.new(SECRET_KEY, f"{PASSWORD}:{ts}".encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(parts[1], expected)
    except Exception:
        return False

# ── 3. 客户端防卡顿加速脚本（注入在 HTML <head> 最前）──────────
SHIELD_SCRIPT = f"""<script>
(function() {{
    window.dataLayer = window.dataLayer || [];
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
                    val = "about:blank";
                }} else {{
                    val = mapUrl(val);
                }}
            }}
        }}
        return origSetAttr.call(this, name, val);
    }};

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
        <div class="logo">Hajimi</div>
        <div class="subtitle">私有专用反向代理 · 请输入访问口令</div>
        <form method="POST" action="/__login">
            <input type="password" name="pwd" placeholder="访问口令" required autofocus>
            <button type="submit">进 入</button>
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

CSP_META = ('<meta http-equiv="Content-Security-Policy" content="'
            "default-src 'self' data: blob:; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob: https://fonts.gstatic.com; "
            "font-src 'self' data: https://fonts.gstatic.com https://fonts.googleapis.com; "
            "media-src 'self' data: blob:; "
            "connect-src 'self' data: blob:; "
            "frame-src 'self' data: blob:; "
            "worker-src 'self' blob:; "
            "object-src 'none'; base-uri 'self'"
            '">')

class FastProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # 过滤高频静态日志
        if not any(self.path.startswith(p) for p in [
            "/_gstatic_/", "/_www_gstatic_/", "/_fonts_gstatic_/", "/_fonts_api_/",
            "/_ssl_gstatic_/", "/_static_/", "/_static/", "/_lh3_/", "/_lh3_usercontent_/", "/_gg_/",
            "/__mock_ok__", "/favicon.ico"
        ]):
            sys.stderr.write(f"[{self.date_time_string()}] {fmt % args}\n")

    def is_authenticated(self):
        cookie_header = self.headers.get("Cookie", "")
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if pair.startswith("gemini_auth="):
                token = pair[len("gemini_auth="):]
                if verify_auth_token(token):
                    return True

        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if "pwd" in qs and qs["pwd"][0] == PASSWORD:
            return True

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                _, pwd = decoded.split(":", 1)
                if pwd == PASSWORD:
                    return True
            except Exception:
                pass
        return False

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

    def do_POST(self):
        self._body_read = False
        self._body = None
        self._drain_body()
        parsed = urllib.parse.urlparse(self.path)

        # 🔴 P2 根治：POST /__mock_ok__ 秒回 200
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

        if self.path == "/__login":
            body = (getattr(self, "_body", None) or b"").decode("utf-8", "replace")
            data = urllib.parse.parse_qs(body)
            pwd = data.get("pwd", [""])[0]
            if pwd == PASSWORD:
                token = make_auth_token()
                self.send_response(303)
                self.send_header("Location", "/app")
                self.send_header("Set-Cookie", f"gemini_auth={token}; Path=/; Max-Age=2592000; SameSite=Lax; Secure; HttpOnly")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(303)
                self.send_header("Location", "/__login?err=1")
                self.send_header("Content-Length", "0")
                self.end_headers()
            return

        self.handle_proxy("POST")

    def do_GET(self):
        self._body_read = False
        self._body = None
        self._drain_body()
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

        if not self.is_authenticated():
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

        # 拦截残留的遥测/打点请求，秒回 200
        if any(x in path for x in ["ccm/collect", "$rpc/google.internal.waa", "punctual/v1/chooseServer", "play.google.com", "google-analytics"]):
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
            if not re.match(r"^[a-z0-9.-]+\.(clients6\.google\.com|googleusercontent\.com|usercontent\.goog|googleapis\.com|google\.co\.[a-z]{2}|google\.com\.[a-z]{2}|google\.com|gstatic\.com)$", _h, re.I):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # 账号/组件类直连会挂 21~31s，直接秒回空
            if _h in ("ogs.google.com", "accounts.google.com", "play.google.com"):
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

        # 内存 -> 磁盘缓存直接命中（0 毫秒直出）
        if method == "GET" and is_static:
            if upstream_url in STATIC_MEM_CACHE:
                ct, body = STATIC_MEM_CACHE[upstream_url]
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
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
                    with open(cache_file, "rb") as cf:
                        body = cf.read()
                    STATIC_MEM_CACHE[upstream_url] = (ct, body)
                    self.send_response(200)
                    self.send_header("Content-Type", ct)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "public, max-age=31536000, immutable")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    if method != "HEAD":
                        self.wfile.write(body)
                        self.wfile.flush()
                    return
                except Exception:
                    pass

        if "upload" in path:
            _b = getattr(self, "_body", b"") or b""
            sys.stderr.write(f"[UPLOAD] {method} {path[:120]} te={self.headers.get('Transfer-Encoding','-')} "
                             f"cl={self.headers.get('Content-Length','-')} body={len(_b)}B hex={_b[:60].hex()}\n")
        # 使用已缓存的请求体（do_POST/do_GET 开头已读取，不会残留）
        req_body = getattr(self, "_body", None)
        if not getattr(self, "_body_read", False):
            req_body = self._drain_body() if method in ("POST", "PUT", "PATCH") else None

        # 构造上游请求头：白名单（与「会话能正常落库」时期的转发一致）。
        # ⚠️ 不要把浏览器自带的 x-goog-ext-* / x-client-data / sec-ch-ua 透给 Google：
        # 那是「浏览器客户端身份」，与服务端 Cookie 混用会让写请求被当成匿名客户端，
        # 表现为「能拿到回复文本，但新会话不进列表、URL 不跳转、远程桌面上也看不到」。
        # 上传接口额外放行 x-goog-upload-*（Google 上传协议必需），否则文件传不上去。
        forward_headers = {
            "Host": target_host,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0",
            "Accept": self.headers.get("Accept", "*/*"),
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://gemini.google.com/",
            "Origin": "https://gemini.google.com",
            "X-Same-Domain": "1",
            "Sec-Fetch-Site": "same-origin",
        }
        # 上传头已合并到上面的 x-goog-* 转发

        if target_host.endswith(".google.com") or target_host in ("gemini.google.com",):
            cookie_str = get_cookies_str(target_host)
            if cookie_str:
                forward_headers["Cookie"] = cookie_str
                # 客户端身份 blob（浏览器生成的 x-goog-ext-* / 账号索引）必须透传，
                # 否则服务端把写请求当成「未注册客户端」→ 临时会话（能回复但不落库）。
                # 转发所有 x-goog-* 头（ext 为客户端身份，upload 为上传协议，缺一不可）
                for _k, _v in self.headers.items():
                    if _k.lower().startswith("x-goog-"):
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
                    _sid = _ck.get("SAPISID") or _ck.get("__Secure-1PAPISID") or _ck.get("APISID")
                    if _sid and ("batchexecute" in path or "processSession" in path or method in ("POST", "PUT")):
                        forward_headers["Authorization"] = make_sapisidhash(_sid)
                        sys.stderr.write(f"[AUTH-HASH] {path[:50]} 已注入 SAPISIDHASH\n")
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
        if authz:
            forward_headers["Authorization"] = authz
        sys.stderr.write(f"[AUTH] {method} {path[:60]} auth={'YES ' + authz[:22] if authz else 'NO'}\n")

        # 流式原样直通：StreamGenerate 打字机 + 所有 batchexecute RPC（RPC 响应禁止重写，否则破坏前端状态）
        # 2026-10-29: 媒体下载**不能**走手工 chunked 分支：
        #   上游 gzip/br 被 httpx 解压后，手工声明的 Content-Length 与实际字节数不符，
        #   Caddy 转 h2 时直接判协议错误（浏览器 ERR_HTTP2_PROTOCOL_ERROR）。
        #   这里让它走普通分支：读全量 → 按 len(body) 声明长度，必然一致；
        #   Range/206 由普通分支自身透传（body 即片段长度）。
        is_stream = any(k in path for k in [
            "StreamGenerate", "assistant.lamda", "batchexecute",
            # WebChannel 长连接（geminiweb-pa）必须逐帧透传；缓冲会让前端收不到「会话已建立」的帧，
            # 表现为：能拿到回复文本，但新会话不入列表、URL 不跳转、不落到账号里。
            "processSession", "geminiweb_pa",
        ])

        skip_headers = {
            "set-cookie", "content-security-policy", "content-security-policy-report-only",
            "x-frame-options", "content-encoding", "transfer-encoding", "content-length",
            "connection", "server-timing", "report-to", "nel", "alt-svc", "date", "server"
        }

        try:
            if is_stream:
                # 🔴 P0 修复：规范 HTTP/1.1 Chunked 分块传输流
                with GLOBAL_CLIENT.stream(method, upstream_url, headers=forward_headers, content=req_body) as resp:
                    self.send_response(resp.status_code)
                    for k, v in resp.headers.items():
                        if k.lower() not in skip_headers:
                            self.send_header(k, v)
                    # 2026-10-29: 媒体下载（视频/图片）走 206/Content-Length 直通，
                    # 只有真·增量流（无 CL）才用 chunked —— 否则播放器/下载器进度条会失效。
                    _cl = resp.headers.get("content-length")
                    if _cl and resp.status_code in (200, 206):
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
                        for chunk in resp.iter_bytes(chunk_size=1):
                            if chunk:
                                if _first_byte_ms is None:
                                    _first_byte_ms = int((time.time() - _t0) * 1000)
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
                        sys.stderr.write(f"[STREAM] {path[:40]} first_byte={_first_byte_ms}ms "
                                         f"total={int((time.time()-_t0)*1000)}ms\n")
                        try:
                            if _use_chunked:
                                # 🔴 终结分块：RFC 规范必须发送 0\r\n\r\n 结束帧，杜绝无限 pending
                                self.wfile.write(b"0\r\n\r\n")
                                self.wfile.flush()
                        except Exception:
                            pass
                return

            last_err = None
            resp = None
            for attempt in range(3):
                try:
                    resp = GLOBAL_CLIENT.request(method, upstream_url, headers=forward_headers, content=req_body)
                    break
                except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout) as e:
                    last_err = e
                    sys.stderr.write(f"[RETRY] {method} {path[:70]} attempt={attempt+1} err={type(e).__name__}: {e}\n")
                    if attempt < 2:
                        time.sleep(0.25 * (attempt + 1))
            if resp is None:
                raise last_err

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
            is_text_replace = any(t in resp_ct for t in ["text/html", "text/css", "javascript"])
            # PWA manifest 里带 www.gstatic.com 图标地址，浏览器会去取 → 也必须重写（非 RPC，安全）
            if "manifest" in path:
                is_text_replace = True
            body = resp.content

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
                    # 注入客户端补丁（fetch/XHR/img/srcset/CSS/CSSOM/ShadowDOM/SW 等）
                    if "<head>" in text:
                        text = text.replace("<head>", "<head>" + ACTIVE_SHIELD, 1)
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

            if method == "GET" and resp.status_code == 200 and is_static:
                STATIC_MEM_CACHE[upstream_url] = (resp_ct, body)
                try:
                    with open(cache_file, "wb") as cf:
                        cf.write(body)
                    with open(cache_file + ".meta", "w") as mf:
                        mf.write(resp_ct)
                except Exception:
                    pass

            self.send_response(resp.status_code)
            _is_manifest = "manifest" in path
            for k, v in resp.headers.items():
                if k.lower() in skip_headers:
                    continue
                # manifest 不能沿用 Google 的「缓存一年」，否则浏览器长期持有旧图标地址
                if _is_manifest and k.lower() == "cache-control":
                    continue
                self.send_header(k, v)
            if _is_manifest:
                self.send_header("Cache-Control", "no-cache, must-revalidate")

            # 🔴 P0 修复：非流式响应严格显式声明 Content-Length，绝不带 chunked 头，确保连接干净结算
            self.send_header("Content-Length", str(len(body)))
            sys.stderr.write(f"[RESP] {method} {path[:90]} -> {resp.status_code} len={len(body)} ct={resp_ct[:40]}\n")
            if is_static and not _is_manifest:
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            self.send_header("Access-Control-Allow-Origin", f"https://{DOMAIN}")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("X-DNS-Prefetch-Control", "off")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body)
                self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
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

def start_direct_tls():
    """直连入口：0.0.0.0:<DIRECT_TLS_PORT> 走 HTTPS（复用通配证书（DIRECT_TLS_CERT/KEY））。
    与 FRP 用的 127.0.0.1:8322（明文）互不影响。
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
        srv = ThreadingHTTPServer(("0.0.0.0", DIRECT_TLS_PORT), FastProxyHandler)
        srv.daemon_threads = True
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"[*] 直连 HTTPS 已监听 0.0.0.0:{DIRECT_TLS_PORT}", flush=True)
        return srv
    except Exception as e:
        print(f"[!] 直连 HTTPS 启动失败: {e}", flush=True)
        return None


def main():
    print(f"[*] 哈吉米网关 V6 已启动，监听 127.0.0.1:{PORT} ...", flush=True)
    # 直连 TLS 已关闭（2026-10-28）：Python 自带 TLS 不稳定（握手卡死无自愈），
    # 统一走阿里 nginx 中转。如需恢复，取消下行注释并把路由器 18444 映射到 8322。
    # start_direct_tls()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), FastProxyHandler)
    server.daemon_threads = True
    server.serve_forever()

if __name__ == "__main__":
    main()
