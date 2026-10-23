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
    timeout=httpx.Timeout(120.0, connect=15.0),
    limits=httpx.Limits(max_keepalive_connections=100, max_connections=200, keepalive_expiry=120.0),
    follow_redirects=False
)

STATIC_MEM_CACHE = {}

# ── 2. Cookie 智能内存缓存（基于 mtime 检查）─────────────────────
CACHED_COOKIE_STR = ""
LAST_COOKIE_MTIME = 0
LAST_COOKIE_CHECK = 0

def _load_cookies():
    """从 Firefox profile 读取全部 google 域 Cookie，按 host 建索引。返回 {host: [(name,value)]}。"""
    global CACHED_COOKIES, LAST_COOKIE_MTIME, LAST_COOKIE_CHECK
    now = time.time()
    if now - LAST_COOKIE_CHECK < 5.0 and CACHED_COOKIES:
        return CACHED_COOKIES

    LAST_COOKIE_CHECK = now
    db_path = os.path.join(FIREFOX_PROFILE, "cookies.sqlite")
    if not os.path.exists(db_path):
        return CACHED_COOKIES

    try:
        mtime = os.path.getmtime(db_path)
        if mtime == LAST_COOKIE_MTIME and CACHED_COOKIES:
            return CACHED_COOKIES

        tmp_path = "/tmp/hajimi_cookie_sync.db"
        shutil.copy2(db_path, tmp_path)
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
        CACHED_COOKIES = data
        LAST_COOKIE_MTIME = mtime
        return data
    except Exception as e:
        sys.stderr.write(f"[COOKIE] 读取失败: {e}\n")
        return CACHED_COOKIES


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
            var gm = s.match(/^(?:https?:)?\\/\\/([a-z0-9.-]+\\.(?:clients6\\.google\\.com|googleusercontent\\.com|googleapis\\.com|google\\.com|gstatic\\.com))(.*)$/i);
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
        var u = typeof input === "string" ? input : (input && input.url ? input.url : "");
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
        if (mapped !== u) {{
            if (typeof input === "string") {{
                input = mapped;
            }} else if (input && typeof input === "object") {{
                try {{ input = new Request(mapped, init); }} catch(e) {{}}
            }}
        }}
        return _fetch.call(this, input, init);
    }};

    // 3. Intercept XMLHttpRequest
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {{
        var rest = Array.prototype.slice.call(arguments, 2);
        if (isBlocked(url)) {{
            try {{ (window.__shieldLog = window.__shieldLog || []).push("XHR-BLOCK " + url); }} catch(e) {{}}
            url = "/__mock_ok__?src=" + encodeURIComponent(url);
        }} else {{
            url = mapUrl(url);
        }}
        return _open.apply(this, [method, url].concat(rest));
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
            var gm = s.match(/^(?:https?:)?\/\/([a-z0-9.-]+\.(?:clients6\.google\.com|googleusercontent\.com|googleapis\.com|google\.com|gstatic\.com))(.*)$/i);
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
    m = re.match(r"^https?://([a-z0-9.-]+\.(?:clients6\.google\.com|googleusercontent\.com|googleapis\.com|google\.com|gstatic\.com))(.*)$", u, re.I)
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
