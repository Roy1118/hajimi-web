# 踩坑笔记 —— 把哈吉米网页版完整搬到自己域名下的全过程

> 真实排障得出的结论，按"症状 → 根因 → 修法"组织。做网页会话转发类项目大概率会踩到其中几个。

## 1. 会话"能用但不落库"：SAPISIDHASH 签名

**症状**：站内聊天正常，但上游账号的活动记录里根本没有这些会话；且被降级为游客模式。

**根因**：网页前端的每个写请求都带 `Authorization: SAPISIDHASH {ts}_{sha1("{ts} {sapisid} {origin}")}` 头，origin 固定为上游站点地址。转发时丢了这个头，上游就把你当匿名游客——对话能通，但**会话不落库**。

**修法**：服务端对每个写请求实时计算并注入：

```python
def make_sapisidhash(sapisid, origin):
    ts = int(time.time())
    raw = f"{ts} {sapisid} {origin}"
    return f"SAPISIDHASH {ts}_{hashlib.sha1(raw.encode()).hexdigest()}"
```

## 2. 上传 400 "Request without ClientId"：客户端头不能挑着转发

**症状**：对话正常，文件上传必 400。

**根因**：前端给上传链路带了一整套 `x-goog-*` 头（客户端身份 blob、上传协议版本等），只转发常见头不够，缺任何一个上传就断。

**修法**：**转发全部 `x-goog-*` 头**；cookie 按目标域名后缀完整匹配（与浏览器行为一致），不是只挑几个"知名"cookie。

## 3. 内容安全策略：图标变文字、动态资源全灭

**症状**：页面能开，但图标全变文字、控制台 300+ 报错、动态加载的 JS/CSS 全被拦。

**根因**：上游返回的 CSP 是按它自己的域名签发的，镜像域名下所有资源引用都算违规；且前端大量用 `link.href` / `script.src` 动态注入，光改响应头不够。

**修法**（三件套）：
1. 重写响应头 CSP 为白名单：`script-src 'self' 'unsafe-inline'` + 本站代理前缀；`font-src`/`img-src` 放行字体与图标域
2. HTML/JS 里把资源域名改写为本站路径（单次正则，别贪多——改写越多越慢越易碎）
3. 注入 setter 补丁：包一层 `HTMLLinkElement.href` / `HTMLScriptElement.src` / `HTMLElement.style`，把动态设置的跨域 URL 也改写到本站前缀

## 4. 掉登录几秒又自动恢复：时间戳 cookie 的轮换真空窗

**症状**：用着用着突然掉登录，过十几秒自己恢复。

**根因**：上游每 15~20 分钟轮换一次时间戳 cookie。轮换瞬间存在真空窗：旧值已被服务端作废、新值还没写进浏览器 profile。窗口期内携带旧值的请求被判未登录。官方前端有静默重试所以无感，透传型网关会把"未登录"原样呈现。

**缓解**：服务端检测到未登录特征时先重读 profile 最新 cookie 重试（限时 15 秒、限 3 次），而不是直接透传失败；真死了再放行给保活兜底。

## 5. 凭据保活：静态快照必死，实时 profile 才是正解

**症状**：用凭据快照的服务跑几天后生图 502、聊天降级。

**根因**：快照里的时间戳 cookie 会过期；库内自动刷新只更新内存不回写磁盘，且降级后刷新循环会 break 永不自愈；重启服务又回退到磁盘旧值。

**修法（保活闭环设计）**：
- **读侧**：不用快照，直接读专用浏览器 profile 的 `cookies.sqlite`（拷贝 sqlite+wal+shm 到临时路径再读，避免锁冲突），浏览器活着凭据就永远新鲜
- **检侧**：每 3 分钟探测自身健康接口，读会话状态
- **愈侧**：状态异常 → 先确保浏览器进程活着 → 重启服务（重启即读到最新凭据）→ 轮询确认；**正常时绝不重启**（会丢内存里已轮换的好值）
- 失败分类返回 401 `authentication_error` 而非笼统 500，让调用方能分辨"会话死了"

## 6. 链路层：隧道与入口 TLS

- 隧道客户端默认只有 1 条工作连接，页面 300+ 并发请求会打空连接池出现**间歇性整页 502**：连接池拉到 30 + 心跳缩到 10s/30s（默认 90s 的断线感知窗口太长，断线期间登录态表现为丢失）
- 入口用 Caddy 终止 TLS 时**必须 `flush_interval -1`**，否则上游流式输出被缓冲，前端一直转圈
- 一个 8443 端口服务多个域名：Caddy 按 TLS SNI 分流，路由器只需一条映射，加新站点零路由器改动
- 内网机器访问自己的公网域名不通 ≠ 外网不通，先排除 hairpin NAT 再排查

## 8. 流式透传最忌「聚合缓冲」：chunk_size 设大了，前端会一直转圈

**症状**：发消息后界面长时间停在"思考中"，但刷新页面答案早就生成好了（说明上游早算完，是流没送出去）。

**根因**：流式读取用 `resp.iter_bytes(chunk_size=4096)`。httpx 的 ByteChunker 会**攒够 4096 字节才吐出一次**；而思考阶段的增量帧只有几百字节 → 一个字节都不转发 → 前端零反馈；等正文生成完（大块）才一次性到达。同时默认 `Timeout(120)` 会在深度思考超 2 分钟时把连接掐断。

**修法**：`chunk_size=1`（收到即转发）；`Timeout(600, connect=15, read=600, write=120, pool=60)`；并在流式分支打 `[STREAM] first_byte=…ms total=…ms` 日志，下次卡顿时一眼定位卡在哪一段。

## 9. 媒体下载三个连环坑（静态缓存 / 手工 chunked / fetch(URL)）

**症状**：视频能预览播放，点"下载"却报错；或请求到了本站却 `ERR_HTTP2_PROTOCOL_ERROR`。

1. **被当静态资源**：`/_gg_/` 若归类为静态，会把整个视频读进内存并写磁盘缓存。修：判定媒体下载（路径含 `/download` 或 host 以 `contribution.usercontent.` 开头）→ 排除静态缓存。
2. **手工 chunked 与解压长度不一致**：上游 gzip/br 被 httpx 解压后，手工声明的 `Content-Length` 与实际字节数不符 → 前置代理转 HTTP/2 时直接判协议错误。修：媒体下载走普通分支（全量读完按 `len(body)` 声明），或透传 `content-encoding` 配 `iter_raw()`。
3. **`fetch(new URL(...))` 被漏掉**：只认 `string` 和 `Request` 的 `input.url` 不够——`URL` 对象只有 `.href`，取不到 URL 就静默不改写 → 直连上游超时。修：`input.url || input.href || String(input)`，且 `new Request()` 失败时退化为字符串 URL，**绝不回落到上游绝对地址**。

**附带**：原生 `<a download>` 不经过 `fetch`/`XHR`，必须单独拦截（click/pointerdown 捕获 + MutationObserver + `composedPath()` 穿透 Shadow DOM）。

## 10. 并发首调竞态：`global` 变量名与定义不一致 → 偶发 502

**症状**：偶发 `502 Bad Gateway`，日志里有 `NameError: name 'CACHED_XXX' is not defined`。

**根因**：缓存函数先更新时间戳再读库；并发首调时 B 线程看到"时间戳已更新"但缓存仍为空，去读一个**从未定义**的全局变量（定义处写的是另一个名字）→ 抛异常 → 响应中断。

**修法**：变量名统一 + `threading.Lock()` 加锁 + 双重检查；读库逻辑拆到独立函数。凡"时间戳 + 缓存"结构都要防这个窗口。

## 11. 域名改写覆盖面：地区域与 `.goog` 域

上游会在不同场景使用 `www.google.co.kr`、`www.google.com.hk`（地区域）、`<uuid>.scf.usercontent.goog`（交互式 Applet 的 iframe）等域名。只覆盖 `google.com` / `googleusercontent.com` 会漏：

- 地区域：`google\.(com|co\.[a-z]{2}|com\.[a-z]{2})`
- `.goog` 域：`[a-z0-9.-]+\.usercontent\.goog`
- **服务端路径白名单也要同步放行**，否则前端改写了、服务端仍 404

**注意**：iframe 里的内容是独立文档，主页面补丁进不去；把 iframe 的 `src` 改写到本站前缀后，它内部相对路径自然同源，服务端再对该 HTML 注入补丁即可。

---

## 12. 第三方统计脚本：CSP 拦得住，但 `dns-prefetch` 拦不住

页面里常带 GTM / analytics / doubleclick。三种加载通道，**只有第三种能被服务端一次解决**：

| 通道 | 形态 | JS 侧 hook 能否拦 |
|---|---|---|
| 动态插入 | `createElement('script')` + `script.src = url` | ✅ 需要**专门**拦 `HTMLScriptElement.prototype.src` 的 setter |
| 动态插入 | `setAttribute('src', url)` | ✅ 拦 `Element.prototype.setAttribute` |
| **解析期标签** | HTML 里直接写的 `<script async src="...">` | ❌ 全部绕开，浏览器解析时直接建元素 |

最容易漏的是第一种：`setAttribute` 补丁对 `script.src = x` **完全无效**（属性 setter 不经过 `setAttribute`）。而 Google 的 jsloader（`PendingScript` / `_.Cja.load`）正是这么干的。

**症状**：CSP 确实拦住了（违规请求连 DNS 都不发），但 console 一片红字：

```
Refused to load the script 'https://www.googletagmanager.com/gtm.js?id=GTM-XXXX'
because it violates ... "script-src 'self' ..."
```

还会连带上层组件报 `No ID or name found in config.`（脚本没执行，全局对象不存在）。

**修法（服务端改写 + 同源空桩）**：把命中的 `<script src>` 换成同源空端点 `/__mock_js__`，返回一段定义 `dataLayer` / `gtag` / `google_tag_manager` 的空 JS。同源不违反 CSP、`onload` 照常触发、依旧零外连，console 也干净了。

```python
_TELEMETRY_SRC_RE = re.compile(
    r'(<script\b[^>]*?\bsrc\s*=\s*)(["\'])(?:https?:)?//(?:[a-z0-9.-]+\.)?'
    r'(?:googletagmanager\.com|google-analytics\.com|googlesyndication\.com|'
    r'googleadservices\.com|doubleclick\.net)(?:[^"\']*)\2', re.I)
```

**⚠️ 真正的 DNS 泄露点，CSP 根本管不到**：

```html
<link rel="dns-prefetch" href="https://www.googletagmanager.com">
```

CSP 只约束「取资源」，不约束 DNS 预解析 —— 浏览器会老老实实去解析这个域名。想做到「零 Google DNS」，必须把 `rel="dns-prefetch"` / `rel="preconnect"` 里未改写成同源的外域 hint **整条删掉**（已指向本站的保留，同源预连接是有益的）。

> 顺序坑：通用的"把 Google 域改写成 `/_gg_/` 前缀"那条正则，通常只白名单 `google.com` / `gstatic.com` 家族，`googletagmanager.com`、`doubleclick.net` **不在名单里会被原样留下** → 交给 CSP 硬拦。所以这两个清理必须在通用改写**之后**单独跑一遍。

---

## 7. 生态坑：临时目录被核心清理机制删掉

某 bot 框架的核心自带临时目录清理器（超配额按最旧删文件），删完还会**把清空的子目录 rmdir 掉**；而插件保存文件时不重建目录 → 偶发"No such file or directory"、重启即愈、循环复发。修法：保存前 `os.makedirs(..., exist_ok=True)`。凡是"写临时目录"的插件都要防这一手。
