# 04 · 资源与页面改写

> 私人镜像站逆向手册（4/7）
>
> 白屏、样式崩、点了没反应，集中在这一层。

[← 传输层](03-transport-layer.md) · [目录](01-overview-and-topology.md) · [iframe 宿主页 →](05-iframe-hosting.md)

---

## 4. 资源与页面改写（"白屏/报错/点了没反应"集中区）

### 4.1 域名覆盖不全
必须同时覆盖：`google.com`、`google.co.[a-z]{2}`、`google.com.[a-z]{2}`（地区域）、`googleusercontent.com`、**`*.usercontent.goog`**、`googleapis.com`、`gstatic.com`、`drive.google.com`、`drive.goog`。
- 少一个，对应内容就"响应时间太长"。

### 4.2 服务端路径白名单要同步放行
前端改写对了、服务端不认这个 host → 404。**两处必须一起改**。

### 4.3 CSP 拦动态资源
- **现象**：SVG 图标变文字、控制台一片 CSP 报错。
- **修法**：服务端剥掉上游 CSP 头；客户端补 `__patchSetter`（`HTMLLinkElement.href` / `HTMLScriptElement.src` / `HTMLImageElement.src` / `srcset` 等 setter），让运行时设置的 URL 也走改写。

### 4.4 `fetch(new URL(...))` 被漏掉
- **根因**：只判 `typeof input === "string"` 和 `input.url`；`URL` 对象只有 `.href`，取不到 → 静默不改写 → 直连上游超时。
- **修法**：`input.url || input.href || String(input)`；`new Request()` 失败要退化成字符串 URL，**绝不回落到上游绝对地址**。

### 4.5 原生 `<a download>` / `window.open` 不经过 fetch/XHR
- **修法**：`click` 捕获阶段改写 `href` + `MutationObserver` + 覆写 `window.open`。

### 4.6 Shadow DOM：`e.target.closest('a')` 永远拿不到
- **修法**：用 `e.composedPath()` 穿透 shadow 边界；并定时扫描各 `shadowRoot` 里的 `<a>`。

### 4.7 🔴 HTML 被当静态资源缓存 → 所有注入与改写**静默失效**（教训 §45，最坑的一个）
- **现象**：服务端日志明明 `rewrite applied 4/4`、`len` 也在变，但浏览器 `outerHTML` 里搜不到注入的标记；刷新多少次都一样。
- **根因（两层）**：
  1. 缓存命中的分支**在改写之前就 return**（只要 HTML 落在"静态前缀"下，例如承载 iframe 的 `/_gg_/`）；
  2. 响应头还发了 `Cache-Control: immutable`（一年）→ 副本钉死在浏览器，**服务端怎么改用户都看不到**。
- **修法**：读、写两侧都排除 HTML（`"html" not in content_type`）；按 `.meta` 里的 content-type 清历史缓存；给必须回源的 URL 加**每页固定**的一次性参数。
- **验证**：不看日志看页面——注入的标记字符串必须能在浏览器侧 `outerHTML` 里搜到。

### 4.8 缓存击穿参数要"每页固定"
- 用 `Date.now()` 每次调用生成不同值 → 同一 iframe 被改写成两个 URL，中途重载，消息丢失。
- **修法**：`if (!window.__hajT) window.__hajT = String(Date.now())`，一页一个。
- 另注意：**别把这个参数加到下载链路上**（会污染签名 URL / 造成重复下载）。

---
