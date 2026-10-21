# 05 · iframe 宿主页

> 私人镜像站逆向手册（5/7）
>
> 最复杂的一类内容：交互式演示 / Applet。三级机制缺一不可。

[← 资源与页面改写](04-resource-rewrite.md) · [目录](01-overview-and-topology.md) · [下载与文件 →](06-download-and-files.md)

---

## 5. iframe 宿主页（最复杂的一类内容：AI Studio Applet / 互动演示）

**机制三层**：
1. iframe 指向 `https://<50位哈希>-h<版本>.scf.usercontent.goog/?origin=<父页面origin>` —— 这一页只是**空壳宿主页（shim）**，本身没有内容；
2. 父页面把 applet 正文（HTML 字符串）用 `postMessage` 递进去；
3. shim 用 `?origin=` 重算哈希、与域名里的 50 位哈希比对，不等就**拒绝渲染**；通过后 `document.write` 写入。

### 5.1 域名哈希校验
- 报错：`Hashed domain '...' must match /^([a-z0-9]{50})-h(\d+)[.]scf[.]usercontent[.]goog$/`
- **修法**：从 `/_gg_/<host>` 路径段提取真实 host；product 取路径首段（要跳过前缀，并给兜底）；`let L=c` 让重算校验恒真（origin 无法伪造成 google 域名，这是唯一出路）；强制走 `document.write`，让相对资源落在 `/_gg_/<host>/` 下。

### 5.2 `postMessage` 的 `targetOrigin` 由**发送方**决定
- 报错：`target origin provided ('https://xxx.scf.usercontent.goog') does not match the recipient window's origin`
- **根因**：接收方 origin 已被我们改成自有域名，浏览器**直接拒绝投递**，正文永远进不去 → 无限转圈。
- **修法**：给目标 window 装 `postMessage` 包装，把 `.usercontent.goog` 的 targetOrigin 换成自身 origin。

### 5.3 `postMessage` 不在 `Window.prototype` 上
- 在 `Window.prototype` 上打补丁会**静默无效**（`'postMessage' in Window.prototype === false`）。
- **修法**：给**目标窗口实例** `Object.defineProperty(w, "postMessage", ...)`；**成功才打标记**（否则一旦首次失败会被永久跳过），失败退回直接赋值。

### 5.4 补丁必须早于父页面首次投递（时序竞态）
多路兜底才稳：`contentWindow` getter 改写 + `Document.prototype.createElement` + `load` 捕获 + `MutationObserver` + `attachShadow` 钩子 + 100ms 轮询。

### 5.5 iframe 在 Shadow DOM 里，`document.querySelectorAll('iframe')` 扫不到
- **症状**：诊断显示 `IFRAMES=1`（只有一个 `about:blank`），误判"页面没建 iframe"。
- **修法**：递归 `shadowRoot` 扫描（`<a>`、`<iframe>` 都是同理）。

### 5.6 `document.write` 会清空注入，但 `window` 全局保留
- 注入的脚本标签会被清掉，但打在 `window` 上的补丁（fetch/XHR/setter）**还在**，所以正文里的资源请求仍能走改写。

### 5.7 🔴 第三方统计脚本的三条加载通道，只有一条拦得住（2026-10-31）

页面里带 GTM / analytics / doubleclick，它们进来有三条路：

| 通道 | 形态 | JS 侧 hook |
|---|---|---|
| 动态插入 | `createElement('script')` + **`script.src = url`** | ❌ 漏！`setAttribute` 补丁对属性 setter **完全无效** |
| 动态插入 | `setAttribute('src', url)` | ✅ 拦 `Element.prototype.setAttribute` |
| **解析期标签** | HTML 里直接写的 `<script async src="...">` | ❌ 全绕开，解析时就建元素了 |

- **症状**：CSP 确实拦住了（违规请求连 DNS 都不发），但 console 一片红字，
  还连带 `No ID or name found in config.`（脚本没执行，全局对象不存在）。
- **修法**：服务端把命中的 `<script src>` 换成同源空桩 `/__mock_js__`（返回定义
  `dataLayer`/`gtag`/`google_tag_manager` 的空 JS）。同源不违反 CSP、`onload` 照常、
  零外连，console 干净。JS 侧再补一条 `HTMLScriptElement.prototype.src` setter 兜动态插入。
- **⚠️ 顺序坑**：通用的"Google 域改写成 `/_gg_/`"正则只白名单 `google.com`/`gstatic.com` 家族，
  `googletagmanager.com`、`doubleclick.net` **不在里面 → 原样留下** → 只能靠 CSP 硬拦。
  所以这两个清理必须在通用改写**之后**单独跑。

### 5.8 🔴 `dns-prefetch` 是 CSP 管不到的 DNS 泄露点（2026-10-31）
```html
<link rel="dns-prefetch" href="https://www.googletagmanager.com">
```
- CSP 只约束「取资源」，**不约束 DNS 预解析** —— 浏览器会老老实实去解析这个域名。
  做了严格同源 CSP 也不等于零 DNS。
- **修法**：`rel="dns-prefetch"` / `rel="preconnect"` 里凡未改写成同源的**外域 hint 整条删掉**；
  已指向本站的保留（同源预连接有益）。
- **验证**：`curl` 首页 → `grep -oE '<link[^>]+rel="(dns-prefetch|preconnect)"[^>]*>'` 里不应出现裸 Google 域。

---
