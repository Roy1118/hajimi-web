# 06 · 下载与文件

> 私人镜像站逆向手册（6/7）
>
> 预览正常、下载报错；或者反过来。都是独立的一类坑。

[← iframe 宿主页](05-iframe-hosting.md) · [目录](01-overview-and-topology.md) · [保活、验收与 SOP →](07-ops-and-playbook.md)

---

## 6. 下载与文件

### 6.1 🔴 中文文件名 → 响应头 latin-1 编码崩溃 → 502（2026-10-31 今日事故）
- **现象**：点下载 → 浏览器跳到 `/_gg_/contribution.usercontent.google.com/download?...` → **HTTP ERROR 502**（Caddy 的错误页）。
- **根因**：上游 `Content-Disposition: attachment; filename="运维随笔_8张配图.zip"`；Python `http.server` 的 `send_header` 用 **latin-1 strict** 编码 → `UnicodeEncodeError` → 连接中断 → 反代侧只能回 502。
- **修法**：转发头前统一做 `_safe_header()`：
  - `content-disposition`：ASCII 兜底名 + 追加 RFC 5987 `filename*=UTF-8''<percent-encoded>`；
  - 其它头：`backslashreplace` 兜底，绝不让 `send_header` 抛异常。
- **验证**：`curl -D -` 看到 `filename*=UTF-8''...`，`content-type: application/zip`，字节数与源一致。
- **推广**：任何"透传上游响应头"的代理都要防这个；其它语言里对应的是"响应头必须 ISO-8859-1 兼容"。

### 6.2 大文件不能全量读内存
- 媒体/附件要流式 + 透传 `Range` 支持 206（播放器拖进度、断点续传都靠它）。

### 6.3 下载链接不能被缓存击穿参数污染
- 只给"需要每次回源的 HTML"加参数，`/download` 一律不加。

### 6.4 🔴 静态资源的 `immutable` 会把人坑死：一次坏副本 = 图标变文字（2026-10-31）
- **现象**：Material Symbols 图标全变成文字（`riv` / `e_|` / `I0t` 这类 ligature 名），控制台 `Failed to decode downloaded font` + `OTS parsing error: Size of decompressed WOFF 2.0 is less than compressed size`。
- **根因**：静态资源被我们标成 `Cache-Control: public, max-age=31536000, immutable`。只要有过一次异常响应（例如服务重启把字体下载掐断），**坏副本就被钉在浏览器里一年**，之后服务端再正确也没用。
- **另一个坑**：静态分支同时透传了上游的 `Cache-Control`，导致同一响应出现**两个** `Cache-Control` 头。
- **修法**：
  1. 静态资源由我们**自己**声明缓存策略，跳过上游的 `cache-control`；
  2. 不用 `immutable`，改成 `public, max-age=604800`（7 天可复验）——出问题最多 7 天自愈；
  3. 排查时先分辨"服务端坏"还是"客户端缓存坏"：**新开一个标签页看是否正常**，正常就是缓存问题。
- **验证**：`curl -D -` 只应出现**一个** `cache-control`；字体响应 `magic=774f4632`（wOF2）且与上游 `cmp` 一致。

---
