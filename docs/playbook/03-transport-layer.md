# 03 · 传输层

> 私人镜像站逆向手册（3/7）
>
> 「卡在思考中」「转圈不给字」十有八九在这层。

[← 身份链](02-identity-chain.md) · [目录](01-overview-and-topology.md) · [资源与页面改写 →](04-resource-rewrite.md)

---

## 3. 传输层（"卡住"十有八九在这层）

### 3.1 `iter_bytes(chunk_size=4096)` 会攒包 → 卡在"思考中"
- **现象**：发消息后长时间停在思考中；**刷新一下答案早就生成好了**。
- **根因**：httpx 的 ByteChunker 攒满 4KB 才吐。思考期增量帧只有几百字节 → 一个字节都不转发。
- **修法**：`chunk_size=1`（收到即转发）。
- **验证**：日志 `[STREAM] first_byte=XXms`，思考动画应该持续有反馈。

### 3.2 `Timeout(120)` 掐断长思考
- **修法**：`Timeout(600, connect=15, read=600, write=120, pool=60)`。

### 3.3 手工 chunked 与解压后长度不符 → `ERR_HTTP2_PROTOCOL_ERROR`
- **根因**：上游 gzip 被 httpx 解压后，手工声明的 `Content-Length` 与实际字节数不一致，前置代理转 h2 直接判协议违规。
- **修法**：要么走普通分支按 `len(body)` 声明长度，要么透传 `content-encoding` 配 `iter_raw()`；**不要手工拼 chunk 头还声明 CL**。

### 3.4 流式通道前置代理必须不缓冲
- Caddy：`reverse_proxy ... { flush_interval -1 }`。

### 3.5 frp `poolCount=1` 被页面并发打空 → 整页 502
- **现象**：间歇性整页 502，frpc 日志 `work connection pool is empty`。
- **修法**：`transport.poolCount = 30`，心跳 10s/30s。

### 3.6 并发首调竞态 → 偶发 502
- **现象**：日志 `NameError: name 'CACHED_XXX' is not defined`。
- **根因**：缓存函数先更新时间戳再赋值；并发下另一线程读到"时间戳已更新但缓存仍空"，去读一个**名字写错**的全局。
- **修法**：变量名统一 + `threading.Lock` + 双重检查。

---
