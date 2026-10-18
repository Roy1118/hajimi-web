# 02 · 身份链

> 私人镜像站逆向手册（2/7）
>
> 全部问题里最优先的一层——身份错了，后面每一层都在白费力气。

[← 总纲与架构拓扑](01-overview-and-topology.md) · [目录](01-overview-and-topology.md) · [传输层 →](03-transport-layer.md)

---

## 2. 身份链（最优先，错了后面全白费）

### 2.1 只转发 Cookie、不注入 `SAPISIDHASH` → 能读不能写
- **现象**：能看历史、能发消息拿到回复，但**新会话不落库**（远程端看不到、URL 不跳转）；表现为「被降智」。
- **根因**：Google 用 `Authorization: SAPISIDHASH <ts>_<sha1(ts + " " + SAPISID + " " + origin)>` 判定写权限。缺这个头 → 上游把我们当游客/临时会话。
- **修法**：服务端按目标域名匹配**全套** Cookie（含 `SAPISID`），实时算签名注入；`origin` 固定 `https://gemini.google.com`。
- **验证**：远程端（另一台设备）刷新能看到新会话；日志出现 `[AUTH-HASH] ... 已注入 SAPISIDHASH`。

### 2.2 只挑几个 Cookie 转发
- **现象**：签名算不出来 / 部分接口 401。
- **修法**：按 host 匹配全部 cookie 转发，不要白名单挑。

### 2.3 `x-goog-*` 头必须全量透传
- **现象**：上传文件报 `400 Request without ClientId`。
- **根因**：`x-goog-ext-*` 里带客户端身份与上传协议指纹。
- **修法**：转发**所有** `x-goog-*`，上传路径额外放行（别被黑名单拦）。

### 2.4 `cookies.sqlite` 只拷主库 → 读到过期 cookie（教训 §44）
- **现象**：**持续**未登录（不是几秒，是一直），刷新也不恢复；同一账号的生图 API 却 `AVAILABLE`。
- **根因**：Firefox 的 cookie 库是 **WAL 模式**，新 cookie 先落 `cookies.sqlite-wal`，主库要等 checkpoint。只 `copy2(db)` 拿到的是旧值。
- **修法**：`sqlite` + `-wal` + `-shm` **三件套一起拷**，只读不写。
- **验证**：两种读法取同一 cookie，值必须一致且为最新；用该 cookie 直连上游 `/app` 应 200 且无 `signin`。

### 2.5 缓存失效只看主库 mtime
- **现象**：修好 §2.4 后仍偶尔"抱着旧值不放"。
- **根因**：WAL 更新不改主库 mtime → 5 秒缓存永不刷新。
- **修法**：缓存 key 的 mtime 取 `max(主库, -wal)`。

### 2.6 Firefox 必须常驻
- `__Secure-1PSIDTS` 靠**活跃浏览器会话**周期性续签。浏览器一关，快照几小时内降级。
- 空闲 profile 只占几十 MB；自愈脚本负责拉起。

### 2.7 不要用 Chrome 做 cookie 源
- Chrome 新版的 cookie 用系统 keyring 加密、离线无法解密；且启用 DBSC 让 cookie 短命。
- **实时读 cookie 这套机制对 Chrome 不成立**，只能用 Firefox。

---
