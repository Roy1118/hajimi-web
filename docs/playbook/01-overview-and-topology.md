# 私人镜像站逆向手册

> 把一个「网页版 AI 应用」逆向成私人 1:1 镜像站时踩过的全部坑，按**层次**切成 7 篇。
> 每篇自带「现象 / 根因 / 修法 / 验证」，可单独读；整套方法可直接搬到其它站点。

**怎么用**：别从第一篇顺读到最后一篇。先看症状，查
[07 篇的速查表](07-ops-and-playbook.md)，直接跳到对应层，改完再回来补上下文。

## 系列

- [01 总纲与架构拓扑](01-overview-and-topology.md)
- [02 身份链](02-identity-chain.md)
- [03 传输层](03-transport-layer.md)
- [04 资源与页面改写](04-resource-rewrite.md)
- [05 iframe 宿主页](05-iframe-hosting.md)
- [06 下载与文件](06-download-and-files.md)
- [07 保活、验收与 SOP](07-ops-and-playbook.md)

---

## 0. 总纲：镜像站只有四层问题

把网页版做成私人镜像 = **身份链 + 传输层 + 资源改写 + 可观测**。

线上 90% 的「玄学 bug」（卡住、掉登录、白屏、下载失败）都能归到这四层。排查顺序也应该是这个顺序——**从最靠近上游的身份链开始，一层层往外**，不要一上来改前端。

一条铁律：**结论必须由证据支撑**。服务端日志说成功、浏览器里却没变化，那就一定是中间有缓存/改写没生效（见 §4.7）。

## 1. 架构与进程拓扑（家里云实测）

| 组件 | 端口 | 说明 |
|---|---|---|
| `gemini-mirror-direct` | 8325 | 唯一在用的镜像实例（Caddy 终止 TLS 后转发到此） |
| Caddy | 8443 | SNI 复用：`mirror.example.com` → 8325，`ai.*` → 8080；路由器只映射 18443→8443 |
| `gemini-webapi` | 8321 | 生图 API（OpenAI 兼容），读同一个 Firefox profile |
| 专用 Firefox | — | `firefox-gemini` profile，**唯一账号源** |
| mihomo | 12450 | 唯一出口；`region-guard` 固定地区 |
| `gemini-cookie-heal.timer` | — | 每 3 分钟巡检 account_status |
| ~~8324 + frpc~~ | — | 阿里中转链路，2026-10-29 已停用（3Mbps 太慢，直连快 4 倍） |

---
