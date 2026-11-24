# LanFast 传输协议（v5 · SPAKE2 抗主动中间人攻击版）

LanFast v5 全面采用 **RFC 9382 SPAKE2（NIST P-256）+ SAS 4-Emoji 安全核对码 + AES-256-GCM 全程端到端加密**，并彻底消除中转服务器与内置网页端上的明文 6 位验证码传输。

---

## 1. 相比 v4 的核心安全升级

| 威胁场景 | v4（普通 ECDH + HMAC） | v5（RFC 9382 SPAKE2-P256 + SAS） |
|---|---|---|
| 被动抓包 | 防护 | 防护 |
| **主动中间人（MITM）离线穷举 6 位码** | 可离线枚举 100 万种组合 | **彻底免疫**（每次在线握手最多猜 1 次，5 次错即锁定 30 秒） |
| **中转服务器 / 沿途看到明文 PIN** | 注册/查找含明文 `pin` | **零明文**（仅发送加盐路由哈希 `pin_tag`，并支持原生 TLS） |
| **恶意信令/中转篡改握手** | 无法肉眼校验 | 双方顶栏展示 **4 位 Emoji 安全核对码（SAS）** |
| **内置网页端 HTTP 提交明文 PIN** | `POST /api/pair` 明文 | 纯 JS `BigInt` **SPAKE2-P256** 零明文校验 |

---

## 2. SPAKE2-P256 握手流程

曲线为 NIST P-256，盲化基点 $M, N$ 采用 RFC 9382 官方常量。口令标量：
```text
w = (int(SHA-256("lanfast-spake2-w|" || UTF8(pin))) mod (n - 1)) + 1
```

1. **`spake_hello`（A → B）**：A 随机选 $x$，发送 $pA = xG + wM$（65 字节非压缩点 Base64）。
2. **`spake_reply`（B → A）**：B 验证 $pA$ 在曲线上，随机选 $y$，计算 $pB = yG + wN$、共享点 $K = y(pA - wM)$ 并返回 $pB$。
3. **转录哈希与密钥派生（两端独立计算）**：
   ```text
   TT      = SHA-256(u32be(|idA|) || idA || u32be(|idB|) || idB || pA || pB || K || to32(w))
   aesKey  = SHA-256(TT || "aes-256-gcm")
   confA   = HMAC-SHA256(TT, "confirm-A")
   confB   = HMAC-SHA256(TT, "confirm-B")
   sasCode = 4 个 Emoji（取 SHA-256(TT || "sas-emoji") 前 4 字节模 64）
   ```
4. **`spake_confirm`（A → B）**：A 计算 $K = x(pB - wN)$ 与 `confA` 发给 B。
5. **`spake_ok`（B → A）**：B 常量时间校验 `confA`（失败计入 5 次/30 秒限流）；通过后用 `AES-256-GCM(aesKey, AAD="spake_ok")` 加密返回 `{"token": token, "confB": confB}`。A 解密并核对 `confB`，完成双向密钥确认。

---

## 3. 中转服务器零明文路由（`server/relay_server.py`）

- 客户端注册与发起配对隧道时，只发送 `pin_tag = SHA-256("lanfast-route|" || relay_key || "|" || pin)[:32]`；
- 服务端支持 `--cert` / `--keyfile` 开启原生 TLS，客户端在服务器地址前加 `tls://`（如 `tls://your-domain.com:53532`）即可启用 TLS 验证连接。

---

## 4. 加密收发帧（`enc` + 分块 AES-256-GCM 流）

所有文字和文件头均封装在 `enc` 密文帧中（`AAD="frame"`），大文件按 256 KiB 分块以 `12B nonce || AES-256-GCM(chunk, AAD=uint64_be(seq))` 流式传输。
