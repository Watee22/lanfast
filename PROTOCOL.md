# LanFast 传输协议（v4 · 端到端加密版）

LanFast v4 采用 **「ECDH P-256 临时密钥交换 + 零明文 6 位验证码证明 + AES-256-GCM 全程端到端加密」**。
无论是局域网抓包、公网沿途抓包，还是公网中转服务器本身，都**无法看到 6 位验证码、会话令牌、文字正文、文件名或任何文件字节**。

---

## 1. 端口与地址

| 用途 | 协议 | 默认端口 / 地址 |
|---|---|---|
| 局域网设备发现 | UDP 组播 + 广播 + 单播回应 | `224.0.0.167:53530`、`255.255.255.255:53530`、子网广播 `:53530` |
| 局域网直连传输 | TCP | `53531` |
| 公网中转服务器（可选） | TCP | `53532`（`server/relay_server.py`） |

---

## 2. 端到端加密握手（零明文 6 位码配对）

TCP 帧头固定为 `4 字节大端无符号长度 + UTF-8 JSON`。

1. **`pair_hello`（A → B）**：A 生成临时 P-256 密钥对 `(privA, pubA)` 与 16 字节随机 `saltA`，发送 `pubA`（X.509 SPKI DER Base64）与 `saltA`。
2. **`pair_challenge`（B → A）**：B 生成临时 P-256 密钥对 `(privB, pubB)` 与 16 字节随机 `saltB`，计算 ECDH 共享密钥 `Z = ECDH(privB, pubA)`，返回 `pubB` 与 `saltB`。
3. **`pair_verify`（A → B）**：A 计算 `Z = ECDH(privA, pubB)`，计算验证码证明：
   ```text
   proof = HMAC-SHA256(Z, "lanfast-pin|" || UTF8(pin) || "|" || saltA || "|" || saltB)
   ```
   A 仅发送 `proof`（6 位 `pin` 本身**绝不明文上网**）。
4. **`pair_ok`（B → A）**：B 用本机 `pin` 校验 `proof`（单来源连续错 5 次锁定 30 秒）。通过后双方派生 256-bit 会话密钥：
   ```text
   aesKey = SHA-256(Z || "lanfast-e2ee-v4" || UTF8(pin) || saltA || saltB)
   ```
   B 生成 24 字节随机 `token`，用 `AES-256-GCM(aesKey, AAD="pair_ok")` 加密 `{"token": token}` 返回给 A。

---

## 3. 端到端加密收发（`enc` + 分块 AES-256-GCM 流）

所有文字和文件头均封装在 `enc` 密文帧中：

```json
{"app":"lanfast","v":4,"type":"enc","id":"<sender_id>","n":"<12B nonce b64>","ct":"<AES-256-GCM密文+16B标签 b64>"}
```

解密后（`AAD = "frame"`）：
- **文字**：`{"type":"text","token":"...","text":"..."}`
- **文件头**：`{"type":"file","token":"...","fileName":"相对路径","size":1048576,"chunkSize":262144,"index":1,"count":1}`

**加密文件流**：紧随加密文件头之后，按每块明文最大 `chunkSize`（默认 `256 KiB`）流式传输，第 `seq` 块（从 0 递增）格式为：
```text
12 字节随机 nonce || AES-256-GCM(key=aesKey, nonce=nonce, plaintext=chunk, AAD=uint64_be(seq))
```
任意篡改、乱序或截断都会在 GCM 标签校验时立即报错并清理 `.lfpart` 临时文件。
