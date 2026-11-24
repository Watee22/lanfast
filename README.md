# LanFast v5 — 抗中间人端到端加密快传（Windows + Android + WebRTC P2P）

支持 **多台 Windows 电脑、Android 手机与苹果/任意浏览器** 通过 **逐对 6 位验证码加好友** 建立独立对话窗口，全程采用 **RFC 9382 SPAKE2-P256 + SAS 4-Emoji 核对码 + AES-256-GCM 端到端加密** 互传文字、剪贴板、文件与文件夹。

## 核心特点

- **抗主动中间人攻击（SPAKE2-P256 + SAS 安全码 + AES-256-GCM）**：
  - 加好友握手采用 **RFC 9382 SPAKE2-P256**（口令认证密钥交换），**6 位验证码与会话令牌全程不明文上网，且彻底杜绝主动中间人离线穷举 6 位码**；
  - 对话顶栏自动展示 **4 位 Emoji 安全核对码（SAS）**（如 `🐻🐢🍪🍑`），两端核对一致即可数学保证零中间人；
  - 所有文字、文件名、令牌和文件数据均按 **AES-256-GCM** 分块加密传输；公网中转服只按加盐哈希 `pin_tag` 路由且支持原生 TLS。
- **纯网页 WebRTC 内网 P2P 版（零客户端安装，两台 iPhone 直接互联）**：
  - 部署单文件 [server/web_p2p.py](server/web_p2p.py)（纯 Python 标准库，零依赖），**任意两台设备（两台 iPhone / iPad / Mac / 安卓 / 电脑）打开同一个网页、输入对方 6 位验证码即可建立 WebRTC P2P 直连**；
  - 服务端只负责约 5 KB 握手牵线，后续所有文字与大文件在局域网内浏览器间直接 **DTLS 端到端加密点对点传输（0 服务器大文件流量）**。
- **Windows 端内置网页端（无公网服务器也能连苹果）**：
  - Windows 端启动后自动开启端口 `53533`，iPhone / iPad / Mac 同一 WiFi 下 Safari 访问 `http://<电脑局域网IP>:53533` 输入 6 位验证码即可与电脑实时双向互传。
- **逐对 6 位验证码加好友 + 微信式多独立对话窗口 + 随时删消息**：
  - Windows 端与 Android 端每次启动各自生成 6 位随机验证码；
  - 每个已验证好友拥有独立对话窗口与未读消息红点，互不串台；三端均支持**单条删除**（含可选删除本地文件）与**一键清空当前对话**。
- **局域网直连优先（兼容 Clash TUN）+ 可选公网中转**：
  - Windows 端自动跳过 Clash TUN 虚拟网段（`198.18.0.0/15`）并在局域网直连时显式绑定物理网卡；
  - 附带 [windows/flclash_lanfast_override.js](windows/flclash_lanfast_override.js) 一键在 FlClash 中排除 LanFast 与局域网段；
  - 可选部署 [server/relay_server.py](server/relay_server.py) 实现跨公网 5G / 异地互传。

---

## 快速使用

### 1. Windows 电脑端（带完整可视化桌面界面）

- **启动界面**：直接双击 [windows/run.bat](windows/run.bat)，或在终端运行：
  ```powershell
  python windows\main.py
  ```
- **依赖**：Python 3.8+，安装依赖：
  ```powershell
  pip install -r windows\requirements.txt
  ```
- **放行局域网防火墙**：右键以管理员身份运行一次 [windows/allow_firewall.bat](windows/allow_firewall.bat)（仅放行同一局域网子网的 UDP `53530` / TCP `53531`，即使开启 Clash TUN 使网络被识别为公用网络也能正常互通）。

### 2. Android 手机端

- 直接从本仓库的 **Releases** 页面下载已签名的 `LanFast.apk`（仅约 81 KB）传到手机安装并打开。
- 手机不需开代理，连在和电脑同一个 WiFi 下，点击 **「＋ 输入对方 6 位验证码添加好友」**，输入电脑顶部显示的 6 位数字即可自动建立加密连接。
- 重新编译 APK：
  ```powershell
  powershell -ExecutionPolicy Bypass -File android\build.ps1
  ```

### 3. 苹果设备（iPhone / iPad / Mac）免安装网页端

1. 确保苹果设备与 Windows 电脑连接在同一个 WiFi；
2. 打开 Safari（或任意浏览器）访问电脑端顶部显示的网页地址：`http://<电脑局域网IP>:53533`；
3. 输入电脑顶部的 **6 位数字验证码** 即可进入聊天互传界面（发文字、选相册多张照片或大文件流式上传，实时接收电脑推来的文字和文件下载卡片）。

### 4. FlClash（带 TUN 虚拟网卡）排除配置

如果你在电脑上常开 FlClash（特别是 **Global 全局模式 + TUN**）：
1. 打开 FlClash → 左侧 **「脚本」** → 新建脚本（命名为 `LanFast`）；
2. 将 [windows/flclash_lanfast_override.js](windows/flclash_lanfast_override.js) 的全部内容粘贴进去保存；
3. 在 **「配置」** 中点击当前配置右侧菜单 → **「覆写」→「脚本」** → 勾选 `LanFast`。

*(同时 LanFast 程序自身已自动过滤 `198.18.x.x` 并绑定物理网卡，同一路由器子网内开着 FlClash 也能直接高速局域网直连。)*

### 5. 可选：跨互联网中转部署（零明文 PIN 路由 + 可选 TLS）

```bash
# 基础启动
python3 server/relay_server.py --host 0.0.0.0 --port 53532 --key 你的自定义密钥
# 开启原生 TLS（客户端服务器地址填 tls://你的域名:53532）
python3 server/relay_server.py --host 0.0.0.0 --port 53532 --key 你的自定义密钥 --cert fullchain.pem --keyfile privkey.pem
```
两端填入服务器地址与密钥即可跨网按 6 位码加好友；中转服务器既看不到明文 6 位码，也无法解密隧道内的 SPAKE2 + AES-256-GCM 密文。

### 6. 纯网页 WebRTC 内网 P2P 版部署（无需安装任何 App，支持两台 iPhone 直接互联）

在你的公网服务器上运行（仅需 Python 3.8+，零依赖，内存占用几 MB）：

```bash
nohup python3 server/web_p2p.py --host 0.0.0.0 --port 53534 > web_p2p.log 2>&1 &
```

> **iPhone Safari 强烈建议开启 HTTPS**（否则 iOS Safari 可能限制 WebRTC 内网候选采集）。如果你有域名，用 **Caddy** 写 3 行 `Caddyfile` 即可自动免费签发 HTTPS 证书：
> ```caddy
> your-domain.com {
>     reverse_proxy 127.0.0.1:53534
> }
> ```
> 或已有证书时直接传参启动：
> ```bash
> python3 server/web_p2p.py --host 0.0.0.0 --port 443 --cert fullchain.pem --key privkey.pem
> ```

部署后，任意两台处于同一局域网（甚至跨网）的 iPhone / 安卓 / Mac / Windows 只要打开浏览器访问 `https://your-domain.com`，互相输入页面顶部的 **6 位验证码** 即可建立多好友独立对话窗口，直接走 **WebRTC 内网 P2P 端到端加密直连**（不消耗服务器文件流量）。
