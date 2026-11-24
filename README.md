# LanFast v4 — 端到端加密局域网 / 跨网多窗口快传（Windows + Android）

支持 **多台 Windows 电脑与 Android 手机** 通过 **逐对 6 位验证码加好友** 建立独立对话窗口，全程 **ECDH P-256 + AES-256-GCM 端到端加密** 互传文字、剪贴板、文件与文件夹。

## 核心特点

- **全程端到端加密（防抓包、防篡改）**：
  - 加好友时通过 **ECDH P-256** 协商临时前向保密密钥，并用 HMAC 证明 6 位验证码（**验证码与令牌绝不明文上网**）；
  - 所有文字、文件名、令牌和文件数据均按 **AES-256-GCM** 分块加密传输；即使局域网、公网沿途或公网中转服务器被抓包，看到的也全部是无法解密的密文。
- **苹果 / 任意浏览器免安装网页端**：
  - Windows 端内置轻量网页服务（端口 `53533`），iPhone / iPad / Mac 无需安装任何 App，Safari 打开 `http://<电脑局域网IP>:53533` 输入 6 位验证码即可与电脑实时双向互传文字、照片与大文件（支持图片缩略图预览与拖拽上传）。
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

### 5. 可选：跨互联网中转部署

```bash
python3 server/relay_server.py --host 0.0.0.0 --port 53532 --key 你的自定义密钥
```
两端填入 `公网IP:53532` 与密钥即可跨网按 6 位码加好友；中转服务器仅转发密文，无法窥探任何内容。
