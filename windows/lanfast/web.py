"""
LanFast 内置网页端服务（端口 53533，纯 Python 标准库 + 单页原生 HTML/JS）

作用：
  让 iPhone / iPad / Mac 或任意未安装 App 的设备，打开浏览器访问
  http://<电脑局域网IP>:53533 即可通过 6 位验证码连接电脑并双向互传文字与文件。
"""
import hmac
import json
import mimetypes
import os
import queue
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

WEB_PORT = 53533
UPLOAD_CHUNK = 512 * 1024

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>LanFast 网页快传</title>
<style>
  :root {
    --blue: #2563eb; --blue-dark: #1d4ed8; --bg: #f3f4f6; --card: #ffffff;
    --text: #111827; --muted: #6b7280; --border: #e5e7eb; --green: #065f46;
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body { margin: 0; padding: 0; height: 100%; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .hidden { display: none !important; }

  /* 验证码登录页 */
  #loginView { min-height: 100%; display: flex; align-items: center; justify-content: center; padding: 20px; }
  .card { width: 100%; max-width: 390px; background: var(--card); border-radius: 18px;
    padding: 28px 22px; box-shadow: 0 10px 30px rgba(0,0,0,.07); text-align: center; }
  .logo { font-size: 24px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
  .sub { font-size: 13px; color: var(--muted); line-height: 1.5; margin-bottom: 18px; }
  .pin-input { width: 100%; font-size: 30px; font-weight: 700; letter-spacing: 8px; text-align: center;
    padding: 12px; border: 2px solid #93c5fd; border-radius: 12px; background: #eff6ff; color: var(--blue);
    outline: none; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .pin-input:focus { border-color: var(--blue); }
  .name-input { width: 100%; margin-top: 12px; padding: 10px 12px; border: 1px solid var(--border);
    border-radius: 10px; font-size: 14px; outline: none; }
  .btn { width: 100%; margin-top: 14px; padding: 13px; border: none; border-radius: 12px;
    background: var(--blue); color: #fff; font-size: 16px; font-weight: 600; cursor: pointer; }
  .btn:active { background: var(--blue-dark); }
  .btn:disabled { opacity: .6; cursor: default; }
  .err { margin-top: 10px; color: #b91c1c; font-size: 13px; min-height: 18px; }

  /* 聊天主界面 */
  #chatView { height: 100%; display: flex; flex-direction: column; max-width: 860px; margin: 0 auto; background: var(--bg); }
  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 8px;
    padding: 10px 14px; background: #ecfdf5; border-bottom: 1px solid #d1fae5; flex-shrink: 0; }
  .topbar-title { font-size: 15px; font-weight: 700; color: var(--green); }
  .topbar-sub { font-size: 11px; color: #047857; margin-top: 2px; }
  .btn-sm { border: 1px solid #a7f3d0; background: #fff; color: var(--green); border-radius: 8px;
    padding: 6px 10px; font-size: 12px; font-weight: 600; cursor: pointer; flex-shrink: 0; }

  #msgs { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 10px;
    -webkit-overflow-scrolling: touch; }
  .row { display: flex; flex-direction: column; max-width: 84%; }
  .row.in { align-self: flex-start; align-items: flex-start; }
  .row.out { align-self: flex-end; align-items: flex-end; }
  .meta { font-size: 11px; color: var(--muted); margin: 0 4px 3px; }
  .bubble { background: #fff; border-radius: 14px; padding: 10px 13px; font-size: 15px; line-height: 1.45;
    word-break: break-word; white-space: pre-wrap; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
  .row.out .bubble { background: #dbeafe; }
  .row.err .bubble { background: #fee2e2; color: #b91c1c; }
  .copy-tag { display: inline-block; margin-top: 6px; font-size: 12px; color: var(--blue); cursor: pointer; }
  .file-card { display: flex; flex-direction: column; gap: 6px; min-width: 190px; }
  .file-name { font-weight: 600; word-break: break-all; }
  .file-meta { font-size: 12px; color: var(--muted); }
  .file-preview { max-width: 240px; max-height: 220px; border-radius: 8px; object-fit: cover; margin-top: 4px; }
  .dl-btn { display: inline-block; text-align: center; text-decoration: none; background: var(--blue);
    color: #fff; padding: 7px 12px; border-radius: 8px; font-size: 13px; font-weight: 600; }

  .prog-wrap { height: 4px; background: #e5e7eb; flex-shrink: 0; }
  .prog-bar { height: 100%; width: 0%; background: var(--blue); transition: width .12s linear; }
  .status { font-size: 12px; color: var(--muted); padding: 4px 12px; white-space: nowrap;
    overflow: hidden; text-overflow: ellipsis; flex-shrink: 0; }

  .composer { display: flex; align-items: flex-end; gap: 8px; padding: 8px 10px calc(8px + env(safe-area-inset-bottom));
    background: #fff; border-top: 1px solid var(--border); flex-shrink: 0; }
  .icon-btn { border: 1px solid var(--border); background: #f9fafb; color: var(--text); border-radius: 10px;
    padding: 9px 12px; font-size: 14px; font-weight: 600; cursor: pointer; flex-shrink: 0; }
  #textInput { flex: 1; resize: none; border: 1px solid var(--border); border-radius: 10px; padding: 9px 11px;
    font-size: 15px; line-height: 1.35; max-height: 120px; outline: none; font-family: inherit; }
  #textInput:focus { border-color: var(--blue); }
  .send-btn { border: none; background: var(--blue); color: #fff; border-radius: 10px;
    padding: 9px 15px; font-size: 14px; font-weight: 600; cursor: pointer; flex-shrink: 0; }
  .drag-over { outline: 3px dashed var(--blue); outline-offset: -6px; background: #eff6ff !important; }
  .toast { position: fixed; top: 18px; left: 50%; transform: translateX(-50%); background: rgba(17,24,39,.9);
    color: #fff; padding: 8px 16px; border-radius: 999px; font-size: 13px; z-index: 999; pointer-events: none; }
</style>
</head>
<body>

<div id="loginView">
  <div class="card">
    <div class="logo">⚡ LanFast 网页快传</div>
    <div class="sub" id="serverHint">正在连接电脑…</div>
    <input id="pinInput" class="pin-input" type="tel" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code">
    <input id="nameInput" class="name-input" type="text" maxlength="32" placeholder="本机名称（例如 我的 iPhone）">
    <button id="loginBtn" class="btn">验证并连接电脑</button>
    <div id="loginErr" class="err"></div>
  </div>
</div>

<div id="chatView" class="hidden">
  <div class="topbar">
    <div>
      <div class="topbar-title" id="peerTitle">✓ 已连接电脑</div>
      <div class="topbar-sub" id="connSub">实时通道已建立 · 可直接拖入或选择文件</div>
    </div>
    <div style="display:flex;gap:6px;flex-shrink:0">
      <button id="clearBtn" class="btn-sm">清空</button>
      <button id="logoutBtn" class="btn-sm">断开</button>
    </div>
  </div>
  <div id="msgs"></div>
  <div class="prog-wrap hidden" id="progWrap"><div class="prog-bar" id="progBar"></div></div>
  <div class="status" id="statusText">就绪</div>
  <div class="composer">
    <button id="fileBtn" class="icon-btn">文件</button>
    <input id="fileInput" type="file" multiple class="hidden">
    <textarea id="textInput" rows="1" placeholder="输入要发送的文字…"></textarea>
    <button id="sendBtn" class="send-btn">发送</button>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
let state = { token: "", clientId: "", peerName: "", es: null };

function guessDeviceName() {
  const ua = navigator.userAgent || "";
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua) || (/Macintosh/i.test(ua) && navigator.maxTouchPoints > 1)) return "iPad";
  if (/Macintosh/i.test(ua)) return "Mac 浏览器";
  if (/Android/i.test(ua)) return "Android 浏览器";
  if (/Windows/i.test(ua)) return "Windows 浏览器";
  return "网页设备";
}

function human(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = Number(n) || 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${v.toFixed(0)} B` : `${v.toFixed(1)} ${u[i]}`;
}

function nowStr() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map(x => String(x).padStart(2, "0")).join(":");
}

function showToast(text) {
  const t = document.createElement("div");
  t.className = "toast";
  t.textContent = text;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 1800);
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.focus(); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    showToast("已复制到剪贴板");
  } catch (e) {
    showToast("请长按文字手动复制");
  }
}

function setStatus(s, pct = -1) {
  $("statusText").textContent = s;
  if (pct < 0) {
    $("progWrap").classList.add("hidden");
  } else {
    $("progWrap").classList.remove("hidden");
    $("progBar").style.width = Math.min(100, Math.max(0, pct)) + "%";
  }
}

function addMsg({ dir, kind, text, fileName, size, url, isImage }) {
  const box = $("msgs");
  const row = document.createElement("div");
  row.className = "row " + dir;
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = (dir === "in" ? "← " + state.peerName : (dir === "out" ? "→ 我" : "✕ 错误")) + " · " + nowStr();
  row.appendChild(meta);

  const bub = document.createElement("div");
  bub.className = "bubble";
  if (kind === "file") {
    const fc = document.createElement("div");
    fc.className = "file-card";
    const fn = document.createElement("div");
    fn.className = "file-name";
    fn.textContent = "📄 " + fileName;
    const fm = document.createElement("div");
    fm.className = "file-meta";
    fm.textContent = human(size);
    fc.appendChild(fn); fc.appendChild(fm);
    if (url && isImage) {
      const img = document.createElement("img");
      img.className = "file-preview";
      img.src = url + "&inline=1";
      img.loading = "lazy";
      fc.appendChild(img);
    }
    if (url) {
      const a = document.createElement("a");
      a.className = "dl-btn";
      a.href = url;
      a.download = fileName;
      a.textContent = "下载保存";
      fc.appendChild(a);
    }
    const del = document.createElement("div");
    del.className = "copy-tag";
    del.style.color = "#ef4444";
    del.textContent = "删除";
    del.onclick = () => row.remove();
    fc.appendChild(del);
    bub.appendChild(fc);
  } else {
    const span = document.createElement("div");
    span.textContent = text;
    bub.appendChild(span);
    const ops = document.createElement("div");
    ops.style.display = "flex"; ops.style.gap = "12px";
    if (dir !== "err") {
      const cp = document.createElement("div");
      cp.className = "copy-tag";
      cp.textContent = "复制";
      cp.onclick = () => copyText(text);
      ops.appendChild(cp);
    }
    const del = document.createElement("div");
    del.className = "copy-tag";
    del.style.color = "#ef4444";
    del.textContent = "删除";
    del.onclick = () => row.remove();
    ops.appendChild(del);
    bub.appendChild(ops);
  }
  row.appendChild(bub);
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
}

async function initInfo() {
  $("nameInput").value = localStorage.getItem("lf_web_name") || guessDeviceName();
  try {
    const r = await fetch("/api/info");
    const d = await r.json();
    $("serverHint").textContent = `请输入电脑「${d.name}」顶部显示的 6 位数字验证码`;
  } catch (e) {
    $("serverHint").textContent = "请输入电脑端显示的 6 位数字验证码";
  }
  const saved = sessionStorage.getItem("lf_session");
  if (saved) {
    try {
      const s = JSON.parse(saved);
      const chk = await fetch("/api/check?token=" + encodeURIComponent(s.token));
      const cd = await chk.json();
      if (cd.ok) {
        enterChat(s.token, s.clientId, cd.name || s.peerName);
        return;
      }
    } catch (e) {}
    sessionStorage.removeItem("lf_session");
  }
}

async function doLogin() {
  const pin = $("pinInput").value.replace(/\D/g, "");
  const name = $("nameInput").value.trim() || guessDeviceName();
  if (pin.length !== 6) {
    $("loginErr").textContent = "请输入完整的 6 位数字验证码";
    return;
  }
  localStorage.setItem("lf_web_name", name);
  $("loginErr").textContent = "";
  $("loginBtn").disabled = true;
  $("loginBtn").textContent = "正在验证…";
  try {
    const r = await fetch("/api/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: pin, name })
    });
    const d = await r.json();
    if (!d.ok) {
      $("loginErr").textContent = d.error || "验证码错误";
    } else {
      $("pinInput").value = "";
      sessionStorage.setItem("lf_session", JSON.stringify({ token: d.token, clientId: d.clientId, peerName: d.name }));
      enterChat(d.token, d.clientId, d.name);
    }
  } catch (e) {
    $("loginErr").textContent = "连接失败：" + e.message;
  } finally {
    $("loginBtn").disabled = false;
    $("loginBtn").textContent = "验证并连接电脑";
  }
}

function enterChat(token, clientId, peerName) {
  state.token = token; state.clientId = clientId; state.peerName = peerName;
  $("peerTitle").textContent = "✓ 已连接：" + peerName;
  $("loginView").classList.add("hidden");
  $("chatView").classList.remove("hidden");
  startEvents();
}

function leaveChat(reason) {
  if (state.es) { state.es.close(); state.es = null; }
  state.token = "";
  sessionStorage.removeItem("lf_session");
  $("chatView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
  $("loginErr").textContent = reason || "";
}

function startEvents() {
  if (state.es) state.es.close();
  const es = new EventSource("/api/events?token=" + encodeURIComponent(state.token));
  state.es = es;
  es.onopen = () => { $("connSub").textContent = "实时通道已连接 · 支持直接收发文字与文件"; };
  es.onmessage = ev => {
    let m;
    try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (m.type === "text") {
      addMsg({ dir: "in", kind: "text", text: m.text });
      setStatus("收到来自 " + state.peerName + " 的文字");
    } else if (m.type === "file") {
      const url = "/api/download/" + encodeURIComponent(m.fid) + "?token=" + encodeURIComponent(state.token);
      addMsg({ dir: "in", kind: "file", fileName: m.fileName, size: m.size, url, isImage: m.isImage });
      setStatus("收到文件：" + m.fileName);
    } else if (m.type === "kicked") {
      leaveChat(m.reason || "电脑端已断开连接，请重新输入验证码");
    }
  };
  es.onerror = () => {
    $("connSub").textContent = "连接波动，正在自动重连…";
  };
}

async function sendText() {
  const el = $("textInput");
  const text = el.value;
  if (!text.trim()) return;
  el.value = ""; el.style.height = "auto";
  try {
    const r = await fetch("/api/text", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Token": state.token },
      body: JSON.stringify({ text })
    });
    const d = await r.json();
    if (!d.ok) {
      if (d.auth_error) { leaveChat(d.error); return; }
      addMsg({ dir: "err", kind: "text", text: "发送失败：" + (d.error || "未知错误") });
    } else {
      addMsg({ dir: "out", kind: "text", text });
      setStatus("文字已发送到 " + state.peerName);
    }
  } catch (e) {
    addMsg({ dir: "err", kind: "text", text: "发送失败：" + e.message });
  }
}

function uploadOne(file, idx, totalCount) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    xhr.setRequestHeader("X-Token", state.token);
    xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name || "file"));
    const t0 = Date.now();
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) {
        const pct = Math.round(e.loaded * 100 / Math.max(e.total, 1));
        const spd = e.loaded / Math.max((Date.now() - t0) / 1000, 0.1);
        setStatus(`上传 [${idx}/${totalCount}] ${file.name}  ${human(e.loaded)}/${human(e.total)}  ${human(spd)}/s`, pct);
      }
    };
    xhr.onload = () => {
      try {
        const d = JSON.parse(xhr.responseText);
        if (d.ok) resolve(d);
        else {
          if (d.auth_error) leaveChat(d.error);
          reject(new Error(d.error || "上传失败"));
        }
      } catch (e) { reject(new Error("服务器响应异常")); }
    };
    xhr.onerror = () => reject(new Error("网络中断"));
    xhr.send(file);
  });
}

async function uploadFiles(files) {
  const arr = Array.from(files || []);
  if (!arr.length) return;
  for (let i = 0; i < arr.length; i++) {
    const f = arr[i];
    try {
      await uploadOne(f, i + 1, arr.length);
      addMsg({ dir: "out", kind: "file", fileName: f.name, size: f.size });
      setStatus(`已发送 ${f.name} → ${state.peerName}`, 100);
    } catch (e) {
      addMsg({ dir: "err", kind: "text", text: `上传 ${f.name} 失败：${e.message}` });
      setStatus("上传失败：" + e.message, -1);
      break;
    }
  }
  setTimeout(() => setStatus("就绪", -1), 1500);
}

$("loginBtn").onclick = doLogin;
$("pinInput").addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
$("clearBtn").onclick = () => { $("msgs").innerHTML = ""; showToast("已清空当前记录"); };
$("logoutBtn").onclick = async () => {
  try { await fetch("/api/logout", { method: "POST", headers: { "X-Token": state.token } }); } catch (e) {}
  leaveChat("");
};
$("sendBtn").onclick = sendText;
$("textInput").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendText(); }
});
$("textInput").addEventListener("input", e => {
  e.target.style.height = "auto";
  e.target.style.height = Math.min(120, e.target.scrollHeight) + "px";
});
$("fileBtn").onclick = () => $("fileInput").click();
$("fileInput").onchange = e => { uploadFiles(e.target.files); e.target.value = ""; };

// 桌面浏览器（如 Mac Safari/Chrome）拖拽上传
document.addEventListener("dragover", e => {
  if (!state.token) return;
  e.preventDefault();
  $("chatView").classList.add("drag-over");
});
document.addEventListener("dragleave", e => {
  if (e.target === document.documentElement || e.target === document.body) $("chatView").classList.remove("drag-over");
});
document.addEventListener("drop", e => {
  $("chatView").classList.remove("drag-over");
  if (!state.token) return;
  e.preventDefault();
  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
});

initInfo();
</script>
</body>
</html>
"""


class WebClient:
    def __init__(self, device_id, name, ip, token):
        self.id = device_id
        self.name = name
        self.ip = ip
        self.token = token
        self.queue = queue.Queue()
        self.files = {}  # fid -> (abspath, rel_name, size)


class WebBridge:
    """挂在 LanFastCore 上的轻量 HTTP 服务，服务苹果/任意浏览器客户端。"""

    def __init__(self, core, port=WEB_PORT):
        self.core = core
        self.port = port
        self._lock = threading.Lock()
        self._by_token = {}  # token -> WebClient
        self._by_id = {}     # device_id -> WebClient
        self._srv = None

    def start(self):
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _send_json(self, obj, code=200):
                body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _auth(self, qs=None):
                tok = self.headers.get("X-Token", "")
                if not tok and qs:
                    tok = (qs.get("token") or [""])[0]
                return bridge.get_by_token(tok)

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                qs = parse_qs(parsed.query)

                if path in ("/", "/index.html"):
                    body = HTML_PAGE.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if path == "/api/info":
                    self._send_json({"name": bridge.core.name, "app": "lanfast"})
                    return

                if path == "/api/check":
                    cli = self._auth(qs)
                    if cli:
                        self._send_json({"ok": True, "name": bridge.core.name})
                    else:
                        self._send_json({"ok": False})
                    return

                if path == "/api/events":
                    cli = self._auth(qs)
                    if not cli:
                        self._send_json({"ok": False, "auth_error": True, "error": "未验证或已断开"}, 401)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("X-Accel-Buffering", "no")
                    self.end_headers()
                    try:
                        self.wfile.write(b": ok\n\n")
                        self.wfile.flush()
                        while bridge.core._running and bridge.get_by_token(cli.token) is cli:
                            try:
                                item = cli.queue.get(timeout=20)
                                data = json.dumps(item, ensure_ascii=False).encode("utf-8")
                                self.wfile.write(b"data: " + data + b"\n\n")
                                self.wfile.flush()
                                if item.get("type") == "kicked":
                                    break
                            except queue.Empty:
                                self.wfile.write(b": ping\n\n")
                                self.wfile.flush()
                    except OSError:
                        pass
                    return

                if path.startswith("/api/download/"):
                    cli = self._auth(qs)
                    if not cli:
                        self.send_error(403, "Forbidden")
                        return
                    fid = unquote(path[len("/api/download/"):])
                    with bridge._lock:
                        entry = cli.files.get(fid)
                    if not entry or not os.path.isfile(entry[0]):
                        self.send_error(404, "File not found")
                        return
                    abspath, rel_name, size = entry
                    fname = os.path.basename(rel_name)
                    inline = (qs.get("inline") or ["0"])[0] == "1"
                    mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
                    disp = "inline" if inline else "attachment"
                    self.send_response(200)
                    self.send_header("Content-Type", mime)
                    self.send_header("Content-Length", str(size))
                    self.send_header("Content-Disposition", f"{disp}; filename*=UTF-8''{quote(fname)}")
                    self.end_headers()
                    try:
                        with open(abspath, "rb") as f:
                            while True:
                                chunk = f.read(UPLOAD_CHUNK)
                                if not chunk:
                                    break
                                self.wfile.write(chunk)
                    except OSError:
                        pass
                    return

                self.send_error(404)

            def do_POST(self):
                parsed = urlparse(self.path)
                path = parsed.path
                ip = self.client_address[0]

                if path == "/api/pair":
                    cl = int(self.headers.get("Content-Length", "0"))
                    if cl <= 0 or cl > 65536:
                        self._send_json({"ok": False, "error": "请求无效"}, 400)
                        return
                    try:
                        body = json.loads(self.rfile.read(cl).decode("utf-8"))
                    except ValueError:
                        self._send_json({"ok": False, "error": "JSON 格式错误"}, 400)
                        return
                    code = str(body.get("code", "")).strip()
                    name = str(body.get("name", "网页设备")).strip()[:32] or "网页设备"
                    ok, res = bridge.handle_pair(code, name, ip)
                    self._send_json(res, 200 if ok else 403)
                    return

                if path == "/api/logout":
                    cli = self._auth()
                    if cli:
                        bridge.core.remove_device(cli.id)
                    self._send_json({"ok": True})
                    return

                if path == "/api/text":
                    cli = self._auth()
                    if not cli:
                        self._send_json({"ok": False, "auth_error": True, "error": "连接已失效，请重新输入 6 位验证码"}, 401)
                        return
                    cl = int(self.headers.get("Content-Length", "0"))
                    if cl <= 0 or cl > 2 * 1024 * 1024:
                        self._send_json({"ok": False, "error": "文字过长"}, 400)
                        return
                    body = json.loads(self.rfile.read(cl).decode("utf-8"))
                    text = str(body.get("text", ""))
                    bridge.core._emit("text", {
                        "peer_id": cli.id, "from": cli.name, "ip": ip,
                        "route": "网页端", "text": text, "time": time.time(),
                    })
                    self._send_json({"ok": True})
                    return

                if path == "/api/upload":
                    cli = self._auth()
                    if not cli:
                        self._send_json({"ok": False, "auth_error": True, "error": "连接已失效，请重新输入 6 位验证码"}, 401)
                        return
                    size = int(self.headers.get("Content-Length", "-1"))
                    if size < 0:
                        self._send_json({"ok": False, "error": "缺少 Content-Length"}, 400)
                        return
                    raw_name = unquote(self.headers.get("X-File-Name", "file"))
                    from .core import safe_parts, unique_path
                    parts = safe_parts(raw_name)
                    dest = unique_path(os.path.join(bridge.core.save_dir, *parts))
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    tmp = dest + ".lfpart"
                    disp_name = "/".join(parts)
                    got, last = 0, 0.0
                    try:
                        with open(tmp, "wb") as f:
                            while got < size:
                                chunk = self.rfile.read(min(UPLOAD_CHUNK, size - got))
                                if not chunk:
                                    raise ConnectionError("浏览器中断了上传")
                                f.write(chunk)
                                got += len(chunk)
                                now = time.time()
                                if now - last > 0.15 or got == size:
                                    last = now
                                    bridge.core._emit("recv_progress", {
                                        "peer_id": cli.id, "from": cli.name, "route": "网页端",
                                        "name": disp_name, "done": got, "total": size,
                                    })
                        os.replace(tmp, dest)
                    except BaseException as e:
                        try:
                            os.remove(tmp)
                        except OSError:
                            pass
                        self._send_json({"ok": False, "error": str(e)}, 500)
                        return
                    bridge.core._emit("recv_file", {
                        "peer_id": cli.id, "from": cli.name, "ip": ip,
                        "route": "网页端", "path": dest, "size": size, "time": time.time(),
                    })
                    self._send_json({"ok": True})
                    return

                self.send_error(404)

        self._srv = ThreadingHTTPServer(("", self.port), Handler)
        self._srv.daemon_threads = True
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self):
        if self._srv:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except OSError:
                pass
            self._srv = None

    def get_by_token(self, tok):
        if not tok:
            return None
        with self._lock:
            return self._by_token.get(tok)

    def handle_pair(self, code, name, ip):
        now = time.time()
        rate_key = "web:" + ip
        with self.core._lock:
            fails, lock_until = self.core._fail_state.get(rate_key, (0, 0.0))
            if now < lock_until:
                wait = int(lock_until - now) + 1
                return False, {"ok": False, "error": f"验证码尝试次数过多，请 {wait} 秒后再试"}
            if not code or not hmac.compare_digest(code, self.core.pin):
                fails += 1
                if fails >= 5:
                    self.core._fail_state[rate_key] = (0, now + 30)
                    return False, {"ok": False, "error": "验证码错误次数过多，请 30 秒后再试"}
                self.core._fail_state[rate_key] = (fails, 0.0)
                return False, {"ok": False, "error": "验证码错误"}
            self.core._fail_state.pop(rate_key, None)

        token = secrets.token_hex(24)
        cid = "web-" + secrets.token_hex(8)
        cli = WebClient(cid, name, ip, token)
        with self._lock:
            self._by_token[token] = cli
            self._by_id[cid] = cli
        self.core.register_web_device(cid, name, ip, token)
        return True, {"ok": True, "token": token, "clientId": cid, "name": self.core.name}

    def kick(self, device_id, reason="电脑端已断开连接"):
        with self._lock:
            cli = self._by_id.pop(device_id, None)
            if cli:
                self._by_token.pop(cli.token, None)
        if cli:
            cli.queue.put({"type": "kicked", "reason": reason})

    def push_text(self, device_id, text):
        with self._lock:
            cli = self._by_id.get(device_id)
        if not cli:
            raise ConnectionError("网页端已断开连接")
        cli.queue.put({"type": "text", "text": text})

    def push_files(self, device_id, items):
        with self._lock:
            cli = self._by_id.get(device_id)
            if not cli:
                raise ConnectionError("网页端已断开连接")
            for abspath, rel in items:
                size = os.path.getsize(abspath)
                fid = secrets.token_hex(10)
                cli.files[fid] = (abspath, rel, size)
                ext = os.path.splitext(rel)[1].lower()
                is_img = ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")
                cli.queue.put({"type": "file", "fid": fid, "fileName": rel, "size": size, "isImage": is_img})
