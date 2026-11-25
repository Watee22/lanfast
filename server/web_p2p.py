#!/usr/bin/env python3
"""
LanFast 纯网页 WebRTC 内网 P2P 版（纯 Python 3.8+ 标准库，零第三方依赖）

工作原理：
  1. 任意两台设备（两台 iPhone / iPhone+Mac / iPhone+安卓 / 两台电脑）无需安装任何 App，
     只要打开浏览器访问同一个网址即可各自获得一个 6 位数字验证码；
  2. 一方输入对方的 6 位验证码后，本服务端仅负责转发约 5 KB 的 WebRTC 握手信令；
  3. 握手完成后，两台设备通过 WebRTC DataChannel（原生 DTLS 端到端加密）在局域网内
     点对点直连互传文字与大文件——完全不经过本服务器（0 服务器流量、0 存储、内网满速）。

启动示例：
  python3 web_p2p.py --host 0.0.0.0 --port 53534
  python3 web_p2p.py --host 0.0.0.0 --port 443 --cert fullchain.pem --key privkey.pem
  （或前面挂 Caddy / Nginx 反代自动签发 HTTPS 证书，iPhone Safari 完美兼容）
"""
import argparse
import hmac
import json
import logging
import queue
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("lanfast-webp2p")

MAX_PIN_FAILS = 5
PIN_LOCK_SECONDS = 30
CLIENT_TIMEOUT = 65

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>LanFast 网页 P2P 快传</title>
<style>
  :root {
    --blue: #2563eb; --blue-dark: #1d4ed8; --bg: #f3f4f6; --card: #ffffff;
    --text: #111827; --muted: #6b7280; --border: #e5e7eb; --green: #065f46;
  }
  * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body { margin: 0; padding: 0; height: 100%; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", "Microsoft YaHei", sans-serif; }
  .hidden { display: none !important; }

  .app { height: 100%; max-width: 960px; margin: 0 auto; display: flex; flex-direction: column; background: var(--bg); }

  /* 首页：本机验证码 + 好友列表 */
  #homeView { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .pin-card { margin: 12px 12px 8px; padding: 14px 16px; background: #eff6ff; border: 1px solid #bfdbfe;
    border-radius: 16px; }
  .pin-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .pin-lbl { font-size: 12px; color: #1e3a8a; font-weight: 600; }
  .pin-val { font-size: 28px; font-weight: 800; letter-spacing: 4px; color: var(--blue); cursor: pointer;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; margin-top: 2px; }
  .pin-ops { display: flex; gap: 6px; }
  .btn-lite { border: 1px solid #93c5fd; background: #fff; color: var(--blue); border-radius: 9px;
    padding: 7px 11px; font-size: 12px; font-weight: 600; cursor: pointer; }
  .lan-bar { margin-top: 10px; padding: 7px 10px; background: #fff; border-radius: 10px; border: 1px solid #dbeafe;
    font-size: 12px; color: #475569; display: flex; justify-content: space-between; align-items: center; gap: 8px; }

  .add-bar { margin: 0 12px 10px; display: flex; gap: 8px; }
  .add-input { flex: 1; padding: 11px 14px; border: 1.5px solid #cbd5e1; border-radius: 12px; background: #fff;
    font-size: 18px; font-weight: 700; letter-spacing: 4px; text-align: center; outline: none;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .add-input:focus { border-color: var(--blue); }
  .add-btn { border: none; background: var(--blue); color: #fff; border-radius: 12px; padding: 0 18px;
    font-size: 15px; font-weight: 600; cursor: pointer; flex-shrink: 0; }
  .add-btn:disabled { opacity: .6; }

  .sec-title { padding: 2px 14px 6px; font-size: 13px; font-weight: 700; color: #374151; }
  #friendList { flex: 1; overflow-y: auto; padding: 0 12px 12px; display: flex; flex-direction: column; gap: 8px; }
  .friend-item { background: #fff; border-radius: 14px; padding: 12px 14px; display: flex; align-items: center;
    justify-content: space-between; gap: 10px; box-shadow: 0 1px 2px rgba(0,0,0,.04); cursor: pointer; }
  .friend-name { font-size: 15px; font-weight: 700; color: var(--text); }
  .friend-preview { font-size: 12px; color: var(--muted); margin-top: 3px; white-space: nowrap;
    overflow: hidden; text-overflow: ellipsis; max-width: 65vw; }
  .badge { background: #ef4444; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px;
    border-radius: 999px; }
  .empty { text-align: center; color: var(--muted); font-size: 13px; line-height: 1.7; padding: 40px 24px; }
  .footer { padding: 8px 14px calc(8px + env(safe-area-inset-bottom)); font-size: 11px; color: var(--muted);
    display: flex; justify-content: space-between; align-items: center; }

  /* 独立对话窗口 */
  #chatView { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .topbar { display: flex; align-items: center; gap: 8px; padding: 9px 10px; background: #fff;
    border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .topbar-mid { flex: 1; min-width: 0; }
  .topbar-title { font-size: 15px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .topbar-sub { font-size: 11px; color: var(--green); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .btn-sm { border: 1px solid var(--border); background: #f9fafb; color: var(--text); border-radius: 8px;
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
  .ops { display: flex; gap: 14px; margin-top: 6px; font-size: 12px; }
  .op-copy { color: var(--blue); cursor: pointer; }
  .op-del { color: #ef4444; cursor: pointer; }
  .file-card { display: flex; flex-direction: column; gap: 6px; min-width: 190px; }
  .file-name { font-weight: 600; word-break: break-all; }
  .file-meta { font-size: 12px; color: var(--muted); }
  .file-preview { max-width: 240px; max-height: 220px; border-radius: 8px; object-fit: cover; }
  .dl-btn { display: inline-block; text-align: center; text-decoration: none; background: var(--blue);
    color: #fff; padding: 7px 12px; border-radius: 8px; font-size: 13px; font-weight: 600; }

  .prog-wrap { height: 4px; background: #e5e7eb; flex-shrink: 0; }
  .prog-bar { height: 100%; width: 0%; background: var(--blue); transition: width .1s linear; }
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
    color: #fff; padding: 8px 16px; border-radius: 999px; font-size: 13px; z-index: 999; pointer-events: none; max-width: 90vw; text-align: center; }
  .warn-banner { margin: 8px 12px 0; padding: 8px 12px; border-radius: 10px; background: #fffbeb;
    border: 1px solid #fde68a; color: #92400e; font-size: 12px; line-height: 1.5; }
  .modal-bg { position: fixed; inset: 0; background: rgba(15,23,42,.55); display: flex;
    align-items: center; justify-content: center; padding: 20px; z-index: 900; }
  .modal-card { background: #fff; border-radius: 18px; padding: 22px 20px; width: 100%; max-width: 340px;
    text-align: center; box-shadow: 0 20px 50px rgba(0,0,0,.22); }
  .modal-card canvas { width: 220px; height: 220px; image-rendering: pixelated; border-radius: 8px;
    border: 1px solid var(--border); margin: 12px 0; }
</style>
</head>
<body>
<div class="app">

  <!-- 首页：本机 6 位码 + 多好友对话列表 -->
  <div id="homeView">
    <div id="httpsWarn" class="warn-banner hidden">
      当前为非 HTTPS 页面：iPhone Safari 可能限制 WebRTC 内网直连。建议在服务器配置 HTTPS 域名以获得最佳体验。
    </div>
    <div class="pin-card">
      <div class="pin-row">
        <div>
          <div class="pin-lbl">本机 6 位验证码（告诉对方即可 P2P 加密直连）</div>
          <div id="myPin" class="pin-val">--- ---</div>
        </div>
        <div class="pin-ops">
          <button id="qrBtn" class="btn-lite">扫码直连</button>
          <button id="copyPinBtn" class="btn-lite">复制</button>
          <button id="refreshPinBtn" class="btn-lite">刷新</button>
        </div>
      </div>
      <div class="lan-bar">
        <span id="sigStatus">正在连接信令服务…</span>
        <span id="lanCount">同内网：-</span>
      </div>
    </div>

    <div class="add-bar">
      <input id="peerPinInput" class="add-input" type="tel" inputmode="numeric" maxlength="6" placeholder="输入对方6位码">
      <button id="connectBtn" class="add-btn">直连加好友</button>
    </div>

    <div class="sec-title">已连接的 P2P 好友（每个好友独立对话窗口）</div>
    <div id="friendList"></div>

    <div class="footer">
      <span id="myNameLabel">本机：-</span>
      <button id="renameBtn" class="btn-sm">改名</button>
    </div>
  </div>

  <!-- 单好友独立对话窗口 -->
  <div id="chatView" class="hidden">
    <div class="topbar">
      <button id="backBtn" class="btn-sm">← 好友</button>
      <div class="topbar-mid">
        <div id="chatTitle" class="topbar-title">-</div>
        <div id="chatSub" class="topbar-sub">🔒 WebRTC P2P 端到端加密直连（0 服务器流量）</div>
      </div>
      <button id="clearBtn" class="btn-sm">清空</button>
      <button id="discBtn" class="btn-sm">断开</button>
    </div>
    <div id="msgs"></div>
    <div id="progWrap" class="prog-wrap hidden"><div id="progBar" class="prog-bar"></div></div>
    <div id="statusText" class="status">就绪</div>
    <div class="composer">
      <button id="fileBtn" class="icon-btn">文件</button>
      <input id="fileInput" type="file" multiple class="hidden">
      <textarea id="textInput" rows="1" placeholder="输入要发送的文字…"></textarea>
      <button id="sendBtn" class="send-btn">发送</button>
    </div>
  </div>

</div>

<div id="qrModal" class="modal-bg hidden">
  <div class="modal-card">
    <div style="font-size:16px;font-weight:700">扫码 WebRTC P2P 直连</div>
    <div style="font-size:12px;color:#6b7280;margin-top:4px">另一台 iPhone / 安卓相机扫一扫即可自动建立内网 P2P 加密直连</div>
    <canvas id="qrCanvas" width="240" height="240"></canvas>
    <div id="qrHint" style="font-size:12px;color:#0f766e;word-break:break-all;margin-bottom:12px"></div>
    <button id="qrCloseBtn" class="add-btn" style="width:100%;padding:10px">关闭</button>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const SLAB_SIZE = 4 * 1024 * 1024;   // 每次从磁盘预读 4 MB，大幅减少异步磁盘 I/O
const HIGH_WATER = 6 * 1024 * 1024;  // 发送缓冲高水位 6 MB，保持 SCTP 窗口满载
const LOW_WATER = 3 * 1024 * 1024;   // 低水位 3 MB 提前续发，消除锯齿停顿
const DEFAULT_CHUNK = 64 * 1024;     // 兜底分片 64 KB
const MAX_CHUNK = 256 * 1024;        // 单消息上限 256 KB（跨浏览器 SCTP 安全上限）
const RTC_CFG = {
  iceServers: [
    { urls: "stun:stun.cloudflare.com:3478" },
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun.miwifi.com:3478" }
  ]
};

let me = { id: "", secret: "", pin: "", name: "" };
let es = null;
let peers = new Map(); // connId -> { connId, peerId, name, pc, dc, ready, msgs:[], unread:0, recv:null, route:"" }
let activeConnId = null;

function guessName() {
  const ua = navigator.userAgent || "";
  if (/iPhone/i.test(ua)) return "iPhone";
  if (/iPad/i.test(ua) || (/Macintosh/i.test(ua) && navigator.maxTouchPoints > 1)) return "iPad";
  if (/Macintosh/i.test(ua)) return "Mac";
  if (/Android/i.test(ua)) return "Android";
  if (/Windows/i.test(ua)) return "Windows";
  return "网页设备";
}
function fmtPin(p) { return p && p.length === 6 ? p.slice(0,3) + " " + p.slice(3) : "--- ---"; }
function human(n) {
  const u = ["B","KB","MB","GB","TB"]; let i = 0, v = Number(n) || 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${v.toFixed(0)} B` : `${v.toFixed(1)} ${u[i]}`;
}
function nowStr() {
  const d = new Date();
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map(x => String(x).padStart(2,"0")).join(":");
}
function toast(s) {
  const t = document.createElement("div"); t.className = "toast"; t.textContent = s;
  document.body.appendChild(t); setTimeout(() => t.remove(), 2200);
}
async function copyText(s) {
  try {
    if (window.AndroidApp && window.AndroidApp.copyText) {
      window.AndroidApp.copyText(String(s));
      toast("已复制");
      return;
    }
    if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(s);
    else {
      const ta = document.createElement("textarea"); ta.value = s;
      ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.focus(); ta.select();
      document.execCommand("copy"); ta.remove();
    }
    toast("已复制");
  } catch (e) { toast("请长按手动复制"); }
}

async function saveBlobInAndroid(blob, fileName) {
  const CH = 192 * 1024; // 192 KiB -> ~256 KiB Base64，安全避开 Android Binder 单次限制
  const id = window.AndroidApp.beginSave(fileName || "file");
  if (!id) { toast("无法创建保存文件"); return; }
  try {
    let off = 0;
    while (off < blob.size) {
      const buf = new Uint8Array(await blob.slice(off, off + CH).arrayBuffer());
      let bin = "";
      for (let i = 0; i < buf.length; i += 8192) {
        bin += String.fromCharCode.apply(null, buf.subarray(i, i + 8192));
      }
      if (!window.AndroidApp.appendSave(id, btoa(bin))) throw new Error("写入失败");
      off += buf.length;
    }
    const saved = window.AndroidApp.finishSave(id);
    toast(saved ? ("已保存：" + saved) : "保存失败");
  } catch (e) {
    window.AndroidApp.abortSave(id);
    toast("保存失败：" + e.message);
  }
}
function setStatus(s, pct = -1) {
  $("statusText").textContent = s;
  if (pct < 0) $("progWrap").classList.add("hidden");
  else { $("progWrap").classList.remove("hidden"); $("progBar").style.width = Math.min(100, Math.max(0, pct)) + "%"; }
}

// ---------------------------------------------------------------- 信令通道
async function api(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.assign({ id: me.id, secret: me.secret }, body || {}))
  });
  return r.json();
}

async function boot() {
  if (!window.isSecureContext && location.hostname !== "localhost" && location.hostname !== "127.0.0.1") {
    $("httpsWarn").classList.remove("hidden");
  }
  if (typeof RTCPeerConnection === "undefined") {
    $("sigStatus").textContent = "当前浏览器不支持 WebRTC";
    return;
  }
  me.name = localStorage.getItem("lf_p2p_name") || guessName();
  $("myNameLabel").textContent = "本机：" + me.name;
  const reg = await api("/api/register", { name: me.name });
  me.id = reg.id; me.secret = reg.secret; me.pin = reg.pin;
  $("myPin").textContent = fmtPin(me.pin);
  $("lanCount").textContent = "同内网在线：" + reg.lanOnline + " 台";
  renderFriends();
  openEventStream();
  // 支持扫码一键触发 WebRTC P2P 直连：#pair=123456
  const pm = (location.hash || "").match(/pair=(\d{6})/);
  if (pm) {
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}
    $("peerPinInput").value = pm[1];
    setTimeout(() => $("connectBtn").click(), 250);
  }
}

// ---- 零依赖标准 QR Code 编码器（ISO/IEC 18004, Byte 模式, EC Level M, V1~10）
const _QR_SPEC = [null,[10,1,16,0,0],[16,1,28,0,0],[26,1,44,0,0],[18,2,32,0,0],[24,2,43,0,0],[16,4,27,0,0],[18,4,31,0,0],[22,2,38,2,39],[22,3,36,2,37],[26,4,43,1,44]];
const _QR_AL = [null,[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]];
const _QEXP = new Uint8Array(512), _QLOG = new Uint8Array(256);
{ let v = 1; for (let i = 0; i < 255; i++) { _QEXP[i] = v; _QLOG[v] = i; v <<= 1; if (v & 0x100) v ^= 0x11d; } for (let i = 255; i < 512; i++) _QEXP[i] = _QEXP[i - 255]; }
const _qmul = (a, b) => (a && b) ? _QEXP[_QLOG[a] + _QLOG[b]] : 0;
function _qrs(data, deg) {
  let g = [1];
  for (let i = 0; i < deg; i++) {
    const n = new Array(g.length + 1).fill(0), rt = _QEXP[i];
    for (let j = 0; j < g.length; j++) { n[j] ^= g[j]; n[j + 1] ^= _qmul(g[j], rt); }
    g = n;
  }
  const r = new Array(deg).fill(0);
  for (const b of data) {
    const f = b ^ r.shift(); r.push(0);
    if (f) for (let i = 0; i < deg; i++) r[i] ^= _qmul(g[i + 1], f);
  }
  return r;
}
function encodeQrJs(text) {
  const pay = new TextEncoder().encode(text);
  let ver = 0;
  for (let v = 1; v <= 10; v++) {
    const s = _QR_SPEC[v];
    if (pay.length + (v <= 9 ? 2 : 3) <= s[1]*s[2] + s[3]*s[4]) { ver = v; break; }
  }
  if (!ver) throw new Error("URL 过长");
  const [ecLen, g1, d1, g2, d2] = _QR_SPEC[ver], cap = g1*d1 + g2*d2;
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  push(4, 4); push(pay.length, ver <= 9 ? 8 : 16);
  for (const b of pay) push(b, 8);
  push(0, Math.min(4, cap*8 - bits.length));
  while (bits.length & 7) bits.push(0);
  const db = [];
  for (let i = 0; i < bits.length; i += 8) { let v = 0; for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j]; db.push(v); }
  for (let p = 0; db.length < cap; p ^= 1) db.push(p ? 0x11 : 0xec);
  const blks = [], ecs = []; let off = 0;
  for (const [cnt, dl] of [[g1, d1], [g2, d2]]) for (let i = 0; i < cnt; i++) {
    const b = db.slice(off, off + dl); off += dl; blks.push(b); ecs.push(_qrs(b, ecLen));
  }
  const cw = [], maxD = Math.max(d1, d2);
  for (let i = 0; i < maxD; i++) for (const b of blks) if (i < b.length) cw.push(b[i]);
  for (let i = 0; i < ecLen; i++) for (const e of ecs) cw.push(e[i]);
  const sz = ver*4 + 17;
  const grid = Array.from({length: sz}, () => new Uint8Array(sz));
  const fn = Array.from({length: sz}, () => new Uint8Array(sz));
  const setF = (r, c, v) => { if (r >= 0 && r < sz && c >= 0 && c < sz) { grid[r][c] = v ? 1 : 0; fn[r][c] = 1; } };
  const finder = (r0, c0) => { for (let dr = -1; dr <= 7; dr++) for (let dc = -1; dc <= 7; dc++) {
    const d = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 && (dr===0||dr===6||dc===0||dc===6||(dr>=2&&dr<=4&&dc>=2&&dc<=4));
    setF(r0 + dr, c0 + dc, d);
  }};
  finder(0, 0); finder(0, sz - 7); finder(sz - 7, 0);
  for (let i = 8; i < sz - 8; i++) { setF(6, i, (i & 1) === 0); setF(i, 6, (i & 1) === 0); }
  for (const r0 of _QR_AL[ver]) for (const c0 of _QR_AL[ver]) {
    if ((r0===6&&c0===6)||(r0===6&&c0===sz-7)||(r0===sz-7&&c0===6)) continue;
    for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) setF(r0+dr, c0+dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
  }
  setF(sz - 8, 8, 1);
  for (let i = 0; i < 9; i++) if (i !== 6) { setF(8, i, 0); setF(i, 8, 0); }
  for (let i = 0; i < 8; i++) { setF(8, sz - 1 - i, 0); setF(sz - 1 - i, 8, 0); }
  if (ver >= 7) {
    let rem = ver; for (let i = 0; i < 12; i++) rem = (rem << 1) ^ (((rem >> 11) & 1) * 0x1f25);
    const vb = (ver << 12) | rem;
    for (let i = 0; i < 18; i++) { const b = (vb >> i) & 1, a = sz - 11 + (i % 3), c = (i / 3) | 0; setF(a, c, b); setF(c, a, b); }
  }
  let bp = 0, up = true, col = sz - 1;
  while (col > 0) {
    if (col === 6) col--;
    for (let st = 0; st < sz; st++) {
      const r = up ? sz - 1 - st : st;
      for (let dc = 0; dc >= -1; dc--) {
        const cc = col + dc;
        if (!fn[r][cc]) { grid[r][cc] = bp < cw.length*8 ? ((cw[bp >> 3] >> (7 - (bp & 7))) & 1) : 0; bp++; }
      }
    }
    col -= 2; up = !up;
  }
  const mfn = [(r,c)=>(r+c)%2===0,(r,c)=>r%2===0,(r,c)=>c%3===0,(r,c)=>(r+c)%3===0,(r,c)=>(((r>>1)+((c/3)|0))&1)===0,(r,c)=>((r*c)%2+(r*c)%3)===0,(r,c)=>(((r*c)%2+(r*c)%3)%2)===0,(r,c)=>(((r+c)%2+(r*c)%3)%2)===0];
  let best = null, bestSc = 1e9;
  for (let m = 0; m < 8; m++) {
    const g = grid.map((row, r) => row.map((v, c) => (!fn[r][c] && mfn[m](r, c)) ? (v ^ 1) : v));
    let rem = m; for (let i = 0; i < 10; i++) rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
    const fb = ((m << 10) | rem) ^ 0x5412;
    for (let i = 0; i < 6; i++) g[8][i] = (fb >> (14 - i)) & 1;
    g[8][7] = (fb >> 8) & 1; g[8][8] = (fb >> 7) & 1; g[7][8] = (fb >> 6) & 1;
    for (let i = 0; i < 6; i++) g[5 - i][8] = (fb >> (5 - i)) & 1;
    for (let i = 0; i < 8; i++) g[8][sz - 1 - i] = (fb >> i) & 1;
    for (let i = 0; i < 7; i++) g[sz - 1 - i][8] = (fb >> (14 - i)) & 1;
    let sc = 0, dark = 0;
    for (let r = 0; r < sz; r++) { let run = 1; dark += g[r][0]; for (let c = 1; c < sz; c++) { dark += g[r][c]; if (g[r][c]===g[r][c-1]) { run++; if (run===5) sc+=3; else if (run>5) sc++; } else run=1; } }
    for (let c = 0; c < sz; c++) { let run = 1; for (let r = 1; r < sz; r++) { if (g[r][c]===g[r-1][c]) { run++; if (run===5) sc+=3; else if (run>5) sc++; } else run=1; } }
    for (let r = 0; r < sz - 1; r++) for (let c = 0; c < sz - 1; c++) if (g[r][c]===g[r][c+1]&&g[r][c]===g[r+1][c]&&g[r][c]===g[r+1][c+1]) sc += 3;
    sc += Math.abs(((dark * 20) / (sz * sz) | 0) - 10) * 10;
    if (sc < bestSc) { bestSc = sc; best = g; }
  }
  return best;
}
function drawQrCanvas(canvas, text) {
  const m = encodeQrJs(text), n = m.length, q = 4, tot = n + q * 2;
  const cell = Math.max(4, Math.floor(240 / tot)), sz = tot * cell;
  canvas.width = sz; canvas.height = sz;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, sz, sz);
  ctx.fillStyle = "#000";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (m[r][c]) ctx.fillRect((c + q) * cell, (r + q) * cell, cell, cell);
}

function openEventStream() {
  if (es) es.close();
  es = new EventSource(`/api/events?id=${encodeURIComponent(me.id)}&secret=${encodeURIComponent(me.secret)}`);
  es.onopen = () => { $("sigStatus").textContent = "● 信令就绪（仅牵线，文件直传不耗流量）"; };
  es.onerror = () => { $("sigStatus").textContent = "○ 信令波动，重连中…"; };
  es.onmessage = async ev => {
    let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (m.type === "lan_count") {
      $("lanCount").textContent = "同内网在线：" + m.count + " 台";
    } else if (m.type === "incoming_pair") {
      toast(`${m.fromName} 正在与你建立 P2P 加密直连…`);
      createPeer(m.connId, m.fromId, m.fromName, false);
    } else if (m.type === "signal") {
      await handleSignal(m);
    }
  };
}

// ---------------------------------------------------------------- WebRTC P2P
function createPeer(connId, peerId, name, initiator) {
  const pc = new RTCPeerConnection(RTC_CFG);
  const p = { connId, peerId, name, pc, dc: null, ready: false, msgs: [], unread: 0, recv: null, route: "正在建立 P2P…" };
  peers.set(connId, p);

  pc.onicecandidate = e => {
    if (e.candidate) {
      api("/api/signal", { to: peerId, connId, data: { kind: "ice", candidate: e.candidate } }).catch(() => {});
    }
  };
  pc.onconnectionstatechange = () => {
    const st = pc.connectionState;
    if (st === "connected") {
      inspectRoute(p);
    } else if (st === "failed" || st === "disconnected" || st === "closed") {
      p.ready = false;
      p.route = "连接已断开";
      if (activeConnId === connId) $("chatSub").textContent = "✕ P2P 连接已断开，请重新输入验证码连接";
      renderFriends();
    }
  };

  if (initiator) {
    const dc = pc.createDataChannel("lanfast", { ordered: true });
    bindDataChannel(p, dc);
    pc.createOffer().then(o => pc.setLocalDescription(o)).then(() => {
      return api("/api/signal", { to: peerId, connId, data: { kind: "offer", sdp: pc.localDescription } });
    }).catch(err => toast("握手失败：" + err.message));
  } else {
    pc.ondatachannel = e => bindDataChannel(p, e.channel);
  }
  renderFriends();
  return p;
}

const SAS_EMOJIS = ["🐶","🐱","🦊","🐻","🐼","🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔","🐧","🐦","🦆","🦉","🦇","🐺","🐴","🦄","🐝","🦋","🐌","🐞","🐢","🐍","🐙","🐠","🐳","🐬","🦈","🌵","🌲","🌸","🌻","🍀","🍁","🍎","🍊","🍋","🍉","🍇","🍓","🍒","🍑","🍍","🥑","🍕","🍔","🍟","🍩","🍪","🎂","⚽","🏀","🎸","🎹","🚀","✈️","🚗","⛵","⭐","🔥"];

function extractDtlsFp(sdp) {
  const m = (sdp || "").match(/a=fingerprint:\S+\s+([0-9A-Fa-f:]+)/);
  return m ? m[1].toUpperCase() : "";
}
function dtlsSasEmoji(pc) {
  const f1 = extractDtlsFp(pc.localDescription && pc.localDescription.sdp);
  const f2 = extractDtlsFp(pc.remoteDescription && pc.remoteDescription.sdp);
  if (!f1 || !f2) return "";
  const pair = [f1, f2].sort().join("|");
  // 双哈希生成 4 个确定性 Emoji（无需 crypto.subtle，两端独立从 DTLS 证书指纹导出）
  let h1 = 0x811c9dc5, h2 = 0x243f6a88;
  for (let i = 0; i < pair.length; i++) {
    const c = pair.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (c + i), 0x85ebca6b) >>> 0;
  }
  const bytes = [h1 & 63, (h1 >>> 8) & 63, h2 & 63, (h2 >>> 8) & 63];
  return bytes.map(i => SAS_EMOJIS[i]).join("");
}

async function inspectRoute(p) {
  try {
    const stats = await p.pc.getStats();
    let pair = null;
    stats.forEach(s => {
      if (s.type === "transport" && s.selectedCandidatePairId) {
        const cand = stats.get(s.selectedCandidatePairId);
        if (cand) pair = cand;
      }
    });
    if (!pair) {
      stats.forEach(s => {
        if (s.type === "candidate-pair" && s.state === "succeeded" && (s.nominated || s.selected)) {
          pair = s;
        }
      });
    }
    if (!pair) {
      stats.forEach(s => {
        if (s.type === "candidate-pair" && s.state === "succeeded") pair = s;
      });
    }
    const lc = pair && stats.get(pair.localCandidateId);
    const rc = pair && stats.get(pair.remoteCandidateId);
    const localType = (lc && lc.candidateType) || "";
    const remoteType = (rc && rc.candidateType) || "";
    const sas = dtlsSasEmoji(p.pc);
    const sasTag = sas ? `安全码 ${sas} · ` : "";
    let routeLabel = "WebRTC P2P 直连";
    if (localType === "host" && (!remoteType || remoteType === "host")) {
      routeLabel = "内网直连 (host)";
    } else if (localType === "relay" || remoteType === "relay") {
      routeLabel = "中继转发 (relay)";
    } else if (localType === "srflx" || remoteType === "srflx") {
      routeLabel = `公网回环/穿透 (${localType || "?"}↔${remoteType || "?"})`;
    } else if (localType === "prflx" || remoteType === "prflx") {
      routeLabel = `对等直连 (${localType || "?"}↔${remoteType || "?"})`;
    } else if (localType) {
      routeLabel = `P2P 直连 (${localType})`;
    }
    p.route = `🔒 ${sasTag}${routeLabel}`;
    if (activeConnId === p.connId) $("chatSub").textContent = p.route;
  } catch (e) {}
}

function getChunkSize(pc) {
  const maxMsg = pc && pc.sctp && Number(pc.sctp.maxMessageSize);
  if (maxMsg && Number.isFinite(maxMsg) && maxMsg >= 16 * 1024) {
    return Math.min(MAX_CHUNK, Math.floor(maxMsg));
  }
  return DEFAULT_CHUNK;
}

function bindDataChannel(p, dc) {
  p.dc = dc;
  dc.binaryType = "arraybuffer";
  dc.bufferedAmountLowThreshold = LOW_WATER;
  dc.onopen = () => {
    p.ready = true;
    p.route = "🔒 WebRTC P2P 端到端加密直连（0 服务器流量）";
    inspectRoute(p);
    setTimeout(() => { if (p.ready) inspectRoute(p); }, 1200);
    toast("🔒 已与 " + p.name + " 建立 P2P 直连！");
    renderFriends();
    if (!activeConnId) openChat(p.connId);
    else if (activeConnId === p.connId) $("chatSub").textContent = p.route;
  };
  dc.onclose = () => {
    p.ready = false;
    if (activeConnId === p.connId) $("chatSub").textContent = "✕ 对方已断开连接";
    renderFriends();
  };
  dc.onmessage = e => onDataMessage(p, e.data);
}

async function handleSignal(m) {
  const p = peers.get(m.connId);
  if (!p) return;
  const d = m.data;
  try {
    if (d.kind === "offer") {
      await p.pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
      const ans = await p.pc.createAnswer();
      await p.pc.setLocalDescription(ans);
      await api("/api/signal", { to: p.peerId, connId: p.connId, data: { kind: "answer", sdp: p.pc.localDescription } });
    } else if (d.kind === "answer") {
      await p.pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
    } else if (d.kind === "ice" && d.candidate) {
      await p.pc.addIceCandidate(new RTCIceCandidate(d.candidate));
    }
  } catch (e) {}
}

// ---------------------------------------------------------------- 收到 P2P 消息/文件
function onDataMessage(p, data) {
  if (typeof data === "string") {
    let m; try { m = JSON.parse(data); } catch (e) { return; }
    if (m.type === "text") {
      pushMsg(p, { id: Math.random().toString(36).slice(2), dir: "in", kind: "text", text: m.text, time: nowStr() });
      if (activeConnId === p.connId) setStatus("收到来自 " + p.name + " 的加密文字");
    } else if (m.type === "file_meta") {
      p.recv = { name: m.name, size: m.size, mime: m.mime || "application/octet-stream", chunks: [], got: 0, t0: Date.now(), lastUi: 0 };
      if (activeConnId === p.connId) setStatus(`正在接收 ${m.name}…`, 0);
    } else if (m.type === "file_end" && p.recv) {
      const r = p.recv; p.recv = null;
      const blob = new Blob(r.chunks, { type: r.mime });
      const url = URL.createObjectURL(blob);
      const isImg = /^image\//i.test(r.mime) || /\.(png|jpe?g|gif|webp|bmp)$/i.test(r.name);
      pushMsg(p, { id: Math.random().toString(36).slice(2), dir: "in", kind: "file", fileName: r.name, size: r.size, url, blob, isImg, time: nowStr() });
      if (activeConnId === p.connId) {
        const secs = Math.max((Date.now() - r.t0) / 1000, 0.05);
        setStatus(`已接收 ${r.name}（${human(r.size)}，均速 ${human(r.size / secs)}/s）`, 100);
        setTimeout(() => setStatus("就绪", -1), 1500);
      }
    }
  } else if (data instanceof ArrayBuffer && p.recv) {
    const r = p.recv;
    r.chunks.push(data);
    r.got += data.byteLength;
    if (activeConnId === p.connId) {
      const now = Date.now();
      if (now - r.lastUi > 120 || r.got >= r.size) {
        r.lastUi = now;
        const pct = r.size > 0 ? Math.round(r.got * 100 / r.size) : 100;
        const spd = r.got / Math.max((now - r.t0) / 1000, 0.05);
        setStatus(`接收 ${r.name}  ${human(r.got)}/${human(r.size)}  ${human(spd)}/s`, pct);
      }
    }
  }
}

// ---------------------------------------------------------------- 发送文字 / 流控发送大文件
function sendText() {
  const p = peers.get(activeConnId);
  if (!p || !p.ready || !p.dc) { toast("连接尚未就绪或已断开"); return; }
  const el = $("textInput");
  const text = el.value;
  if (!text.trim()) return;
  el.value = ""; el.style.height = "auto";
  p.dc.send(JSON.stringify({ type: "text", text }));
  pushMsg(p, { id: Math.random().toString(36).slice(2), dir: "out", kind: "text", text, time: nowStr() });
  setStatus("已通过 P2P 直连发送");
}

function waitBufferLow(dc) {
  return new Promise((resolve, reject) => {
    if (dc.readyState !== "open") { reject(new Error("P2P 通道中断")); return; }
    if (dc.bufferedAmount <= HIGH_WATER) { resolve(); return; }
    let timer = null;
    const cleanup = () => {
      dc.removeEventListener("bufferedamountlow", onLow);
      dc.removeEventListener("close", onClose);
      dc.removeEventListener("error", onClose);
      if (timer) clearInterval(timer);
    };
    const onLow = () => { cleanup(); resolve(); };
    const onClose = () => { cleanup(); reject(new Error("P2P 通道中断")); };
    dc.addEventListener("bufferedamountlow", onLow);
    dc.addEventListener("close", onClose);
    dc.addEventListener("error", onClose);
    timer = setInterval(() => {
      if (dc.readyState !== "open") onClose();
      else if (dc.bufferedAmount <= LOW_WATER) onLow();
    }, 100);
  });
}

async function sendFiles(files) {
  const p = peers.get(activeConnId);
  if (!p || !p.ready || !p.dc) { toast("连接尚未就绪或已断开"); return; }
  const arr = Array.from(files || []);
  const chunkSize = getChunkSize(p.pc);
  for (let i = 0; i < arr.length; i++) {
    const f = arr[i];
    const t0 = Date.now();
    try {
      p.dc.send(JSON.stringify({ type: "file_meta", name: f.name, size: f.size, mime: f.type || "application/octet-stream" }));
      let offset = 0, lastUi = 0;
      while (offset < f.size) {
        const slabEnd = Math.min(f.size, offset + SLAB_SIZE);
        const slab = await f.slice(offset, slabEnd).arrayBuffer();
        let pos = 0;
        while (pos < slab.byteLength) {
          if (p.dc.bufferedAmount > HIGH_WATER) {
            await waitBufferLow(p.dc);
          }
          if (p.dc.readyState !== "open") throw new Error("P2P 通道中断");
          const len = Math.min(chunkSize, slab.byteLength - pos);
          p.dc.send(new Uint8Array(slab, pos, len));
          pos += len;
          offset += len;
          const now = Date.now();
          if (now - lastUi > 120 || offset >= f.size) {
            lastUi = now;
            const pct = Math.round(offset * 100 / Math.max(f.size, 1));
            const spd = offset / Math.max((now - t0) / 1000, 0.05);
            setStatus(`发送 [${i+1}/${arr.length}] ${f.name}  ${human(offset)}/${human(f.size)}  ${human(spd)}/s`, pct);
          }
        }
      }
      if (p.dc.bufferedAmount > HIGH_WATER) await waitBufferLow(p.dc);
      p.dc.send(JSON.stringify({ type: "file_end" }));
      pushMsg(p, { id: Math.random().toString(36).slice(2), dir: "out", kind: "file", fileName: f.name, size: f.size, time: nowStr() });
      const secs = Math.max((Date.now() - t0) / 1000, 0.05);
      setStatus(`已发送 ${f.name}，平均 ${human(f.size / secs)}/s`, 100);
    } catch (e) {
      pushMsg(p, { id: Math.random().toString(36).slice(2), dir: "err", kind: "text", text: `发送 ${f.name} 失败：${e.message}`, time: nowStr() });
      setStatus("发送失败：" + e.message, -1);
      break;
    }
  }
  setTimeout(() => setStatus("就绪", -1), 1500);
}

// ---------------------------------------------------------------- UI 渲染与删除消息
function pushMsg(p, rec) {
  p.msgs.push(rec);
  if (activeConnId === p.connId) {
    appendMsgDom(p, rec);
  } else if (rec.dir === "in") {
    p.unread++;
  }
  renderFriends();
}

function renderFriends() {
  const box = $("friendList");
  box.innerHTML = "";
  const list = Array.from(peers.values());
  if (!list.length) {
    box.innerHTML = `<div class="empty">还没有连接的 P2P 好友<br><br>让另一台设备（iPhone / 安卓 / 电脑）也打开这个网页，<br>在上方输入对方的 6 位验证码即可零流量内网直连！</div>`;
    return;
  }
  for (const p of list) {
    const item = document.createElement("div");
    item.className = "friend-item";
    item.onclick = () => openChat(p.connId);
    const left = document.createElement("div");
    const nm = document.createElement("div");
    nm.className = "friend-name";
    nm.textContent = (p.ready ? "🟢 " : "🟡 ") + p.name;
    const prev = document.createElement("div");
    prev.className = "friend-preview";
    const last = p.msgs[p.msgs.length - 1];
    prev.textContent = last
      ? ((last.dir === "in" ? "对方：" : "我：") + (last.kind === "file" ? "📄 " + last.fileName : last.text))
      : (p.ready ? "P2P 直连已就绪，点击进入对话" : "正在建立 P2P 直连…");
    left.appendChild(nm); left.appendChild(prev);
    item.appendChild(left);
    if (p.unread > 0) {
      const b = document.createElement("div"); b.className = "badge"; b.textContent = p.unread;
      item.appendChild(b);
    }
    box.appendChild(item);
  }
}

function openChat(connId) {
  const p = peers.get(connId);
  if (!p) return;
  activeConnId = connId;
  p.unread = 0;
  $("homeView").classList.add("hidden");
  $("chatView").classList.remove("hidden");
  $("chatTitle").textContent = p.name;
  $("chatSub").textContent = p.route;
  $("msgs").innerHTML = "";
  for (const rec of p.msgs) appendMsgDom(p, rec);
  renderFriends();
}

function closeChat() {
  activeConnId = null;
  $("chatView").classList.add("hidden");
  $("homeView").classList.remove("hidden");
  renderFriends();
}

function deleteMsg(p, rec, rowEl) {
  if (rec.url) URL.revokeObjectURL(rec.url);
  rec.blob = null;
  const idx = p.msgs.indexOf(rec);
  if (idx >= 0) p.msgs.splice(idx, 1);
  rowEl.remove();
  renderFriends();
}

function appendMsgDom(p, rec) {
  const box = $("msgs");
  const row = document.createElement("div");
  row.className = "row " + rec.dir;
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = (rec.dir === "in" ? "← " + p.name : (rec.dir === "out" ? "→ 我" : "✕ 错误")) + " · " + rec.time;
  row.appendChild(meta);

  const bub = document.createElement("div");
  bub.className = "bubble";
  if (rec.kind === "file") {
    const fc = document.createElement("div"); fc.className = "file-card";
    const fn = document.createElement("div"); fn.className = "file-name"; fn.textContent = "📄 " + rec.fileName;
    const fm = document.createElement("div"); fm.className = "file-meta"; fm.textContent = human(rec.size);
    fc.appendChild(fn); fc.appendChild(fm);
    if (rec.url && rec.isImg) {
      const img = document.createElement("img"); img.className = "file-preview"; img.src = rec.url;
      fc.appendChild(img);
    }
    if (rec.url) {
      const a = document.createElement("a"); a.className = "dl-btn"; a.href = rec.url; a.download = rec.fileName;
      a.textContent = "保存文件";
      if (window.AndroidApp && window.AndroidApp.beginSave && rec.blob) {
        a.onclick = ev => { ev.preventDefault(); saveBlobInAndroid(rec.blob, rec.fileName); };
      }
      fc.appendChild(a);
    }
    const ops = document.createElement("div"); ops.className = "ops";
    const del = document.createElement("span"); del.className = "op-del"; del.textContent = "删除";
    del.onclick = () => deleteMsg(p, rec, row);
    ops.appendChild(del); fc.appendChild(ops);
    bub.appendChild(fc);
  } else {
    const sp = document.createElement("div"); sp.textContent = rec.text;
    bub.appendChild(sp);
    const ops = document.createElement("div"); ops.className = "ops";
    if (rec.dir !== "err") {
      const cp = document.createElement("span"); cp.className = "op-copy"; cp.textContent = "复制";
      cp.onclick = () => copyText(rec.text);
      ops.appendChild(cp);
    }
    const del = document.createElement("span"); del.className = "op-del"; del.textContent = "删除";
    del.onclick = () => deleteMsg(p, rec, row);
    ops.appendChild(del);
    bub.appendChild(ops);
  }
  row.appendChild(bub);
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
}

// ---------------------------------------------------------------- 事件绑定
$("qrBtn").onclick = () => {
  const url = location.origin + location.pathname + "#pair=" + me.pin;
  drawQrCanvas($("qrCanvas"), url);
  $("qrHint").textContent = location.origin + location.pathname + "  （已内嵌本机 6 位码）";
  $("qrModal").classList.remove("hidden");
};
$("qrCloseBtn").onclick = () => $("qrModal").classList.add("hidden");
$("qrModal").onclick = e => { if (e.target === $("qrModal")) $("qrModal").classList.add("hidden"); };
$("myPin").onclick = $("copyPinBtn").onclick = () => copyText(me.pin);
$("refreshPinBtn").onclick = async () => {
  const r = await api("/api/refresh_pin");
  if (r.ok) { me.pin = r.pin; $("myPin").textContent = fmtPin(me.pin); toast("验证码已刷新为 " + me.pin); }
};
$("renameBtn").onclick = async () => {
  const n = prompt("修改本机显示名称：", me.name);
  if (n && n.trim()) {
    me.name = n.trim().slice(0, 32);
    localStorage.setItem("lf_p2p_name", me.name);
    $("myNameLabel").textContent = "本机：" + me.name;
    await api("/api/rename", { name: me.name });
  }
};
$("connectBtn").onclick = async () => {
  const pin = $("peerPinInput").value.replace(/\D/g, "");
  if (pin.length !== 6) { toast("请输入完整的 6 位数字验证码"); return; }
  $("connectBtn").disabled = true; $("connectBtn").textContent = "连接中…";
  try {
    const r = await api("/api/pair", { pin });
    if (!r.ok) {
      toast(r.error || "连接失败");
    } else {
      $("peerPinInput").value = "";
      const p = createPeer(r.connId, r.peerId, r.peerName, true);
      openChat(p.connId);
      setTimeout(() => {
        if (!p.ready && p.pc.connectionState !== "closed") {
          toast("P2P 握手较慢：请确认两端连在同一 WiFi（iPhone 建议使用 HTTPS 域名）");
        }
      }, 8000);
    }
  } catch (e) { toast("请求失败：" + e.message); }
  finally { $("connectBtn").disabled = false; $("connectBtn").textContent = "直连加好友"; }
};
$("peerPinInput").addEventListener("keydown", e => { if (e.key === "Enter") $("connectBtn").click(); });
$("backBtn").onclick = closeChat;
$("clearBtn").onclick = () => {
  const p = peers.get(activeConnId);
  if (!p) return;
  for (const r of p.msgs) if (r.url) URL.revokeObjectURL(r.url);
  p.msgs = [];
  $("msgs").innerHTML = "";
  renderFriends();
  toast("已清空当前对话");
};
$("discBtn").onclick = () => {
  const p = peers.get(activeConnId);
  if (!p) return;
  for (const r of p.msgs) if (r.url) URL.revokeObjectURL(r.url);
  try { p.pc.close(); } catch (e) {}
  peers.delete(p.connId);
  closeChat();
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
$("fileInput").onchange = e => { sendFiles(e.target.files); e.target.value = ""; };

document.addEventListener("dragover", e => {
  if (!activeConnId) return;
  e.preventDefault(); $("chatView").classList.add("drag-over");
});
document.addEventListener("dragleave", e => {
  if (e.target === document.documentElement || e.target === document.body) $("chatView").classList.remove("drag-over");
});
document.addEventListener("drop", e => {
  $("chatView").classList.remove("drag-over");
  if (!activeConnId) return;
  e.preventDefault();
  if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) sendFiles(e.dataTransfer.files);
});

boot();
</script>
</body>
</html>
"""


class Peer:
    def __init__(self, cid, secret, pin, name, ip):
        self.id = cid
        self.secret = secret
        self.pin = pin
        self.name = name
        self.ip = ip
        self.queue = queue.Queue()
        self.last_seen = time.time()


class SignalingHub:
    def __init__(self):
        self.lock = threading.Lock()
        self.peers = {}       # id -> Peer
        self.fail_state = {}  # ip -> (fails, lock_until)

    def _gen_pin(self):
        used = {p.pin for p in self.peers.values()}
        for _ in range(32):
            pin = f"{secrets.randbelow(1_000_000):06d}"
            if pin not in used:
                return pin
        return f"{secrets.randbelow(1_000_000):06d}"

    def _broadcast_lan_count(self, ip):
        same = [p for p in self.peers.values() if p.ip == ip]
        cnt = len(same)
        for p in same:
            p.queue.put({"type": "lan_count", "count": cnt})

    def register(self, name, ip):
        with self.lock:
            cid = secrets.token_hex(8)
            secret = secrets.token_hex(16)
            pin = self._gen_pin()
            p = Peer(cid, secret, pin, (name or "网页设备")[:32], ip)
            self.peers[cid] = p
            lan_cnt = sum(1 for x in self.peers.values() if x.ip == ip)
            self._broadcast_lan_count(ip)
        log.info("JOIN   %s (%s)  online=%d", p.name, ip, len(self.peers))
        return p, lan_cnt

    def auth(self, cid, secret):
        with self.lock:
            p = self.peers.get(cid)
            if p and hmac.compare_digest(p.secret, str(secret or "")):
                p.last_seen = time.time()
                return p
            return None

    def remove(self, cid):
        with self.lock:
            p = self.peers.pop(cid, None)
            if p:
                self._broadcast_lan_count(p.ip)
                log.info("LEAVE  %s (%s)  online=%d", p.name, p.ip, len(self.peers))

    def refresh_pin(self, p):
        with self.lock:
            p.pin = self._gen_pin()
            return p.pin

    def pair_by_pin(self, initiator: Peer, pin: str):
        now = time.time()
        pin = (pin or "").strip()
        with self.lock:
            fails, lock_until = self.fail_state.get(initiator.ip, (0, 0.0))
            if now < lock_until:
                wait = int(lock_until - now) + 1
                return False, {"ok": False, "error": f"验证码尝试次数过多，请 {wait} 秒后再试"}
            target = None
            for cand in self.peers.values():
                if cand.id != initiator.id and hmac.compare_digest(cand.pin, pin):
                    target = cand
                    break
            if target is None:
                fails += 1
                if fails >= MAX_PIN_FAILS:
                    self.fail_state[initiator.ip] = (0, now + PIN_LOCK_SECONDS)
                    return False, {"ok": False, "error": f"验证码错误次数过多，请 {PIN_LOCK_SECONDS} 秒后再试"}
                self.fail_state[initiator.ip] = (fails, 0.0)
                return False, {"ok": False, "error": "未找到该 6 位验证码对应的在线网页设备"}
            self.fail_state.pop(initiator.ip, None)
            conn_id = secrets.token_hex(8)
            target.queue.put({
                "type": "incoming_pair", "connId": conn_id,
                "fromId": initiator.id, "fromName": initiator.name,
            })
            return True, {"ok": True, "connId": conn_id, "peerId": target.id, "peerName": target.name}

    def forward_signal(self, sender: Peer, to_id: str, conn_id: str, data: dict):
        with self.lock:
            target = self.peers.get(to_id)
        if not target:
            return False
        target.queue.put({"type": "signal", "fromId": sender.id, "connId": conn_id, "data": data})
        return True

    def reap_loop(self):
        while True:
            time.sleep(20)
            now = time.time()
            with self.lock:
                dead = [cid for cid, p in self.peers.items() if now - p.last_seen > CLIENT_TIMEOUT]
                ips = set()
                for cid in dead:
                    ips.add(self.peers[cid].ip)
                    del self.peers[cid]
                for ip in ips:
                    self._broadcast_lan_count(ip)


def make_handler(hub: SignalingHub):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def _client_ip(self):
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
            return self.headers.get("X-Real-IP", "") or self.client_address[0]

        def _send_json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            cl = int(self.headers.get("Content-Length", "0"))
            if cl <= 0 or cl > 256 * 1024:
                return {}
            return json.loads(self.rfile.read(cl).decode("utf-8"))

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path in ("/", "/index.html"):
                body = HTML_PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/api/events":
                qs = parse_qs(parsed.query)
                cid = (qs.get("id") or [""])[0]
                sec = (qs.get("secret") or [""])[0]
                p = hub.auth(cid, sec)
                if not p:
                    self._send_json({"ok": False, "error": "unauthorized"}, 401)
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
                    while True:
                        p.last_seen = time.time()
                        try:
                            item = p.queue.get(timeout=20)
                            data = json.dumps(item, ensure_ascii=False).encode("utf-8")
                            self.wfile.write(b"data: " + data + b"\n\n")
                            self.wfile.flush()
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                except OSError:
                    pass
                finally:
                    hub.remove(cid)
                return

            self.send_error(404)

        def do_POST(self):
            path = urlparse(self.path).path
            try:
                body = self._read_json()
            except ValueError:
                self._send_json({"ok": False, "error": "bad json"}, 400)
                return

            if path == "/api/register":
                p, lan_cnt = hub.register(str(body.get("name", "")), self._client_ip())
                self._send_json({"ok": True, "id": p.id, "secret": p.secret, "pin": p.pin, "lanOnline": lan_cnt})
                return

            p = hub.auth(body.get("id", ""), body.get("secret", ""))
            if not p:
                self._send_json({"ok": False, "error": "会话已过期，请刷新页面"}, 401)
                return

            if path == "/api/refresh_pin":
                self._send_json({"ok": True, "pin": hub.refresh_pin(p)})
            elif path == "/api/rename":
                p.name = str(body.get("name", p.name))[:32]
                self._send_json({"ok": True})
            elif path == "/api/pair":
                ok, res = hub.pair_by_pin(p, str(body.get("pin", "")))
                self._send_json(res, 200 if ok else 404)
            elif path == "/api/signal":
                ok = hub.forward_signal(p, str(body.get("to", "")), str(body.get("connId", "")), body.get("data") or {})
                self._send_json({"ok": ok})
            else:
                self.send_error(404)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="LanFast 纯网页 WebRTC P2P 信令服务")
    ap.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    ap.add_argument("--port", type=int, default=53534, help="监听端口（默认 53534）")
    ap.add_argument("--cert", default="", help="可选 HTTPS 证书文件路径（PEM）")
    ap.add_argument("--key", default="", help="可选 HTTPS 私钥文件路径（PEM）")
    args = ap.parse_args()

    hub = SignalingHub()
    threading.Thread(target=hub.reap_loop, daemon=True).start()
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(hub))
    srv.daemon_threads = True
    scheme = "http"
    if args.cert and args.key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        scheme = "https"
    log.info("LanFast WebRTC P2P 网页服务已启动：%s://%s:%d", scheme, args.host, args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log.info("服务已停止")


if __name__ == "__main__":
    main()
