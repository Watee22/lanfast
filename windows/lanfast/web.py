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

from . import crypto

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
let state = { token: "", clientId: "", peerName: "", sas: "", es: null };

// ---- 纯 JS SHA-256 / HMAC-SHA256 / RFC 9382 SPAKE2-P256（不依赖 crypto.subtle，HTTP 下也能零明文校验 6 位码）
const _K256 = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];
function sha256Bytes(msg) {
  const l = msg.length, bitLen = l * 8;
  const padLen = ((l + 9 + 63) & ~63);
  const b = new Uint8Array(padLen); b.set(msg); b[l] = 0x80;
  const dv = new DataView(b.buffer);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(padLen - 4, bitLen >>> 0, false);
  let H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let o = 0; o < padLen; o += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >>> 3);
      const s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >>> 10);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) >>> 0;
    }
    let [a,b0,c,d,e,f,g,h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ ((~e) & g);
      const t1 = (h + S1 + ch + _K256[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b0) ^ (a & c) ^ (b0 & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b0; b0 = a; a = (t1 + t2) >>> 0;
    }
    H = [(H[0]+a)>>>0,(H[1]+b0)>>>0,(H[2]+c)>>>0,(H[3]+d)>>>0,(H[4]+e)>>>0,(H[5]+f)>>>0,(H[6]+g)>>>0,(H[7]+h)>>>0];
  }
  const out = new Uint8Array(32), od = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) od.setUint32(i * 4, H[i], false);
  return out;
}
function concatBytes(...arrs) {
  let n = 0; for (const a of arrs) n += a.length;
  const r = new Uint8Array(n); let o = 0;
  for (const a of arrs) { r.set(a, o); o += a.length; }
  return r;
}
function utf8(s) { return new TextEncoder().encode(s); }
function toHex(b) { return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join(""); }
function b64e(b) { let s = ""; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
function b64d(s) { const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; }
function hmacSha256Hex(key, msg) {
  let k = key.length > 64 ? sha256Bytes(key) : key;
  const pad = new Uint8Array(64); pad.set(k);
  const ip = new Uint8Array(64), op = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ip[i] = pad[i] ^ 0x36; op[i] = pad[i] ^ 0x5c; }
  return toHex(sha256Bytes(concatBytes(op, sha256Bytes(concatBytes(ip, msg)))));
}
function u32be(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, false); return b; }
function bigTo32(x) {
  const b = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}
function bytesToBig(b) { let v = 0n; for (const x of b) v = (v << 8n) | BigInt(x); return v; }

const _P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const _A = _P - 3n;
const _B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const _N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const _G = [0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n];
const _M = [0x886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12fn, 0x5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20n];
const _NPT = [0xd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49n, 0x07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7n];
const SAS_EMOJIS = ["🐶","🐱","🦊","🐻","🐼","🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔","🐧","🐦","🦆","🦉","🦇","🐺","🐴","🦄","🐝","🦋","🐌","🐞","🐢","🐍","🐙","🐠","🐳","🐬","🦈","🌵","🌲","🌸","🌻","🍀","🍁","🍎","🍊","🍋","🍉","🍇","🍓","🍒","🍑","🍍","🥑","🍕","🍔","🍟","🍩","🍪","🎂","⚽","🏀","🎸","🎹","🚀","✈️","🚗","⛵","⭐","🔥"];

function mod(x, m = _P) { const r = x % m; return r >= 0n ? r : r + m; }
function modInv(a, m = _P) {
  let t = 0n, nt = 1n, r = m, nr = mod(a, m);
  while (nr !== 0n) { const q = r / nr; [t, nt] = [nt, t - q * nt]; [r, nr] = [nr, r - q * nr]; }
  return mod(t, m);
}
function ptAdd(p1, p2) {
  if (!p1) return p2; if (!p2) return p1;
  const [x1, y1] = p1, [x2, y2] = p2;
  let lam;
  if (x1 === x2) {
    if (mod(y1 + y2) === 0n) return null;
    lam = mod((3n * x1 * x1 + _A) * modInv(2n * y1));
  } else {
    lam = mod((y2 - y1) * modInv(x2 - x1));
  }
  const x3 = mod(lam * lam - x1 - x2);
  return [x3, mod(lam * (x1 - x3) - y1)];
}
function ptSub(p1, p2) { return ptAdd(p1, p2 ? [p2[0], mod(-p2[1])] : null); }
function ptMul(k, pt) {
  let r = null, add = pt, v = mod(k, _N);
  while (v > 0n) { if (v & 1n) r = ptAdd(r, add); add = ptAdd(add, add); v >>= 1n; }
  return r;
}
function encPt(pt) { return concatBytes(new Uint8Array([4]), bigTo32(pt[0]), bigTo32(pt[1])); }
function decPt(raw) {
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("bad point");
  const x = bytesToBig(raw.slice(1, 33)), y = bytesToBig(raw.slice(33, 65));
  if (mod(y * y - (x * x * x + _A * x + _B)) !== 0n) throw new Error("not on curve");
  return [x, y];
}
function randScalar() {
  const b = new Uint8Array(32); crypto.getRandomValues(b);
  return (bytesToBig(b) % (_N - 1n)) + 1n;
}
function spakeStart(clientId, pin) {
  const w = (bytesToBig(sha256Bytes(utf8("lanfast-spake2-w|" + pin))) % (_N - 1n)) + 1n;
  const x = randScalar();
  const pARaw = encPt(ptAdd(ptMul(x, _G), ptMul(w, _M)));
  return {
    pAB64: b64e(pARaw),
    finish(serverId, pBB64) {
      const pBRaw = b64d(pBB64);
      const K = ptMul(x, ptSub(decPt(pBRaw), ptMul(w, _NPT)));
      const aB = utf8(clientId), bB = utf8(serverId);
      const tt = sha256Bytes(concatBytes(u32be(aB.length), aB, u32be(bB.length), bB, pARaw, pBRaw, encPt(K), bigTo32(w)));
      const confA = hmacSha256Hex(tt, utf8("confirm-A"));
      const confB = hmacSha256Hex(tt, utf8("confirm-B"));
      const sd = sha256Bytes(concatBytes(tt, utf8("sas-emoji")));
      const sas = [0,1,2,3].map(i => SAS_EMOJIS[sd[i] & 63]).join("");
      return { confA, confB, sas };
    }
  };
}

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
    const fops = document.createElement("div");
    fops.style.display = "flex"; fops.style.gap = "12px";
    if (url) {
      const alt = document.createElement("div");
      alt.className = "copy-tag";
      alt.textContent = "兼容下载";
      alt.onclick = () => compatDownload(url, fileName);
      fops.appendChild(alt);
    }
    const del = document.createElement("div");
    del.className = "copy-tag";
    del.style.color = "#ef4444";
    del.textContent = "删除";
    del.onclick = () => row.remove();
    fops.appendChild(del);
    fc.appendChild(fops);
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
        enterChat(s.token, s.clientId, cd.name || s.peerName, s.sas || "");
        return;
      }
    } catch (e) {}
    sessionStorage.removeItem("lf_session");
  }
  // 支持扫码一键直连：#pin=123456（URL Fragment 不经网络发送，读完立即从地址栏抹除再走 SPAKE2 握手）
  const hm = (location.hash || "").match(/pin=(\d{6})/);
  if (hm) {
    try { history.replaceState(null, "", location.pathname + location.search); } catch (e) {}
    $("pinInput").value = hm[1];
    doLogin();
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
  $("loginBtn").textContent = "SPAKE2 安全校验中…";
  try {
    const cid = "web-" + toHex(crypto.getRandomValues(new Uint8Array(8)));
    const sp = spakeStart(cid, pin);
    const r1 = await fetch("/api/spake/hello", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: cid, name, pA: sp.pAB64 })
    });
    const d1 = await r1.json();
    if (!d1.ok) { $("loginErr").textContent = d1.error || "握手失败"; return; }
    const { confA, confB, sas } = sp.finish(d1.serverId, d1.pB);
    const r2 = await fetch("/api/spake/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hsId: d1.hsId, confA })
    });
    const d2 = await r2.json();
    if (!d2.ok) {
      $("loginErr").textContent = d2.error || "验证码错误";
    } else if (d2.confB !== confB) {
      $("loginErr").textContent = "双向校验失败（疑似中间人攻击）";
    } else {
      $("pinInput").value = "";
      sessionStorage.setItem("lf_session", JSON.stringify({ token: d2.token, clientId: cid, peerName: d2.name, sas }));
      enterChat(d2.token, cid, d2.name, sas);
    }
  } catch (e) {
    $("loginErr").textContent = "连接失败：" + e.message;
  } finally {
    $("loginBtn").disabled = false;
    $("loginBtn").textContent = "验证并连接电脑";
  }
}

function enterChat(token, clientId, peerName, sas) {
  state.token = token; state.clientId = clientId; state.peerName = peerName; state.sas = sas || "";
  $("peerTitle").textContent = "✓ 已连接：" + peerName + (sas ? "  ·  " + sas : "");
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

async function compatDownload(url, fileName) {
  try {
    setStatus("正在兼容模式下载 " + fileName + "…", 0);
    const r = await fetch(url);
    if (!r.ok) throw new Error("HTTP " + r.status);
    const total = Number(r.headers.get("Content-Length") || 0);
    let blob;
    if (r.body && r.body.getReader) {
      const reader = r.body.getReader();
      const chunks = [];
      let got = 0, lastUi = 0;
      const t0 = Date.now();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        got += value.byteLength;
        const now = Date.now();
        if (now - lastUi > 120) {
          lastUi = now;
          const pct = total > 0 ? Math.round(got * 100 / total) : 50;
          const spd = got / Math.max((now - t0) / 1000, 0.05);
          setStatus(`兼容下载 ${fileName}  ${human(got)}${total ? "/" + human(total) : ""}  ${human(spd)}/s`, pct);
        }
      }
      blob = new Blob(chunks, { type: r.headers.get("Content-Type") || "application/octet-stream" });
    } else {
      blob = await r.blob();
    }
    const burl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = burl;
    a.download = fileName || "file";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(burl), 60000);
    setStatus("已触发保存：" + fileName, 100);
    setTimeout(() => setStatus("就绪", -1), 1500);
  } catch (e) {
    setStatus("兼容下载失败：" + e.message, -1);
    showToast("兼容下载失败：" + e.message);
  }
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
      const baseName = (m.fileName || "file").split(/[\\/]/).pop() || "file";
      const url = "/api/download/" + encodeURIComponent(m.fid) + "/" + encodeURIComponent(baseName) + "?token=" + encodeURIComponent(state.token);
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


def _ascii_fallback_name(fname: str) -> str:
    """生成纯 ASCII 兜底文件名（保留扩展名），避免部分安卓/Quest 下载器无法解析纯 filename*。"""
    base = os.path.basename(fname or "file")
    stem, ext = os.path.splitext(base)
    safe_stem = "".join(ch if ("0" <= ch <= "9" or "A" <= ch <= "Z" or "a" <= ch <= "z" or ch in "._-") else "_" for ch in stem).strip("_")
    safe_ext = "".join(ch if ("0" <= ch <= "9" or "A" <= ch <= "Z" or "a" <= ch <= "z" or ch == ".") else "" for ch in ext)
    if not safe_stem:
        safe_stem = "download"
    return (safe_stem[:80] + safe_ext[:16]) or "download"


def _parse_range_header(range_hdr: str, total_size: int):
    """解析单段 HTTP Range 头：返回 None（无 Range）、'invalid'（416）或 (start, end) 闭区间。"""
    if not range_hdr:
        return None
    hdr = range_hdr.strip()
    if not hdr.lower().startswith("bytes="):
        return None
    spec = hdr[6:].split(",", 1)[0].strip()
    if "-" not in spec:
        return "invalid"
    if total_size <= 0:
        return "invalid"
    s_part, e_part = spec.split("-", 1)
    s_part, e_part = s_part.strip(), e_part.strip()
    try:
        if not s_part:
            # 后缀范围：bytes=-500
            suffix = int(e_part)
            if suffix <= 0:
                return "invalid"
            start = max(0, total_size - suffix)
            end = total_size - 1
        else:
            start = int(s_part)
            end = int(e_part) if e_part else (total_size - 1)
            if start < 0 or start >= total_size:
                return "invalid"
            if end < start:
                return "invalid"
            end = min(end, total_size - 1)
        return (start, end)
    except ValueError:
        return "invalid"


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
        self._pending_hs = {}  # hsId -> dict
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

            def _serve_download(self, path, qs, head_only=False):
                cli = self._auth(qs)
                if not cli:
                    self.send_error(403, "Forbidden")
                    return
                raw_tail = path[len("/api/download/"):]
                fid = unquote(raw_tail.split("/", 1)[0])
                with bridge._lock:
                    entry = cli.files.get(fid)
                if not entry or not os.path.isfile(entry[0]):
                    self.send_error(404, "File not found")
                    return
                abspath, rel_name, _cached_size = entry
                try:
                    size = os.path.getsize(abspath)
                except OSError:
                    self.send_error(404, "File not found")
                    return
                fname = os.path.basename(rel_name)
                ascii_name = _ascii_fallback_name(fname)
                inline = (qs.get("inline") or ["0"])[0] == "1"
                mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
                disp = "inline" if inline else "attachment"
                rng = _parse_range_header(self.headers.get("Range", ""), size)
                if rng == "invalid":
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.close_connection = True
                    self.end_headers()
                    return
                if rng is not None:
                    start, end = rng
                    length = end - start + 1
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                else:
                    start, length = 0, size
                    self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(length))
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("ETag", f'"{fid}"')
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header(
                    "Content-Disposition",
                    f'{disp}; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(fname)}',
                )
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
                if head_only or length <= 0:
                    return
                try:
                    with open(abspath, "rb") as f:
                        if start > 0:
                            f.seek(start)
                        rem = length
                        while rem > 0:
                            chunk = f.read(min(UPLOAD_CHUNK, rem))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            rem -= len(chunk)
                    self.wfile.flush()
                except OSError:
                    pass

            def do_HEAD(self):
                parsed = urlparse(self.path)
                path = parsed.path
                qs = parse_qs(parsed.query)
                if path.startswith("/api/download/"):
                    self._serve_download(path, qs, head_only=True)
                    return
                if path in ("/", "/index.html"):
                    body = HTML_PAGE.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    return
                self.send_error(404)

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
                    self._serve_download(path, qs, head_only=False)
                    return

                self.send_error(404)

            def do_POST(self):
                parsed = urlparse(self.path)
                path = parsed.path
                ip = self.client_address[0]

                if path == "/api/spake/hello":
                    cl = int(self.headers.get("Content-Length", "0"))
                    if cl <= 0 or cl > 65536:
                        self._send_json({"ok": False, "error": "请求无效"}, 400)
                        return
                    try:
                        body = json.loads(self.rfile.read(cl).decode("utf-8"))
                    except ValueError:
                        self._send_json({"ok": False, "error": "JSON 格式错误"}, 400)
                        return
                    ok, res = bridge.handle_spake_hello(
                        str(body.get("id", "")).strip(),
                        str(body.get("name", "网页设备")).strip()[:32] or "网页设备",
                        str(body.get("pA", "")).strip(),
                        ip,
                    )
                    self._send_json(res, 200 if ok else 400)
                    return

                if path == "/api/spake/confirm":
                    cl = int(self.headers.get("Content-Length", "0"))
                    if cl <= 0 or cl > 65536:
                        self._send_json({"ok": False, "error": "请求无效"}, 400)
                        return
                    try:
                        body = json.loads(self.rfile.read(cl).decode("utf-8"))
                    except ValueError:
                        self._send_json({"ok": False, "error": "JSON 格式错误"}, 400)
                        return
                    ok, res = bridge.handle_spake_confirm(
                        str(body.get("hsId", "")).strip(),
                        str(body.get("confA", "")).strip(),
                        ip,
                    )
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

    def handle_spake_hello(self, cid, name, pA_b64, ip):
        now = time.time()
        rate_key = "web:" + ip
        with self.core._lock:
            fails, lock_until = self.core._fail_state.get(rate_key, (0, 0.0))
            if now < lock_until:
                wait = int(lock_until - now) + 1
                return False, {"ok": False, "error": f"验证码尝试次数过多，请 {wait} 秒后再试"}
            pin_now = self.core.pin
        if not cid or not pA_b64:
            return False, {"ok": False, "error": "握手参数不完整"}
        sp = crypto.Spake2Responder(self.core.id, pin_now)
        try:
            _aes_key, conf_a, conf_b, sas = sp.finish(cid, pA_b64)
        except Exception:
            return False, {"ok": False, "error": "无效的曲线参数"}
        hs_id = secrets.token_hex(12)
        with self._lock:
            # 清理过期握手
            for k in [k for k, v in self._pending_hs.items() if now > v["exp"]]:
                del self._pending_hs[k]
            self._pending_hs[hs_id] = {
                "cid": cid, "name": name, "ip": ip,
                "confA": conf_a, "confB": conf_b, "sas": sas, "exp": now + 60,
            }
        return True, {"ok": True, "hsId": hs_id, "serverId": self.core.id, "pB": sp.pB_b64()}

    def handle_spake_confirm(self, hs_id, conf_a, ip):
        now = time.time()
        rate_key = "web:" + ip
        with self._lock:
            hs = self._pending_hs.pop(hs_id, None)
        if not hs or now > hs["exp"]:
            return False, {"ok": False, "error": "握手已超时，请重试"}
        with self.core._lock:
            fails, lock_until = self.core._fail_state.get(rate_key, (0, 0.0))
            if now < lock_until:
                wait = int(lock_until - now) + 1
                return False, {"ok": False, "error": f"验证码尝试次数过多，请 {wait} 秒后再试"}
            if not hmac.compare_digest(conf_a, hs["confA"]):
                fails += 1
                if fails >= 5:
                    self.core._fail_state[rate_key] = (0, now + 30)
                    return False, {"ok": False, "error": "验证码错误次数过多，请 30 秒后再试"}
                self.core._fail_state[rate_key] = (fails, 0.0)
                return False, {"ok": False, "error": "验证码错误"}
            self.core._fail_state.pop(rate_key, None)

        token = secrets.token_hex(24)
        cid = hs["cid"]
        cli = WebClient(cid, hs["name"], ip, token)
        with self._lock:
            self._by_token[token] = cli
            self._by_id[cid] = cli
        self.core.register_web_device(cid, hs["name"], ip, token, sas=hs["sas"])
        return True, {"ok": True, "token": token, "clientId": cid, "name": self.core.name,
                      "confB": hs["confB"], "sas": hs["sas"]}

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
