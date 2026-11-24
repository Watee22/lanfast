#!/usr/bin/env python3
"""
LanFast 轻量级公网中转服务器 v5（零明文 PIN 路由 + 可选原生 TLS）

安全特性：
  * 客户端注册与查找时只发送加盐哈希 pin_tag，不向中转服务器发送明文 6 位验证码；
  * 隧道内部运行端到端 SPAKE2-P256 + AES-256-GCM，中转服务器无法看到任何聊天内容、文件或令牌；
  * 支持 --cert / --key 开启原生 TLS 传输加密，零第三方依赖。

启动示例：
  python3 relay_server.py --host 0.0.0.0 --port 53532 --key my-secret-key
  python3 relay_server.py --host 0.0.0.0 --port 53532 --key my-secret-key --cert fullchain.pem --keyfile privkey.pem
"""
import argparse
import asyncio
import hmac
import json
import logging
import secrets
import ssl
import struct
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("lanfast-relay")

APP = "lanfast"
MAX_HEADER = 1 * 1024 * 1024
PIPE_CHUNK = 64 * 1024
TUNNEL_WAIT_TIMEOUT = 15
MAX_PIN_FAILS = 8
PIN_LOCK_SECONDS = 30


async def read_frame(reader: asyncio.StreamReader, timeout=None):
    hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    (n,) = struct.unpack(">I", hdr)
    if n <= 0 or n > MAX_HEADER:
        raise ValueError("invalid frame length")
    data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
    return json.loads(data.decode("utf-8"))


async def write_frame(writer: asyncio.StreamWriter, obj: dict):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


class ClientInfo:
    def __init__(self, device_id, name, os_, route_code, boot, writer, ip):
        self.id = device_id
        self.name = name
        self.os = os_
        self.route_code = route_code.upper()  # 与 SPAKE2 PIN 完全无关的随机路由码
        self.boot = boot
        self.writer = writer
        self.ip = ip
        self.lock = asyncio.Lock()

    async def send(self, obj: dict):
        async with self.lock:
            await write_frame(self.writer, obj)


class PendingTunnel:
    def __init__(self, stream_id, target_id, initiator_reader, initiator_writer):
        self.stream_id = stream_id
        self.target_id = target_id
        self.initiator_reader = initiator_reader
        self.initiator_writer = initiator_writer
        self.joined = asyncio.Event()
        self.target_reader = None
        self.target_writer = None


class RelayServer:
    def __init__(self, server_key=""):
        self.server_key = server_key or ""
        self.clients: dict[str, ClientInfo] = {}
        self.pending: dict[str, PendingTunnel] = {}
        self.fail_state: dict[str, tuple[int, float]] = {}

    def _check_key(self, msg):
        if not self.server_key:
            return True
        return hmac.compare_digest(str(msg.get("key", "")), self.server_key)

    def _find_by_route(self, route_code: str, exclude_id: str = ""):
        rc = route_code.upper()
        for c in self.clients.values():
            if c.id != exclude_id and c.route_code and hmac.compare_digest(c.route_code, rc):
                return c
        return None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        close_here = True
        try:
            first = await read_frame(reader, timeout=15)
            if first.get("app") != APP:
                return
            if not self._check_key(first):
                await write_frame(writer, {"ok": False, "error": "中转服务器密钥不正确"})
                return
            t = first.get("type")
            if t == "relay_register":
                await self._handle_control(first, reader, writer, ip)
            elif t == "tunnel_open":
                close_here = await self._handle_tunnel_open(first, reader, writer, ip)
            elif t == "tunnel_join":
                close_here = await self._handle_tunnel_join(first, reader, writer)
            else:
                await write_frame(writer, {"ok": False, "error": "unknown relay command"})
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError, ValueError):
            pass
        except Exception as e:  # noqa
            log.warning("connection error from %s: %s", ip, e)
        finally:
            if close_here:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _handle_control(self, first, reader, writer, ip):
        did = str(first.get("id", ""))
        if not did:
            await write_frame(writer, {"ok": False, "error": "missing device id"})
            return
        rc = str(first.get("route_code", "")).strip().upper()
        info = ClientInfo(did, first.get("name", "?"), first.get("os", "?"),
                          rc, str(first.get("boot", "")), writer, ip)
        old = self.clients.get(did)
        if old is not None and old.writer is not writer:
            try:
                old.writer.close()
            except Exception:
                pass
        self.clients[did] = info
        await info.send({"ok": True, "type": "registered", "online": len(self.clients)})
        log.info("ONLINE  %s (%s) from %s  [total=%d]", info.name, info.os, ip, len(self.clients))
        try:
            while True:
                msg = await read_frame(reader, timeout=75)
                mt = msg.get("type")
                if mt == "relay_ping":
                    await info.send({"type": "relay_pong", "ok": True, "online": len(self.clients)})
                elif mt == "relay_update":
                    if "route_code" in msg:
                        info.route_code = str(msg["route_code"]).strip().upper()
                    if "name" in msg:
                        info.name = str(msg["name"])
                    if "boot" in msg:
                        info.boot = str(msg["boot"])
                    await info.send({"type": "relay_updated", "ok": True})
                elif mt == "relay_bye":
                    break
        finally:
            if self.clients.get(did) is info:
                del self.clients[did]
                log.info("OFFLINE %s (%s)  [total=%d]", info.name, info.os, len(self.clients))

    async def _handle_tunnel_open(self, first, reader, writer, ip):
        now = time.time()
        from_id = str(first.get("from", ""))
        to_id = str(first.get("to", ""))
        route_code = str(first.get("route_code", "")).strip().upper()

        target = None
        if to_id:
            target = self.clients.get(to_id)
            if target is None:
                await write_frame(writer, {"ok": False, "error": "对方当前未连接到中转服务器"})
                return True
        elif route_code:
            fails, lock_until = self.fail_state.get(ip, (0, 0.0))
            if now < lock_until:
                wait = int(lock_until - now) + 1
                await write_frame(writer, {"ok": False, "error": f"尝试次数过多，请 {wait} 秒后再试"})
                return True
            target = self._find_by_route(route_code, exclude_id=from_id)
            if target is None:
                fails += 1
                if fails >= MAX_PIN_FAILS:
                    self.fail_state[ip] = (0, now + PIN_LOCK_SECONDS)
                    await write_frame(writer, {"ok": False, "error": f"路由码错误次数过多，请 {PIN_LOCK_SECONDS} 秒后再试"})
                else:
                    self.fail_state[ip] = (fails, 0.0)
                    await write_frame(writer, {"ok": False, "error": f"中转服务器上未找到路由码 {route_code} 对应的在线设备"})
                return True
            self.fail_state.pop(ip, None)
        else:
            await write_frame(writer, {"ok": False, "error": "缺少目标设备或中转路由码"})
            return True

        stream_id = secrets.token_hex(12)
        pt = PendingTunnel(stream_id, target.id, reader, writer)
        self.pending[stream_id] = pt
        try:
            await target.send({"type": "tunnel_incoming", "streamId": stream_id, "from": from_id})
        except Exception:
            self.pending.pop(stream_id, None)
            await write_frame(writer, {"ok": False, "error": "通知对方建立中转隧道失败"})
            return True

        try:
            await asyncio.wait_for(pt.joined.wait(), timeout=TUNNEL_WAIT_TIMEOUT)
        except asyncio.TimeoutError:
            self.pending.pop(stream_id, None)
            await write_frame(writer, {"ok": False, "error": "等待对方响应中转超时"})
            return True

        await write_frame(writer, {"ok": True, "type": "tunnel_ready", "streamId": stream_id,
                                   "targetId": target.id, "targetName": target.name})
        await self._bridge(reader, writer, pt.target_reader, pt.target_writer)
        return False

    async def _handle_tunnel_join(self, first, reader, writer):
        stream_id = str(first.get("streamId", ""))
        pt = self.pending.pop(stream_id, None)
        if pt is None:
            await write_frame(writer, {"ok": False, "error": "隧道已过期或不存在"})
            return True
        await write_frame(writer, {"ok": True, "type": "tunnel_ready", "streamId": stream_id})
        pt.target_reader = reader
        pt.target_writer = writer
        pt.joined.set()
        return False

    async def _bridge(self, r1, w1, r2, w2):
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while True:
                    chunk = await src.read(PIPE_CHUNK)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    if dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    pass

        try:
            await asyncio.gather(pump(r1, w2), pump(r2, w1))
        finally:
            for w in (w1, w2):
                try:
                    w.close()
                except Exception:
                    pass


async def run_server(host: str, port: int, key: str, cert: str, keyfile: str):
    relay = RelayServer(server_key=key)
    ssl_ctx = None
    if cert and keyfile:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert, keyfile)
    srv = await asyncio.start_server(relay.handle_client, host, port, ssl=ssl_ctx)
    addrs = ", ".join(str(s.getsockname()) for s in srv.sockets)
    log.info("LanFast v5 中转服务器已启动：%s  (TLS：%s，密钥保护：%s)",
             addrs, "开启" if ssl_ctx else "关闭", "开启" if key else "关闭")
    async with srv:
        await srv.serve_forever()


def main():
    p = argparse.ArgumentParser(description="LanFast v5 公网中转服务器（零明文 PIN 路由 + 可选 TLS）")
    p.add_argument("--host", default="0.0.0.0", help="监听地址（默认 0.0.0.0）")
    p.add_argument("--port", type=int, default=53532, help="监听端口（默认 53532）")
    p.add_argument("--key", default="", help="可选接入密钥，客户端需填写相同密钥")
    p.add_argument("--cert", default="", help="可选 TLS 证书文件（PEM），配置后客户端用 tls://host:port 连接")
    p.add_argument("--keyfile", default="", help="可选 TLS 私钥文件（PEM）")
    args = p.parse_args()
    try:
        asyncio.run(run_server(args.host, args.port, args.key, args.cert, args.keyfile))
    except KeyboardInterrupt:
        log.info("中转服务器已停止")


if __name__ == "__main__":
    main()
