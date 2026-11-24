"""
LanFast 核心 v4（端到端加密版）：
  * 逐对 6 位验证码加好友（ECDH P-256 临时密钥交换 + HMAC 验证码零明文校验）
  * 全程端到端加密（AES-256-GCM）：文字、文件名、令牌、文件流全部密文传输，
    局域网沿途与公网中转服务器均无法抓包解密
  * 局域网直连优先（跳过 Clash TUN 198.18.0.0/15，绑定真实物理网卡）+ 公网中转兜底
详见 PROTOCOL.md。
"""
import concurrent.futures
import hmac
import json
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
import uuid

from . import crypto

APP = "lanfast"
PROTO_VERSION = 4
DISCOVERY_PORT = 53530
TRANSFER_PORT = 53531
DEFAULT_RELAY_PORT = 53532
MCAST_GROUP = "224.0.0.167"
ANNOUNCE_INTERVAL = 4
DEVICE_TIMEOUT = 15
MAX_HEADER = 4 * 1024 * 1024
MAX_PIN_FAILS = 5
PIN_LOCK_SECONDS = 30

IS_WINDOWS = sys.platform.startswith("win")
OS_NAME = "windows" if IS_WINDOWS else ("mac" if sys.platform == "darwin" else "linux")


# ----------------------------------------------------------------- 工具函数
def generate_pin():
    return f"{secrets.randbelow(1_000_000):06d}"


def parse_relay_addr(addr):
    s = (addr or "").strip()
    if not s:
        return None
    if ":" in s:
        host, port_s = s.rsplit(":", 1)
        try:
            return host.strip(), int(port_s.strip())
        except ValueError:
            return host.strip(), DEFAULT_RELAY_PORT
    return s, DEFAULT_RELAY_PORT


def _is_clash_tun(ip):
    """过滤 Clash / Mihomo TUN Fake-IP 网段 198.18.0.0/15。"""
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
        return a == 198 and b in (18, 19)
    except ValueError:
        return False


def _is_private(ip):
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
        return a == 10 or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
    except ValueError:
        return False


def local_ipv4s():
    """返回本机真实局域网 IPv4（排除回环、APIPA 与 Clash TUN 198.18.0.0/15）。"""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    p = primary_ip()
    if p:
        ips.add(p)
    return sorted(
        ip for ip in ips
        if not ip.startswith("127.") and not ip.startswith("169.254.") and not _is_clash_tun(ip)
    )


def primary_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def best_ip():
    p = primary_ip()
    if p and _is_private(p) and not _is_clash_tun(p):
        return p
    ips = [ip for ip in local_ipv4s() if _is_private(ip)]
    for ip in ips:
        if not ip.endswith(".1"):
            return ip
    return ips[0] if ips else (p if p and not _is_clash_tun(p) else "无网络")


def match_local_bind_ip(target_ip):
    """若目标 IP 与本机某物理网卡在同一 /24 网段，返回该本机 IP 以绕过 Clash TUN。"""
    if not target_ip or target_ip.startswith("127."):
        return None
    prefix = ".".join(target_ip.split(".")[:3]) + "."
    for ip in local_ipv4s():
        if ip.startswith(prefix):
            return ip
    return None


def create_lan_connection(ip, port, timeout=2.5):
    """直连局域网目标：同网段时显式绑定物理网卡源 IP，避免被 Clash TUN 劫持。"""
    bind_ip = match_local_bind_ip(ip)
    if bind_ip:
        return socket.create_connection((ip, port), timeout=timeout, source_address=(bind_ip, 0))
    return socket.create_connection((ip, port), timeout=timeout)


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_parts(name):
    parts = []
    for p in re.split(r"[\\/]+", name or ""):
        p = _BAD_CHARS.sub("_", p).strip().rstrip(". ")
        if p in ("", ".", ".."):
            continue
        if p.split(".")[0].upper() in _RESERVED:
            p = "_" + p
        parts.append(p[:200])
    return parts or ["file"]


def unique_path(path):
    if not os.path.exists(path) and not os.path.exists(path + ".lfpart"):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while True:
        cand = f"{base} ({i}){ext}"
        if not os.path.exists(cand) and not os.path.exists(cand + ".lfpart"):
            return cand
        i += 1


def send_frame(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n > MAX_HEADER:
        raise ValueError("header too large")
    data = recv_exact(sock, n)
    if data is None:
        raise ConnectionError("连接中断")
    return json.loads(data.decode("utf-8"))


# ----------------------------------------------------------------- 数据结构
class Device:
    def __init__(self, id, name, os_, ip, port, token="", key=b"", boot_id="", via_relay=False):
        self.id, self.name, self.os, self.ip, self.port = id, name, os_, ip, port
        self.token = token
        self.key = key          # 32 字节 AES-256-GCM 端到端会话密钥
        self.boot_id = boot_id
        self.via_relay = via_relay
        self.last_seen = time.time()

    def label(self):
        tag = {"android": "手机", "windows": "电脑", "mac": "Mac", "linux": "Linux"}.get(self.os, self.os)
        loc = self.ip if self.ip else "公网中转"
        return f"[{tag}] {self.name} ({loc})"


# ----------------------------------------------------------------- 核心
class LanFastCore:
    def __init__(self, name, save_dir, device_id=None, on_event=None,
                 discovery_port=DISCOVERY_PORT, transfer_port=TRANSFER_PORT,
                 pin=None, relay_addr="", relay_key=""):
        self.id = device_id or uuid.uuid4().hex
        self.name = name
        self.save_dir = save_dir
        self.on_event = on_event or (lambda k, d: None)
        self.discovery_port = discovery_port
        self.transfer_port = transfer_port
        self.pin = pin or generate_pin()
        self.boot_id = secrets.token_hex(4)

        self.relay_addr = (relay_addr or "").strip()
        self.relay_key = (relay_key or "").strip()
        self._relay_gen = 0
        self._relay_sock = None
        self._relay_send_lock = threading.Lock()
        self.relay_connected = False

        self.paired = {}       # device_id -> Device（含 E2EE 密钥 key 与 token）
        self._discovered = {}  # device_id -> Device
        self._fail_state = {}  # ip -> [count, lock_until]
        self._lock = threading.Lock()
        self._running = False
        self._udp = None
        self._srv = None
        self._joined = set()

    # ---------- 生命周期
    def start(self):
        self._running = True
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not IS_WINDOWS:
            self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("", self.transfer_port))
        self._srv.listen(32)

        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if not IS_WINDOWS:
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._udp.bind(("", self.discovery_port))
        self._join_groups()

        for fn in (self._serve_loop, self._udp_loop, self._announce_loop):
            threading.Thread(target=fn, daemon=True).start()
        self._restart_relay()

    def stop(self):
        if not self._running:
            return
        try:
            self._broadcast("bye")
        except OSError:
            pass
        self._running = False
        self._relay_gen += 1
        for s in (self._udp, self._srv, self._relay_sock):
            try:
                if s:
                    s.close()
            except OSError:
                pass

    def regenerate_pin(self, disconnect_all=False):
        with self._lock:
            self.pin = generate_pin()
            self._fail_state.clear()
            if disconnect_all:
                self.boot_id = secrets.token_hex(4)
                self.paired.clear()
        self._emit("pin", self.pin)
        if disconnect_all:
            self._emit("devices", self.device_list())
        self._send_relay_update()
        self.refresh()
        return self.pin

    def set_name(self, name):
        self.name = name
        self._send_relay_update()
        self.refresh()

    def set_relay(self, addr, key=""):
        self.relay_addr = (addr or "").strip()
        self.relay_key = (key or "").strip()
        self._restart_relay()

    def _emit(self, kind, data=None):
        try:
            self.on_event(kind, data)
        except Exception:
            pass

    def _me(self, type_):
        return {"app": APP, "v": PROTO_VERSION, "type": type_, "id": self.id,
                "name": self.name, "os": OS_NAME, "port": self.transfer_port,
                "boot": self.boot_id}

    # ---------- 公网中转长连接
    def _restart_relay(self):
        self._relay_gen += 1
        old = self._relay_sock
        self._relay_sock = None
        if old:
            try:
                old.close()
            except OSError:
                pass
        self.relay_connected = False
        parsed = parse_relay_addr(self.relay_addr)
        if not parsed or not self._running:
            self._emit("relay_state", {"connected": False, "text": "仅局域网（未配置中转）"})
            return
        g = self._relay_gen
        threading.Thread(target=self._relay_loop, args=(g, parsed[0], parsed[1], self.relay_key),
                         daemon=True).start()

    def _send_relay_update(self):
        s = self._relay_sock
        if not s or not self.relay_connected:
            return
        try:
            with self._relay_send_lock:
                send_frame(s, {"app": APP, "type": "relay_update",
                               "pin": self.pin, "name": self.name, "boot": self.boot_id})
        except OSError:
            pass

    def _relay_loop(self, g, host, port, key):
        while self._running and self._relay_gen == g:
            self._emit("relay_state", {"connected": False, "text": f"正在连接中转 {host}:{port}…"})
            s = None
            try:
                s = socket.create_connection((host, port), timeout=8)
                s.settimeout(25)
                reg = {"app": APP, "type": "relay_register", "key": key,
                       "id": self.id, "name": self.name, "os": OS_NAME,
                       "pin": self.pin, "boot": self.boot_id}
                send_frame(s, reg)
                ack = recv_frame(s)
                if not ack or not ack.get("ok"):
                    err = (ack or {}).get("error", "注册失败")
                    self._emit("relay_state", {"connected": False, "text": f"中转失败：{err}"})
                    s.close()
                    time.sleep(8)
                    continue
                self._relay_sock = s
                self.relay_connected = True
                self._emit("relay_state", {"connected": True, "text": f"中转已连接 ({host}:{port})"})
                while self._running and self._relay_gen == g:
                    try:
                        msg = recv_frame(s)
                        if msg is None:
                            break
                        if msg.get("type") == "tunnel_incoming":
                            sid = msg.get("streamId", "")
                            if sid:
                                threading.Thread(target=self._join_relay_tunnel,
                                                 args=(host, port, key, sid), daemon=True).start()
                    except socket.timeout:
                        with self._relay_send_lock:
                            send_frame(s, {"app": APP, "type": "relay_ping"})
            except OSError:
                pass
            finally:
                self.relay_connected = False
                if self._relay_sock is s:
                    self._relay_sock = None
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass
            if self._running and self._relay_gen == g:
                self._emit("relay_state", {"connected": False, "text": "中转断开，正在重连…"})
                time.sleep(4)

    def _join_relay_tunnel(self, host, port, key, stream_id):
        try:
            s = socket.create_connection((host, port), timeout=8)
            s.settimeout(15)
            send_frame(s, {"app": APP, "type": "tunnel_join", "key": key, "streamId": stream_id})
            ack = recv_frame(s)
            if not ack or not ack.get("ok"):
                s.close()
                return
            self._handle_conn(s, "", via_relay=True)
        except OSError:
            pass

    def _open_relay_tunnel(self, to_id="", pin=""):
        parsed = parse_relay_addr(self.relay_addr)
        if not parsed:
            raise ConnectionError("未配置公网中转服务器")
        host, port = parsed
        s = socket.create_connection((host, port), timeout=8)
        s.settimeout(20)
        req = {"app": APP, "type": "tunnel_open", "key": self.relay_key, "from": self.id}
        if to_id:
            req["to"] = to_id
        if pin:
            req["pin"] = pin
        send_frame(s, req)
        ack = recv_frame(s)
        if not ack or not ack.get("ok"):
            s.close()
            raise ConnectionError((ack or {}).get("error", "建立中转隧道失败"))
        s.settimeout(60)
        return s

    # ---------- 局域网设备发现
    def _join_groups(self):
        group = socket.inet_aton(MCAST_GROUP)
        for ip in ["0.0.0.0"] + local_ipv4s():
            if ip in self._joined:
                continue
            try:
                self._udp.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group + socket.inet_aton(ip))
                self._joined.add(ip)
            except OSError:
                pass

    def _broadcast(self, type_="hello"):
        msg = json.dumps(self._me(type_), ensure_ascii=False).encode("utf-8")
        for ip in local_ipv4s():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
                s.bind((ip, 0))
                directed = ".".join(ip.split(".")[:3] + ["255"])
                for dst in (MCAST_GROUP, "255.255.255.255", directed):
                    try:
                        s.sendto(msg, (dst, self.discovery_port))
                    except OSError:
                        pass
            except OSError:
                pass
            finally:
                s.close()

    def _announce_loop(self):
        while self._running:
            self._join_groups()
            self._broadcast("hello")
            now = time.time()
            with self._lock:
                for k in [k for k, d in self._discovered.items() if now - d.last_seen > DEVICE_TIMEOUT]:
                    del self._discovered[k]
            time.sleep(ANNOUNCE_INTERVAL)

    def _udp_loop(self):
        while self._running:
            try:
                data, (ip, _port) = self._udp.recvfrom(65535)
                msg = json.loads(data.decode("utf-8"))
            except (OSError, ValueError):
                if not self._running:
                    return
                continue
            if msg.get("app") != APP or msg.get("id") == self.id:
                continue
            t = msg.get("type")
            did = msg.get("id")
            if t == "bye":
                changed = False
                with self._lock:
                    self._discovered.pop(did, None)
                    if did in self.paired:
                        del self.paired[did]
                        changed = True
                if changed:
                    self._emit("devices", self.device_list())
                continue
            self._note_discovered(msg, ip)
            if t == "hello":
                try:
                    self._udp.sendto(json.dumps(self._me("reply"), ensure_ascii=False).encode("utf-8"),
                                     (ip, self.discovery_port))
                except OSError:
                    pass

    def _note_discovered(self, msg, ip):
        did = msg.get("id")
        if not did or did == self.id:
            return
        boot = msg.get("boot", "")
        changed = False
        with self._lock:
            self._discovered[did] = Device(did, msg.get("name", "?"), msg.get("os", "?"), ip,
                                           int(msg.get("port", TRANSFER_PORT)), boot_id=boot)
            p = self.paired.get(did)
            if p is not None:
                if p.boot_id and boot and p.boot_id != boot:
                    del self.paired[did]
                    changed = True
                else:
                    if (p.ip, p.name) != (ip, msg.get("name", p.name)):
                        p.ip = ip
                        p.name = msg.get("name", p.name)
                        p.via_relay = False
                        changed = True
                    p.port = int(msg.get("port", p.port))
                    p.last_seen = time.time()
        if changed:
            self._emit("devices", self.device_list())

    def device_list(self):
        with self._lock:
            return sorted(self.paired.values(), key=lambda d: (d.os, d.name))

    def get_device(self, device_id):
        with self._lock:
            return self.paired.get(device_id)

    def refresh(self):
        threading.Thread(target=self._broadcast, daemon=True).start()

    def remove_device(self, device_id):
        with self._lock:
            self.paired.pop(device_id, None)
        self._emit("devices", self.device_list())

    # ---------- 端到端加密配对（ECDH P-256 + 零明文 6 位验证码证明）
    def _do_pair_over_socket(self, s, pin, ip, port, via_relay):
        priv_a, pub_a_b64 = crypto.gen_ec_keypair()
        salt_a = os.urandom(16)
        hello = self._me("pair_hello")
        hello["pub"] = pub_a_b64
        hello["salt"] = crypto.b64e(salt_a)
        send_frame(s, hello)

        chal = recv_frame(s)
        if not chal or not chal.get("ok") or not chal.get("pub") or not chal.get("salt"):
            return False, None, (chal or {}).get("error", "对方不支持端到端加密或拒绝连接")

        salt_b = crypto.b64d(chal["salt"])
        shared_z = crypto.ecdh_secret(priv_a, chal["pub"])
        proof = crypto.pin_proof(shared_z, pin, salt_a, salt_b)
        aes_key = crypto.derive_session_key(shared_z, pin, salt_a, salt_b)

        send_frame(s, {"app": APP, "v": PROTO_VERSION, "type": "pair_verify", "proof": proof})
        ack = recv_frame(s)
        if not ack or not ack.get("ok") or not ack.get("n") or not ack.get("ct"):
            return False, None, (ack or {}).get("error", "验证码错误")

        secret_box = crypto.decrypt_json(aes_key, ack["n"], ack["ct"], b"pair_ok")
        token = secret_box.get("token", "")
        if not token or not chal.get("id"):
            return False, None, "配对令牌校验失败"

        dev = Device(
            chal["id"], chal.get("name", ip or "好友"), chal.get("os", "?"),
            "" if via_relay else ip, int(chal.get("port", port)),
            token=token, key=aes_key, boot_id=chal.get("boot", ""), via_relay=via_relay,
        )
        return True, dev, None

    def pair_by_pin(self, pin, manual_ip="", port=TRANSFER_PORT):
        pin = (pin or "").strip()
        manual_ip = (manual_ip or "").strip()

        def run():
            if not re.fullmatch(r"\d{6}", pin):
                self._emit("pair_result", {"ok": False, "error": "请输入完整的 6 位数字验证码"})
                return
            if manual_ip:
                try:
                    with create_lan_connection(manual_ip, port, timeout=4) as s:
                        s.settimeout(5)
                        ok, dev, err = self._do_pair_over_socket(s, pin, manual_ip, port, False)
                    if ok:
                        self._save_paired(dev, "局域网直连")
                    else:
                        self._emit("pair_result", {"ok": False, "error": err})
                except Exception as e:  # noqa
                    self._emit("pair_result", {"ok": False, "error": f"连接 {manual_ip} 失败：{e}"})
                return

            with self._lock:
                cands = list(self._discovered.values())
            if not cands:
                self._broadcast("hello")
                time.sleep(0.8)
                with self._lock:
                    cands = list(self._discovered.values())

            last_err = None
            if cands:
                def probe(cand):
                    try:
                        with create_lan_connection(cand.ip, cand.port, timeout=2.5) as s:
                            s.settimeout(4)
                            return self._do_pair_over_socket(s, pin, cand.ip, cand.port, False)
                    except Exception as e:  # noqa
                        return False, None, str(e)

                with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, len(cands))) as ex:
                    for ok, dev, err in ex.map(probe, cands):
                        if ok:
                            self._save_paired(dev, "局域网直连")
                            return
                        if err:
                            last_err = err

            if parse_relay_addr(self.relay_addr):
                try:
                    with self._open_relay_tunnel(pin=pin) as s:
                        ok, dev, err = self._do_pair_over_socket(s, pin, "", TRANSFER_PORT, True)
                    if ok:
                        with self._lock:
                            d_lan = self._discovered.get(dev.id)
                            if d_lan:
                                dev.ip, dev.port, dev.via_relay = d_lan.ip, d_lan.port, False
                        self._save_paired(dev, "公网中转")
                        return
                    last_err = err
                except Exception as e:  # noqa
                    last_err = str(e)

            msg = last_err or "未找到该 6 位验证码对应的设备。\n请确认在同一 WiFi（或已连接同一公网中转），或填写对方 IP。"
            self._emit("pair_result", {"ok": False, "error": msg})

        threading.Thread(target=run, daemon=True).start()

    def _save_paired(self, dev, route):
        with self._lock:
            self.paired[dev.id] = dev
        self._emit("devices", self.device_list())
        self._emit("paired", dev)
        self._emit("pair_result", {"ok": True, "device": dev, "route": route})
        self._emit("log", f"🔒 已建立端到端加密好友连接：{dev.name}（{route}）")

    # ---------- 服务端 E2EE 配对处理
    def _handle_pair_handshake(self, conn, hello, ip, via_relay):
        now = time.time()
        rate_key = ip or ("relay:" + str(hello.get("id", "?")))
        with self._lock:
            fails, lock_until = self._fail_state.get(rate_key, (0, 0.0))
            if now < lock_until:
                wait = int(lock_until - now) + 1
                send_frame(conn, {"ok": False, "error": f"验证码尝试次数过多，请 {wait} 秒后再试"})
                return
        did = hello.get("id", "")
        if not did or did == self.id or not hello.get("pub") or not hello.get("salt"):
            send_frame(conn, {"ok": False, "error": "无效的加密握手请求"})
            return

        priv_b, pub_b_b64 = crypto.gen_ec_keypair()
        salt_a = crypto.b64d(hello["salt"])
        salt_b = os.urandom(16)
        shared_z = crypto.ecdh_secret(priv_b, hello["pub"])

        chal = self._me("pair_challenge")
        chal["ok"] = True
        chal["pub"] = pub_b_b64
        chal["salt"] = crypto.b64e(salt_b)
        send_frame(conn, chal)

        ver = recv_frame(conn)
        if not ver or ver.get("type") != "pair_verify":
            return

        expected = crypto.pin_proof(shared_z, self.pin, salt_a, salt_b)
        got = str(ver.get("proof", ""))
        with self._lock:
            if not hmac.compare_digest(got, expected):
                fails, _ = self._fail_state.get(rate_key, (0, 0.0))
                fails += 1
                if fails >= MAX_PIN_FAILS:
                    self._fail_state[rate_key] = (0, now + PIN_LOCK_SECONDS)
                    send_frame(conn, {"ok": False, "error": f"验证码错误次数过多，请 {PIN_LOCK_SECONDS} 秒后再试"})
                else:
                    self._fail_state[rate_key] = (fails, 0.0)
                    send_frame(conn, {"ok": False, "error": "验证码错误"})
                return
            self._fail_state.pop(rate_key, None)
            aes_key = crypto.derive_session_key(shared_z, self.pin, salt_a, salt_b)
            token = secrets.token_hex(24)
            lan_dev = self._discovered.get(did)
            peer_ip = (lan_dev.ip if lan_dev else "") if via_relay else ip
            peer_port = int(hello.get("port", TRANSFER_PORT))
            dev = Device(did, hello.get("name", ip or "好友"), hello.get("os", "?"),
                         peer_ip, peer_port, token=token, key=aes_key,
                         boot_id=hello.get("boot", ""), via_relay=(not peer_ip))
            self.paired[did] = dev

        n_b64, ct_b64 = crypto.encrypt_json(aes_key, {"token": token}, b"pair_ok")
        send_frame(conn, {"ok": True, "type": "pair_ok", "n": n_b64, "ct": ct_b64})
        self._emit("devices", self.device_list())
        self._emit("paired", dev)
        self._emit("log", f"🔒 {dev.name} 已通过端到端加密验证加为好友（{'公网中转' if via_relay else '局域网直连'}）")

    # ---------- 接收端（只接受 AES-256-GCM 密文帧）
    def _serve_loop(self):
        while self._running:
            try:
                conn, addr = self._srv.accept()
            except OSError:
                if not self._running:
                    return
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr[0], False), daemon=True).start()

    def _handle_conn(self, conn, ip, via_relay=False):
        conn.settimeout(60)
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        route = "公网中转" if via_relay else "局域网直连"
        with conn:
            try:
                while True:
                    hdr = recv_frame(conn)
                    if hdr is None or hdr.get("app") != APP:
                        break
                    t = hdr.get("type")
                    if t == "ping":
                        ack = self._me("pong")
                        ack["ok"] = True
                        send_frame(conn, ack)
                    elif t == "pair_hello":
                        self._handle_pair_handshake(conn, hdr, ip, via_relay)
                        break
                    elif t == "enc":
                        did = hdr.get("id", "")
                        with self._lock:
                            dev = self.paired.get(did)
                        if dev is None or not dev.key:
                            send_frame(conn, {"ok": False, "auth_error": True,
                                              "error": "对方已重置连接或不是好友，请重新输入 6 位验证码添加"})
                            break
                        try:
                            inner = crypto.decrypt_json(dev.key, hdr["n"], hdr["ct"], b"frame")
                        except Exception:
                            send_frame(conn, {"ok": False, "auth_error": True,
                                              "error": "加密校验失败，会话密钥已失效，请重新加好友"})
                            break
                        if not hmac.compare_digest(str(inner.get("token", "")), dev.token):
                            send_frame(conn, {"ok": False, "auth_error": True,
                                              "error": "会话令牌无效，请重新加好友"})
                            break
                        with self._lock:
                            if not via_relay and ip:
                                dev.ip = ip
                                dev.via_relay = False
                            dev.last_seen = time.time()

                        it = inner.get("type")
                        if it == "text":
                            self._emit("text", {"peer_id": dev.id, "from": dev.name, "ip": ip or route,
                                                "route": route, "text": inner.get("text", ""), "time": time.time()})
                            send_frame(conn, {"ok": True})
                        elif it == "file":
                            path = self._recv_encrypted_file(conn, inner, dev, route)
                            send_frame(conn, {"ok": True})
                            self._emit("recv_file", {"peer_id": dev.id, "from": dev.name, "ip": ip or route,
                                                     "route": route, "path": path,
                                                     "size": int(inner.get("size", 0)), "time": time.time()})
                        else:
                            send_frame(conn, {"ok": False, "error": "unknown inner type"})
                            break
                    else:
                        send_frame(conn, {"ok": False, "auth_error": True,
                                          "error": "拒绝未加密或旧版本请求，请两端升级并重新配对"})
                        break
            except Exception as e:  # noqa
                self._emit("error", f"接收失败（{ip or route}）：{e}")

    def _recv_encrypted_file(self, conn, inner, dev, route):
        size = int(inner.get("size", 0))
        chunk_size = int(inner.get("chunkSize", crypto.ENC_CHUNK))
        parts = safe_parts(inner.get("fileName", "file"))
        dest = unique_path(os.path.join(self.save_dir, *parts))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".lfpart"
        name = "/".join(parts)
        got, seq, last = 0, 0, 0.0
        try:
            with open(tmp, "wb") as f:
                while got < size:
                    plain_len = min(chunk_size, size - got)
                    packet = recv_exact(conn, crypto.NONCE_LEN + plain_len + crypto.TAG_LEN)
                    if packet is None:
                        raise ConnectionError("对方中断了加密传输")
                    nonce = packet[:crypto.NONCE_LEN]
                    ct = packet[crypto.NONCE_LEN:]
                    pt = crypto.decrypt_bytes(dev.key, nonce, ct, crypto.pack_seq(seq))
                    f.write(pt)
                    got += len(pt)
                    seq += 1
                    now = time.time()
                    if now - last > 0.15 or got == size:
                        last = now
                        self._emit("recv_progress", {"peer_id": dev.id, "from": dev.name, "route": route,
                                                     "name": name, "done": got, "total": size})
            os.replace(tmp, dest)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        return dest

    # ---------- 发送端（AES-256-GCM 端到端加密 + 局域网直连优先）
    def _connect(self, dev):
        if dev.ip:
            try:
                s = create_lan_connection(dev.ip, dev.port, timeout=2.0)
                s.settimeout(60)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
                except OSError:
                    pass
                return s, "局域网直连"
            except OSError as lan_err:
                if not parse_relay_addr(self.relay_addr):
                    raise ConnectionError(f"局域网直连 {dev.ip} 失败（未配置中转）：{lan_err}") from lan_err
        if parse_relay_addr(self.relay_addr):
            s = self._open_relay_tunnel(to_id=dev.id)
            return s, "公网中转"
        raise ConnectionError("无法连接对方（不在同一局域网且未配置公网中转服务器）")

    def _send_enc_frame(self, sock, dev, inner_obj):
        n_b64, ct_b64 = crypto.encrypt_json(dev.key, inner_obj, b"frame")
        send_frame(sock, {"app": APP, "v": PROTO_VERSION, "type": "enc",
                          "id": self.id, "n": n_b64, "ct": ct_b64})

    def _handle_ack(self, dev, ack):
        if not ack:
            raise ConnectionError("对方无响应")
        if not ack.get("ok"):
            if ack.get("auth_error"):
                self.remove_device(dev.id)
            raise ConnectionError(ack.get("error", "对方拒绝接收"))

    def send_text(self, dev, text):
        def run():
            try:
                s, route = self._connect(dev)
                with s:
                    self._send_enc_frame(s, dev, {"type": "text", "token": dev.token, "text": text})
                    self._handle_ack(dev, recv_frame(s))
                self._emit("send_done", {"ok": True, "kind": "text", "peer_id": dev.id,
                                         "to": dev.name, "route": route, "text": text})
            except Exception as e:  # noqa
                self._emit("send_done", {"ok": False, "kind": "text", "peer_id": dev.id,
                                         "to": dev.name, "error": str(e)})
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def expand_paths(paths):
        items = []
        for p in paths:
            p = os.path.abspath(p)
            if os.path.isdir(p):
                root_parent = os.path.dirname(p.rstrip("\\/"))
                for dirpath, _dirs, files in os.walk(p):
                    for fn in files:
                        full = os.path.join(dirpath, fn)
                        items.append((full, os.path.relpath(full, root_parent).replace("\\", "/")))
            elif os.path.isfile(p):
                items.append((p, os.path.basename(p)))
        return items

    def send_files(self, dev, paths):
        def run():
            items = self.expand_paths(paths)
            if not items:
                self._emit("send_done", {"ok": False, "kind": "file", "peer_id": dev.id,
                                         "to": dev.name, "error": "没有可发送的文件"})
                return
            total = sum(os.path.getsize(a) for a, _ in items)
            sent, last, t0 = 0, 0.0, time.time()
            try:
                s, route = self._connect(dev)
                with s:
                    for idx, (abspath, rel) in enumerate(items, 1):
                        size = os.path.getsize(abspath)
                        self._send_enc_frame(s, dev, {
                            "type": "file", "token": dev.token, "fileName": rel,
                            "size": size, "chunkSize": crypto.ENC_CHUNK,
                            "index": idx, "count": len(items),
                        })
                        with open(abspath, "rb") as f:
                            remaining, seq = size, 0
                            while remaining > 0:
                                pt = f.read(min(crypto.ENC_CHUNK, remaining))
                                if not pt:
                                    raise IOError("文件在发送过程中被修改")
                                nonce, ct = crypto.encrypt_bytes(dev.key, pt, crypto.pack_seq(seq))
                                s.sendall(nonce + ct)
                                remaining -= len(pt)
                                sent += len(pt)
                                seq += 1
                                now = time.time()
                                if now - last > 0.15:
                                    last = now
                                    self._emit("send_progress", {"peer_id": dev.id, "to": dev.name, "route": route,
                                                                 "name": rel, "done": sent, "total": total,
                                                                 "index": idx, "count": len(items),
                                                                 "speed": sent / max(now - t0, 1e-3)})
                        self._handle_ack(dev, recv_frame(s))
                self._emit("send_done", {"ok": True, "kind": "file", "peer_id": dev.id, "to": dev.name,
                                         "route": route, "count": len(items), "total": total,
                                         "names": [r for _, r in items], "seconds": time.time() - t0})
            except Exception as e:  # noqa
                self._emit("send_done", {"ok": False, "kind": "file", "peer_id": dev.id,
                                         "to": dev.name, "error": str(e)})
        threading.Thread(target=run, daemon=True).start()
