"""
LanFast v5 端到端加密与 PAKE 认证（RFC 9382 SPAKE2-P256 + SAS 4-Emoji + AES-256-GCM）
- 抗被动抓包 + 抗主动中间人离线穷举（SPAKE2 每次握手最多在线试 1 个 6 位码，彻底杜绝离线爆破）
- 与 Android 原生 Java BigInteger + JCA 以及浏览器纯 JS BigInt 字节级完全互通
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16
ENC_CHUNK = 256 * 1024

# NIST P-256 (secp256r1) 曲线参数
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
)
# RFC 9382 官方 P-256 Nothing-Up-My-Sleeve 点 M、N
M_PT = (
    0x886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f,
    0x5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20,
)
N_PT = (
    0xd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49,
    0x07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7,
)

# 64 个全平台通用 Emoji（用于 SAS 安全核对码，64^4 = 1677 万种组合）
SAS_EMOJIS = (
    "🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁",
    "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🐦", "🦆",
    "🦉", "🦇", "🐺", "🐴", "🦄", "🐝", "🦋", "🐌",
    "🐞", "🐢", "🐍", "🐙", "🐠", "🐳", "🐬", "🦈",
    "🌵", "🌲", "🌸", "🌻", "🍀", "🍁", "🍎", "🍊",
    "🍋", "🍉", "🍇", "🍓", "🍒", "🍑", "🍍", "🥑",
    "🍕", "🍔", "🍟", "🍩", "🍪", "🎂", "⚽", "🏀",
    "🎸", "🎹", "🚀", "✈️", "🚗", "⛵", "⭐", "🔥",
)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ----------------------------------------------------------------- P-256 椭圆曲线点运算
def is_on_curve(pt) -> bool:
    if pt is None:
        return False
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def pt_neg(pt):
    if pt is None:
        return None
    return (pt[0], (-pt[1]) % P)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = ((3 * x1 * x1 + A) * pow((2 * y1) % P, -1, P)) % P
    else:
        lam = ((y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def pt_sub(p1, p2):
    return pt_add(p1, pt_neg(p2))


def pt_mul(k: int, pt):
    k %= N
    if k == 0 or pt is None:
        return None
    res = None
    addend = pt
    while k:
        if k & 1:
            res = pt_add(res, addend)
        addend = pt_add(addend, addend)
        k >>= 1
    return res


def enc_point(pt) -> bytes:
    if not is_on_curve(pt):
        raise ValueError("point not on P-256")
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def dec_point(raw: bytes):
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("invalid uncompressed P-256 point")
    pt = (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big"))
    if not is_on_curve(pt):
        raise ValueError("point not on P-256 curve")
    return pt


# ----------------------------------------------------------------- SPAKE2-P256 核心
def pin_to_scalar(pin: str) -> int:
    h = hashlib.sha256(b"lanfast-spake2-w|" + pin.encode("utf-8")).digest()
    return (int.from_bytes(h, "big") % (N - 1)) + 1


def pin_route_tag(pin: str, relay_key: str = "") -> str:
    """中转服务器按此哈希索引在线设备，绝不向中转服发送明文 6 位验证码。"""
    h = hashlib.sha256(b"lanfast-route|" + relay_key.encode("utf-8") + b"|" + pin.encode("utf-8")).hexdigest()
    return h[:32]


def sas_from_digest(digest: bytes) -> str:
    return "".join(SAS_EMOJIS[digest[i] & 63] for i in range(4))


def _derive_spake2(id_a: str, id_b: str, pA_raw: bytes, pB_raw: bytes, K_pt, w: int):
    if K_pt is None:
        raise ValueError("invalid shared point")
    K_raw = enc_point(K_pt)
    a_b = id_a.encode("utf-8")
    b_b = id_b.encode("utf-8")
    tt = hashlib.sha256(
        struct.pack(">I", len(a_b)) + a_b +
        struct.pack(">I", len(b_b)) + b_b +
        pA_raw + pB_raw + K_raw + w.to_bytes(32, "big")
    ).digest()
    aes_key = hashlib.sha256(tt + b"aes-256-gcm").digest()
    conf_a = hmac.new(tt, b"confirm-A", hashlib.sha256).hexdigest()
    conf_b = hmac.new(tt, b"confirm-B", hashlib.sha256).hexdigest()
    sas = sas_from_digest(hashlib.sha256(tt + b"sas-emoji").digest())
    return aes_key, conf_a, conf_b, sas


class Spake2Initiator:
    """发起方 A（输入对方 B 的 6 位验证码）。"""

    def __init__(self, id_a: str, pin: str):
        self.id_a = id_a
        self.w = pin_to_scalar(pin)
        self.x = secrets.randbelow(N - 1) + 1
        self.pA_raw = enc_point(pt_add(pt_mul(self.x, G), pt_mul(self.w, M_PT)))

    def pA_b64(self) -> str:
        return b64e(self.pA_raw)

    def finish(self, id_b: str, pB_b64: str):
        pB_raw = b64d(pB_b64)
        pB = dec_point(pB_raw)
        K_pt = pt_mul(self.x, pt_sub(pB, pt_mul(self.w, N_PT)))
        return _derive_spake2(self.id_a, id_b, self.pA_raw, pB_raw, K_pt, self.w)


class Spake2Responder:
    """响应方 B（持有本机 6 位验证码）。"""

    def __init__(self, id_b: str, pin: str):
        self.id_b = id_b
        self.w = pin_to_scalar(pin)
        self.y = secrets.randbelow(N - 1) + 1
        self.pB_raw = enc_point(pt_add(pt_mul(self.y, G), pt_mul(self.w, N_PT)))

    def pB_b64(self) -> str:
        return b64e(self.pB_raw)

    def finish(self, id_a: str, pA_b64: str):
        pA_raw = b64d(pA_b64)
        pA = dec_point(pA_raw)
        K_pt = pt_mul(self.y, pt_sub(pA, pt_mul(self.w, M_PT)))
        return _derive_spake2(id_a, self.id_b, pA_raw, self.pB_raw, K_pt, self.w)


# ----------------------------------------------------------------- AES-256-GCM 加解密
def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return nonce, ct


def decrypt_bytes(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad or None)


def encrypt_json(key: bytes, obj: dict, aad: bytes = b"") -> tuple[str, str]:
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    nonce, ct = encrypt_bytes(key, raw, aad)
    return b64e(nonce), b64e(ct)


def decrypt_json(key: bytes, nonce_b64: str, ct_b64: str, aad: bytes = b"") -> dict:
    raw = decrypt_bytes(key, b64d(nonce_b64), b64d(ct_b64), aad)
    return json.loads(raw.decode("utf-8"))


def pack_seq(seq: int) -> bytes:
    return struct.pack(">Q", seq)
