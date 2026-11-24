"""
LanFast 端到端加密工具（ECDH P-256 + HMAC-SHA256 + AES-256-GCM）
与 Android 原生 JCA (secp256r1 / X.509 SPKI / AES/GCM/NoPadding) 完全互通。
"""
import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16
ENC_CHUNK = 256 * 1024  # 256 KiB 明文分块，兼顾内存与流式吞吐


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def gen_ec_keypair():
    """生成临时 P-256 密钥对，返回 (private_key, spki_der_b64)。"""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_der = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, b64e(pub_der)


def ecdh_secret(priv, peer_pub_b64: str) -> bytes:
    """计算 ECDH 共享密钥 Z（32 字节）。"""
    peer_pub = serialization.load_der_public_key(b64d(peer_pub_b64))
    return priv.exchange(ec.ECDH(), peer_pub)


def pin_proof(shared_z: bytes, pin: str, salt_a: bytes, salt_b: bytes) -> str:
    """用 ECDH 共享密钥对 6 位验证码做 HMAC 证明，验证码本身不明文传输。"""
    msg = b"lanfast-pin|" + pin.encode("utf-8") + b"|" + salt_a + b"|" + salt_b
    return hmac.new(shared_z, msg, hashlib.sha256).hexdigest()


def derive_session_key(shared_z: bytes, pin: str, salt_a: bytes, salt_b: bytes) -> bytes:
    """派生 256-bit (32 字节) AES 会话密钥（具备前向保密 + 绑定 6 位验证码防中间人）。"""
    h = hashlib.sha256()
    h.update(shared_z)
    h.update(b"lanfast-e2ee-v4")
    h.update(pin.encode("utf-8"))
    h.update(salt_a)
    h.update(salt_b)
    return h.digest()


def encrypt_bytes(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """返回 (12字节 nonce, 密文+16字节GCM标签)。"""
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
