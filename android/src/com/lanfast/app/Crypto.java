package com.lanfast.app;

import android.util.Base64;

import org.json.JSONObject;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * LanFast v5 端到端加密与 PAKE 认证（RFC 9382 SPAKE2-P256 + SAS 4-Emoji + AES-256-GCM）
 * 100% Android 原生 Java（BigInteger + JCA），零第三方依赖，与 Windows 端字节级互通。
 */
public class Crypto {
    static final int NONCE_LEN = 12;
    static final int TAG_LEN = 16;
    static final int ENC_CHUNK = 256 * 1024;
    static final Charset UTF8 = Charset.forName("UTF-8");
    static final SecureRandom RNG = new SecureRandom();

    // NIST P-256 参数
    static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    static final BigInteger N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    static final BigInteger TWO = BigInteger.valueOf(2);
    static final BigInteger THREE = BigInteger.valueOf(3);

    static final Pt G = new Pt(
            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16));
    // RFC 9382 官方 P-256 M / N 点
    static final Pt M_PT = new Pt(
            new BigInteger("886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f", 16),
            new BigInteger("5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20", 16));
    static final Pt N_PT = new Pt(
            new BigInteger("d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49", 16),
            new BigInteger("07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7", 16));

    static final String[] SAS_EMOJIS = {
            "🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁",
            "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🐦", "🦆",
            "🦉", "🦇", "🐺", "🐴", "🦄", "🐝", "🦋", "🐌",
            "🐞", "🐢", "🐍", "🐙", "🐠", "🐳", "🐬", "🦈",
            "🌵", "🌲", "🌸", "🌻", "🍀", "🍁", "🍎", "🍊",
            "🍋", "🍉", "🍇", "🍓", "🍒", "🍑", "🍍", "🥑",
            "🍕", "🍔", "🍟", "🍩", "🍪", "🎂", "⚽", "🏀",
            "🎸", "🎹", "🚀", "✈️", "🚗", "⛵", "⭐", "🔥"
    };

    public static class Pt {
        public final BigInteger x, y;

        public Pt(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    public static class SpakeResult {
        public byte[] aesKey;
        public String confA;
        public String confB;
        public String sas;
    }

    public static class EncBox {
        public String nB64;
        public String ctB64;
    }

    public static class EncBytes {
        public byte[] nonce;
        public byte[] ct;
    }

    public static String b64e(byte[] b) {
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }

    public static byte[] b64d(String s) {
        return Base64.decode(s, Base64.NO_WRAP);
    }

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    public static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format(Locale.US, "%02x", v & 0xff));
        return sb.toString();
    }

    static byte[] to32(BigInteger v) {
        byte[] src = v.toByteArray();
        byte[] dst = new byte[32];
        if (src.length == 32) {
            System.arraycopy(src, 0, dst, 0, 32);
        } else if (src.length > 32) {
            System.arraycopy(src, src.length - 32, dst, 0, 32);
        } else {
            System.arraycopy(src, 0, dst, 32 - src.length, src.length);
        }
        return dst;
    }

    // ------------------------------------------------------------------ P-256 椭圆曲线点运算
    static boolean isOnCurve(Pt pt) {
        if (pt == null) return false;
        if (pt.x.signum() < 0 || pt.x.compareTo(P) >= 0 || pt.y.signum() < 0 || pt.y.compareTo(P) >= 0) return false;
        BigInteger lhs = pt.y.multiply(pt.y).mod(P);
        BigInteger rhs = pt.x.modPow(THREE, P).add(A.multiply(pt.x)).add(B).mod(P);
        return lhs.equals(rhs);
    }

    static Pt ptNeg(Pt pt) {
        return pt == null ? null : new Pt(pt.x, P.subtract(pt.y).mod(P));
    }

    static Pt ptAdd(Pt p1, Pt p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        BigInteger lam;
        if (p1.x.equals(p2.x)) {
            if (p1.y.add(p2.y).mod(P).signum() == 0) return null;
            BigInteger num = THREE.multiply(p1.x).multiply(p1.x).add(A).mod(P);
            BigInteger den = TWO.multiply(p1.y).mod(P).modInverse(P);
            lam = num.multiply(den).mod(P);
        } else {
            BigInteger num = p2.y.subtract(p1.y).mod(P);
            BigInteger den = p2.x.subtract(p1.x).mod(P).modInverse(P);
            lam = num.multiply(den).mod(P);
        }
        BigInteger x3 = lam.multiply(lam).subtract(p1.x).subtract(p2.x).mod(P);
        BigInteger y3 = lam.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(P);
        return new Pt(x3, y3);
    }

    static Pt ptSub(Pt p1, Pt p2) {
        return ptAdd(p1, ptNeg(p2));
    }

    static Pt ptMul(BigInteger k, Pt pt) {
        BigInteger v = k.mod(N);
        if (v.signum() == 0 || pt == null) return null;
        Pt res = null;
        Pt add = pt;
        int bits = v.bitLength();
        for (int i = 0; i < bits; i++) {
            if (v.testBit(i)) res = ptAdd(res, add);
            add = ptAdd(add, add);
        }
        return res;
    }

    static byte[] encPoint(Pt pt) {
        if (!isOnCurve(pt)) throw new IllegalArgumentException("point not on P-256");
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(to32(pt.x), 0, out, 1, 32);
        System.arraycopy(to32(pt.y), 0, out, 33, 32);
        return out;
    }

    static Pt decPoint(byte[] raw) {
        if (raw == null || raw.length != 65 || raw[0] != 0x04) throw new IllegalArgumentException("bad point");
        byte[] xb = new byte[32], yb = new byte[32];
        System.arraycopy(raw, 1, xb, 0, 32);
        System.arraycopy(raw, 33, yb, 0, 32);
        Pt pt = new Pt(new BigInteger(1, xb), new BigInteger(1, yb));
        if (!isOnCurve(pt)) throw new IllegalArgumentException("point not on curve");
        return pt;
    }

    // ------------------------------------------------------------------ SPAKE2-P256 核心
    static BigInteger randScalar() {
        BigInteger nm1 = N.subtract(BigInteger.ONE);
        return new BigInteger(256, RNG).mod(nm1).add(BigInteger.ONE);
    }

    static BigInteger pinToScalar(String pin) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("lanfast-spake2-w|".getBytes(UTF8));
        md.update(pin.getBytes(UTF8));
        BigInteger nm1 = N.subtract(BigInteger.ONE);
        return new BigInteger(1, md.digest()).mod(nm1).add(BigInteger.ONE);
    }

    public static String pinRouteTag(String pin, String relayKey) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("lanfast-route|".getBytes(UTF8));
        md.update((relayKey == null ? "" : relayKey).getBytes(UTF8));
        md.update("|".getBytes(UTF8));
        md.update(pin.getBytes(UTF8));
        return toHex(md.digest()).substring(0, 32);
    }

    static String hmacHex(byte[] key, String msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return toHex(mac.doFinal(msg.getBytes(UTF8)));
    }

    static SpakeResult deriveSpake2(String idA, String idB, byte[] pARaw, byte[] pBRaw, Pt kPt, BigInteger w) throws Exception {
        if (kPt == null) throw new IllegalArgumentException("invalid shared point");
        byte[] kRaw = encPoint(kPt);
        byte[] aB = idA.getBytes(UTF8);
        byte[] bB = idB.getBytes(UTF8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(ByteBuffer.allocate(4).putInt(aB.length).array());
        md.update(aB);
        md.update(ByteBuffer.allocate(4).putInt(bB.length).array());
        md.update(bB);
        md.update(pARaw);
        md.update(pBRaw);
        md.update(kRaw);
        md.update(to32(w));
        byte[] tt = md.digest();

        SpakeResult r = new SpakeResult();
        MessageDigest kd = MessageDigest.getInstance("SHA-256");
        kd.update(tt);
        kd.update("aes-256-gcm".getBytes(UTF8));
        r.aesKey = kd.digest();
        r.confA = hmacHex(tt, "confirm-A");
        r.confB = hmacHex(tt, "confirm-B");

        MessageDigest sd = MessageDigest.getInstance("SHA-256");
        sd.update(tt);
        sd.update("sas-emoji".getBytes(UTF8));
        byte[] dig = sd.digest();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) sb.append(SAS_EMOJIS[dig[i] & 63]);
        r.sas = sb.toString();
        return r;
    }

    public static class Spake2Initiator {
        final String idA;
        final BigInteger w, x;
        final byte[] pARaw;

        public Spake2Initiator(String idA, String pin) throws Exception {
            this.idA = idA;
            this.w = pinToScalar(pin);
            this.x = randScalar();
            this.pARaw = encPoint(ptAdd(ptMul(x, G), ptMul(w, M_PT)));
        }

        public String pAB64() {
            return b64e(pARaw);
        }

        public SpakeResult finish(String idB, String pBB64) throws Exception {
            byte[] pBRaw = b64d(pBB64);
            Pt pB = decPoint(pBRaw);
            Pt kPt = ptMul(x, ptSub(pB, ptMul(w, N_PT)));
            return deriveSpake2(idA, idB, pARaw, pBRaw, kPt, w);
        }
    }

    public static class Spake2Responder {
        final String idB;
        final BigInteger w, y;
        final byte[] pBRaw;

        public Spake2Responder(String idB, String pin) throws Exception {
            this.idB = idB;
            this.w = pinToScalar(pin);
            this.y = randScalar();
            this.pBRaw = encPoint(ptAdd(ptMul(y, G), ptMul(w, N_PT)));
        }

        public String pBB64() {
            return b64e(pBRaw);
        }

        public SpakeResult finish(String idA, String pAB64) throws Exception {
            byte[] pARaw = b64d(pAB64);
            Pt pA = decPoint(pARaw);
            Pt kPt = ptMul(y, ptSub(pA, ptMul(w, M_PT)));
            return deriveSpake2(idA, idB, pARaw, pBRaw, kPt, w);
        }
    }

    // ------------------------------------------------------------------ AES-256-GCM
    public static EncBytes encryptBytes(byte[] key, byte[] pt, int offset, int len, byte[] aad) throws Exception {
        byte[] nonce = randomBytes(NONCE_LEN);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, nonce));
        if (aad != null && aad.length > 0) c.updateAAD(aad);
        EncBytes res = new EncBytes();
        res.nonce = nonce;
        res.ct = c.doFinal(pt, offset, len);
        return res;
    }

    public static byte[] decryptBytes(byte[] key, byte[] nonce, byte[] ct, byte[] aad) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, nonce));
        if (aad != null && aad.length > 0) c.updateAAD(aad);
        return c.doFinal(ct);
    }

    public static EncBox encryptJson(byte[] key, JSONObject obj, String aadStr) throws Exception {
        byte[] raw = obj.toString().getBytes(UTF8);
        EncBytes eb = encryptBytes(key, raw, 0, raw.length, aadStr.getBytes(UTF8));
        EncBox box = new EncBox();
        box.nB64 = b64e(eb.nonce);
        box.ctB64 = b64e(eb.ct);
        return box;
    }

    public static JSONObject decryptJson(byte[] key, String nB64, String ctB64, String aadStr) throws Exception {
        byte[] raw = decryptBytes(key, b64d(nB64), b64d(ctB64), aadStr.getBytes(UTF8));
        return new JSONObject(new String(raw, UTF8));
    }

    public static byte[] packSeq(long seq) {
        return ByteBuffer.allocate(8).putLong(seq).array();
    }
}
