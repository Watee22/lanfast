package com.lanfast.app;

import android.util.Base64;

import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * LanFast 端到端加密工具（ECDH P-256 + HMAC-SHA256 + AES-256-GCM）
 * 全部使用 Android 内置 JCA，零第三方依赖，与 Windows 端 cryptography 字节级互通。
 */
public class Crypto {
    static final int NONCE_LEN = 12;
    static final int TAG_LEN = 16;
    static final int ENC_CHUNK = 256 * 1024;
    static final Charset UTF8 = Charset.forName("UTF-8");
    static final SecureRandom RNG = new SecureRandom();

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

    public static KeyPair genEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), RNG);
        return kpg.generateKeyPair();
    }

    public static String pubB64(KeyPair kp) {
        return b64e(kp.getPublic().getEncoded());
    }

    public static byte[] ecdhSecret(PrivateKey priv, String peerPubB64) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        PublicKey peerPub = kf.generatePublic(new X509EncodedKeySpec(b64d(peerPubB64)));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(peerPub, true);
        return ka.generateSecret();
    }

    public static String pinProof(byte[] sharedZ, String pin, byte[] saltA, byte[] saltB) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(sharedZ, "HmacSHA256"));
        mac.update("lanfast-pin|".getBytes(UTF8));
        mac.update(pin.getBytes(UTF8));
        mac.update("|".getBytes(UTF8));
        mac.update(saltA);
        mac.update("|".getBytes(UTF8));
        mac.update(saltB);
        return toHex(mac.doFinal());
    }

    public static byte[] deriveSessionKey(byte[] sharedZ, String pin, byte[] saltA, byte[] saltB) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sharedZ);
        md.update("lanfast-e2ee-v4".getBytes(UTF8));
        md.update(pin.getBytes(UTF8));
        md.update(saltA);
        md.update(saltB);
        return md.digest();
    }

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
