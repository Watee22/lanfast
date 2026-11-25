package com.lanfast.app;

import android.content.ContentResolver;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.SystemClock;
import android.webkit.MimeTypeMap;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Android 内置极简 HTTP/1.1 网页端服务（端口 53533，纯 Java 标准库）：
 * 让 iPhone / iPad / Mac 在同一 WiFi 或连上安卓热点时，无需安装任何 App，
 * 直接 Safari 打开 http://<安卓IP>:53533 通过 SPAKE2-P256 零明文 6 位码验证并双向互传文件与文字。
 */
public class WebBridge {
    public static final int WEB_PORT = 53533;
    static final int IO_CHUNK = 256 * 1024;
    static final Charset UTF8 = Charset.forName("UTF-8");

    static class SharedFile {
        Uri uri;
        String name;
        long size;
    }

    static class WebClient {
        String id, name, ip, token;
        final BlockingQueue<JSONObject> queue = new LinkedBlockingQueue<>();
        final HashMap<String, SharedFile> files = new HashMap<>();
    }

    static class PendingHs {
        String cid, name, ip, confA, confB, sas;
        long exp;
    }

    static class FailRec {
        int count;
        long lockUntil;
    }

    private final Core core;
    private final int port;
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final Object lock = new Object();
    private final HashMap<String, WebClient> byToken = new HashMap<>();
    private final HashMap<String, WebClient> byId = new HashMap<>();
    private final HashMap<String, PendingHs> pendingHs = new HashMap<>();
    private final HashMap<String, FailRec> failMap = new HashMap<>();

    private volatile boolean running;
    private volatile ServerSocket srv;
    private byte[] htmlBytes;

    public WebBridge(Core core, int port) {
        this.core = core;
        this.port = port;
    }

    public synchronized void start() {
        if (running) return;
        running = true;
        htmlBytes = loadHtml();
        pool.execute(this::acceptLoop);
    }

    public synchronized void stop() {
        running = false;
        Core.closeQuietly(srv);
        srv = null;
    }

    private byte[] loadHtml() {
        try (InputStream is = core.ctx.getResources().openRawResource(R.raw.web_ui);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = is.read(buf)) > 0) baos.write(buf, 0, r);
            return baos.toByteArray();
        } catch (Exception e) {
            return "<html><body>LanFast Web UI load error</body></html>".getBytes(UTF8);
        }
    }

    private void acceptLoop() {
        while (running) {
            ServerSocket ss = null;
            try {
                ss = new ServerSocket();
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress(port));
                srv = ss;
                while (running) {
                    final Socket c = ss.accept();
                    pool.execute(() -> handleHttp(c));
                }
            } catch (Exception e) {
                Core.closeQuietly(ss);
                Core.sleep(2000);
            }
        }
    }

    private void handleHttp(Socket sock) {
        String ip = sock.getInetAddress().getHostAddress();
        try (Socket s = sock) {
            s.setSoTimeout(30000);
            BufferedInputStream in = new BufferedInputStream(s.getInputStream(), IO_CHUNK);
            BufferedOutputStream out = new BufferedOutputStream(s.getOutputStream(), IO_CHUNK);

            String reqLine = readLine(in);
            if (reqLine == null || reqLine.isEmpty()) return;
            String[] parts = reqLine.split(" ");
            if (parts.length < 2) return;
            String method = parts[0];
            String fullPath = parts[1];

            HashMap<String, String> headers = new HashMap<>();
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                int idx = line.indexOf(':');
                if (idx > 0) {
                    headers.put(line.substring(0, idx).trim().toLowerCase(Locale.US), line.substring(idx + 1).trim());
                }
            }

            String path = fullPath;
            HashMap<String, String> qs = new HashMap<>();
            int q = fullPath.indexOf('?');
            if (q >= 0) {
                path = fullPath.substring(0, q);
                parseQuery(fullPath.substring(q + 1), qs);
            }

            if ("GET".equals(method) || "HEAD".equals(method)) {
                handleGet(path, qs, headers, out, s, "HEAD".equals(method));
            } else if ("POST".equals(method)) {
                handlePost(path, headers, in, out, ip);
            } else {
                sendSimple(out, 405, "text/plain", "Method Not Allowed".getBytes(UTF8));
            }
        } catch (Exception ignored) {
        }
    }

    private static String asciiFallbackName(String fname) {
        if (fname == null || fname.isEmpty()) return "download";
        int dot = fname.lastIndexOf('.');
        String stem = dot > 0 ? fname.substring(0, dot) : fname;
        String ext = dot > 0 ? fname.substring(dot) : "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < stem.length() && sb.length() < 80; i++) {
            char c = stem.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == '_' || c == '-') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        String safeStem = sb.toString().replaceAll("^_+|_+$", "");
        if (safeStem.isEmpty()) safeStem = "download";
        StringBuilder eb = new StringBuilder();
        for (int i = 0; i < ext.length() && eb.length() < 16; i++) {
            char c = ext.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.') eb.append(c);
        }
        return safeStem + eb.toString();
    }

    private static long[] parseRange(String rangeHdr, long totalSize) {
        if (rangeHdr == null || rangeHdr.isEmpty()) return null;
        String h = rangeHdr.trim();
        if (!h.toLowerCase(Locale.US).startsWith("bytes=")) return null;
        String spec = h.substring(6).trim();
        int comma = spec.indexOf(',');
        if (comma >= 0) spec = spec.substring(0, comma).trim();
        int dash = spec.indexOf('-');
        if (dash < 0 || totalSize <= 0) return new long[]{-1, -1};
        String sPart = spec.substring(0, dash).trim();
        String ePart = spec.substring(dash + 1).trim();
        try {
            long start, end;
            if (sPart.isEmpty()) {
                long suffix = Long.parseLong(ePart);
                if (suffix <= 0) return new long[]{-1, -1};
                start = Math.max(0, totalSize - suffix);
                end = totalSize - 1;
            } else {
                start = Long.parseLong(sPart);
                end = ePart.isEmpty() ? (totalSize - 1) : Long.parseLong(ePart);
                if (start < 0 || start >= totalSize || end < start) return new long[]{-1, -1};
                end = Math.min(end, totalSize - 1);
            }
            return new long[]{start, end};
        } catch (NumberFormatException e) {
            return new long[]{-1, -1};
        }
    }

    private static void skipFully(InputStream is, long n) throws IOException {
        long rem = n;
        byte[] tmp = null;
        while (rem > 0) {
            long skipped = is.skip(rem);
            if (skipped > 0) {
                rem -= skipped;
            } else {
                if (tmp == null) tmp = new byte[8192];
                int r = is.read(tmp, 0, (int) Math.min(tmp.length, rem));
                if (r < 0) break;
                rem -= r;
            }
        }
    }

    private void handleGet(String path, Map<String, String> qs, Map<String, String> headers,
                           OutputStream out, Socket s, boolean headOnly) throws Exception {
        if ("/".equals(path) || "/index.html".equals(path)) {
            if (headOnly) {
                String hdr = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=utf-8\r\n"
                        + "Content-Length: " + htmlBytes.length + "\r\n"
                        + "Cache-Control: no-store\r\n"
                        + "Connection: close\r\n\r\n";
                out.write(hdr.getBytes(UTF8));
                out.flush();
            } else {
                sendSimple(out, 200, "text/html; charset=utf-8", htmlBytes);
            }
            return;
        }
        if ("/api/info".equals(path)) {
            JSONObject j = new JSONObject();
            j.put("name", core.name);
            j.put("app", "lanfast");
            sendJson(out, 200, j);
            return;
        }
        if ("/api/check".equals(path)) {
            WebClient cli = auth(headers, qs);
            JSONObject j = new JSONObject();
            j.put("ok", cli != null);
            if (cli != null) j.put("name", core.name);
            sendJson(out, 200, j);
            return;
        }
        if ("/api/events".equals(path)) {
            WebClient cli = auth(headers, qs);
            if (cli == null) {
                sendJson(out, 401, Core.errObj("未验证或已断开", true));
                return;
            }
            s.setSoTimeout(0);
            String hdr = "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: text/event-stream; charset=utf-8\r\n"
                    + "Cache-Control: no-cache\r\n"
                    + "Connection: keep-alive\r\n\r\n: ok\n\n";
            out.write(hdr.getBytes(UTF8));
            out.flush();
            while (running && getByToken(cli.token) == cli) {
                JSONObject item = cli.queue.poll(20, TimeUnit.SECONDS);
                if (item == null) {
                    out.write(": ping\n\n".getBytes(UTF8));
                    out.flush();
                } else {
                    out.write(("data: " + item.toString() + "\n\n").getBytes(UTF8));
                    out.flush();
                    if ("kicked".equals(item.optString("type"))) break;
                }
            }
            return;
        }
        if (path.startsWith("/api/download/")) {
            WebClient cli = auth(headers, qs);
            if (cli == null) {
                sendSimple(out, 403, "text/plain", "Forbidden".getBytes(UTF8));
                return;
            }
            String rawTail = path.substring("/api/download/".length());
            int slash = rawTail.indexOf('/');
            String fid = URLDecoder.decode(slash >= 0 ? rawTail.substring(0, slash) : rawTail, "UTF-8");
            SharedFile sf;
            synchronized (lock) {
                sf = cli.files.get(fid);
            }
            if (sf == null) {
                sendSimple(out, 404, "text/plain", "Not Found".getBytes(UTF8));
                return;
            }
            boolean inline = "1".equals(qs.get("inline"));
            String ext = MimeTypeMap.getFileExtensionFromUrl(sf.name);
            String mime = ext == null ? null : MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext.toLowerCase(Locale.US));
            if (mime == null || mime.isEmpty()) mime = "application/octet-stream";
            String encodedName = URLEncoder.encode(sf.name, "UTF-8").replace("+", "%20");
            String asciiName = asciiFallbackName(sf.name);
            long[] rng = sf.size >= 0 ? parseRange(headers.get("range"), sf.size) : null;
            if (rng != null && rng[0] < 0) {
                String hdr416 = "HTTP/1.1 416 Range Not Satisfiable\r\n"
                        + "Content-Range: bytes */" + Math.max(sf.size, 0) + "\r\n"
                        + "Accept-Ranges: bytes\r\n"
                        + "Content-Length: 0\r\n"
                        + "Connection: close\r\n\r\n";
                out.write(hdr416.getBytes(UTF8));
                out.flush();
                return;
            }
            long start = 0;
            long len = sf.size;
            StringBuilder sb = new StringBuilder();
            if (rng != null) {
                start = rng[0];
                len = rng[1] - rng[0] + 1;
                sb.append("HTTP/1.1 206 Partial Content\r\n");
                sb.append("Content-Range: bytes ").append(rng[0]).append("-").append(rng[1]).append("/").append(sf.size).append("\r\n");
            } else {
                sb.append("HTTP/1.1 200 OK\r\n");
            }
            sb.append("Content-Type: ").append(mime).append("\r\n");
            if (len >= 0) {
                sb.append("Content-Length: ").append(len).append("\r\n");
                sb.append("Accept-Ranges: bytes\r\n");
            }
            sb.append("ETag: \"").append(fid).append("\"\r\n");
            sb.append("X-Content-Type-Options: nosniff\r\n");
            sb.append("Content-Disposition: ").append(inline ? "inline" : "attachment")
                    .append("; filename=\"").append(asciiName)
                    .append("\"; filename*=UTF-8''").append(encodedName).append("\r\n");
            sb.append("Connection: close\r\n\r\n");
            out.write(sb.toString().getBytes(UTF8));
            if (headOnly || len == 0) {
                out.flush();
                return;
            }
            s.setSoTimeout(0);
            ContentResolver cr = core.ctx.getContentResolver();
            try (InputStream is = cr.openInputStream(sf.uri)) {
                if (is != null) {
                    if (start > 0) skipFully(is, start);
                    byte[] buf = new byte[IO_CHUNK];
                    long rem = len;
                    while (true) {
                        int want = rem >= 0 ? (int) Math.min(buf.length, rem) : buf.length;
                        if (want <= 0) break;
                        int r = is.read(buf, 0, want);
                        if (r <= 0) break;
                        out.write(buf, 0, r);
                        if (rem >= 0) rem -= r;
                    }
                }
            }
            out.flush();
            return;
        }
        sendSimple(out, 404, "text/plain", "Not Found".getBytes(UTF8));
    }

    private void handlePost(String path, Map<String, String> headers, InputStream in,
                            OutputStream out, String ip) throws Exception {
        long cl = -1;
        String clStr = headers.get("content-length");
        if (clStr != null) {
            try {
                cl = Long.parseLong(clStr.trim());
            } catch (NumberFormatException ignored) {
            }
        }

        if ("/api/spake/hello".equals(path)) {
            if (cl <= 0 || cl > 65536) {
                sendJson(out, 400, Core.errObj("请求无效", false));
                return;
            }
            JSONObject body = new JSONObject(new String(readExact(in, (int) cl), UTF8));
            handleSpakeHello(body, ip, out);
            return;
        }
        if ("/api/spake/confirm".equals(path)) {
            if (cl <= 0 || cl > 65536) {
                sendJson(out, 400, Core.errObj("请求无效", false));
                return;
            }
            JSONObject body = new JSONObject(new String(readExact(in, (int) cl), UTF8));
            handleSpakeConfirm(body, ip, out);
            return;
        }
        if ("/api/logout".equals(path)) {
            WebClient cli = auth(headers, null);
            if (cli != null) core.removeFriend(cli.id);
            sendJson(out, 200, Core.ok());
            return;
        }
        if ("/api/text".equals(path)) {
            WebClient cli = auth(headers, null);
            if (cli == null) {
                sendJson(out, 401, Core.errObj("连接已失效，请重新输入 6 位验证码", true));
                return;
            }
            if (cl <= 0 || cl > 2 * 1024 * 1024) {
                sendJson(out, 400, Core.errObj("文字过长", false));
                return;
            }
            JSONObject body = new JSONObject(new String(readExact(in, (int) cl), UTF8));
            core.onWebIncomingText(cli.id, cli.name, body.optString("text", ""));
            sendJson(out, 200, Core.ok());
            return;
        }
        if ("/api/upload".equals(path)) {
            WebClient cli = auth(headers, null);
            if (cli == null) {
                sendJson(out, 401, Core.errObj("连接已失效，请重新输入 6 位验证码", true));
                return;
            }
            if (cl < 0) {
                sendJson(out, 400, Core.errObj("缺少 Content-Length", false));
                return;
            }
            String rawName = headers.get("x-file-name");
            String fileName = rawName == null ? "file" : URLDecoder.decode(rawName, "UTF-8");
            File dest = Core.uniqueFile(core.saveDir(), Core.safeParts(fileName));
            File parent = dest.getParentFile();
            if (parent != null) parent.mkdirs();
            File tmp = new File(dest.getPath() + ".lfpart");
            byte[] buf = new byte[IO_CHUNK];
            long got = 0, last = 0, t0 = SystemClock.uptimeMillis();
            try (FileOutputStream fo = new FileOutputStream(tmp)) {
                while (got < cl) {
                    int r = in.read(buf, 0, (int) Math.min(buf.length, cl - got));
                    if (r < 0) throw new IOException("浏览器中断了上传");
                    fo.write(buf, 0, r);
                    got += r;
                    long now = SystemClock.uptimeMillis();
                    if (now - last > 200) {
                        last = now;
                        core.reportWebStatus("🌐 接收 " + dest.getName() + "  " + Core.human(got) + "/" + Core.human(cl)
                                + "  " + Core.human(got * 1000 / Math.max(now - t0, 1)) + "/s", Core.pct(got, cl));
                    }
                }
            } catch (Exception e) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
                sendJson(out, 500, Core.errObj(e.getMessage(), false));
                return;
            }
            if (!tmp.renameTo(dest)) {
                sendJson(out, 500, Core.errObj("保存文件失败", false));
                return;
            }
            MediaScannerConnection.scanFile(core.ctx, new String[]{dest.getAbsolutePath()}, null, null);
            core.onWebIncomingFile(cli.id, cli.name, dest);
            sendJson(out, 200, Core.ok());
            return;
        }
        sendSimple(out, 404, "text/plain", "Not Found".getBytes(UTF8));
    }

    // ------------------------------------------------------------------ SPAKE2-P256 零明文验证
    private void handleSpakeHello(JSONObject body, String ip, OutputStream out) throws Exception {
        long now = System.currentTimeMillis();
        synchronized (lock) {
            FailRec fr = failMap.get(ip);
            if (fr != null && now < fr.lockUntil) {
                long wait = (fr.lockUntil - now) / 1000 + 1;
                sendJson(out, 403, Core.errObj("验证码尝试次数过多，请 " + wait + " 秒后再试", false));
                return;
            }
        }
        String cid = body.optString("id", "").trim();
        String name = body.optString("name", "网页设备").trim();
        if (name.isEmpty()) name = "网页设备";
        if (name.length() > 32) name = name.substring(0, 32);
        String pA = body.optString("pA", "").trim();
        if (cid.isEmpty() || pA.isEmpty()) {
            sendJson(out, 400, Core.errObj("握手参数不完整", false));
            return;
        }
        Crypto.Spake2Responder sp = new Crypto.Spake2Responder(core.id, core.pin);
        Crypto.SpakeResult sr;
        try {
            sr = sp.finish(cid, pA);
        } catch (Exception e) {
            sendJson(out, 400, Core.errObj("无效的曲线参数", false));
            return;
        }
        String hsId = Crypto.toHex(Crypto.randomBytes(12));
        PendingHs hs = new PendingHs();
        hs.cid = cid;
        hs.name = name;
        hs.ip = ip;
        hs.confA = sr.confA;
        hs.confB = sr.confB;
        hs.sas = sr.sas;
        hs.exp = now + 60000;
        synchronized (lock) {
            pendingHs.put(hsId, hs);
        }
        JSONObject res = new JSONObject();
        res.put("ok", true);
        res.put("hsId", hsId);
        res.put("serverId", core.id);
        res.put("pB", sp.pBB64());
        sendJson(out, 200, res);
    }

    private void handleSpakeConfirm(JSONObject body, String ip, OutputStream out) throws Exception {
        long now = System.currentTimeMillis();
        String hsId = body.optString("hsId", "").trim();
        String confA = body.optString("confA", "").trim();
        PendingHs hs;
        synchronized (lock) {
            hs = pendingHs.remove(hsId);
        }
        if (hs == null || now > hs.exp) {
            sendJson(out, 403, Core.errObj("握手已超时，请重试", false));
            return;
        }
        synchronized (lock) {
            FailRec fr = failMap.get(ip);
            if (fr != null && now < fr.lockUntil) {
                long wait = (fr.lockUntil - now) / 1000 + 1;
                sendJson(out, 403, Core.errObj("验证码尝试次数过多，请 " + wait + " 秒后再试", false));
                return;
            }
            if (!MessageDigest.isEqual(confA.getBytes(UTF8), hs.confA.getBytes(UTF8))) {
                if (fr == null) {
                    fr = new FailRec();
                    failMap.put(ip, fr);
                }
                fr.count++;
                if (fr.count >= 5) {
                    fr.count = 0;
                    fr.lockUntil = now + 30000;
                    sendJson(out, 403, Core.errObj("验证码错误次数过多，请 30 秒后再试", false));
                } else {
                    sendJson(out, 403, Core.errObj("验证码错误", false));
                }
                return;
            }
            failMap.remove(ip);
        }

        String token = Crypto.toHex(Crypto.randomBytes(24));
        WebClient cli = new WebClient();
        cli.id = hs.cid;
        cli.name = hs.name;
        cli.ip = ip;
        cli.token = token;
        synchronized (lock) {
            byToken.put(token, cli);
            byId.put(cli.id, cli);
        }
        core.registerWebDevice(cli.id, cli.name, ip, token, hs.sas);

        JSONObject res = new JSONObject();
        res.put("ok", true);
        res.put("token", token);
        res.put("clientId", cli.id);
        res.put("name", core.name);
        res.put("confB", hs.confB);
        res.put("sas", hs.sas);
        sendJson(out, 200, res);
    }

    // ------------------------------------------------------------------ 供 Core 调用的推送方法
    public void kick(String deviceId) {
        WebClient cli;
        synchronized (lock) {
            cli = byId.remove(deviceId);
            if (cli != null) byToken.remove(cli.token);
        }
        if (cli != null) {
            try {
                JSONObject j = new JSONObject();
                j.put("type", "kicked");
                j.put("reason", "对方已断开连接");
                cli.queue.offer(j);
            } catch (Exception ignored) {
            }
        }
    }

    public void pushText(String deviceId, String text) throws Exception {
        WebClient cli;
        synchronized (lock) {
            cli = byId.get(deviceId);
        }
        if (cli == null) throw new IOException("网页端已断开连接");
        JSONObject j = new JSONObject();
        j.put("type", "text");
        j.put("text", text);
        cli.queue.offer(j);
    }

    public void pushUris(String deviceId, List<Uri> uris) throws Exception {
        WebClient cli;
        synchronized (lock) {
            cli = byId.get(deviceId);
        }
        if (cli == null) throw new IOException("网页端已断开连接");
        ContentResolver cr = core.ctx.getContentResolver();
        for (Uri u : uris) {
            String nm = Core.queryName(cr, u);
            long sz = Core.querySize(cr, u);
            String fid = Crypto.toHex(Crypto.randomBytes(10));
            SharedFile sf = new SharedFile();
            sf.uri = u;
            sf.name = nm;
            sf.size = sz;
            synchronized (lock) {
                cli.files.put(fid, sf);
            }
            String low = nm.toLowerCase(Locale.US);
            boolean isImg = low.endsWith(".png") || low.endsWith(".jpg") || low.endsWith(".jpeg")
                    || low.endsWith(".gif") || low.endsWith(".webp") || low.endsWith(".bmp");
            JSONObject j = new JSONObject();
            j.put("type", "file");
            j.put("fid", fid);
            j.put("fileName", nm);
            j.put("size", Math.max(sz, 0));
            j.put("isImage", isImg);
            cli.queue.offer(j);
        }
    }

    // ------------------------------------------------------------------ HTTP 工具
    private WebClient getByToken(String tok) {
        if (tok == null || tok.isEmpty()) return null;
        synchronized (lock) {
            return byToken.get(tok);
        }
    }

    private WebClient auth(Map<String, String> headers, Map<String, String> qs) {
        String tok = headers.get("x-token");
        if ((tok == null || tok.isEmpty()) && qs != null) tok = qs.get("token");
        return getByToken(tok);
    }

    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) >= 0) {
            if (b == '\n') break;
            if (b != '\r') baos.write(b);
            if (baos.size() > 16384) throw new IOException("header line too long");
        }
        if (b < 0 && baos.size() == 0) return null;
        return new String(baos.toByteArray(), UTF8);
    }

    static byte[] readExact(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) throw new IOException("unexpected EOF");
            off += r;
        }
        return buf;
    }

    static void parseQuery(String q, Map<String, String> out) {
        for (String kv : q.split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0) {
                try {
                    out.put(URLDecoder.decode(kv.substring(0, eq), "UTF-8"),
                            URLDecoder.decode(kv.substring(eq + 1), "UTF-8"));
                } catch (Exception ignored) {
                }
            }
        }
    }

    static void sendJson(OutputStream out, int code, JSONObject obj) throws IOException {
        sendSimple(out, code, "application/json; charset=utf-8", obj.toString().getBytes(UTF8));
    }

    static void sendSimple(OutputStream out, int code, String contentType, byte[] body) throws IOException {
        String status = code == 200 ? "OK" : (code == 401 ? "Unauthorized" : (code == 403 ? "Forbidden" : (code == 404 ? "Not Found" : "Error")));
        String hdr = "HTTP/1.1 " + code + " " + status + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Cache-Control: no-store\r\n"
                + "Connection: close\r\n\r\n";
        out.write(hdr.getBytes(UTF8));
        out.write(body);
        out.flush();
    }
}
