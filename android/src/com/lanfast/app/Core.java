package com.lanfast.app;

import android.app.Notification;
import android.app.NotificationManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.provider.OpenableColumns;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * LanFast 核心 v3：
 *  * 逐对 6 位验证码加好友（双向校验会话 token，支持多好友独立对话窗口）
 *  * 局域网直连（UDP 组播/广播发现 + TCP 直传）
 *  * 公网中转兜底（透明 TCP 隧道，局域网不通时自动走公网中转，跨网也只需输 6 位码）
 */
public class Core {
    public static final String APP = "lanfast";
    public static final int PROTO_VERSION = 5;
    public static final int DISCOVERY_PORT = 53530;
    public static final int TRANSFER_PORT = 53531;
    public static final int DEFAULT_RELAY_PORT = 53532;
    public static final String MCAST = "224.0.0.167";
    static final int CHUNK = 256 * 1024;
    static final long DEVICE_TIMEOUT = 15000;
    static final int MAX_PIN_FAILS = 5;
    static final long PIN_LOCK_MS = 30000;
    static final Charset UTF8 = Charset.forName("UTF-8");

    public interface Listener {
        void onFriendsChanged();

        void onFriendAdded(Device d);

        void onDiscoveredChanged();

        void onRelayState(boolean connected, String text);

        void onMessage(Msg m);

        void onStatus(String text, int percent);
    }

    public interface PairCallback {
        void onResult(boolean ok, Device dev, String message);
    }

    public static class Device {
        public String id, name, os, ip, token, sas, bootId;
        public byte[] key; // 32 字节 AES-256-GCM 端到端会话密钥
        public int port;
        public boolean viaRelay;
        public long lastSeen;

        public String label() {
            if ("web".equals(os)) return "🌐 " + name;
            return ("android".equals(os) ? "📱 " : "💻 ") + name;
        }

        public String loc() {
            return (ip != null && !ip.isEmpty()) ? ip : "公网中转";
        }
    }

    public static class Msg {
        public String peerId, peer, text, path, route;
        public boolean incoming, isFile, error;
        public long size;
        public long time = System.currentTimeMillis();
    }

    static class FailState {
        int count;
        long lockUntil;
    }

    static class HostPort {
        String host;
        int port;
        boolean useTls;
    }

    static class Conn {
        Socket sock;
        String route;
    }

    private static Core inst;

    public static synchronized Core get(Context c) {
        if (inst == null) inst = new Core(c.getApplicationContext());
        return inst;
    }

    public final Context ctx;
    public final String id;
    public volatile String bootId;
    public volatile String pin;
    public volatile String name;
    public volatile String relayAddr;
    public volatile String relayKey;
    public volatile String p2pUrl;
    public volatile boolean relayConnected;
    public volatile String relayStatusText = "仅局域网（点击配置公网中转）";
    public volatile Listener listener;

    // 仅在主线程访问：每个好友独立的聊天记录与未读数
    public final LinkedHashMap<String, ArrayList<Msg>> chats = new LinkedHashMap<>();
    public final HashMap<String, Integer> unread = new HashMap<>();

    private final Handler main = new Handler(Looper.getMainLooper());
    private final SharedPreferences prefs;
    private final SecureRandom rng = new SecureRandom();
    private final LinkedHashMap<String, Device> paired = new LinkedHashMap<>();
    private final LinkedHashMap<String, Device> discovered = new LinkedHashMap<>();
    private final Map<String, FailState> failMap = new HashMap<>();
    private final Set<String> joined = new HashSet<>();
    private final ExecutorService sender = Executors.newSingleThreadExecutor();
    private final ExecutorService pool = Executors.newCachedThreadPool();
    public final WebBridge webBridge;

    private volatile boolean running;
    private volatile int gen;
    private volatile int relayGen;
    private volatile Socket relaySock;
    private final Object relayWriteLock = new Object();
    private volatile MulticastSocket udp;
    private volatile ServerSocket server;
    private WifiManager.MulticastLock mlock;
    private WifiManager.WifiLock wlock;
    private int notifyId = 100;

    private Core(Context c) {
        ctx = c;
        prefs = c.getSharedPreferences("lanfast", 0);
        String i = prefs.getString("id", null);
        if (i == null) {
            i = UUID.randomUUID().toString().replace("-", "");
            prefs.edit().putString("id", i).apply();
        }
        id = i;
        bootId = randomHex(4);
        pin = generatePin();
        name = prefs.getString("name", Build.MODEL);
        relayAddr = prefs.getString("relay_addr", "");
        relayKey = prefs.getString("relay_key", "");
        p2pUrl = prefs.getString("p2p_url", "");
        webBridge = new WebBridge(this, WebBridge.WEB_PORT);
    }

    public void setP2pUrl(String url) {
        String u = url == null ? "" : url.trim();
        if (!u.isEmpty() && !u.startsWith("http://") && !u.startsWith("https://")) {
            u = "https://" + u;
        }
        p2pUrl = u;
        prefs.edit().putString("p2p_url", p2pUrl).apply();
    }

    private String generatePin() {
        return String.format(Locale.US, "%06d", rng.nextInt(1_000_000));
    }

    private String randomHex(int bytes) {
        byte[] b = new byte[bytes];
        rng.nextBytes(b);
        StringBuilder sb = new StringBuilder(bytes * 2);
        for (byte v : b) sb.append(String.format(Locale.US, "%02x", v & 0xff));
        return sb.toString();
    }

    public static String fmtPin(String p) {
        return (p != null && p.length() == 6) ? (p.substring(0, 3) + " " + p.substring(3)) : (p == null ? "" : p);
    }

    static HostPort parseRelay(String addr) {
        if (addr == null) return null;
        String s = addr.trim();
        if (s.isEmpty()) return null;
        HostPort hp = new HostPort();
        String low = s.toLowerCase(Locale.US);
        if (low.startsWith("tls://")) {
            hp.useTls = true;
            s = s.substring(6);
        } else if (low.startsWith("tcp://")) {
            s = s.substring(6);
        }
        int idx = s.lastIndexOf(':');
        if (idx > 0 && idx < s.length() - 1) {
            hp.host = s.substring(0, idx).trim();
            try {
                hp.port = Integer.parseInt(s.substring(idx + 1).trim());
            } catch (NumberFormatException e) {
                hp.port = DEFAULT_RELAY_PORT;
            }
        } else {
            hp.host = s;
            hp.port = DEFAULT_RELAY_PORT;
        }
        return hp.host.isEmpty() ? null : hp;
    }

    static Socket connectRelaySocket(String host, int port, boolean useTls, int timeoutMs) throws IOException {
        Socket raw = new Socket();
        raw.connect(new InetSocketAddress(host, port), timeoutMs);
        if (!useTls) return raw;
        SSLSocket ssl = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, port, true);
        ssl.setSoTimeout(timeoutMs);
        ssl.startHandshake();
        return ssl;
    }

    // ------------------------------------------------------------------ 生命周期
    public synchronized void start() {
        if (running) return;
        running = true;
        WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
        if (wm != null) {
            mlock = wm.createMulticastLock("lanfast");
            mlock.setReferenceCounted(false);
            mlock.acquire();
            wlock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "lanfast");
            wlock.setReferenceCounted(true);
        }
        final int g = ++gen;
        pool.execute(() -> serverLoop(g));
        pool.execute(() -> udpLoop(g));
        pool.execute(() -> announceLoop(g));
        webBridge.start();
        restartRelay();
    }

    private boolean alive(int g) {
        return running && gen == g;
    }

    public synchronized void stop() {
        if (!running) return;
        running = false;
        relayGen++;
        webBridge.stop();
        final MulticastSocket u = udp;
        final ServerSocket s = server;
        final Socket rs = relaySock;
        relaySock = null;
        new Thread(() -> {
            try {
                sendAll("bye");
            } catch (Exception ignored) {
            }
            closeQuietly(u);
            closeQuietly(s);
            closeQuietly(rs);
        }).start();
        if (mlock != null && mlock.isHeld()) mlock.release();
    }

    public String regeneratePin() {
        pin = generatePin();
        synchronized (failMap) {
            failMap.clear();
        }
        sendRelayUpdate();
        return pin;
    }

    public void setName(String n) {
        name = n;
        prefs.edit().putString("name", n).apply();
        sendRelayUpdate();
        refresh();
    }

    public void setRelay(String addr, String key) {
        relayAddr = addr == null ? "" : addr.trim();
        relayKey = key == null ? "" : key.trim();
        prefs.edit().putString("relay_addr", relayAddr).putString("relay_key", relayKey).apply();
        restartRelay();
    }

    public void refresh() {
        pool.execute(() -> sendAll("hello"));
    }

    // ------------------------------------------------------------------ 好友与聊天记录
    public List<Device> friends() {
        ArrayList<Device> l;
        synchronized (paired) {
            l = new ArrayList<>(paired.values());
        }
        Collections.sort(l, (a, b) -> (a.os + a.name).compareTo(b.os + b.name));
        return l;
    }

    public Device friend(String did) {
        synchronized (paired) {
            return did == null ? null : paired.get(did);
        }
    }

    public void registerWebDevice(String cid, String nm, String ip, String token, String sas) {
        Device d = new Device();
        d.id = cid;
        d.name = nm;
        d.os = "web";
        d.ip = ip;
        d.port = WebBridge.WEB_PORT;
        d.token = token;
        d.sas = sas;
        d.lastSeen = System.currentTimeMillis();
        saveFriend(d);
        status("🌐 网页设备 " + nm + " 已通过 SPAKE2 连接（安全码 " + sas + "）", -1);
    }

    public void onWebIncomingText(String peerId, String peerName, String text) {
        Msg m = new Msg();
        m.peerId = peerId;
        m.peer = peerName;
        m.incoming = true;
        m.route = "网页端";
        m.text = text;
        post(m);
    }

    public void onWebIncomingFile(String peerId, String peerName, File f) {
        Msg m = new Msg();
        m.peerId = peerId;
        m.peer = peerName;
        m.incoming = true;
        m.isFile = true;
        m.route = "网页端";
        m.text = f.getName();
        m.path = f.getAbsolutePath();
        m.size = f.length();
        post(m);
        status("🌐 [网页端] 已接收 " + f.getName(), 100);
    }

    public void reportWebStatus(String s, int percent) {
        status(s, percent);
    }

    public void removeFriend(String did) {
        Device removed;
        synchronized (paired) {
            removed = paired.remove(did);
        }
        if (removed != null && "web".equals(removed.os)) {
            webBridge.kick(did);
        }
        fireFriends();
    }

    public int discoveredCount() {
        synchronized (discovered) {
            return discovered.size();
        }
    }

    public ArrayList<Msg> chatOf(String peerId) {
        ArrayList<Msg> l = chats.get(peerId);
        if (l == null) {
            l = new ArrayList<>();
            chats.put(peerId, l);
        }
        return l;
    }

    // ------------------------------------------------------------------ 公网中转长连接
    private void restartRelay() {
        final int rg = ++relayGen;
        closeQuietly(relaySock);
        relaySock = null;
        relayConnected = false;
        HostPort hp = parseRelay(relayAddr);
        if (hp == null || !running) {
            fireRelayState(false, "仅局域网（点击配置公网中转）");
            return;
        }
        final String host = hp.host;
        final int port = hp.port;
        final boolean useTls = hp.useTls;
        final String key = relayKey;
        pool.execute(() -> relayLoop(rg, host, port, useTls, key));
    }

    private void sendRelayUpdate() {
        final Socket s = relaySock;
        if (s == null || !relayConnected) return;
        pool.execute(() -> {
            try {
                JSONObject j = new JSONObject();
                j.put("app", APP);
                j.put("type", "relay_update");
                j.put("pin_tag", Crypto.pinRouteTag(pin, relayKey));
                j.put("name", name);
                j.put("boot", bootId);
                synchronized (relayWriteLock) {
                    writeFrame(new DataOutputStream(new BufferedOutputStream(s.getOutputStream())), j);
                }
            } catch (Exception ignored) {
            }
        });
    }

    private void relayLoop(int rg, String host, int port, boolean useTls, String key) {
        while (running && relayGen == rg) {
            fireRelayState(false, "正在连接中转 " + host + ":" + port + "…");
            Socket s = null;
            try {
                s = connectRelaySocket(host, port, useTls, 8000);
                s.setSoTimeout(25000);
                DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
                DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
                JSONObject reg = new JSONObject();
                reg.put("app", APP);
                reg.put("type", "relay_register");
                reg.put("key", key);
                reg.put("id", id);
                reg.put("name", name);
                reg.put("os", "android");
                reg.put("pin_tag", Crypto.pinRouteTag(pin, key));
                reg.put("boot", bootId);
                synchronized (relayWriteLock) {
                    writeFrame(out, reg);
                }
                JSONObject ack = readFrame(in);
                if (ack == null || !ack.optBoolean("ok")) {
                    String err = ack == null ? "注册失败" : ack.optString("error", "注册失败");
                    fireRelayState(false, "中转失败：" + err);
                    closeQuietly(s);
                    sleep(8000);
                    continue;
                }
                relaySock = s;
                relayConnected = true;
                fireRelayState(true, (useTls ? "TLS " : "") + "公网中转已连接 (" + host + ":" + port + ")");
                while (running && relayGen == rg) {
                    try {
                        JSONObject msg = readFrame(in);
                        if (msg == null) break;
                        if ("tunnel_incoming".equals(msg.optString("type"))) {
                            final String sid = msg.optString("streamId");
                            if (!sid.isEmpty()) {
                                pool.execute(() -> joinRelayTunnel(host, port, useTls, key, sid));
                            }
                        }
                    } catch (SocketTimeoutException te) {
                        JSONObject ping = new JSONObject();
                        ping.put("app", APP);
                        ping.put("type", "relay_ping");
                        synchronized (relayWriteLock) {
                            writeFrame(out, ping);
                        }
                    }
                }
            } catch (Exception ignored) {
            } finally {
                relayConnected = false;
                if (relaySock == s) relaySock = null;
                closeQuietly(s);
            }
            if (running && relayGen == rg) {
                fireRelayState(false, "中转已断开，正在重连…");
                sleep(4000);
            }
        }
    }

    private void joinRelayTunnel(String host, int port, boolean useTls, String key, String streamId) {
        try {
            Socket s = connectRelaySocket(host, port, useTls, 8000);
            s.setSoTimeout(15000);
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
            JSONObject j = new JSONObject();
            j.put("app", APP);
            j.put("type", "tunnel_join");
            j.put("key", key);
            j.put("streamId", streamId);
            writeFrame(out, j);
            JSONObject ack = readFrame(in);
            if (ack == null || !ack.optBoolean("ok")) {
                closeQuietly(s);
                return;
            }
            handleConn(s, "", true);
        } catch (Exception ignored) {
        }
    }

    private Socket openRelayTunnel(String toId, String targetPin) throws Exception {
        HostPort hp = parseRelay(relayAddr);
        if (hp == null) throw new IOException("未配置公网中转服务器");
        Socket s = null;
        try {
            s = connectRelaySocket(hp.host, hp.port, hp.useTls, 8000);
            s.setSoTimeout(20000);
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
            JSONObject req = new JSONObject();
            req.put("app", APP);
            req.put("type", "tunnel_open");
            req.put("key", relayKey);
            req.put("from", id);
            if (toId != null && !toId.isEmpty()) req.put("to", toId);
            if (targetPin != null && !targetPin.isEmpty()) req.put("pin_tag", Crypto.pinRouteTag(targetPin, relayKey));
            writeFrame(out, req);
            JSONObject ack = readFrame(in);
            if (ack == null || !ack.optBoolean("ok")) {
                throw new IOException(ack == null ? "中转服务器无响应" : ack.optString("error", "建立中转隧道失败"));
            }
            s.setSoTimeout(60000);
            return s;
        } catch (Exception e) {
            closeQuietly(s);
            throw e;
        }
    }

    // ------------------------------------------------------------------ 网络接口与局域网发现
    static class Iface {
        NetworkInterface ni;
        Inet4Address addr;
        InetAddress bcast;
    }

    static boolean skipIface(String n) {
        n = n.toLowerCase(Locale.US);
        return n.startsWith("rmnet") || n.startsWith("ccmni") || n.startsWith("dummy") || n.startsWith("lo");
    }

    static List<Iface> ifaces() {
        ArrayList<Iface> list = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback() || skipIface(ni.getName())) continue;
                for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                    InetAddress a = ia.getAddress();
                    if (a instanceof Inet4Address && !a.isLinkLocalAddress() && !a.isLoopbackAddress()) {
                        Iface f = new Iface();
                        f.ni = ni;
                        f.addr = (Inet4Address) a;
                        f.bcast = ia.getBroadcast();
                        list.add(f);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return list;
    }

    public static String localIp() {
        String fallback = "";
        for (Iface f : ifaces()) {
            String n = f.ni.getName().toLowerCase(Locale.US);
            String ip = f.addr.getHostAddress();
            if (n.startsWith("wlan") || n.startsWith("ap") || n.startsWith("swlan") || n.startsWith("eth")) return ip;
            if (fallback.isEmpty()) fallback = ip;
        }
        return fallback.isEmpty() ? "未连 WiFi" : fallback;
    }

    private JSONObject me(String type) {
        JSONObject j = new JSONObject();
        try {
            j.put("app", APP);
            j.put("v", PROTO_VERSION);
            j.put("type", type);
            j.put("id", id);
            j.put("name", name);
            j.put("os", "android");
            j.put("port", TRANSFER_PORT);
            j.put("boot", bootId);
        } catch (Exception ignored) {
        }
        return j;
    }

    private void sendAll(String type) {
        byte[] data = me(type).toString().getBytes(UTF8);
        for (Iface f : ifaces()) {
            MulticastSocket s = null;
            try {
                s = new MulticastSocket(new InetSocketAddress(f.addr, 0));
                s.setBroadcast(true);
                s.setTimeToLive(1);
                try {
                    s.setNetworkInterface(f.ni);
                } catch (Exception ignored) {
                }
                trySend(s, data, InetAddress.getByName(MCAST));
                trySend(s, data, InetAddress.getByName("255.255.255.255"));
                if (f.bcast != null) trySend(s, data, f.bcast);
            } catch (Exception ignored) {
            } finally {
                if (s != null) s.close();
            }
        }
    }

    private static void trySend(MulticastSocket s, byte[] data, InetAddress dst) {
        try {
            s.send(new DatagramPacket(data, data.length, dst, DISCOVERY_PORT));
        } catch (Exception ignored) {
        }
    }

    private void joinGroups() {
        MulticastSocket s = udp;
        if (s == null) return;
        try {
            InetAddress g = InetAddress.getByName(MCAST);
            for (Iface f : ifaces()) {
                String key = f.ni.getName();
                synchronized (joined) {
                    if (joined.contains(key)) continue;
                }
                try {
                    s.joinGroup(new InetSocketAddress(g, 0), f.ni);
                    synchronized (joined) {
                        joined.add(key);
                    }
                } catch (Exception ignored) {
                }
            }
            synchronized (joined) {
                if (!joined.contains("*")) {
                    try {
                        s.joinGroup(g);
                        joined.add("*");
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void udpLoop(int g) {
        while (alive(g)) {
            MulticastSocket s = null;
            try {
                s = new MulticastSocket(null);
                s.setReuseAddress(true);
                s.bind(new InetSocketAddress(DISCOVERY_PORT));
                s.setBroadcast(true);
                udp = s;
                synchronized (joined) {
                    joined.clear();
                }
                joinGroups();
                byte[] buf = new byte[8192];
                while (alive(g)) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    s.receive(p);
                    handleUdp(new String(p.getData(), p.getOffset(), p.getLength(), UTF8),
                            p.getAddress().getHostAddress());
                }
            } catch (Exception e) {
                closeQuietly(s);
                sleep(2000);
            }
        }
    }

    private void handleUdp(String text, String ip) {
        try {
            JSONObject j = new JSONObject(text);
            if (!APP.equals(j.optString("app")) || id.equals(j.optString("id"))) return;
            String t = j.optString("type");
            String did = j.optString("id");
            if ("bye".equals(t)) {
                boolean fChanged;
                synchronized (discovered) {
                    discovered.remove(did);
                }
                synchronized (paired) {
                    fChanged = (paired.remove(did) != null);
                }
                fireDiscovered();
                if (fChanged) fireFriends();
                return;
            }
            touchDiscovered(j, ip);
            if ("hello".equals(t)) {
                byte[] r = me("reply").toString().getBytes(UTF8);
                MulticastSocket s = udp;
                if (s != null) s.send(new DatagramPacket(r, r.length, InetAddress.getByName(ip), DISCOVERY_PORT));
            }
        } catch (Exception ignored) {
        }
    }

    private void announceLoop(int g) {
        while (alive(g)) {
            joinGroups();
            sendAll("hello");
            boolean changed;
            long now = System.currentTimeMillis();
            synchronized (discovered) {
                ArrayList<String> dead = new ArrayList<>();
                for (Device d : discovered.values())
                    if (now - d.lastSeen > DEVICE_TIMEOUT) dead.add(d.id);
                for (String k : dead) discovered.remove(k);
                changed = !dead.isEmpty();
            }
            if (changed) fireDiscovered();
            sleep(4000);
        }
    }

    private void touchDiscovered(JSONObject j, String ip) {
        String did = j.optString("id");
        if (did.isEmpty() || did.equals(id)) return;
        String nm = j.optString("name", "?");
        String os = j.optString("os", "?");
        String boot = j.optString("boot", "");
        int port = j.optInt("port", TRANSFER_PORT);

        boolean dChanged;
        synchronized (discovered) {
            Device d = discovered.get(did);
            if (d == null) {
                d = new Device();
                d.id = did;
                d.name = nm;
                d.os = os;
                d.ip = ip;
                d.port = port;
                d.bootId = boot;
                d.lastSeen = System.currentTimeMillis();
                discovered.put(did, d);
                dChanged = true;
            } else {
                dChanged = !ip.equals(d.ip) || !nm.equals(d.name);
                d.ip = ip;
                d.name = nm;
                d.os = os;
                d.port = port;
                d.bootId = boot;
                d.lastSeen = System.currentTimeMillis();
            }
        }
        if (dChanged) fireDiscovered();

        boolean fChanged = false;
        synchronized (paired) {
            Device p = paired.get(did);
            if (p != null) {
                if (p.bootId != null && !p.bootId.isEmpty() && !boot.isEmpty() && !p.bootId.equals(boot)) {
                    paired.remove(did);
                    fChanged = true;
                } else {
                    if (!ip.equals(p.ip) || !nm.equals(p.name)) {
                        p.ip = ip;
                        p.name = nm;
                        p.viaRelay = false;
                        fChanged = true;
                    }
                    p.port = port;
                    p.lastSeen = System.currentTimeMillis();
                }
            }
        }
        if (fChanged) fireFriends();
    }

    // ------------------------------------------------------------------ 6 位验证码加好友
    static class PairTry {
        boolean ok;
        Device device;
        String error;
        String route;
    }

    private PairTry doPairOverSocket(Socket s, String targetPin, String ip, int port, boolean viaRelay) throws Exception {
        PairTry r = new PairTry();
        r.route = viaRelay ? "公网中转" : "局域网直连";
        DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
        DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));

        Crypto.Spake2Initiator sp = new Crypto.Spake2Initiator(id, targetPin);
        JSONObject hello = me("spake_hello");
        hello.put("pA", sp.pAB64());
        writeFrame(out, hello);

        JSONObject reply = readFrame(in);
        if (reply == null || !reply.optBoolean("ok") || reply.optString("pB").isEmpty() || reply.optString("id").isEmpty()) {
            r.error = reply == null ? "对方无响应" : reply.optString("error", "对方版本过旧，请升级两端至 v5 (SPAKE2)");
            return r;
        }
        Crypto.SpakeResult sr = sp.finish(reply.optString("id"), reply.optString("pB"));

        JSONObject ver = new JSONObject();
        ver.put("app", APP);
        ver.put("v", PROTO_VERSION);
        ver.put("type", "spake_confirm");
        ver.put("confA", sr.confA);
        writeFrame(out, ver);

        JSONObject ack = readFrame(in);
        if (ack != null && ack.optBoolean("ok") && !ack.optString("n").isEmpty() && !ack.optString("ct").isEmpty()) {
            JSONObject box = Crypto.decryptJson(sr.aesKey, ack.optString("n"), ack.optString("ct"), "spake_ok");
            if (!MessageDigest.isEqual(sr.confB.getBytes(UTF8), box.optString("confB", "").getBytes(UTF8))) {
                r.error = "双向密钥确认失败（疑似中间人攻击）";
                return r;
            }
            String tok = box.optString("token");
            if (tok.isEmpty()) {
                r.error = "加密令牌校验失败";
                return r;
            }
            Device d = new Device();
            d.id = reply.optString("id");
            d.name = reply.optString("name", ip.isEmpty() ? "好友" : ip);
            d.os = reply.optString("os", "windows");
            d.ip = viaRelay ? "" : ip;
            d.port = reply.optInt("port", port);
            d.token = tok;
            d.key = sr.aesKey;
            d.sas = sr.sas;
            d.bootId = reply.optString("boot", "");
            d.viaRelay = viaRelay;
            d.lastSeen = System.currentTimeMillis();
            if (viaRelay) {
                synchronized (discovered) {
                    Device lan = discovered.get(d.id);
                    if (lan != null) {
                        d.ip = lan.ip;
                        d.port = lan.port;
                        d.viaRelay = false;
                    }
                }
            }
            r.ok = true;
            r.device = d;
        } else {
            r.error = ack == null ? "对方无响应" : ack.optString("error", "验证码错误");
        }
        return r;
    }

    public void pairByPin(final String targetPin, final String manualIp, final PairCallback cb) {
        final String cleanPin = targetPin == null ? "" : targetPin.trim().replace(" ", "");
        final String cleanIp = manualIp == null ? "" : manualIp.trim();
        pool.execute(() -> {
            if (!cleanPin.matches("\\d{6}")) {
                postPair(cb, false, null, "请输入完整的 6 位数字验证码");
                return;
            }
            if (!cleanIp.isEmpty()) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(cleanIp, TRANSFER_PORT), 4000);
                    s.setSoTimeout(5000);
                    PairTry r = doPairOverSocket(s, cleanPin, cleanIp, TRANSFER_PORT, false);
                    if (r.ok) {
                        saveFriend(r.device);
                        postPair(cb, true, r.device, "已添加好友 " + r.device.name + "（局域网直连）");
                    } else {
                        postPair(cb, false, null, r.error);
                    }
                } catch (Exception e) {
                    postPair(cb, false, null, "连接 " + cleanIp + " 失败：" + e.getMessage());
                }
                return;
            }

            // 1) 优先在局域网已发现设备中并发匹配
            List<Device> cands;
            synchronized (discovered) {
                cands = new ArrayList<>(discovered.values());
            }
            if (cands.isEmpty()) {
                sendAll("hello");
                sleep(900);
                synchronized (discovered) {
                    cands = new ArrayList<>(discovered.values());
                }
            }

            final AtomicReference<PairTry> winner = new AtomicReference<>();
            final AtomicReference<String> lastErr = new AtomicReference<>(null);
            if (!cands.isEmpty()) {
                final CountDownLatch latch = new CountDownLatch(cands.size());
                for (final Device cand : cands) {
                    pool.execute(() -> {
                        try (Socket s = new Socket()) {
                            s.connect(new InetSocketAddress(cand.ip, cand.port), 2500);
                            s.setSoTimeout(4000);
                            PairTry r = doPairOverSocket(s, cleanPin, cand.ip, cand.port, false);
                            if (r.ok) winner.compareAndSet(null, r);
                            else if (r.error != null) lastErr.set(r.error);
                        } catch (Exception e) {
                            lastErr.set(e.getMessage());
                        } finally {
                            latch.countDown();
                        }
                    });
                }
                try {
                    latch.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                }
                PairTry win = winner.get();
                if (win != null) {
                    saveFriend(win.device);
                    postPair(cb, true, win.device, "已添加好友 " + win.device.name + "（局域网直连）");
                    return;
                }
            }

            // 2) 局域网未命中，若配置了公网中转，通过中转按 6 位码查找对方
            if (parseRelay(relayAddr) != null) {
                try (Socket s = openRelayTunnel("", cleanPin)) {
                    PairTry r = doPairOverSocket(s, cleanPin, "", TRANSFER_PORT, true);
                    if (r.ok) {
                        saveFriend(r.device);
                        postPair(cb, true, r.device, "已添加好友 " + r.device.name + "（公网中转）");
                        return;
                    }
                    lastErr.set(r.error);
                } catch (Exception e) {
                    lastErr.set(e.getMessage());
                }
            }

            String err = lastErr.get();
            if (err == null || err.isEmpty()) {
                err = "未找到该 6 位验证码对应的设备。\n请确认在同一 WiFi（或已连接同一公网中转），或填写对方 IP。";
            }
            postPair(cb, false, null, err);
        });
    }

    private void saveFriend(final Device d) {
        synchronized (paired) {
            paired.put(d.id, d);
        }
        fireFriends();
        main.post(() -> {
            Listener l = listener;
            if (l != null) l.onFriendAdded(d);
        });
    }

    private void postPair(final PairCallback cb, final boolean ok, final Device d, final String msg) {
        main.post(() -> {
            if (cb != null) cb.onResult(ok, d, msg);
        });
    }

    // ------------------------------------------------------------------ 接收端（含本机 6 位码验证）
    private void serverLoop(int g) {
        while (alive(g)) {
            ServerSocket ss = null;
            try {
                ss = new ServerSocket();
                ss.setReuseAddress(true);
                ss.bind(new InetSocketAddress(TRANSFER_PORT));
                server = ss;
                while (alive(g)) {
                    final Socket c = ss.accept();
                    pool.execute(() -> handleConn(c, c.getInetAddress().getHostAddress(), false));
                }
            } catch (Exception e) {
                closeQuietly(ss);
                sleep(2000);
            }
        }
    }

    private void handlePairHandshake(DataInputStream in, DataOutputStream out, JSONObject hello, String ip, boolean viaRelay) throws Exception {
        long now = System.currentTimeMillis();
        String rateKey = viaRelay ? ("relay:" + hello.optString("id")) : ip;
        synchronized (failMap) {
            FailState fs = failMap.get(rateKey);
            if (fs != null && now < fs.lockUntil) {
                long wait = (fs.lockUntil - now) / 1000 + 1;
                writeFrame(out, errObj("验证码尝试次数过多，请 " + wait + " 秒后再试", false));
                return;
            }
        }
        String did = hello.optString("id");
        String pA = hello.optString("pA");
        if (did.isEmpty() || did.equals(id) || pA.isEmpty()) {
            writeFrame(out, errObj("无效的 SPAKE2 握手请求", false));
            return;
        }
        Crypto.Spake2Responder sp = new Crypto.Spake2Responder(id, pin);
        Crypto.SpakeResult sr;
        try {
            sr = sp.finish(did, pA);
        } catch (Exception ex) {
            writeFrame(out, errObj("无效的椭圆曲线点", false));
            return;
        }

        JSONObject reply = me("spake_reply");
        reply.put("ok", true);
        reply.put("pB", sp.pBB64());
        writeFrame(out, reply);

        JSONObject ver = readFrame(in);
        if (ver == null || !"spake_confirm".equals(ver.optString("type"))) return;

        String gotA = ver.optString("confA", "");
        synchronized (failMap) {
            if (!MessageDigest.isEqual(gotA.getBytes(UTF8), sr.confA.getBytes(UTF8))) {
                FailState fs = failMap.get(rateKey);
                if (fs == null) {
                    fs = new FailState();
                    failMap.put(rateKey, fs);
                }
                fs.count++;
                if (fs.count >= MAX_PIN_FAILS) {
                    fs.count = 0;
                    fs.lockUntil = now + PIN_LOCK_MS;
                    writeFrame(out, errObj("验证码错误次数过多，请 30 秒后再试", false));
                } else {
                    writeFrame(out, errObj("验证码错误", false));
                }
                return;
            }
            failMap.remove(rateKey);
        }

        String token = randomHex(24);
        Device d = new Device();
        d.id = did;
        d.name = hello.optString("name", ip.isEmpty() ? "好友" : ip);
        d.os = hello.optString("os", "windows");
        d.port = hello.optInt("port", TRANSFER_PORT);
        d.token = token;
        d.key = sr.aesKey;
        d.sas = sr.sas;
        d.bootId = hello.optString("boot", "");
        d.lastSeen = System.currentTimeMillis();
        if (viaRelay) {
            synchronized (discovered) {
                Device lan = discovered.get(did);
                d.ip = lan != null ? lan.ip : "";
            }
            d.viaRelay = d.ip.isEmpty();
        } else {
            d.ip = ip;
            d.viaRelay = false;
        }
        saveFriend(d);
        status("🔒 " + d.name + " 已通过 SPAKE2 验证加为好友（安全码 " + sr.sas + "）", -1);

        JSONObject tokObj = new JSONObject();
        tokObj.put("token", token);
        tokObj.put("confB", sr.confB);
        Crypto.EncBox box = Crypto.encryptJson(sr.aesKey, tokObj, "spake_ok");
        JSONObject ack = new JSONObject();
        ack.put("ok", true);
        ack.put("type", "spake_ok");
        ack.put("n", box.nB64);
        ack.put("ct", box.ctB64);
        writeFrame(out, ack);
    }

    private void handleConn(Socket c, String ip, boolean viaRelay) {
        String route = viaRelay ? "公网中转" : "局域网直连";
        try (Socket s = c) {
            s.setSoTimeout(60000);
            DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream(), CHUNK));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            while (true) {
                JSONObject h = readFrame(in);
                if (h == null || !APP.equals(h.optString("app"))) break;
                String t = h.optString("type");
                if ("ping".equals(t)) {
                    JSONObject a = me("pong");
                    a.put("ok", true);
                    writeFrame(out, a);
                } else if ("spake_hello".equals(t)) {
                    handlePairHandshake(in, out, h, ip, viaRelay);
                    break;
                } else if ("enc".equals(t)) {
                    String did = h.optString("id");
                    Device dev;
                    synchronized (paired) {
                        dev = paired.get(did);
                    }
                    if (dev == null || dev.key == null) {
                        writeFrame(out, errObj("对方已重置连接或不是好友，请重新输入 6 位验证码添加", true));
                        break;
                    }
                    JSONObject inner;
                    try {
                        inner = Crypto.decryptJson(dev.key, h.optString("n"), h.optString("ct"), "frame");
                    } catch (Exception ex) {
                        writeFrame(out, errObj("加密校验失败，请重新加好友", true));
                        break;
                    }
                    if (!MessageDigest.isEqual(dev.token.getBytes(UTF8), inner.optString("token", "").getBytes(UTF8))) {
                        writeFrame(out, errObj("会话令牌无效，请重新加好友", true));
                        break;
                    }
                    synchronized (paired) {
                        if (!viaRelay && ip != null && !ip.isEmpty()) {
                            dev.ip = ip;
                            dev.viaRelay = false;
                        }
                        dev.lastSeen = System.currentTimeMillis();
                    }
                    String it = inner.optString("type");
                    if ("text".equals(it)) {
                        Msg m = new Msg();
                        m.peerId = dev.id;
                        m.peer = dev.name;
                        m.incoming = true;
                        m.route = route;
                        m.text = inner.optString("text");
                        writeFrame(out, ok());
                        post(m);
                    } else if ("file".equals(it)) {
                        File f = recvEncryptedFile(in, inner, dev, route);
                        writeFrame(out, ok());
                        Msg m = new Msg();
                        m.peerId = dev.id;
                        m.peer = dev.name;
                        m.incoming = true;
                        m.isFile = true;
                        m.route = route;
                        m.text = f.getName();
                        m.path = f.getAbsolutePath();
                        m.size = f.length();
                        post(m);
                        status("🔒 [" + route + "] 已接收 " + f.getName(), 100);
                        MediaScannerConnection.scanFile(ctx, new String[]{f.getAbsolutePath()}, null, null);
                    } else {
                        writeFrame(out, errObj("unknown inner type", false));
                        break;
                    }
                } else {
                    writeFrame(out, errObj("拒绝未加密或旧版本请求，请两端升级并重新配对", true));
                    break;
                }
            }
        } catch (Exception e) {
            status("接收失败（" + route + "）：" + e.getMessage(), -1);
        }
    }

    private File recvEncryptedFile(DataInputStream in, JSONObject inner, Device dev, String route) throws Exception {
        long size = inner.getLong("size");
        int chunkSize = inner.optInt("chunkSize", Crypto.ENC_CHUNK);
        File dest = uniqueFile(saveDir(), safeParts(inner.optString("fileName", "file")));
        File parent = dest.getParentFile();
        if (parent != null) parent.mkdirs();
        File tmp = new File(dest.getPath() + ".lfpart");
        byte[] nonce = new byte[Crypto.NONCE_LEN];
        long got = 0, seq = 0, last = 0, t0 = SystemClock.uptimeMillis();
        busy(true);
        try (FileOutputStream fo = new FileOutputStream(tmp)) {
            while (got < size) {
                int plainLen = (int) Math.min(chunkSize, size - got);
                byte[] ct = new byte[plainLen + Crypto.TAG_LEN];
                in.readFully(nonce);
                in.readFully(ct);
                byte[] pt = Crypto.decryptBytes(dev.key, nonce, ct, Crypto.packSeq(seq));
                fo.write(pt);
                got += pt.length;
                seq++;
                long now = SystemClock.uptimeMillis();
                if (now - last > 200) {
                    last = now;
                    status("🔒 [" + route + "] 接收 " + dest.getName() + "  " + human(got) + "/" + human(size) + "  "
                            + human(got * 1000 / Math.max(now - t0, 1)) + "/s", pct(got, size));
                }
            }
        } catch (Exception e) {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            throw e;
        } finally {
            busy(false);
        }
        if (!tmp.renameTo(dest)) throw new IOException("无法保存文件");
        return dest;
    }

    public File saveDir() {
        File d = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "LanFast");
        if ((d.isDirectory() || d.mkdirs()) && d.canWrite()) return d;
        File base = ctx.getExternalFilesDir(null);
        File f = new File(base != null ? base : ctx.getFilesDir(), "LanFast");
        //noinspection ResultOfMethodCallIgnored
        f.mkdirs();
        return f;
    }

    static List<String> safeParts(String name) {
        ArrayList<String> parts = new ArrayList<>();
        for (String p : name.split("[\\\\/]+")) {
            p = p.replaceAll("[<>:\"|?*\\x00-\\x1f]", "_").trim();
            while (p.endsWith(".") || p.endsWith(" ")) p = p.substring(0, p.length() - 1);
            if (p.isEmpty() || p.equals(".") || p.equals("..")) continue;
            if (p.length() > 200) p = p.substring(0, 200);
            parts.add(p);
        }
        if (parts.isEmpty()) parts.add("file");
        return parts;
    }

    static File uniqueFile(File dir, List<String> parts) {
        File f = dir;
        for (String p : parts) f = new File(f, p);
        if (!f.exists() && !new File(f.getPath() + ".lfpart").exists()) return f;
        String n = f.getName();
        int dot = n.lastIndexOf('.');
        String base = dot > 0 ? n.substring(0, dot) : n;
        String ext = dot > 0 ? n.substring(dot) : "";
        for (int i = 1; ; i++) {
            File c = new File(f.getParentFile(), base + " (" + i + ")" + ext);
            if (!c.exists() && !new File(c.getPath() + ".lfpart").exists()) return c;
        }
    }

    // ------------------------------------------------------------------ 发送（局域网优先，自动回落公网中转）
    private Conn connectSmart(Device d) throws Exception {
        if (d.ip != null && !d.ip.isEmpty()) {
            try {
                Socket s = new Socket();
                s.connect(new InetSocketAddress(d.ip, d.port), 2000);
                s.setSoTimeout(60000);
                Conn c = new Conn();
                c.sock = s;
                c.route = "局域网直连";
                return c;
            } catch (IOException lanErr) {
                if (parseRelay(relayAddr) == null) {
                    throw new IOException("局域网直连失败（未配置中转）：" + lanErr.getMessage());
                }
            }
        }
        if (parseRelay(relayAddr) != null) {
            Conn c = new Conn();
            c.sock = openRelayTunnel(d.id, "");
            c.route = "公网中转";
            return c;
        }
        throw new IOException("无法连接对方（不在同一局域网且未配置公网中转）");
    }

    private void checkAck(Device d, JSONObject a) throws IOException {
        if (a == null) throw new IOException("对方无响应");
        if (!a.optBoolean("ok")) {
            String err = a.optString("error", "对方拒绝");
            if (a.optBoolean("auth_error")) removeFriend(d.id);
            throw new IOException(err);
        }
    }

    private void sendEncFrame(DataOutputStream out, Device d, JSONObject inner) throws Exception {
        Crypto.EncBox box = Crypto.encryptJson(d.key, inner, "frame");
        JSONObject outer = new JSONObject();
        outer.put("app", APP);
        outer.put("v", PROTO_VERSION);
        outer.put("type", "enc");
        outer.put("id", id);
        outer.put("n", box.nB64);
        outer.put("ct", box.ctB64);
        writeFrame(out, outer);
    }

    static int readFullChunk(InputStream is, byte[] buf, int want) throws IOException {
        int off = 0;
        while (off < want) {
            int r = is.read(buf, off, want - off);
            if (r < 0) break;
            off += r;
        }
        return off;
    }

    public void sendText(final Device d, final String text) {
        sender.execute(() -> {
            Msg m = new Msg();
            m.peerId = d.id;
            m.peer = d.name;
            m.text = text;
            try {
                if ("web".equals(d.os)) {
                    m.route = "网页端";
                    webBridge.pushText(d.id, text);
                    status("🌐 [网页端] 文字已推送到 " + d.name, -1);
                    post(m);
                    return;
                }
                Conn c = connectSmart(d);
                m.route = c.route;
                try (Socket s = c.sock) {
                    DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
                    DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
                    JSONObject inner = new JSONObject();
                    inner.put("type", "text");
                    inner.put("token", d.token);
                    inner.put("text", text);
                    sendEncFrame(out, d, inner);
                    checkAck(d, readFrame(in));
                }
                status("🔒 [" + c.route + "] 加密文字已发送到 " + d.name, -1);
            } catch (Exception e) {
                m.error = true;
                m.text = "发送失败：" + e.getMessage();
                status(m.text, -1);
            }
            post(m);
        });
    }

    static class Item {
        Uri uri;
        String name;
        long size;
        File tmp;
    }

    public void sendUris(final Device d, final List<Uri> uris) {
        final ArrayList<Uri> copy = new ArrayList<>(uris);
        sender.execute(() -> {
            ContentResolver cr = ctx.getContentResolver();
            ArrayList<Item> items = new ArrayList<>();
            long total = 0;
            Msg m = new Msg();
            m.peerId = d.id;
            m.peer = d.name;
            m.isFile = true;
            busy(true);
            try {
                if ("web".equals(d.os)) {
                    m.route = "网页端";
                    long webTotal = 0;
                    String firstName = "文件";
                    for (int i = 0; i < copy.size(); i++) {
                        String nm = queryName(cr, copy.get(i));
                        if (i == 0) firstName = nm;
                        long sz = querySize(cr, copy.get(i));
                        if (sz > 0) webTotal += sz;
                    }
                    webBridge.pushUris(d.id, copy);
                    m.text = copy.size() == 1 ? firstName : firstName + " 等 " + copy.size() + " 个文件";
                    m.size = webTotal;
                    status("🌐 [网页端] 已推送给 " + d.name + "（请在浏览器点下载）", 100);
                    post(m);
                    return;
                }
                status("正在准备文件…", 0);
                for (Uri u : copy) {
                    Item it = new Item();
                    it.uri = u;
                    it.name = queryName(cr, u);
                    it.size = querySize(cr, u);
                    if (it.size < 0) {
                        it.tmp = File.createTempFile("send", ".tmp", ctx.getCacheDir());
                        try (InputStream is = cr.openInputStream(u); OutputStream os = new FileOutputStream(it.tmp)) {
                            if (is == null) throw new IOException("无法读取 " + it.name);
                            copyStream(is, os, Long.MAX_VALUE);
                        }
                        it.size = it.tmp.length();
                        it.uri = Uri.fromFile(it.tmp);
                    }
                    total += it.size;
                    items.add(it);
                }
                long sent = 0, last = 0, t0 = SystemClock.uptimeMillis();
                byte[] buf = new byte[Crypto.ENC_CHUNK];
                Conn c = connectSmart(d);
                m.route = c.route;
                try (Socket s = c.sock) {
                    DataOutputStream out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream(), CHUNK));
                    DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream()));
                    for (int i = 0; i < items.size(); i++) {
                        Item it = items.get(i);
                        JSONObject inner = new JSONObject();
                        inner.put("type", "file");
                        inner.put("token", d.token);
                        inner.put("fileName", it.name);
                        inner.put("size", it.size);
                        inner.put("chunkSize", Crypto.ENC_CHUNK);
                        inner.put("index", i + 1);
                        inner.put("count", items.size());
                        sendEncFrame(out, d, inner);
                        try (InputStream is = cr.openInputStream(it.uri)) {
                            if (is == null) throw new IOException("无法读取 " + it.name);
                            long remaining = it.size;
                            long seq = 0;
                            while (remaining > 0) {
                                int want = (int) Math.min(Crypto.ENC_CHUNK, remaining);
                                int r = readFullChunk(is, buf, want);
                                if (r < want) throw new IOException("文件长度与预期不符：" + it.name);
                                Crypto.EncBytes eb = Crypto.encryptBytes(d.key, buf, 0, r, Crypto.packSeq(seq));
                                out.write(eb.nonce);
                                out.write(eb.ct);
                                remaining -= r;
                                sent += r;
                                seq++;
                                long now = SystemClock.uptimeMillis();
                                if (now - last > 200) {
                                    last = now;
                                    status("🔒 [" + c.route + "] 发送 [" + (i + 1) + "/" + items.size() + "] " + it.name + "  "
                                            + human(sent) + "/" + human(total) + "  "
                                            + human(sent * 1000 / Math.max(now - t0, 1)) + "/s", pct(sent, total));
                                }
                            }
                        }
                        out.flush();
                        checkAck(d, readFrame(in));
                    }
                }
                long secs = Math.max(SystemClock.uptimeMillis() - t0, 1);
                m.text = items.size() == 1 ? items.get(0).name : items.get(0).name + " 等 " + items.size() + " 个文件";
                m.size = total;
                status("🔒 [" + c.route + "] 已加密发送到 " + d.name + "，平均 " + human(total * 1000 / secs) + "/s", 100);
            } catch (Exception e) {
                m.error = true;
                m.isFile = false;
                m.text = "发送失败：" + e.getMessage();
                status(m.text, -1);
            } finally {
                busy(false);
                for (Item it : items) if (it.tmp != null) //noinspection ResultOfMethodCallIgnored
                    it.tmp.delete();
            }
            post(m);
        });
    }

    static String queryName(ContentResolver cr, Uri u) {
        if ("file".equals(u.getScheme())) return new File(u.getPath()).getName();
        try (Cursor c = cr.query(u, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getString(0);
        } catch (Exception ignored) {
        }
        String s = u.getLastPathSegment();
        return s == null ? "file" : s;
    }

    static long querySize(ContentResolver cr, Uri u) {
        if ("file".equals(u.getScheme())) return new File(u.getPath()).length();
        try (Cursor c = cr.query(u, new String[]{OpenableColumns.SIZE}, null, null, null)) {
            if (c != null && c.moveToFirst() && !c.isNull(0)) return c.getLong(0);
        } catch (Exception ignored) {
        }
        try (AssetFileDescriptor fd = cr.openAssetFileDescriptor(u, "r")) {
            if (fd != null && fd.getLength() >= 0) return fd.getLength();
        } catch (Exception ignored) {
        }
        return -1;
    }

    // ------------------------------------------------------------------ 帧编解码
    static JSONObject readFrame(DataInputStream in) throws Exception {
        int b0 = in.read();
        if (b0 < 0) return null;
        int n = (b0 << 24) | (in.readUnsignedByte() << 16) | (in.readUnsignedByte() << 8) | in.readUnsignedByte();
        if (n < 0 || n > (4 << 20)) throw new IOException("bad header");
        byte[] buf = new byte[n];
        in.readFully(buf);
        return new JSONObject(new String(buf, UTF8));
    }

    static void writeFrame(DataOutputStream out, JSONObject j) throws IOException {
        byte[] b = j.toString().getBytes(UTF8);
        out.writeInt(b.length);
        out.write(b);
        out.flush();
    }

    static JSONObject ok() {
        JSONObject j = new JSONObject();
        try {
            j.put("ok", true);
        } catch (Exception ignored) {
        }
        return j;
    }

    static JSONObject errObj(String msg, boolean authErr) {
        JSONObject j = new JSONObject();
        try {
            j.put("ok", false);
            j.put("error", msg);
            if (authErr) j.put("auth_error", true);
        } catch (Exception ignored) {
        }
        return j;
    }

    // ------------------------------------------------------------------ 回调与杂项
    private synchronized void busy(boolean on) {
        if (wlock == null) return;
        try {
            if (on) wlock.acquire();
            else if (wlock.isHeld()) wlock.release();
        } catch (Exception ignored) {
        }
    }

    private void post(final Msg m) {
        main.post(() -> {
            chatOf(m.peerId).add(m);
            Listener l = listener;
            if (l != null) l.onMessage(m);
            else if (m.incoming) {
                Integer u = unread.get(m.peerId);
                unread.put(m.peerId, (u == null ? 0 : u) + 1);
                notifyBackground(m);
            }
        });
    }

    private void status(final String s, final int percent) {
        main.post(() -> {
            Listener l = listener;
            if (l != null) l.onStatus(s, percent);
        });
    }

    private void fireFriends() {
        main.post(() -> {
            Listener l = listener;
            if (l != null) l.onFriendsChanged();
        });
    }

    private void fireDiscovered() {
        main.post(() -> {
            Listener l = listener;
            if (l != null) l.onDiscoveredChanged();
        });
    }

    private void fireRelayState(final boolean connected, final String text) {
        relayStatusText = text;
        main.post(() -> {
            Listener l = listener;
            if (l != null) l.onRelayState(connected, text);
        });
    }

    private void notifyBackground(Msg m) {
        try {
            NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            Notification n = LanService.builder(ctx, LanService.CH_MSG)
                    .setSmallIcon(R.drawable.ic_stat)
                    .setContentTitle(m.isFile ? "收到文件（来自 " + m.peer + "）" : "收到文字（来自 " + m.peer + "）")
                    .setContentText(m.text)
                    .setStyle(new Notification.BigTextStyle().bigText(m.text))
                    .setContentIntent(LanService.openApp(ctx))
                    .setAutoCancel(true)
                    .build();
            nm.notify(notifyId++, n);
        } catch (Exception ignored) {
        }
    }

    static void copyStream(InputStream is, OutputStream os, long max) throws IOException {
        byte[] buf = new byte[CHUNK];
        long n = 0;
        int r;
        while (n < max && (r = is.read(buf)) > 0) {
            os.write(buf, 0, r);
            n += r;
        }
    }

    static int pct(long a, long b) {
        return b <= 0 ? 100 : (int) (a * 100 / b);
    }

    public static String human(long n) {
        if (n < 1024) return n + " B";
        double v = n;
        String[] u = {"KB", "MB", "GB", "TB"};
        int i = -1;
        while (v >= 1024 && i < u.length - 1) {
            v /= 1024;
            i++;
        }
        return String.format(Locale.US, "%.1f %s", v, u[i]);
    }

    static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }

    static void closeQuietly(java.io.Closeable c) {
        try {
            if (c != null) c.close();
        } catch (Exception ignored) {
        }
    }
}
