"""LanFast Windows 桌面端 v3（逐对 6 位验证码加好友 · 独立多对话窗口 · 局域网/公网中转双模）"""
import json
import os
import queue
import socket
import subprocess
import sys
import time
import tkinter as tk
import uuid
from tkinter import filedialog, messagebox, simpledialog, ttk

from .core import LanFastCore, best_ip, human_size, local_ipv4s

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:  # noqa
    HAS_DND = False

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".lanfast")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


def load_config():
    cfg = {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        pass
    cfg.setdefault("id", uuid.uuid4().hex)
    cfg.setdefault("name", socket.gethostname())
    cfg.setdefault("save_dir", os.path.join(os.path.expanduser("~"), "Downloads", "LanFast"))
    cfg.setdefault("auto_copy", True)
    cfg.setdefault("relay_addr", "")
    cfg.setdefault("relay_key", "")
    save_config(cfg)
    return cfg


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def open_path(path):
    if sys.platform.startswith("win"):
        os.startfile(path)  # noqa
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def reveal(path):
    if sys.platform.startswith("win") and os.path.exists(path):
        subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
    else:
        open_path(os.path.dirname(path))


def fmt_pin(pin):
    return f"{pin[:3]} {pin[3:]}" if len(pin) == 6 else pin


class AddFriendDialog(tk.Toplevel):
    """添加好友弹窗：输入对方 6 位验证码 + 可选 IP。"""

    def __init__(self, parent, on_submit):
        super().__init__(parent)
        self.title("添加好友（输入对方 6 位验证码）")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_submit = on_submit

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="对方设备屏幕顶部显示的 6 位数字验证码：",
                  font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        self.pin_var = tk.StringVar()
        e_pin = tk.Entry(body, textvariable=self.pin_var, font=("Consolas", 20, "bold"),
                         fg="#2563eb", justify="center", width=12)
        e_pin.pack(fill="x", pady=(6, 12))
        e_pin.focus_set()

        ttk.Label(body, text="对方 IP（选填，同局域网或已连同一中转服务器时留空即可）：",
                  foreground="#64748b").pack(anchor="w")
        self.ip_var = tk.StringVar()
        ttk.Entry(body, textvariable=self.ip_var, width=34).pack(fill="x", pady=(4, 14))

        btns = ttk.Frame(body)
        btns.pack(fill="x")
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="验证并加为好友", command=self.submit).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self.submit())
        self.bind("<Escape>", lambda e: self.destroy())

    def submit(self):
        pin = self.pin_var.get().strip().replace(" ", "")
        ip = self.ip_var.get().strip()
        if len(pin) != 6 or not pin.isdigit():
            messagebox.showwarning("LanFast", "请输入完整的 6 位数字验证码", parent=self)
            return
        self.on_submit(pin, ip)
        self.destroy()


class RelayDialog(tk.Toplevel):
    """配置公网中转服务器弹窗。"""

    def __init__(self, parent, addr, key, on_save):
        super().__init__(parent)
        self.title("公网中转服务器设置（跨互联网使用）")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_save = on_save

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="配置你部署的 relay_server.py 地址后，即使手机开 5G 或不在同一 WiFi，\n"
                             "也能直接用 6 位验证码加好友并互传文件；在同一局域网时仍优先走内网直连。",
                  foreground="#475569", justify="left").pack(anchor="w", pady=(0, 10))

        ttk.Label(body, text="服务器地址（IP:端口，开启 TLS 时填 tls://域名:端口，留空仅局域网）：").pack(anchor="w")
        self.addr_var = tk.StringVar(value=addr)
        e = ttk.Entry(body, textvariable=self.addr_var, width=42)
        e.pack(fill="x", pady=(4, 10))
        e.focus_set()

        ttk.Label(body, text="接入密钥（可选，须与服务端 --key 一致；服务端未设则留空）：").pack(anchor="w")
        self.key_var = tk.StringVar(value=key)
        ttk.Entry(body, textvariable=self.key_var, width=42).pack(fill="x", pady=(4, 14))

        btns = ttk.Frame(body)
        btns.pack(fill="x")
        ttk.Button(btns, text="取消", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="保存并连接", command=self.save).pack(side="right", padx=(0, 8))
        self.bind("<Return>", lambda e: self.save())
        self.bind("<Escape>", lambda e: self.destroy())

    def save(self):
        self.on_save(self.addr_var.get().strip(), self.key_var.get().strip())
        self.destroy()


class App:
    def __init__(self):
        self.cfg = load_config()
        os.makedirs(self.cfg["save_dir"], exist_ok=True)
        self.root = TkinterDnD.Tk() if HAS_DND else tk.Tk()
        self.root.title("LanFast 局域网 / 跨网快传")
        ico = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lanfast.ico")
        if os.path.exists(ico):
            try:
                self.root.iconbitmap(ico)
            except tk.TclError:
                pass
        self.root.geometry("960x640")
        self.root.minsize(760, 500)

        self.events = queue.Queue()
        self.devices = []
        self.active_peer_id = None
        self.chats = {}      # peer_id -> list of {time, dir, peer, content, payload}
        self.unread = {}     # peer_id -> int
        self.row_rec = {}    # treeview iid -> rec dict

        self.core = LanFastCore(
            self.cfg["name"], self.cfg["save_dir"], self.cfg["id"],
            on_event=lambda k, d: self.events.put((k, d)),
            relay_addr=self.cfg.get("relay_addr", ""),
            relay_key=self.cfg.get("relay_key", ""),
        )
        self._build_ui()
        try:
            self.core.start()
        except OSError as e:
            messagebox.showerror("LanFast", f"端口被占用，可能已经打开了一个 LanFast：\n{e}")
            self.root.destroy()
            raise SystemExit(1)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._poll)
        self._update_header()

    # ------------------------------------------------------------ UI
    def _build_ui(self):
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=26)

        # 顶部信息栏
        top = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        top.pack(fill="x")
        self.header = ttk.Label(top, font=("Microsoft YaHei UI", 10))
        self.header.pack(side="left")
        ttk.Button(top, text="打开接收目录", command=lambda: open_path(self.cfg["save_dir"])).pack(side="right")
        ttk.Button(top, text="更改目录", command=self.change_dir).pack(side="right", padx=4)
        ttk.Button(top, text="改名", command=self.rename).pack(side="right")
        self.relay_btn = ttk.Button(top, text="○ 公网中转设置", command=self.open_relay_dialog)
        self.relay_btn.pack(side="right", padx=(0, 8))

        # 本机 6 位验证码卡片
        pin_bar = tk.Frame(self.root, bg="#eff6ff", highlightbackground="#bfdbfe", highlightthickness=1, padx=12, pady=7)
        pin_bar.pack(fill="x", padx=10, pady=(2, 8))
        tk.Label(pin_bar, text="本机 6 位验证码：", bg="#eff6ff", fg="#1e3a8a",
                 font=("Microsoft YaHei UI", 11, "bold")).pack(side="left")
        self.pin_label = tk.Label(pin_bar, text=fmt_pin(self.core.pin), bg="#eff6ff", fg="#2563eb",
                                  font=("Consolas", 21, "bold"), padx=6)
        self.pin_label.pack(side="left")
        self.web_label = tk.Label(pin_bar, text="", bg="#eff6ff", fg="#0f766e",
                                  font=("Microsoft YaHei UI", 9, "bold"), padx=8, cursor="hand2")
        self.web_label.pack(side="left")
        self.web_label.bind("<Button-1>", lambda e: self.copy_web_url())
        ttk.Button(pin_bar, text="刷新验证码", command=self.refresh_pin).pack(side="right")
        ttk.Button(pin_bar, text="复制码", command=self.copy_pin).pack(side="right", padx=4)
        ttk.Button(pin_bar, text="复制网页地址", command=self.copy_web_url).pack(side="right")

        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10)

        # 左侧：好友对话列表
        left = ttk.Frame(paned, padding=(0, 0, 8, 0))
        ttk.Button(left, text="＋ 添加好友（输入 6 位验证码）", command=self.open_add_friend).pack(fill="x", pady=(0, 6))
        ttk.Label(left, text="好友对话窗口（点击切换）", font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
        self.dev_list = tk.Listbox(left, activestyle="none", font=("Microsoft YaHei UI", 10),
                                   selectbackground="#2563eb", exportselection=False, width=30)
        self.dev_list.pack(fill="both", expand=True, pady=4)
        self.dev_list.bind("<<ListboxSelect>>", self.on_select_friend)
        self.empty_hint = ttk.Label(left, foreground="#64748b", wraplength=240, justify="left",
                                    text="还没有好友对话。\n点击上方「添加好友」输入对方 6 位验证码，或让对方输入你的 6 位验证码。")
        self.empty_hint.pack(anchor="w")
        row = ttk.Frame(left)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="断开当前好友", command=self.disconnect_selected).pack(side="left")
        paned.add(left, weight=1)

        # 右侧：当前选中好友的独立对话窗口
        right = ttk.Frame(paned)
        hdr_bar = tk.Frame(right, bg="#f1f5f9")
        hdr_bar.pack(fill="x", pady=(0, 4))
        self.chat_header = tk.Label(hdr_bar, text="未选择好友对话", anchor="w", bg="#f1f5f9", fg="#0f172a",
                                    font=("Microsoft YaHei UI", 10, "bold"), padx=10, pady=6)
        self.chat_header.pack(side="left", fill="x", expand=True)
        ttk.Button(hdr_bar, text="清空当前记录", command=self.clear_active_chat).pack(side="right", padx=6, pady=3)

        cols = ("time", "dir", "content")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", selectmode="browse")
        for c, t, w, st in (("time", "时间", 72, False), ("dir", "", 48, False),
                            ("content", "消息 / 文件（双击：文字=复制，文件=打开；右键更多）", 460, True)):
            self.tree.heading(c, text=t, anchor="w")
            self.tree.column(c, width=w, stretch=st, anchor="w")
        sb = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.tag_configure("in", foreground="#065f46")
        self.tree.tag_configure("out", foreground="#1e3a8a")
        self.tree.tag_configure("err", foreground="#b91c1c")
        self.tree.bind("<Double-1>", self.on_log_double)
        self.tree.bind("<Button-3>", self.on_log_menu)
        self.tree.bind("<Delete>", lambda e: self.delete_selected_msg())

        box = ttk.Frame(right)
        self.input = tk.Text(box, height=4, font=("Microsoft YaHei UI", 10), wrap="word", undo=True)
        self.input.pack(fill="both", expand=True, pady=(6, 4))
        self.input.bind("<Control-Return>", lambda e: (self.send_text(), "break")[1])
        btns = ttk.Frame(box)
        btns.pack(fill="x")
        ttk.Button(btns, text="发送文字 (Ctrl+Enter)", command=self.send_text).pack(side="left")
        ttk.Button(btns, text="发送剪贴板", command=self.send_clipboard).pack(side="left", padx=4)
        ttk.Button(btns, text="发送文件", command=self.pick_files).pack(side="left")
        ttk.Button(btns, text="发送文件夹", command=self.pick_folder).pack(side="left", padx=4)
        self.auto_copy = tk.BooleanVar(value=self.cfg.get("auto_copy", True))
        ttk.Checkbutton(btns, text="收到文字自动复制", variable=self.auto_copy,
                        command=self._save_auto_copy).pack(side="right")

        box.pack(side="bottom", fill="x")
        sb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        paned.add(right, weight=3)

        bottom = ttk.Frame(self.root, padding=(10, 6))
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, length=220, maximum=1000)
        self.progress.pack(side="right")
        tip = "  ·  可直接把文件拖进窗口发给当前对话好友" if HAS_DND else ""
        self.status = ttk.Label(bottom, text="就绪" + tip, foreground="#555")
        self.status.pack(side="left", fill="x", expand=True)

        if HAS_DND:
            for w in (self.root, self.tree, self.input, self.dev_list):
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", self.on_drop)

    def _web_url(self):
        return f"http://{best_ip()}:{self.core.web_port}"

    def _update_header(self):
        self.header.config(text=f"本机：{self.cfg['name']}    IP：{best_ip()}    接收目录：{self.cfg['save_dir']}")
        self.web_label.config(text=f"🍎 苹果/浏览器免安装访问：{self._web_url()}")

    def copy_web_url(self):
        url = self._web_url()
        self.copy(url)
        self.set_status(f"已复制网页端地址：{url}（苹果 Safari 直接打开输入 6 位码即可）")

    # ------------------------------------------------------------ 事件循环
    def _poll(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                getattr(self, f"ev_{kind}", lambda d: None)(data)
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def ev_pin(self, pin):
        self.pin_label.config(text=fmt_pin(pin))

    def ev_relay_state(self, d):
        dot = "● " if d.get("connected") else "○ "
        self.relay_btn.config(text=dot + ("公网中转已连" if d.get("connected") else "公网中转设置"))
        self.set_status(d.get("text", ""))

    def ev_devices(self, devs):
        self.devices = devs
        if self.active_peer_id and not any(d.id == self.active_peer_id for d in devs):
            self.active_peer_id = devs[0].id if devs else None
            self._render_active_chat()
        elif self.active_peer_id is None and devs:
            self.active_peer_id = devs[0].id
            self._render_active_chat()
        self._render_dev_list()

    def ev_paired(self, dev):
        self.active_peer_id = dev.id
        self.unread.pop(dev.id, None)
        self._render_dev_list()
        self._render_active_chat()

    def ev_pair_result(self, d):
        if d.get("ok"):
            self.set_status(f"已添加好友 {d['device'].name}（{d['route']}）")
        else:
            messagebox.showwarning("添加好友失败", d.get("error", "验证失败"))
            self.set_status(d.get("error", "验证失败"))

    def ev_text(self, d):
        pid = d["peer_id"]
        self._append_chat(pid, "in", d["text"], ("text", d["text"]))
        if self.auto_copy.get():
            self.copy(d["text"])
            self.set_status(f"收到来自 {d['from']} 的文字（{d['route']}），已复制到剪贴板")
        else:
            self.set_status(f"收到来自 {d['from']} 的文字（{d['route']}）")
        self.flash()

    def ev_recv_progress(self, d):
        self.progress["value"] = d["done"] * 1000 / max(d["total"], 1)
        self.set_status(f"[{d['route']}] 接收 {d['name']}  {human_size(d['done'])}/{human_size(d['total'])}  来自 {d['from']}")

    def ev_recv_file(self, d):
        self.progress["value"] = 1000
        name = os.path.relpath(d["path"], self.cfg["save_dir"])
        self._append_chat(d["peer_id"], "in", f"📄 {name}  ({human_size(d['size'])})", ("file", d["path"]))
        self.set_status(f"[{d['route']}] 已接收 {name}（来自 {d['from']}）")
        self.flash()

    def ev_send_progress(self, d):
        self.progress["value"] = d["done"] * 1000 / max(d["total"], 1)
        self.set_status(f"[{d['route']}] 发送 [{d['index']}/{d['count']}] {d['name']}  "
                        f"{human_size(d['done'])}/{human_size(d['total'])}  {human_size(d['speed'])}/s  → {d['to']}")

    def ev_send_done(self, d):
        pid = d.get("peer_id")
        if not d["ok"]:
            if pid:
                self._append_chat(pid, "err", f"发送失败：{d['error']}", None)
            self.set_status(f"发送失败：{d['error']}")
            return
        route = d.get("route", "")
        if d["kind"] == "text":
            self._append_chat(pid, "out", d["text"], ("text", d["text"]))
            self.set_status(f"[{route}] 文字已发送到 {d['to']}")
        else:
            self.progress["value"] = 1000
            names = d["names"]
            desc = names[0] if len(names) == 1 else f"{names[0]} 等 {len(names)} 个文件"
            speed = human_size(d["total"] / max(d["seconds"], 1e-3))
            self._append_chat(pid, "out", f"📄 {desc}  ({human_size(d['total'])})", None)
            self.set_status(f"[{route}] 已发送 {desc} → {d['to']}，平均 {speed}/s")

    def ev_error(self, msg):
        self.set_status(msg)

    def ev_log(self, msg):
        self.set_status(msg)

    # ------------------------------------------------------------ 多好友窗口管理
    def _render_dev_list(self):
        self.dev_list.delete(0, "end")
        sel_idx = None
        for i, d in enumerate(self.devices):
            u = self.unread.get(d.id, 0)
            badge = f"  [{u}条新消息]" if u > 0 else ""
            self.dev_list.insert("end", "  " + d.label() + badge)
            if d.id == self.active_peer_id:
                sel_idx = i
        if sel_idx is not None:
            self.dev_list.selection_set(sel_idx)
        if self.devices:
            self.empty_hint.pack_forget()
        else:
            self.empty_hint.pack(anchor="w")

    def on_select_friend(self, _event=None):
        sel = self.dev_list.curselection()
        if not sel or sel[0] >= len(self.devices):
            return
        d = self.devices[sel[0]]
        if d.id != self.active_peer_id:
            self.active_peer_id = d.id
            self.unread.pop(d.id, None)
            self._render_dev_list()
            self._render_active_chat()

    def _render_active_chat(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.row_rec.clear()
        d = self.active_device()
        if d is None:
            self.chat_header.config(text="未选择好友对话 — 请先点击左侧「添加好友」或用浏览器访问网页端")
            return
        loc = d.ip if d.ip else "公网中转"
        if d.os == "web":
            mode_tag = f"🌐 网页端 (安全码 {d.sas})" if d.sas else "🌐 网页直连"
        else:
            mode_tag = f"🔒 SPAKE2+AES256 · 安全码 {d.sas}" if d.sas else "🔒 AES-256-GCM 端到端加密"
        self.chat_header.config(text=f"{mode_tag}：{d.label()}  ({loc})")
        for rec in self.chats.get(d.id, []):
            self._insert_tree_row(rec)

    def _insert_tree_row(self, rec):
        arrow = {"in": "对方", "out": "我 →", "err": "失败"}[rec["dir"]]
        one_line = rec["content"].replace("\r", "").replace("\n", " ⏎ ")
        iid = self.tree.insert("", "end", values=(rec["time"], arrow, one_line), tags=(rec["dir"],))
        self.row_rec[iid] = rec
        self.tree.see(iid)

    def _append_chat(self, peer_id, direction, content, payload):
        rec = {"time": time.strftime("%H:%M:%S"), "dir": direction, "content": content, "payload": payload}
        self.chats.setdefault(peer_id, []).append(rec)
        if peer_id == self.active_peer_id:
            self._insert_tree_row(rec)
        else:
            if direction == "in":
                self.unread[peer_id] = self.unread.get(peer_id, 0) + 1
                self._render_dev_list()

    def active_device(self):
        for d in self.devices:
            if d.id == self.active_peer_id:
                return d
        return None

    def require_device(self):
        d = self.active_device()
        if d is None:
            messagebox.showinfo("LanFast", "请先添加并选择一个好友对话窗口。\n\n"
                                f"你可以点击左侧「添加好友」输入对方的 6 位验证码，或把本机验证码 {self.core.pin} 告诉对方。")
        return d

    # ------------------------------------------------------------ 动作
    def open_add_friend(self):
        AddFriendDialog(self.root, lambda pin, ip: (
            self.set_status("正在验证 6 位验证码并建立连接…"),
            self.core.pair_by_pin(pin, ip),
        ))

    def open_relay_dialog(self):
        RelayDialog(self.root, self.cfg.get("relay_addr", ""), self.cfg.get("relay_key", ""),
                    self._apply_relay)

    def _apply_relay(self, addr, key):
        self.cfg["relay_addr"] = addr
        self.cfg["relay_key"] = key
        save_config(self.cfg)
        self.core.set_relay(addr, key)

    def refresh_pin(self):
        self.core.regenerate_pin(disconnect_all=False)
        self.set_status(f"本机新验证码：{self.core.pin}（已有好友不受影响）")

    def copy_pin(self):
        self.copy(self.core.pin)
        self.set_status(f"已复制验证码 {self.core.pin}")

    def send_text(self):
        text = self.input.get("1.0", "end-1c")
        if not text.strip():
            return
        d = self.require_device()
        if d:
            self.core.send_text(d, text)
            self.input.delete("1.0", "end")

    def send_clipboard(self):
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            text = ""
        if not text:
            self.set_status("剪贴板没有文字")
            return
        d = self.require_device()
        if d:
            self.core.send_text(d, text)

    def pick_files(self):
        d = self.require_device()
        if d:
            paths = filedialog.askopenfilenames(title="选择要发送的文件")
            if paths:
                self.core.send_files(d, list(paths))

    def pick_folder(self):
        d = self.require_device()
        if d:
            p = filedialog.askdirectory(title="选择要发送的文件夹")
            if p:
                self.core.send_files(d, [p])

    def on_drop(self, event):
        paths = self.root.tk.splitlist(event.data)
        d = self.require_device()
        if d and paths:
            self.core.send_files(d, list(paths))

    def disconnect_selected(self):
        d = self.active_device()
        if d:
            self.core.remove_device(d.id)
            self.set_status(f"已断开与 {d.name} 的连接")

    def rename(self):
        name = simpledialog.askstring("改名", "本机显示名称：", initialvalue=self.cfg["name"], parent=self.root)
        if name and name.strip():
            self.cfg["name"] = name.strip()
            save_config(self.cfg)
            self.core.set_name(self.cfg["name"])
            self._update_header()

    def change_dir(self):
        p = filedialog.askdirectory(title="选择接收目录", initialdir=self.cfg["save_dir"])
        if p:
            self.cfg["save_dir"] = self.core.save_dir = os.path.normpath(p)
            save_config(self.cfg)
            self._update_header()

    def _save_auto_copy(self):
        self.cfg["auto_copy"] = bool(self.auto_copy.get())
        save_config(self.cfg)

    # ------------------------------------------------------------ 消息右键、删除与双击
    def clear_active_chat(self):
        if not self.active_peer_id:
            return
        self.chats[self.active_peer_id] = []
        self._render_active_chat()
        self.set_status("已清空当前对话记录")

    def delete_msg(self, iid, also_disk=False):
        rec = self.row_rec.pop(iid, None)
        if rec is None:
            return
        if also_disk and rec["payload"] and rec["payload"][0] == "file":
            p = rec["payload"][1]
            if os.path.isfile(p):
                try:
                    os.remove(p)
                except OSError as e:
                    self.set_status(f"删除本地文件失败：{e}")
        lst = self.chats.get(self.active_peer_id, [])
        if rec in lst:
            lst.remove(rec)
        try:
            self.tree.delete(iid)
        except tk.TclError:
            pass
        self.set_status("已删除消息" + ("及本地文件" if also_disk else ""))

    def delete_selected_msg(self):
        sel = self.tree.selection()
        if sel:
            self.delete_msg(sel[0], also_disk=False)

    def on_log_double(self, event):
        iid = self.tree.identify_row(event.y)
        rec = self.row_rec.get(iid)
        payload = rec["payload"] if rec else None
        if not payload:
            return
        kind, val = payload
        if kind == "text":
            self.copy(val)
            self.set_status("已复制到剪贴板")
        elif kind == "file" and os.path.exists(val):
            open_path(val)

    def on_log_menu(self, event):
        iid = self.tree.identify_row(event.y)
        rec = self.row_rec.get(iid)
        if not rec:
            return
        self.tree.selection_set(iid)
        m = tk.Menu(self.root, tearoff=0)
        payload = rec["payload"]
        if payload:
            kind, val = payload
            if kind == "text":
                m.add_command(label="复制文字", command=lambda: self.copy(val))
            else:
                m.add_command(label="打开文件", command=lambda: open_path(val))
                m.add_command(label="在文件夹中显示", command=lambda: reveal(val))
            m.add_separator()
        m.add_command(label="删除此条记录", command=lambda: self.delete_msg(iid, False))
        if payload and payload[0] == "file" and os.path.isfile(payload[1]):
            m.add_command(label="删除记录并删除本地文件", command=lambda: self.delete_msg(iid, True))
        m.tk_popup(event.x_root, event.y_root)

    def copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def set_status(self, s):
        self.status.config(text=s)

    def flash(self):
        if sys.platform.startswith("win"):
            try:
                import ctypes
                hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                ctypes.windll.user32.FlashWindow(hwnd, True)
            except Exception:  # noqa
                pass

    def on_close(self):
        self.core.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    App().run()
