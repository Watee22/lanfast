package com.lanfast.app;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.StrictMode;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.MimeTypeMap;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * LanFast Android 主界面 v3：
 *  - 好友列表页（本机 6 位验证码 + 公网中转配置 + 添加好友 + 多好友独立对话入口）
 *  - 单好友独立对话窗口（每个好友互不串台，点击文字复制、点击文件打开、支持系统分享）
 */
public class MainActivity extends Activity implements Core.Listener {
    static final int REQ_PICK = 1;
    static final int BLUE = 0xFF2563EB;

    Core core;
    View homeView, chatView;

    // 首页控件
    TextView myPinText, relayBar, homePending, homeEmpty, homeFooter;
    ListView friendListView;
    FriendAdapter friendAdapter;
    final ArrayList<Core.Device> friendItems = new ArrayList<>();

    // 聊天页控件
    TextView chatTitle, chatSub, chatPending, statusText;
    ProgressBar progress;
    ListView msgListView;
    EditText input;
    MsgAdapter msgAdapter;
    String activePeerId;

    final ArrayList<Uri> pending = new ArrayList<>();
    final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm:ss", Locale.US);

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());
        core = Core.get(this);
        Intent svc = new Intent(this, LanService.class);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(svc);
        else startService(svc);
        buildUi();
        askPermissions();
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handleIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        core.listener = this;
        refreshAllUi();
        core.refresh();
    }

    @Override
    protected void onPause() {
        core.listener = null;
        super.onPause();
    }

    @Override
    public void onBackPressed() {
        if (activePeerId != null) {
            closeChat();
        } else {
            super.onBackPressed();
        }
    }

    // ------------------------------------------------------------------ UI 构建
    int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics());
    }

    GradientDrawable round(int fill, int stroke) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(fill);
        g.setCornerRadius(dp(12));
        if (stroke != 0) g.setStroke(dp(1), stroke);
        return g;
    }

    void buildUi() {
        FrameLayout frame = new FrameLayout(this);
        homeView = buildHomeView();
        chatView = buildChatView();
        frame.addView(homeView, new FrameLayout.LayoutParams(-1, -1));
        frame.addView(chatView, new FrameLayout.LayoutParams(-1, -1));
        setContentView(frame);
        syncViewVisibility();
    }

    View buildHomeView() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFFF3F4F6);

        // 本机 6 位验证码卡片
        LinearLayout pinCard = new LinearLayout(this);
        pinCard.setOrientation(LinearLayout.VERTICAL);
        pinCard.setBackground(round(0xFFEFF6FF, 0xFFBFDBFE));
        pinCard.setPadding(dp(14), dp(12), dp(14), dp(12));
        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(-1, -2);
        cardLp.setMargins(dp(12), dp(10), dp(12), dp(8));

        LinearLayout pinRow = new LinearLayout(this);
        pinRow.setOrientation(LinearLayout.HORIZONTAL);
        pinRow.setGravity(Gravity.CENTER_VERTICAL);

        LinearLayout pinLeft = new LinearLayout(this);
        pinLeft.setOrientation(LinearLayout.VERTICAL);
        TextView pLbl = new TextView(this);
        pLbl.setText("本机 6 位验证码（告诉对方即可加好友）");
        pLbl.setTextSize(12);
        pLbl.setTextColor(0xFF1E3A8A);
        pinLeft.addView(pLbl);

        myPinText = new TextView(this);
        myPinText.setTextSize(26);
        myPinText.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        myPinText.setTextColor(BLUE);
        myPinText.setOnClickListener(v -> {
            copy(core.pin);
            toast("已复制本机验证码 " + core.pin);
        });
        pinLeft.addView(myPinText);
        pinRow.addView(pinLeft, new LinearLayout.LayoutParams(0, -2, 1));

        Button refPin = new Button(this);
        refPin.setText("刷新");
        refPin.setTextSize(12);
        refPin.setOnClickListener(v -> {
            core.regeneratePin();
            myPinText.setText(Core.fmtPin(core.pin));
            toast("验证码已刷新为 " + core.pin);
        });
        pinRow.addView(refPin, new LinearLayout.LayoutParams(-2, -2));
        pinCard.addView(pinRow);

        relayBar = new TextView(this);
        relayBar.setTextSize(12);
        relayBar.setPadding(dp(8), dp(6), dp(8), dp(6));
        relayBar.setBackground(round(Color.WHITE, 0xFFD1D5DB));
        relayBar.setOnClickListener(v -> openRelayDialog());
        LinearLayout.LayoutParams rlp = new LinearLayout.LayoutParams(-1, -2);
        rlp.topMargin = dp(8);
        pinCard.addView(relayBar, rlp);
        root.addView(pinCard, cardLp);

        // 添加好友主按钮
        Button addBtn = new Button(this);
        addBtn.setText("＋ 输入对方 6 位验证码添加好友");
        addBtn.setTextSize(15);
        addBtn.setTextColor(Color.WHITE);
        addBtn.setBackground(round(BLUE, 0));
        addBtn.setOnClickListener(v -> openAddFriendDialog());
        LinearLayout.LayoutParams abLp = new LinearLayout.LayoutParams(-1, dp(46));
        abLp.setMargins(dp(12), 0, dp(12), dp(8));
        root.addView(addBtn, abLp);

        homePending = new TextView(this);
        homePending.setBackgroundColor(0xFFFFF4E5);
        homePending.setTextColor(0xFF9A3412);
        homePending.setPadding(dp(12), dp(8), dp(12), dp(8));
        homePending.setVisibility(View.GONE);
        homePending.setOnClickListener(v -> {
            pending.clear();
            updatePendingBanners();
        });
        root.addView(homePending);

        TextView listHdr = new TextView(this);
        listHdr.setText("好友对话窗口（点击进入独立对话，长按可断开）");
        listHdr.setTextSize(13);
        listHdr.setTypeface(Typeface.DEFAULT_BOLD);
        listHdr.setTextColor(0xFF374151);
        listHdr.setPadding(dp(14), dp(4), dp(14), dp(4));
        root.addView(listHdr);

        homeEmpty = new TextView(this);
        homeEmpty.setText("还没有好友对话\n\n点击上方蓝色按钮输入电脑/另一台手机的 6 位验证码，或让对方输入你的验证码。");
        homeEmpty.setGravity(Gravity.CENTER);
        homeEmpty.setTextColor(0xFF6B7280);
        homeEmpty.setPadding(dp(28), dp(40), dp(28), dp(40));
        root.addView(homeEmpty);

        friendListView = new ListView(this);
        friendListView.setDividerHeight(dp(1));
        friendAdapter = new FriendAdapter(this);
        friendListView.setAdapter(friendAdapter);
        friendListView.setOnItemClickListener((p, v, pos, id) -> openChat(friendItems.get(pos).id));
        friendListView.setOnItemLongClickListener((p, v, pos, id) -> {
            final Core.Device d = friendItems.get(pos);
            new AlertDialog.Builder(this)
                    .setTitle("断开好友")
                    .setMessage("确定要断开与「" + d.name + "」的连接吗？")
                    .setPositiveButton("断开", (dlg, w) -> core.removeFriend(d.id))
                    .setNegativeButton("取消", null)
                    .show();
            return true;
        });
        root.addView(friendListView, new LinearLayout.LayoutParams(-1, 0, 1));

        homeFooter = new TextView(this);
        homeFooter.setTextSize(11);
        homeFooter.setTextColor(0xFF6B7280);
        homeFooter.setPadding(dp(12), dp(6), dp(12), dp(8));
        root.addView(homeFooter);
        return root;
    }

    Button compactBtn(String label) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(12);
        b.setMinWidth(0);
        b.setMinimumWidth(0);
        b.setMinHeight(0);
        b.setMinimumHeight(0);
        b.setPadding(dp(10), dp(6), dp(10), dp(6));
        return b;
    }

    View buildChatView() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFFF3F4F6);

        LinearLayout topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        topBar.setBackgroundColor(Color.WHITE);
        topBar.setPadding(dp(8), dp(6), dp(8), dp(6));

        Button back = compactBtn("← 好友");
        back.setOnClickListener(v -> closeChat());
        topBar.addView(back, new LinearLayout.LayoutParams(-2, -2));

        chatTitle = new TextView(this);
        chatTitle.setTextSize(16);
        chatTitle.setTypeface(Typeface.DEFAULT_BOLD);
        chatTitle.setTextColor(0xFF111827);
        chatTitle.setSingleLine(true);
        chatTitle.setEllipsize(TextUtils.TruncateAt.END);
        chatTitle.setPadding(dp(10), 0, dp(8), 0);
        topBar.addView(chatTitle, new LinearLayout.LayoutParams(0, -2, 1));

        Button clr = compactBtn("清空");
        clr.setOnClickListener(v -> {
            if (activePeerId != null) {
                core.chatOf(activePeerId).clear();
                msgAdapter.notifyDataSetChanged();
                friendAdapter.notifyDataSetChanged();
                toast("已清空当前对话记录");
            }
        });
        LinearLayout.LayoutParams clrLp = new LinearLayout.LayoutParams(-2, -2);
        clrLp.rightMargin = dp(4);
        topBar.addView(clr, clrLp);

        Button disc = compactBtn("断开");
        disc.setOnClickListener(v -> {
            if (activePeerId != null) {
                core.removeFriend(activePeerId);
                closeChat();
            }
        });
        topBar.addView(disc, new LinearLayout.LayoutParams(-2, -2));
        root.addView(topBar);

        // 独立通栏安全码状态条，完整展示 4 位 Emoji 安全码与连接地址（点按可放大核对）
        chatSub = new TextView(this);
        chatSub.setTextSize(13);
        chatSub.setTextColor(0xFF065F46);
        chatSub.setBackgroundColor(0xFFECFDF5);
        chatSub.setPadding(dp(12), dp(6), dp(12), dp(6));
        chatSub.setOnClickListener(v -> {
            Core.Device d = core.friend(activePeerId);
            if (d != null && d.sas != null && !d.sas.isEmpty()) {
                new AlertDialog.Builder(this)
                        .setTitle("端到端加密安全码")
                        .setMessage("请确认对方「" + d.name + "」聊天顶栏显示的 4 个图标与此完全一致：\n\n        " + d.sas + "\n\n一致即证明无任何中间人攻击。")
                        .setPositiveButton("知道了", null)
                        .show();
            }
        });
        root.addView(chatSub, new LinearLayout.LayoutParams(-1, -2));

        chatPending = new TextView(this);
        chatPending.setBackgroundColor(0xFFFFF4E5);
        chatPending.setTextColor(0xFF9A3412);
        chatPending.setPadding(dp(12), dp(8), dp(12), dp(8));
        chatPending.setVisibility(View.GONE);
        chatPending.setOnClickListener(v -> {
            pending.clear();
            updatePendingBanners();
        });
        root.addView(chatPending);

        msgListView = new ListView(this);
        msgListView.setDivider(null);
        msgListView.setStackFromBottom(true);
        msgListView.setTranscriptMode(ListView.TRANSCRIPT_MODE_NORMAL);
        msgListView.setPadding(dp(8), 0, dp(8), 0);
        msgListView.setClipToPadding(false);
        msgAdapter = new MsgAdapter(this);
        msgListView.setAdapter(msgAdapter);
        msgListView.setOnItemClickListener((p, v, pos, id) -> onMsgClick(activeMessages().get(pos)));
        msgListView.setOnItemLongClickListener((p, v, pos, id) -> {
            onMsgLongClick(pos, activeMessages().get(pos));
            return true;
        });
        root.addView(msgListView, new LinearLayout.LayoutParams(-1, 0, 1));

        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        progress.setMax(100);
        progress.setVisibility(View.GONE);
        root.addView(progress, new LinearLayout.LayoutParams(-1, dp(6)));

        statusText = new TextView(this);
        statusText.setTextSize(12);
        statusText.setTextColor(0xFF666666);
        statusText.setSingleLine(true);
        statusText.setEllipsize(TextUtils.TruncateAt.MIDDLE);
        statusText.setPadding(dp(12), dp(2), dp(12), dp(2));
        statusText.setText("就绪（局域网直连优先，跨网自动走中转）");
        root.addView(statusText);

        LinearLayout bottom = new LinearLayout(this);
        bottom.setOrientation(LinearLayout.HORIZONTAL);
        bottom.setGravity(Gravity.CENTER_VERTICAL);
        bottom.setBackgroundColor(Color.WHITE);
        bottom.setPadding(dp(6), dp(6), dp(6), dp(6));

        Button file = new Button(this);
        file.setText("文件");
        file.setOnClickListener(v -> pickFiles());
        bottom.addView(file, new LinearLayout.LayoutParams(-2, -2));

        input = new EditText(this);
        input.setHint("输入要发送的文字…");
        input.setMaxLines(5);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        bottom.addView(input, new LinearLayout.LayoutParams(0, -2, 1));

        Button send = new Button(this);
        send.setText("发送");
        send.setOnClickListener(v -> onSendClick());
        bottom.addView(send, new LinearLayout.LayoutParams(-2, -2));

        root.addView(bottom);
        return root;
    }

    // ------------------------------------------------------------------ 视图同步
    ArrayList<Core.Msg> activeMessages() {
        return activePeerId == null ? new ArrayList<>() : core.chatOf(activePeerId);
    }

    void syncViewVisibility() {
        if (activePeerId != null && core.friend(activePeerId) == null) {
            activePeerId = null;
        }
        boolean inChat = activePeerId != null;
        homeView.setVisibility(inChat ? View.GONE : View.VISIBLE);
        chatView.setVisibility(inChat ? View.VISIBLE : View.GONE);
        if (inChat) {
            Core.Device d = core.friend(activePeerId);
            chatTitle.setText(d.label());
            String sasTag = (d.sas != null && !d.sas.isEmpty()) ? ("安全码 " + d.sas + " · ") : "";
            chatSub.setText("🔒 " + sasTag + "SPAKE2+AES256 · " + d.loc());
            core.unread.remove(activePeerId);
            msgAdapter.notifyDataSetChanged();
            if (!pending.isEmpty()) sendPendingTo(d);
        }
        updatePendingBanners();
    }

    void openChat(String peerId) {
        if (core.friend(peerId) == null) return;
        activePeerId = peerId;
        core.unread.remove(peerId);
        syncViewVisibility();
        friendAdapter.notifyDataSetChanged();
    }

    void closeChat() {
        activePeerId = null;
        syncViewVisibility();
        refreshFriendsList();
    }

    void refreshAllUi() {
        myPinText.setText(Core.fmtPin(core.pin));
        renderRelayBar(core.relayConnected, core.relayStatusText);
        refreshFriendsList();
        renderFooter();
        syncViewVisibility();
    }

    void refreshFriendsList() {
        friendItems.clear();
        friendItems.addAll(core.friends());
        homeEmpty.setVisibility(friendItems.isEmpty() ? View.VISIBLE : View.GONE);
        friendAdapter.notifyDataSetChanged();
    }

    void renderRelayBar(boolean connected, String text) {
        relayBar.setText((connected ? "● " : "○ ") + text);
        relayBar.setTextColor(connected ? 0xFF065F46 : 0xFF475569);
    }

    void renderFooter() {
        homeFooter.setText("本机：" + core.name + "  ·  局域网 IP：" + Core.localIp()
                + "  ·  局域网发现 " + core.discoveredCount() + " 台设备\n接收目录：" + core.saveDir().getAbsolutePath());
    }

    void updatePendingBanners() {
        if (pending.isEmpty()) {
            homePending.setVisibility(View.GONE);
            chatPending.setVisibility(View.GONE);
        } else {
            homePending.setVisibility(View.VISIBLE);
            homePending.setText("待发送 " + pending.size() + " 个文件：请点下方好友立即发送（点此取消）");
            chatPending.setVisibility(View.VISIBLE);
            chatPending.setText("待发送 " + pending.size() + " 个文件：点击「发送」立即发送（点此取消）");
        }
    }

    // ------------------------------------------------------------------ 弹窗：加好友 / 配中转
    void openAddFriendDialog() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(12), dp(20), dp(4));

        TextView l1 = new TextView(this);
        l1.setText("对方屏幕上的 6 位数字验证码：");
        l1.setTextSize(13);
        box.addView(l1);

        final EditText ePin = new EditText(this);
        ePin.setHint("000000");
        ePin.setGravity(Gravity.CENTER);
        ePin.setTextSize(24);
        ePin.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        ePin.setTextColor(BLUE);
        ePin.setInputType(InputType.TYPE_CLASS_NUMBER);
        ePin.setFilters(new InputFilter[]{new InputFilter.LengthFilter(6)});
        box.addView(ePin);

        TextView l2 = new TextView(this);
        l2.setText("对方 IP（选填，同局域网或已连同一中转服务器时留空即可）：");
        l2.setTextSize(12);
        l2.setTextColor(0xFF6B7280);
        l2.setPadding(0, dp(10), 0, 0);
        box.addView(l2);

        final EditText eIp = new EditText(this);
        eIp.setHint("例如 192.168.1.5（留空自动匹配）");
        eIp.setInputType(InputType.TYPE_CLASS_PHONE);
        eIp.setSingleLine(true);
        box.addView(eIp);

        new AlertDialog.Builder(this)
                .setTitle("添加好友")
                .setView(box)
                .setPositiveButton("验证并添加", (dlg, w) -> {
                    String pin = ePin.getText().toString().trim();
                    String ip = eIp.getText().toString().trim();
                    toast("正在验证 6 位验证码…");
                    core.pairByPin(pin, ip, (ok, dev, msg) -> {
                        toast(msg);
                        if (ok && dev != null) {
                            openChat(dev.id);
                        }
                    });
                })
                .setNegativeButton("取消", null)
                .show();
    }

    void openRelayDialog() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(12), dp(20), dp(4));

        TextView tip = new TextView(this);
        tip.setText("填入你部署的 relay_server.py 地址后，跨公网（如手机开 5G）也能用 6 位验证码加好友并互传文件；在同一 WiFi 时仍优先局域网直连。");
        tip.setTextSize(12);
        tip.setTextColor(0xFF4B5563);
        tip.setPadding(0, 0, 0, dp(10));
        box.addView(tip);

        TextView l1 = new TextView(this);
        l1.setText("中转服务器地址（IP:端口，留空表示仅局域网）：");
        l1.setTextSize(13);
        box.addView(l1);

        final EditText eAddr = new EditText(this);
        eAddr.setHint("IP:端口 或 tls://域名:端口");
        eAddr.setSingleLine(true);
        eAddr.setText(core.relayAddr);
        box.addView(eAddr);

        TextView l2 = new TextView(this);
        l2.setText("接入密钥（可选，与服务端 --key 一致）：");
        l2.setTextSize(13);
        l2.setPadding(0, dp(8), 0, 0);
        box.addView(l2);

        final EditText eKey = new EditText(this);
        eKey.setHint("服务端未设置则留空");
        eKey.setSingleLine(true);
        eKey.setText(core.relayKey);
        box.addView(eKey);

        new AlertDialog.Builder(this)
                .setTitle("公网中转服务器设置")
                .setView(box)
                .setPositiveButton("保存并连接", (dlg, w) -> {
                    core.setRelay(eAddr.getText().toString(), eKey.getText().toString());
                    toast("已更新中转配置");
                })
                .setNegativeButton("取消", null)
                .show();
    }

    // ------------------------------------------------------------------ 收发动作
    void onSendClick() {
        Core.Device d = core.friend(activePeerId);
        if (d == null) {
            closeChat();
            return;
        }
        String text = input.getText().toString();
        if (pending.isEmpty() && text.trim().isEmpty()) {
            toast("请输入文字，或点「文件」选择文件");
            return;
        }
        if (!text.trim().isEmpty()) {
            core.sendText(d, text);
            input.setText("");
        }
        if (!pending.isEmpty()) sendPendingTo(d);
    }

    void sendPendingTo(Core.Device d) {
        if (d == null || pending.isEmpty()) return;
        core.sendUris(d, new ArrayList<>(pending));
        pending.clear();
        updatePendingBanners();
    }

    void pickFiles() {
        if (core.friend(activePeerId) == null) return;
        Intent i = new Intent(Intent.ACTION_GET_CONTENT);
        i.setType("*/*");
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        try {
            startActivityForResult(Intent.createChooser(i, "选择要发送的文件"), REQ_PICK);
        } catch (ActivityNotFoundException e) {
            toast("没有可用的文件选择器");
        }
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req != REQ_PICK || res != RESULT_OK || data == null) return;
        if (data.getClipData() != null) {
            ClipData cd = data.getClipData();
            for (int i = 0; i < cd.getItemCount(); i++) pending.add(cd.getItemAt(i).getUri());
        } else if (data.getData() != null) {
            pending.add(data.getData());
        }
        Core.Device d = core.friend(activePeerId);
        if (d != null && !pending.isEmpty()) sendPendingTo(d);
        else updatePendingBanners();
    }

    void handleIntent(Intent intent) {
        if (intent == null) return;
        String a = intent.getAction();
        if (Intent.ACTION_SEND.equals(a)) {
            Uri u = intent.getParcelableExtra(Intent.EXTRA_STREAM);
            if (u != null) pending.add(u);
            else {
                CharSequence t = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
                if (t != null && input != null) input.setText(t);
            }
        } else if (Intent.ACTION_SEND_MULTIPLE.equals(a)) {
            ArrayList<Uri> us = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
            if (us != null) pending.addAll(us);
        }
        Core.Device d = core.friend(activePeerId);
        if (d == null && core.friends().size() == 1) d = core.friends().get(0);
        if (d != null && !pending.isEmpty()) {
            openChat(d.id);
            sendPendingTo(d);
        } else {
            updatePendingBanners();
        }
    }

    void rename() {
        final EditText e = new EditText(this);
        e.setText(core.name);
        new AlertDialog.Builder(this)
                .setTitle("本机显示名称")
                .setView(e)
                .setPositiveButton("确定", (dlg, w) -> {
                    String n = e.getText().toString().trim();
                    if (!n.isEmpty()) {
                        core.setName(n);
                        renderFooter();
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    void onMsgClick(Core.Msg m) {
        if (m.error) return;
        if (m.isFile && m.path != null) {
            File f = new File(m.path);
            String ext = MimeTypeMap.getFileExtensionFromUrl(Uri.fromFile(f).toString());
            String mime = ext == null ? null : MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext.toLowerCase(Locale.US));
            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setDataAndType(Uri.fromFile(f), mime == null ? "*/*" : mime);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
            try {
                startActivity(i);
            } catch (Exception e) {
                toast("没有能打开此文件的应用：" + m.path);
            }
        } else if (!m.isFile) {
            copy(m.text);
            toast("已复制");
        }
    }

    void onMsgLongClick(final int pos, final Core.Msg m) {
        final boolean hasLocalFile = m.isFile && m.path != null && new File(m.path).isFile();
        String[] items = hasLocalFile
                ? new String[]{"分享", "删除此条消息", "删除消息并删除本地文件"}
                : new String[]{"分享", "删除此条消息"};
        new AlertDialog.Builder(this)
                .setItems(items, (dlg, which) -> {
                    if (which == 0) {
                        Intent i = new Intent(Intent.ACTION_SEND);
                        if (hasLocalFile) {
                            i.setType("*/*");
                            i.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(new File(m.path)));
                        } else {
                            i.setType("text/plain");
                            i.putExtra(Intent.EXTRA_TEXT, m.text);
                        }
                        try {
                            startActivity(Intent.createChooser(i, "分享"));
                        } catch (Exception ignored) {
                        }
                    } else if (which == 1 || which == 2) {
                        if (which == 2 && hasLocalFile) {
                            //noinspection ResultOfMethodCallIgnored
                            new File(m.path).delete();
                        }
                        ArrayList<Core.Msg> list = activeMessages();
                        if (pos >= 0 && pos < list.size() && list.get(pos) == m) {
                            list.remove(pos);
                        } else {
                            list.remove(m);
                        }
                        msgAdapter.notifyDataSetChanged();
                        friendAdapter.notifyDataSetChanged();
                        toast(which == 2 ? "已删除消息及本地文件" : "已删除消息");
                    }
                })
                .show();
    }

    void copy(String s) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) cm.setPrimaryClip(ClipData.newPlainText("LanFast", s));
    }

    void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }

    void askPermissions() {
        if (Build.VERSION.SDK_INT < 23) return;
        ArrayList<String> need = new ArrayList<>();
        if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED)
            need.add(Manifest.permission.WRITE_EXTERNAL_STORAGE);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED)
            need.add("android.permission.POST_NOTIFICATIONS");
        if (!need.isEmpty()) requestPermissions(need.toArray(new String[0]), 2);
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] results) {
        renderFooter();
    }

    // ------------------------------------------------------------------ 菜单
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, "添加好友（输 6 位验证码）");
        menu.add(0, 2, 0, "配置公网中转服务器");
        menu.add(0, 3, 0, "修改本机名称");
        menu.add(0, 4, 0, "退出（停止接收）");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case 1:
                openAddFriendDialog();
                return true;
            case 2:
                openRelayDialog();
                return true;
            case 3:
                rename();
                return true;
            case 4:
                startService(new Intent(this, LanService.class).setAction(LanService.ACTION_STOP));
                finishAndRemoveTask();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    // ------------------------------------------------------------------ Core 回调（主线程）
    @Override
    public void onFriendsChanged() {
        refreshFriendsList();
        syncViewVisibility();
    }

    @Override
    public void onFriendAdded(Core.Device d) {
        refreshFriendsList();
        toast("新好友加入：" + d.name);
    }

    @Override
    public void onDiscoveredChanged() {
        renderFooter();
    }

    @Override
    public void onRelayState(boolean connected, String text) {
        renderRelayBar(connected, text);
    }

    @Override
    public void onMessage(Core.Msg m) {
        if (m.peerId != null && m.peerId.equals(activePeerId)) {
            msgAdapter.notifyDataSetChanged();
        } else if (m.incoming && m.peerId != null) {
            Integer u = core.unread.get(m.peerId);
            core.unread.put(m.peerId, (u == null ? 0 : u) + 1);
        }
        friendAdapter.notifyDataSetChanged();
        if (m.incoming && !m.isFile) {
            copy(m.text);
            toast("收到 " + m.peer + " 的文字，已复制");
        }
    }

    @Override
    public void onStatus(String text, int percent) {
        statusText.setText(text);
        if (percent < 0) {
            progress.setVisibility(View.GONE);
        } else {
            progress.setVisibility(View.VISIBLE);
            progress.setProgress(percent);
        }
    }

    // ------------------------------------------------------------------ 适配器（全部 static，兼容 d8）
    static class FriendAdapter extends BaseAdapter {
        private final MainActivity act;

        FriendAdapter(MainActivity act) {
            this.act = act;
        }

        @Override
        public int getCount() {
            return act.friendItems.size();
        }

        @Override
        public Object getItem(int i) {
            return act.friendItems.get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int pos, View convert, ViewGroup parent) {
            LinearLayout row;
            TextView title, preview, badge;
            if (convert == null) {
                row = new LinearLayout(act);
                row.setOrientation(LinearLayout.HORIZONTAL);
                row.setGravity(Gravity.CENTER_VERTICAL);
                row.setBackgroundColor(Color.WHITE);
                row.setPadding(act.dp(14), act.dp(12), act.dp(14), act.dp(12));

                LinearLayout left = new LinearLayout(act);
                left.setOrientation(LinearLayout.VERTICAL);
                title = new TextView(act);
                title.setTextSize(15);
                title.setTypeface(Typeface.DEFAULT_BOLD);
                title.setTextColor(0xFF111827);
                preview = new TextView(act);
                preview.setTextSize(12);
                preview.setTextColor(0xFF6B7280);
                preview.setSingleLine(true);
                preview.setEllipsize(TextUtils.TruncateAt.END);
                left.addView(title);
                left.addView(preview);
                row.addView(left, new LinearLayout.LayoutParams(0, -2, 1));

                badge = new TextView(act);
                badge.setTextSize(11);
                badge.setTextColor(Color.WHITE);
                badge.setTypeface(Typeface.DEFAULT_BOLD);
                badge.setGravity(Gravity.CENTER);
                badge.setBackground(act.round(0xFFEF4444, 0));
                badge.setPadding(act.dp(8), act.dp(2), act.dp(8), act.dp(2));
                row.addView(badge, new LinearLayout.LayoutParams(-2, -2));
                row.setTag(new TextView[]{title, preview, badge});
            } else {
                row = (LinearLayout) convert;
                TextView[] h = (TextView[]) row.getTag();
                title = h[0];
                preview = h[1];
                badge = h[2];
            }
            Core.Device d = act.friendItems.get(pos);
            title.setText(d.label() + "  (" + d.loc() + ")");
            ArrayList<Core.Msg> list = act.core.chats.get(d.id);
            if (list == null || list.isEmpty()) {
                preview.setText("点击打开独立对话窗口，直接互传文字与文件");
            } else {
                Core.Msg last = list.get(list.size() - 1);
                preview.setText((last.incoming ? "对方：" : "我：") + (last.isFile ? "📄 " + last.text : last.text));
            }
            Integer u = act.core.unread.get(d.id);
            if (u != null && u > 0) {
                badge.setVisibility(View.VISIBLE);
                badge.setText(String.valueOf(u));
            } else {
                badge.setVisibility(View.GONE);
            }
            return row;
        }
    }

    static class MsgAdapter extends BaseAdapter {
        private final MainActivity act;

        MsgAdapter(MainActivity act) {
            this.act = act;
        }

        @Override
        public int getCount() {
            return act.activeMessages().size();
        }

        @Override
        public Object getItem(int i) {
            return act.activeMessages().get(i);
        }

        @Override
        public long getItemId(int i) {
            return i;
        }

        @Override
        public View getView(int pos, View convert, ViewGroup parent) {
            LinearLayout row;
            TextView meta, bubble;
            if (convert == null) {
                row = new LinearLayout(act);
                row.setOrientation(LinearLayout.VERTICAL);
                row.setPadding(0, act.dp(6), 0, act.dp(2));
                meta = new TextView(act);
                meta.setTextSize(11);
                meta.setTextColor(0xFF888888);
                bubble = new TextView(act);
                bubble.setTextSize(15);
                bubble.setTextIsSelectable(false);
                bubble.setPadding(act.dp(12), act.dp(8), act.dp(12), act.dp(8));
                bubble.setMaxWidth((int) (act.getResources().getDisplayMetrics().widthPixels * 0.8));
                row.addView(meta, new LinearLayout.LayoutParams(-2, -2));
                row.addView(bubble, new LinearLayout.LayoutParams(-2, -2));
                row.setTag(new TextView[]{meta, bubble});
            } else {
                row = (LinearLayout) convert;
                TextView[] h = (TextView[]) row.getTag();
                meta = h[0];
                bubble = h[1];
            }
            Core.Msg m = act.activeMessages().get(pos);
            row.setGravity(m.incoming ? Gravity.START : Gravity.END);
            String rt = (m.route != null && !m.route.isEmpty()) ? (" · " + m.route) : "";
            meta.setText((m.incoming ? "← 对方" : "→ 我") + " · " + act.timeFmt.format(new Date(m.time)) + rt);
            if (m.error) {
                bubble.setText(m.text);
                bubble.setBackground(act.round(0xFFFEE2E2, 0));
                bubble.setTextColor(0xFFB91C1C);
            } else if (m.isFile) {
                bubble.setText("📄 " + m.text + "\n" + Core.human(m.size) + (m.path != null ? " · 点击打开" : ""));
                bubble.setBackground(act.round(m.incoming ? Color.WHITE : 0xFFDBEAFE, 0));
                bubble.setTextColor(0xFF111827);
            } else {
                bubble.setText(m.text);
                bubble.setBackground(act.round(m.incoming ? Color.WHITE : 0xFFDBEAFE, 0));
                bubble.setTextColor(0xFF111827);
            }
            return row;
        }
    }
}
