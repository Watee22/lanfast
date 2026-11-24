package com.lanfast.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/** 前台服务：保证切到后台/锁屏时仍能接收文件。 */
public class LanService extends Service {
    static final String CH_RUN = "run";
    static final String CH_MSG = "msg";
    static final String ACTION_STOP = "com.lanfast.app.STOP";

    static void ensureChannels(Context c) {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
            nm.createNotificationChannel(new NotificationChannel(CH_RUN, "后台运行", NotificationManager.IMPORTANCE_LOW));
            nm.createNotificationChannel(new NotificationChannel(CH_MSG, "收到的消息", NotificationManager.IMPORTANCE_HIGH));
        }
    }

    @SuppressWarnings("deprecation")
    static Notification.Builder builder(Context c, String channel) {
        ensureChannels(c);
        return Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(c, channel) : new Notification.Builder(c);
    }

    static PendingIntent openApp(Context c) {
        Intent i = new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        return PendingIntent.getActivity(c, 0, i, flags);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Notification n = builder(this, CH_RUN)
                .setSmallIcon(R.drawable.ic_stat)
                .setContentTitle("LanFast 正在运行")
                .setContentText("同一局域网的设备可以随时发送文件和文字到本机")
                .setContentIntent(openApp(this))
                .setOngoing(true)
                .build();
        startForeground(1, n);
        Core.get(this).start();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopForeground(true);
            stopSelf();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        Core.get(this).stop();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
