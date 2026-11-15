package com.zerotrace.messenger.network

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.zerotrace.messenger.R

/**
 * Foreground service that keeps the Tor client + onion service alive while a session
 * is active. The notification NEVER contains message content, sender names or
 * fingerprints — only the session state.
 */
class SessionService : Service() {
    companion object {
        const val CHANNEL_ID = "zerotrace_session"
        const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "com.zerotrace.messenger.STOP_SESSION"
    }

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(
                CHANNEL_ID, "ZeroTrace session",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Shows while an encrypted session is active. No message content is shown." }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ZeroTrace session active")
            .setContentText("Encrypted session running. Messages are not stored.")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
