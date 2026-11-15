package com.zerotrace.messenger.security

import android.app.Activity
import android.os.Build
import android.view.WindowManager
import com.zerotrace.messenger.BuildConfig

/**
 * FLAG_SECURE on every screen that can show identity material or chat content.
 *
 * Note: On streaming/cloud emulators (or debug builds streamed over virtual displays),
 * FLAG_SECURE causes SurfaceFlinger to black out the entire window stream. We skip
 * FLAG_SECURE on emulator/debug streaming environments so the UI is visible, while
 * keeping it enforced on physical release builds.
 */
object SecureWindowManager {
    private fun isEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") ||
            Build.FINGERPRINT.startsWith("unknown") ||
            Build.MODEL.contains("google_sdk") ||
            Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for") ||
            Build.MANUFACTURER.contains("Genymotion") ||
            Build.BRAND.startsWith("generic") ||
            Build.DEVICE.startsWith("generic") ||
            Build.PRODUCT.contains("sdk") ||
            Build.HARDWARE.contains("goldfish") ||
            Build.HARDWARE.contains("ranchu")

    fun apply(activity: Activity) {
        if (BuildConfig.DEBUG || isEmulator()) {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            return
        }
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
