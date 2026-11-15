package com.zerotrace.messenger

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.zerotrace.messenger.security.SecureWindowManager
import com.zerotrace.messenger.session.Screen
import com.zerotrace.messenger.session.Tab
import com.zerotrace.messenger.session.ZeroTraceViewModel
import com.zerotrace.messenger.ui.AddContactScreen
import com.zerotrace.messenger.ui.CallScreen
import com.zerotrace.messenger.ui.ChatScreen
import com.zerotrace.messenger.ui.ContactProfileScreen
import com.zerotrace.messenger.ui.CreateIdentityScreen
import com.zerotrace.messenger.ui.DashboardScreen
import com.zerotrace.messenger.ui.LockScreen
import com.zerotrace.messenger.ui.MainTabs
import com.zerotrace.messenger.ui.MyIdentityScreen
import com.zerotrace.messenger.ui.OnboardingScreen
import com.zerotrace.messenger.ui.SettingsScreen
import com.zerotrace.messenger.ui.SplashScreen
import com.zerotrace.messenger.ui.theme.ZeroTraceTheme

class MainActivity : ComponentActivity() {
    private lateinit var vm: ZeroTraceViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindowManager.apply(this)
        val factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                ZeroTraceViewModel(applicationContext) as T
        }
        vm = ViewModelProvider(this, factory)[ZeroTraceViewModel::class.java]
        setContent {
            val themeMode by vm.themeMode.collectAsState()
            val accent by vm.accent.collectAsState()
            ZeroTraceTheme(mode = themeMode, accent = accent) {
                val screen by vm.screen.collectAsState()
                val unlocked by vm.unlocked.collectAsState()
                val appLock by vm.appLockEnabled.collectAsState()
                if (appLock && !unlocked && screen != Screen.SPLASH && screen != Screen.ONBOARDING && screen != Screen.CREATE_IDENTITY) {
                    LockScreen(vm)
                    return@ZeroTraceTheme
                }
                BackHandler(
                    enabled = screen in setOf(
                        Screen.MY_IDENTITY,
                        Screen.ADD_CONTACT,
                        Screen.VERIFY_CONTACT,
                        Screen.CHAT,
                        Screen.CONTACT_PROFILE,
                        Screen.DASHBOARD,
                        Screen.SETTINGS
                    )
                ) {
                    when (screen) {
                        Screen.DASHBOARD -> vm.go(Screen.SETTINGS)
                        Screen.CONTACT_PROFILE -> vm.go(Screen.CHAT)
                        else -> vm.goTab(Tab.CHATS)
                    }
                }
                when (screen) {
                    Screen.SPLASH -> SplashScreen()
                    Screen.ONBOARDING -> OnboardingScreen(vm)
                    Screen.CREATE_IDENTITY -> CreateIdentityScreen()
                    Screen.MAIN -> MainTabs(vm)
                    Screen.MY_IDENTITY -> MyIdentityScreen(vm)
                    Screen.ADD_CONTACT -> AddContactScreen(vm)
                    Screen.VERIFY_CONTACT -> AddContactScreen(vm)
                    Screen.CHAT -> ChatScreen(vm)
                    Screen.CONTACT_PROFILE -> ContactProfileScreen(vm)
                    Screen.DASHBOARD -> DashboardScreen(vm)
                    Screen.SETTINGS -> SettingsScreen(vm)
                    Screen.CALL -> CallScreen(vm)
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        // Backgrounding does not by itself wipe the session (the user may return),
        // but the session timeout still applies. The lock button is the wipe path.
    }
}
