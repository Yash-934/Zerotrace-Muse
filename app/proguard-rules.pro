# ZeroTrace Messenger — ProGuard rules (release builds have minification OFF,
# so these are belt-and-braces only).
# Keep JNI entry points: the Rust core calls these by exact name.
-keep class com.zerotrace.messenger.bridge.RustCoreBridge { *; }
# Keep the foreground service (referenced from the manifest).
-keep class com.zerotrace.messenger.network.SessionService { *; }
