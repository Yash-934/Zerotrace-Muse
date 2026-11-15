package com.zerotrace.messenger.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color

/** UI preference only — never a key or message. Stored in SharedPreferences. */
enum class ThemeMode { SYSTEM, DARK, LIGHT }

enum class Accent(val color: Color, val label: String) {
    GREEN(Color(0xFF4ADE80), "Green"),
    TEAL(Color(0xFF2DD4BF), "Teal"),
    EMERALD(Color(0xFF34D399), "Emerald")
}

private val Charcoal = Color(0xFF0B0D0E)
private val SurfaceDark = Color(0xFF14181A)
private val SurfaceHighDark = Color(0xFF1C2124)
private val GreenDim = Color(0xFF22C55E)
private val Amber = Color(0xFFF59E0B)
private val Red = Color(0xFFEF4444)
private val TextPrimaryDark = Color(0xFFE7ECEE)
private val TextSecondaryDark = Color(0xFF9AA5AB)

private val Paper = Color(0xFFF7F5F0)
private val SurfaceLight = Color(0xFFFFFFFF)
private val SurfaceHighLight = Color(0xFFEDEBE6)
private val GreenDeep = Color(0xFF15803D)
private val TextPrimaryLight = Color(0xFF111827)
private val TextSecondaryLight = Color(0xFF6B7280)

private fun darkScheme(accent: Accent) = darkColorScheme(
    primary = accent.color,
    secondary = GreenDim,
    tertiary = Amber,
    error = Red,
    background = Charcoal,
    surface = SurfaceDark,
    surfaceVariant = SurfaceHighDark,
    onPrimary = Color.Black,
    onBackground = TextPrimaryDark,
    onSurface = TextPrimaryDark,
    onSurfaceVariant = TextSecondaryDark
)

private fun lightScheme(accent: Accent) = lightColorScheme(
    primary = GreenDeep,
    secondary = accent.color,
    tertiary = Amber,
    error = Red,
    background = Paper,
    surface = SurfaceLight,
    surfaceVariant = SurfaceHighLight,
    onPrimary = Color.White,
    onBackground = TextPrimaryLight,
    onSurface = TextPrimaryLight,
    onSurfaceVariant = TextSecondaryLight
)

@Composable
fun ZeroTraceTheme(
    mode: ThemeMode = ThemeMode.DARK,
    accent: Accent = Accent.GREEN,
    content: @Composable () -> Unit
) {
    val dark = when (mode) {
        ThemeMode.DARK -> true
        ThemeMode.LIGHT -> false
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }
    val scheme = if (dark) darkScheme(accent) else lightScheme(accent)
    MaterialTheme(colorScheme = scheme) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = scheme.background,
            contentColor = scheme.onBackground,
            content = content
        )
    }
}

/** Chat bubble colours, derived from the theme so light/dark both read well. */
object ChatColors {
    val OutgoingBubble = Color(0xFF1E5B3C)
    val OutgoingBubbleLight = Color(0xFFD9FDD3)
    val IncomingBubble = Color(0xFF1C2124)
    val IncomingBubbleLight = Color(0xFFFFFFFF)
}
