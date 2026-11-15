package com.zerotrace.messenger.ui

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.Rect
import android.graphics.YuvImage
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FlipCameraAndroid
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executors

/**
 * In-app camera. Captures straight into RAM (YUV -> JPEG bytes) — no photo
 * file is ever written to disk. The bytes go directly to the encrypted file
 * transfer when the user confirms.
 */
@Composable
fun CameraScreen(onCaptured: (ByteArray) -> Unit, onClose: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasPermission = granted
    }
    LaunchedEffect(Unit) { if (!hasPermission) launcher.launch(Manifest.permission.CAMERA) }
    var useFront by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val imageCapture = remember { ImageCapture.Builder().setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY).build() }
    var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    var previewViewRef by remember { mutableStateOf<PreviewView?>(null) }

    // (Re)bind the camera whenever the lens changes.
    LaunchedEffect(useFront, cameraProvider) {
        val provider = cameraProvider ?: return@LaunchedEffect
        val pv = previewViewRef ?: return@LaunchedEffect
        val preview = Preview.Builder().build().also { it.setSurfaceProvider(pv.surfaceProvider) }
        val selector = if (useFront) CameraSelector.DEFAULT_FRONT_CAMERA else CameraSelector.DEFAULT_BACK_CAMERA
        runCatching {
            provider.unbindAll()
            provider.bindToLifecycle(lifecycleOwner, selector, preview, imageCapture)
        }
    }

    if (!hasPermission) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("Camera permission is needed to take a photo.")
        }
        return
    }

    Box(Modifier.fillMaxSize()) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                previewViewRef = previewView
                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener({
                    cameraProvider = providerFuture.get()
                }, ContextCompat.getMainExecutor(ctx))
                previewView
            }
        )
        IconButton(onClick = onClose, modifier = Modifier.align(Alignment.TopStart).padding(16.dp)) {
            Icon(Icons.Filled.Close, contentDescription = "Close camera", tint = Color.White)
        }
        IconButton(
            onClick = { useFront = !useFront },
            modifier = Modifier.align(Alignment.TopEnd).padding(16.dp)
        ) {
            Icon(Icons.Filled.FlipCameraAndroid, contentDescription = "Switch camera", tint = Color.White)
        }
        error?.let {
            Text(it, color = Color.White, modifier = Modifier.align(Alignment.Center).padding(16.dp))
        }
        FloatingActionButton(
            onClick = {
                imageCapture.takePicture(executor, object : ImageCapture.OnImageCapturedCallback() {
                    override fun onCaptureSuccess(image: ImageProxy) {
                        val bytes = imageProxyToJpeg(image)
                        image.close()
                        if (bytes != null) onCaptured(bytes) else error = "Photo could not be captured."
                    }

                    override fun onError(exception: ImageCaptureException) {
                        error = "Camera failed: ${exception.message}"
                    }
                })
            },
            modifier = Modifier.align(Alignment.BottomCenter).padding(bottom = 32.dp).size(72.dp),
            shape = CircleShape
        ) { Text("●", color = Color.White) }
    }
}

/** Converts a YUV_420_888 ImageProxy to JPEG bytes, in memory. */
private fun imageProxyToJpeg(image: ImageProxy): ByteArray? {
    return try {
        if (image.format != ImageFormat.YUV_420_888) return null
        val yPlane = image.planes[0]
        val uPlane = image.planes[1]
        val vPlane = image.planes[2]
        val ySize = yPlane.buffer.remaining()
        val uSize = uPlane.buffer.remaining()
        val vSize = vPlane.buffer.remaining()
        val nv21 = ByteArray(ySize + uSize + vSize)
        yPlane.buffer.get(nv21, 0, ySize)
        // NV21 interleaves V then U.
        val uBytes = ByteArray(uSize).also { uPlane.buffer.get(it) }
        val vBytes = ByteArray(vSize).also { vPlane.buffer.get(it) }
        var pos = ySize
        for (i in vBytes.indices) {
            nv21[pos++] = vBytes[i]
            if (i < uBytes.size) nv21[pos++] = uBytes[i]
        }
        val yuv = YuvImage(nv21, ImageFormat.NV21, image.width, image.height, null)
        val out = ByteArrayOutputStream()
        yuv.compressToJpeg(Rect(0, 0, image.width, image.height), 85, out)
        out.toByteArray()
    } catch (_: Exception) {
        null
    }
}
