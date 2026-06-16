package com.ytdroid

import android.app.DownloadManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.webkit.URLUtil
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import com.ytdroid.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URL

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var formats: List<Format> = emptyList()

    private val writePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* handled in calling function */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.formatsRecycler.layoutManager = LinearLayoutManager(this)

        // Handle incoming share/view intent
        handleIntent(intent)

        binding.fetchBtn.setOnClickListener {
            val input = binding.urlInput.text.toString().trim()
            val videoId = extractVideoId(input)
            if (videoId == null) {
                showErrorDialog("رابط غير صالح",
                    "الرجاء إدخال رابط YouTube صحيح مثل:\n" +
                    "• https://youtube.com/watch?v=VIDEO_ID\n" +
                    "• https://youtu.be/VIDEO_ID\n" +
                    "• VIDEO_ID (11 حرف)")
                return@setOnClickListener
            }
            fetchFormats(videoId)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val uri = intent?.data ?: return
        val videoId = extractVideoId(uri.toString())
        if (videoId != null) {
            binding.urlInput.setText(videoId)
            fetchFormats(videoId)
        }
    }

    private fun extractVideoId(input: String): String? {
        // Try direct 11-char ID
        if (input.matches(Regex("^[\\w-]{11}$"))) return input

        // Extract from various URL formats
        val patterns = listOf(
            Regex("""(?:youtube\\.com|youtu\\.be|m\\.youtube\\.com)"""),
        )
        val uri = try { Uri.parse(input) } catch (_: Exception) { return null }

        // youtube.com/watch?v=ID
        uri.getQueryParameter("v")?.let { if (it.length == 11) return it }

        // youtu.be/ID
        if (uri.host == "youtu.be") {
            uri.path?.trimStart('/')?.let { if (it.length == 11) return it }
        }

        // m.youtube.com/watch?v=ID
        if (uri.host?.contains("youtube") == true) {
            uri.getQueryParameter("v")?.let { if (it.length == 11) return it }
        }

        // embedded: youtube.com/embed/ID
        uri.path?.let { path ->
            val parts = path.trimStart('/').split('/')
            if (parts.size >= 2 && parts[0] == "embed" && parts[1].length == 11) return parts[1]
        }

        return null
    }

    private fun fetchFormats(videoId: String) {
        lifecycleScope.launch {
            binding.statusText.text = getString(R.string.loading)
            binding.fetchBtn.isEnabled = false
            binding.formatsRecycler.adapter = null

            try {
                val formatsJson = withContext(Dispatchers.IO) {
                    val py = Python.getInstance()
                    val module = py.getModule("yt_engine")
                    module.callAttr("get_formats_for_kotlin", videoId).toString()
                }

                val result = org.json.JSONObject(formatsJson)
                if (!result.getBoolean("success")) {
                    val error = result.optString("error", "خطأ غير معروف")
                    val trace = result.optString("traceback", "")
                    showErrorDialog("فشل جلب الفيديو", "$error\n\n$trace")
                    binding.statusText.text = getString(R.string.error_fetch)
                    return@launch
                }

                val formatsArray = result.getJSONArray("formats")
                formats = (0 until formatsArray.length()).map { i ->
                    val f = formatsArray.getJSONObject(i)
                    Format(
                        itag = f.getInt("itag"),
                        mime = f.getString("mime"),
                        url = f.getString("url"),
                        size = f.optLong("size", 0),
                        bitrate = f.optInt("bitrate", 0),
                        width = f.optInt("width", 0),
                        height = f.optInt("height", 0),
                        quality = f.getString("quality"),
                        type = f.getString("type")
                    )
                }

                if (formats.isEmpty()) {
                    binding.statusText.text = getString(R.string.no_formats)
                    return@launch
                }

                binding.statusText.text = "${formats.size} ستريم متاح"
                binding.formatsRecycler.adapter = FormatAdapter(formats) { fmt ->
                    downloadFormat(fmt)
                }
            } catch (e: Exception) {
                showErrorDialog("خطأ", "${e.message}\n\n${e.stackTraceToString()}")
                binding.statusText.text = getString(R.string.error_fetch)
            } finally {
                binding.fetchBtn.isEnabled = true
            }
        }
    }

    private fun downloadFormat(fmt: Format) {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.select_format))
            .setMessage("${fmt.quality}\n${fmt.mime}\n${if (fmt.size > 0) "%.0f MB".format(fmt.size / 1_000_000.0) else ""}")
            .setPositiveButton(getString(R.string.start_download)) { _, _ ->
                startDownload(fmt)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun startDownload(fmt: Format) {
        val fileName = URLUtil.guessFileName(fmt.url, null, fmt.mime)
        val downloadDir = Environment.getExternalStoragePublicDirectory(
            Environment.DIRECTORY_DOWNLOADS
        )

        // For Android 10+, use DownloadManager
        val downloadManager = getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
        val request = DownloadManager.Request(Uri.parse(fmt.url))
            .setTitle(fileName)
            .setDescription("YT Droid - ${fmt.quality}")
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setDestinationInExternalPublicDir(
                Environment.DIRECTORY_DOWNLOADS, fileName
            )
            .setMimeType(fmt.mime)

        try {
            downloadManager.enqueue(request)
            Snackbar.make(binding.root,
                "جاري تحميل ${fmt.quality}...",
                Snackbar.LENGTH_LONG).show()
        } catch (e: SecurityException) {
            // Fallback: download to app cache and share
            lifecycleScope.launch {
                try {
                    val file = withContext(Dispatchers.IO) {
                        val cacheFile = File(cacheDir, fileName)
                        URL(fmt.url).openStream().use { input ->
                            cacheFile.outputStream().use { output ->
                                input.copyTo(output)
                            }
                        }
                        cacheFile
                    }
                    val uri = FileProvider.getUriForFile(
                        this@MainActivity,
                        "${packageName}.fileprovider",
                        file
                    )
                    val shareIntent = Intent(Intent.ACTION_VIEW).apply {
                        setDataAndType(uri, fmt.mime)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    startActivity(Intent.createChooser(shareIntent, "فتح الفيديو"))
                } catch (e: Exception) {
                    showErrorDialog(getString(R.string.download_failed), e.stackTraceToString())
                }
            }
        }
    }

    private fun showErrorDialog(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .setNegativeButton("نسخ") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE)
                    as android.content.ClipboardManager
                clipboard.setPrimaryClip(
                    android.content.ClipData.newPlainText("error", message)
                )
                Toast.makeText(this, "تم النسخ", Toast.LENGTH_SHORT).show()
            }
            .show()
    }
}
