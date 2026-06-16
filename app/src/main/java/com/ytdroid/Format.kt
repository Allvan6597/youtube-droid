package com.ytdroid

data class Format(
    val itag: Int,
    val mime: String,
    val url: String,
    val size: Long,
    val bitrate: Int,
    val width: Int,
    val height: Int,
    val quality: String,
    val type: String
)
