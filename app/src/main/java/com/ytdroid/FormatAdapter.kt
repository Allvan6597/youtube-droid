package com.ytdroid

import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

class FormatAdapter(
    private val formats: List<Format>,
    private val onDownload: (Format) -> Unit
) : RecyclerView.Adapter<FormatAdapter.ViewHolder>() {

    class ViewHolder(root: android.view.View) : RecyclerView.ViewHolder(root) {
        val qualityText: TextView = root.findViewById(R.id.quality_text)
        val infoText: TextView = root.findViewById(R.id.info_text)
        val downloadBtn: Button = root.findViewById(R.id.download_btn)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.format_item, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val fmt = formats[position]
        holder.qualityText.text = fmt.quality
        val sizeMB = if (fmt.size > 0) "%.0f MB".format(fmt.size / 1_000_000.0) else ""
        val bitrateStr = if (fmt.bitrate > 0) "${fmt.bitrate / 1000} kbps" else ""
        val info = buildList {
            add(fmt.mime)
            if (bitrateStr.isNotEmpty()) add(bitrateStr)
            if (sizeMB.isNotEmpty()) add(sizeMB)
        }.joinToString(" · ")
        holder.infoText.text = info
        holder.downloadBtn.setOnClickListener { onDownload(fmt) }
    }

    override fun getItemCount() = formats.size
}
