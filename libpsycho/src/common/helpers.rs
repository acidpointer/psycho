/// Return formatted string with memory in human readable format
/// Example: 20 GB
pub fn format_bytes(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let bytes_f = bytes as f64;

    if bytes_f >= GB {
        format!("{:.1} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.1} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.1} KB", bytes_f / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Format time duration in milliseconds to
/// human readable string
pub fn format_duration(ms: usize) -> String {
    let seconds = ms / 1000;
    let minutes = seconds / 60;
    let hours = minutes / 60;

    if hours > 0 {
        format!("{}h {}m", hours, minutes % 60)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds % 60)
    } else if seconds > 0 {
        format!("{}.{}s", seconds, (ms % 1000) / 100)
    } else {
        format!("{}ms", ms)
    }
}

/// Aligns an address upward to the specified alignment.
///
/// # Arguments
/// * `addr` - Address to align
/// * `align` - Alignment requirement (must be power of two)
///
/// # Returns
/// Aligned address
#[inline(always)]
pub fn align_up(addr: usize, align: usize) -> usize {
    (addr + (align - 1)) & !(align - 1)
}
