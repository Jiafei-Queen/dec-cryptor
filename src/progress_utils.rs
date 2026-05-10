use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::io::Write;

// ANSI 颜色代码
const RESET: &str = "\u{001B}[0m";
const DIM: &str = "\u{001B}[2m";
const CYAN: &str = "\u{001B}[96m";
const BLUE: &str = "\u{001B}[94m";
const GREEN: &str = "\u{001B}[92m";
const BOLD: &str = "\u{001B}[1m";
const PROGRESS_BAR_LENGTH: usize = 40;
const SPINNER_FRAMES: [&str; 4] = ["⠋", "⠙", "⠹", "⠸"];
static LAST_PROGRESS: AtomicI32 = AtomicI32::new(-1);
static SPINNER_INDEX: AtomicUsize = AtomicUsize::new(0);
static PROGRESS_ACTIVE: AtomicBool = AtomicBool::new(false);

fn format_units(bytes: u64) -> (f64, &'static str) {
    const KB_FACTOR: f64 = 1024.0;
    const MB_FACTOR: f64 = 1024.0 * 1024.0;
    const GB_FACTOR: f64 = 1024.0 * 1024.0 * 1024.0;

    if bytes as f64 >= GB_FACTOR {
        (bytes as f64 / GB_FACTOR, "GB")
    } else if bytes as f64 >= MB_FACTOR {
        (bytes as f64 / MB_FACTOR, "MB")
    } else if bytes as f64 >= KB_FACTOR {
        (bytes as f64 / KB_FACTOR, "KB")
    } else {
        (bytes as f64, "B")
    }
}

/// 重置进度跟踪器（用于新任务）
#[allow(dead_code)]
pub fn reset_progress() {
    LAST_PROGRESS.store(-1, Ordering::Relaxed);
    SPINNER_INDEX.store(0, Ordering::Relaxed);
    PROGRESS_ACTIVE.store(false, Ordering::Relaxed);
}

pub fn finish_progress_line() {
    if PROGRESS_ACTIVE.swap(false, Ordering::Relaxed) {
        eprintln!();
    }
}

pub fn clear_progress_line() {
    if PROGRESS_ACTIVE.swap(false, Ordering::Relaxed) {
        eprint!("\r\x1b[2K");
        std::io::stderr().flush().unwrap();
    }
}

pub fn update_stream_progress(total_read: u64) {
    let frame = SPINNER_FRAMES[SPINNER_INDEX.fetch_add(1, Ordering::Relaxed) % SPINNER_FRAMES.len()];
    let (read_units, unit) = format_units(total_read);

    PROGRESS_ACTIVE.store(true, Ordering::Relaxed);
    eprint!(
        "\r{}{}DEC!{} {}{}{}{}  {}{:.2} {}{}",
        BOLD, BLUE, RESET,
        CYAN, frame, RESET, DIM,
        CYAN, read_units, unit, RESET
    );
    std::io::stderr().flush().unwrap();
}

/// 更新并显示带时间的进度
pub fn update_progress(total_read: u64, file_size: u64) {
    // 更新进度
    let mut progress = (total_read * 100 / file_size) as i32;

    // 获得更好体验...yes!
    if progress > 98 {
        progress = 100;
    }

    // 避免出现多个 100 进度条
    if progress == LAST_PROGRESS.load(Ordering::Relaxed) {
        return;
    }

    let (total_units, unit) = format_units(file_size);
    let (read_units, _) = format_units(total_read);

    // 限制进度在 0-100 之间
    progress = progress.min(100).max(0);
    LAST_PROGRESS.store(progress, Ordering::Relaxed);

    // 计算进度条长度
    let filled_length = ((progress as f64 / 100.0) * PROGRESS_BAR_LENGTH as f64) as usize;

    // 构建更顺滑的进度条
    let mut progress_bar = String::with_capacity(256);
    progress_bar.push_str(BOLD);
    progress_bar.push('[');

    for i in 0..PROGRESS_BAR_LENGTH {
        if i < filled_length {
            progress_bar.push_str(GREEN);
            progress_bar.push('█');
        } else if i == filled_length && progress < 100 {
            progress_bar.push_str(CYAN);
            progress_bar.push('▓');
        } else {
            progress_bar.push_str(DIM);
            progress_bar.push('░');
        }
    }

    progress_bar.push_str(RESET);
    progress_bar.push_str(BOLD);
    progress_bar.push(']');
    progress_bar.push_str(RESET);

    // 输出进度（使用回车而不是换行，使进度在同一行更新）
    PROGRESS_ACTIVE.store(true, Ordering::Relaxed);
    eprint!("\r{}{}DEC!{} {}{}{:>3}%{}",
        BOLD, BLUE, RESET, progress_bar, GREEN, progress, RESET);
    if progress < 98 {
        eprint!("  {}{:.2}{} / {}{:.2} {}{}",
            CYAN, read_units, RESET, BOLD, total_units, unit, RESET);
    } else {
        eprint!("  {}{:.2}{} / {}{:.2} {}{}",
            CYAN, total_units, RESET, BOLD, total_units, unit, RESET);
    }
    std::io::stderr().flush().unwrap();

    // 100% 时添加一个换行
    if progress == 100 {
        finish_progress_line();
    }
}
