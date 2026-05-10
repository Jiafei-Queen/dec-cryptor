use std::sync::atomic::{AtomicI32, Ordering};
use std::io::Write;

// ANSI 颜色代码
const RESET: &str = "\u{001B}[0m";
const DIM: &str = "\u{001B}[2m";
const CYAN: &str = "\u{001B}[96m";
const BLUE: &str = "\u{001B}[94m";
const GREEN: &str = "\u{001B}[92m";
const BOLD: &str = "\u{001B}[1m";
const PROGRESS_BAR_LENGTH: usize = 40;
static LAST_PROGRESS: AtomicI32 = AtomicI32::new(-1);

/// 重置进度跟踪器（用于新任务）
#[allow(dead_code)]
pub fn reset_progress() {
    LAST_PROGRESS.store(-1, Ordering::Relaxed);
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

    // 预计算单位转换因子以提高性能
    const KB_FACTOR: f64 = 1024.0;
    const MB_FACTOR: f64 = 1024.0 * 1024.0;
    const GB_FACTOR: f64 = 1024.0 * 1024.0 * 1024.0;

    let mut unit = "B";
    let mut total_units = file_size as f64;
    let mut read_units = total_read as f64;

    // 获得单位
    if file_size as f64 >= GB_FACTOR {
        total_units = file_size as f64 / GB_FACTOR;
        read_units = total_read as f64 / GB_FACTOR;
        unit = "GB";
    } else if file_size as f64 >= MB_FACTOR {
        total_units = file_size as f64 / MB_FACTOR;
        read_units = total_read as f64 / MB_FACTOR;
        unit = "MB";
    } else if file_size as f64 >= KB_FACTOR {
        total_units = file_size as f64 / KB_FACTOR;
        read_units = total_read as f64 / KB_FACTOR;
        unit = "KB";
    }

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
    print!("\r{}{}DEC!{} {}{}{:>3}%{}",
        BOLD, BLUE, RESET, progress_bar, GREEN, progress, RESET);
    if progress < 98 {
        print!("  {}{:.2}{} / {}{:.2} {}{}",
            CYAN, read_units, RESET, BOLD, total_units, unit, RESET);
    } else {
        print!("  {}{:.2}{} / {}{:.2} {}{}",
            CYAN, total_units, RESET, BOLD, total_units, unit, RESET);
    }
    std::io::stdout().flush().unwrap();

    // 100% 时添加一个换行
    if progress == 100 {
        println!();
    }
}
