use std::sync::atomic::{AtomicI32, Ordering};
use std::io::Write;
use std::time::Instant;

// ANSI颜色代码
const RESET: &str = "\u{001B}[0m";
const BLUE: &str = "\u{001B}[94m";
const PROGRESS_BAR_LENGTH: usize = 40;
static LAST_PROGRESS: AtomicI32 = AtomicI32::new(-1);

/// 更新并显示带时间的进度
pub fn update_progress(total_read: u64, file_size: u64) {
    // 更新进度
    let mut progress = (total_read * 100 / file_size) as i32;

    // 获得更好体验...yes!
    if progress > 98 {
        progress = 100;
    }

    // 避免出现多个100进度条
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

    // 限制进度在0-100之间
    progress = progress.min(100).max(0);
    LAST_PROGRESS.store(progress, Ordering::Relaxed);
    
    // 计算进度条长度
    let filled_length = ((progress as f64 / 100.0) * PROGRESS_BAR_LENGTH as f64) as usize;
    
    // 构建进度条
    let mut progress_bar = String::with_capacity(100); // 预分配容量
    progress_bar.push('[');
    
    for i in 1..PROGRESS_BAR_LENGTH {
        if i < filled_length {
            progress_bar.push_str(&format!("{}#", BLUE));
        } else if i == filled_length {
            if progress < 100 {
                progress_bar.push_str(&format!("{}>", BLUE));
            } else {
                progress_bar.push_str(&format!("{}#{}", BLUE, RESET));
            }
        } else {
            progress_bar.push_str(&format!("{}-", RESET));
        }
    }

    progress_bar.push_str(&format!("] {}%", progress));
    
    // 输出进度（使用回车而不是换行，使进度在同一行更新）
    print!("\r{}", progress_bar);
    if progress < 98 {
        print!("\t {:.2} : {:.2} {}", read_units, total_units, unit);
    } else {
        print!("\t {:.2} : {:.2} {}", total_units, total_units, unit);
    }
    std::io::stdout().flush().unwrap();
    
    // 100%时添加一个换行
    if progress == 100 {
        println!();
    }
}

/// 格式化持续时间显示
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    let millis = duration.subsec_millis();
    
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}.{:03}s", seconds, millis)
    }
}

/// 获取开始时间的便捷函数
pub fn start_timer() -> Instant {
    Instant::now()
}