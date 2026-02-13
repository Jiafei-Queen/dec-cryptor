use std::sync::atomic::{AtomicUsize, Ordering};
use rayon::prelude::*;

/// 并行处理的线程数管理器
pub struct ParallelHandler {
    /// 当前使用的线程数
    parts: AtomicUsize,
    /// 最大线程数
    max_parts: usize,
}

impl ParallelHandler {
    /// 创建新的并行处理器
    pub fn new() -> Self {
        let max_parts = std::thread::available_parallelism()
            .map_or(4, |n| n.get());

        Self {
            parts: AtomicUsize::new(max_parts),
            max_parts,
        }
    }

    /// 获取当前使用的线程数
    pub fn get_parts(&self) -> usize {
        self.parts.load(Ordering::Relaxed)
    }

    /// 设置并行处理的线程数
    pub fn set_parts(&self, parts: usize) {
        let parts = parts.min(self.max_parts);
        self.parts.store(parts, Ordering::Relaxed);
    }

    /// 根据文件大小自动调整并行度
    pub fn auto_adjust_parts(&self, file_size: u64) {
        // 对于小文件，使用单线程处理以减少开销
        if file_size < 16 * 1024 { // 16KB
            self.set_parts(1);
        } else {
            // 对于大文件，使用最大并行度
            self.set_parts(self.max_parts);
        }
    }
}

/// 全局并行处理器实例
pub static PARALLEL_HANDLER: once_cell::sync::Lazy<ParallelHandler> =
    once_cell::sync::Lazy::new(|| ParallelHandler::new());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_handler_creation() {
        let handler = ParallelHandler::new();
        assert!(handler.get_parts() >= 1);
        assert!(handler.max_parts >= 1);
    }

    #[test]
    fn test_parallel_handler_set_parts() {
        let handler = ParallelHandler::new();
        let old_parts = handler.get_parts();

        handler.set_parts(2);
        assert_eq!(handler.get_parts(), 2);

        // 重置回最大值
        handler.set_parts(old_parts);
        assert_eq!(handler.get_parts(), old_parts);
    }

    #[test]
    fn test_parallel_handler_auto_adjust() {
        let handler = ParallelHandler::new();
        let max_parts = handler.max_parts;

        // 小文件应该使用单线程
        handler.auto_adjust_parts(1024);
        assert_eq!(handler.get_parts(), 1);

        // 大文件应该使用最大并行度
        handler.auto_adjust_parts(1024 * 1024 * 1024); // 1GB
        assert_eq!(handler.get_parts(), max_parts);
    }
}