use libpsycho::common::helpers::{format_bytes, format_duration};

use crate::mi_process_info;

#[derive(Debug, Clone)]
pub enum MemoryStatus {
    /// < 100MB
    Excellent,
    /// 100MB - 500MB
    Good,
    /// 500MB - 1GB
    Moderate,
    /// 1GB - 2GB
    High,
    /// > 2GB
    Critical,
}

#[derive(Debug, Clone)]
pub enum PerformanceHealth {
    /// Low page faults, good CPU efficiency
    Excellent,
    Good,
    Moderate,
    Poor,
    Critical,
}

#[derive(Debug, Clone)]
pub struct MiMallocProcessInfo {
    /// Elapsed wall-clock time of the process in milli-seconds
    elapsed_ms: usize,

    /// User time in milli-seconds (as the sum over all threads)
    user_ms: usize,

    /// System time in milli-seconds
    system_ms: usize,

    /// Current working set size (touched pages)
    /// Precise on Windows and MacOSX. Other systems estimate this using `current_commit`
    current_rss: usize,

    /// Peak working set size (touched pages)
    peak_rss: usize,

    /// Current committed memory (backed by the page file)
    current_commit: usize,

    /// Peak committed memory (backed by the page file)
    peak_commit: usize,

    /// Count of hard page faults
    page_faults: usize,
}

impl MiMallocProcessInfo {
    pub fn get() -> Self {
        let mut elapsed_ms: usize = 0;
        let mut user_ms: usize = 0;
        let mut system_ms: usize = 0;
        let mut current_rss: usize = 0;
        let mut peak_rss: usize = 0;
        let mut current_commit: usize = 0;
        let mut peak_commit: usize = 0;
        let mut page_faults: usize = 0;

        unsafe {
            mi_process_info(
                &mut elapsed_ms,
                &mut user_ms,
                &mut system_ms,
                &mut current_rss,
                &mut peak_rss,
                &mut current_commit,
                &mut peak_commit,
                &mut page_faults,
            );
        };

        Self {
            elapsed_ms,
            user_ms,
            system_ms,
            current_rss,
            peak_rss,
            current_commit,
            peak_commit,
            page_faults,
        }
    }

    /// Get elapsed wall-clock time of the process in milli-seconds
    pub fn get_elapsed_ms(&self) -> usize {
        self.elapsed_ms
    }

    /// Get user time in milli-seconds (as the sum over all threads)
    pub fn get_user_ms(&self) -> usize {
        self.user_ms
    }

    /// Get system time in milli-seconds
    pub fn get_system_ms(&self) -> usize {
        self.system_ms
    }

    /// Get current working set size (touched pages)
    pub fn get_current_rss(&self) -> usize {
        self.current_rss
    }

    /// Get peak working set size (touched pages)
    pub fn get_peak_rss(&self) -> usize {
        self.peak_rss
    }

    /// Get current committed memory (backed by the page file)
    pub fn get_current_commit(&self) -> usize {
        self.current_commit
    }

    /// Get peak committed memory (backed by the page file)
    pub fn get_peak_commit(&self) -> usize {
        self.peak_commit
    }

    /// Get count of hard page faults
    pub fn get_page_faults(&self) -> usize {
        self.page_faults
    }

    /// Get current memory usage in human-readable format (e.g., "245.7 MB")
    pub fn memory_usage_human(&self) -> String {
        format_bytes(self.current_rss)
    }

    /// Get peak memory usage in human-readable format
    pub fn peak_memory_usage_human(&self) -> String {
        format_bytes(self.peak_rss)
    }

    /// Get virtual memory usage in human-readable format
    pub fn virtual_memory_usage_human(&self) -> String {
        format_bytes(self.current_commit)
    }

    /// Memory efficiency: how much physical memory vs virtual memory we're using
    /// Returns percentage (0-100). Higher is better (less virtual memory overhead)
    pub fn memory_efficiency_percent(&self) -> f64 {
        if self.current_commit == 0 {
            return 100.0;
        }
        (self.current_rss as f64 / self.current_commit as f64) * 100.0
    }

    /// CPU efficiency: user time vs total CPU time
    /// Returns percentage (0-100). Higher is better (less kernel overhead)
    pub fn cpu_efficiency_percent(&self) -> f64 {
        let total_cpu = self.user_ms + self.system_ms;
        if total_cpu == 0 {
            return 100.0;
        }
        (self.user_ms as f64 / total_cpu as f64) * 100.0
    }

    /// Page fault rate per second
    /// Lower is better (fewer disk accesses)
    pub fn page_fault_rate_per_second(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        (self.page_faults as f64 / self.elapsed_ms as f64) * 1000.0
    }

    /// Memory growth rate: current vs peak memory usage
    /// Returns percentage (0-100). Lower is better (more stable memory usage)
    pub fn memory_growth_percent(&self) -> f64 {
        if self.peak_rss == 0 {
            return 0.0;
        }
        ((self.peak_rss - self.current_rss) as f64 / self.peak_rss as f64) * 100.0
    }

    /// Categorize current memory usage level
    pub fn memory_status(&self) -> MemoryStatus {
        match self.current_rss {
            0..=100_000_000 => MemoryStatus::Excellent, // < 100MB
            100_000_001..=500_000_000 => MemoryStatus::Good, // 100-500MB
            500_000_001..=1_000_000_000 => MemoryStatus::Moderate, // 500MB-1GB
            1_000_000_001..=2_000_000_000 => MemoryStatus::High, // 1-2GB
            _ => MemoryStatus::Critical,                // > 2GB
        }
    }

    /// Overall performance health assessment
    pub fn performance_health(&self) -> PerformanceHealth {
        let cpu_eff = self.cpu_efficiency_percent();
        let mem_eff = self.memory_efficiency_percent();
        let fault_rate = self.page_fault_rate_per_second();

        // Simple scoring system
        let mut score = 0;

        if cpu_eff > 80.0 {
            score += 2;
        } else if cpu_eff > 60.0 {
            score += 1;
        }
        if mem_eff > 80.0 {
            score += 2;
        } else if mem_eff > 60.0 {
            score += 1;
        }
        if fault_rate < 1.0 {
            score += 2;
        } else if fault_rate < 10.0 {
            score += 1;
        }

        match score {
            5..=6 => PerformanceHealth::Excellent,
            4 => PerformanceHealth::Good,
            2..=3 => PerformanceHealth::Moderate,
            1 => PerformanceHealth::Poor,
            _ => PerformanceHealth::Critical,
        }
    }

    /// CPU usage as percentage of elapsed time
    pub fn cpu_usage_percent(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return 0.0;
        }
        let total_cpu = self.user_ms + self.system_ms;
        (total_cpu as f64 / self.elapsed_ms as f64) * 100.0
    }

    /// Time spent in different modes as human-readable strings
    pub fn runtime_breakdown(&self) -> (String, String, String) {
        (
            format_duration(self.elapsed_ms),
            format_duration(self.user_ms),
            format_duration(self.system_ms),
        )
    }

    /// Generate a concise summary for logging
    pub fn summary_log(&self) -> String {
        format!(
            "MiMalloc: {} | CPU: {:.1}% ({:.1}% efficient) | Memory: {} ({:.1}% efficient) | Faults: {:.1}/s | Health: {:?}",
            self.memory_usage_human(),
            self.cpu_usage_percent(),
            self.cpu_efficiency_percent(),
            self.memory_usage_human(),
            self.memory_efficiency_percent(),
            self.page_fault_rate_per_second(),
            self.performance_health()
        )
    }

    /// Generate detailed report for debugging
    pub fn detailed_report(&self) -> String {
        format!(
            "=== MiMalloc Process Report ===\n\
             Memory Status: {:?}\n\
             Current Memory: {} (Peak: {})\n\
             Virtual Memory: {}\n\
             Memory Efficiency: {:.1}%\n\
             \n\
             Performance Health: {:?}\n\
             CPU Usage: {:.1}% ({:.1}% efficient)\n\
             Runtime: {} (User: {}, System: {})\n\
             Page Fault Rate: {:.1} faults/second\n\
             Memory Growth: {:.1}% below peak\n",
            self.memory_status(),
            self.memory_usage_human(),
            self.peak_memory_usage_human(),
            self.virtual_memory_usage_human(),
            self.memory_efficiency_percent(),
            self.performance_health(),
            self.cpu_usage_percent(),
            self.cpu_efficiency_percent(),
            format_duration(self.elapsed_ms),
            format_duration(self.user_ms),
            format_duration(self.system_ms),
            self.page_fault_rate_per_second(),
            self.memory_growth_percent()
        )
    }
}
