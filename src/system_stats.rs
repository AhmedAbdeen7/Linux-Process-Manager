// system_stats.rs

use sysinfo::{System, SystemExt};

pub fn system_stats() -> (f32, f32) {
    let mut sys = System::new_all();
    sys.refresh_cpu();

    let cpu_usage = sys.global_cpu_info().cpu_usage(); // in percentage
    let load_average = sys.load_average().one;         // 1-minute load average

    (cpu_usage, load_average)
}
