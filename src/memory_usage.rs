// memory_usage.rs

use sysinfo::{System, SystemExt};

pub fn memory_usage() -> (u64, u64) {
    let mut sys = System::new_all();
    sys.refresh_memory();

    let total_memory = sys.total_memory(); // in kilobytes
    let used_memory = sys.used_memory();   // in kilobytes

    (used_memory, total_memory)
}
