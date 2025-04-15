// disk_usage.rs

use sysinfo::{System, SystemExt, DiskExt};

pub fn disk_usage() {
    let sys = System::new_all();

    for disk in sys.disks() {
        println!(
            "Disk: {:?}, Type: {:?}, Used: {} bytes, Total: {} bytes",
            disk.name(),
            disk.file_system(),
            disk.total_space() - disk.available_space(),
            disk.total_space()
        );
    }
}
