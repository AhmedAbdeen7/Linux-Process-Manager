// memory_map.rs

use procfs::process::Process;

pub fn memory_map(pid: i32) {
    match Process::new(pid) {
        Ok(proc) => {
            match proc.maps() {
                Ok(maps) => {
                    for map in maps {
                        println!(
                            "Start: {:?}, End: {:?}, Permissions: {}, Path: {:?}",
                            map.address.0,
                            map.address.1,
                            map.perms,
                            map.pathname
                        );
                    }
                }
                Err(e) => println!("Failed to get memory map: {}", e),
            }
        }
        Err(e) => println!("Process not found: {}", e),
    }
}
