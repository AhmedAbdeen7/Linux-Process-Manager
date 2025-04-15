// disk_estimate.rs

use std::fs::{self, DirEntry};
use std::path::Path;

fn get_dir_size(path: &Path) -> u64 {
    if !path.is_dir() {
        return 0;
    }

    let mut size = 0;

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                size += get_dir_size(&path);
            } else if let Ok(metadata) = entry.metadata() {
                size += metadata.len();
            }
        }
    }

    size
}

pub fn disk_estimate(path: &str) {
    let size = get_dir_size(Path::new(path));
    println!("Estimated disk usage for {}: {} bytes", path, size);
}
