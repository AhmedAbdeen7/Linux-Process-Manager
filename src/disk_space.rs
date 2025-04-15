// disk_space.rs

use std::fs;
use std::path::Path;

pub fn disk_space(path: &str) {
    match fs::metadata(path) {
        Ok(metadata) => {
            println!("Path: {}", path);
            println!("Is Directory: {}", metadata.is_dir());
            println!("Size: {} bytes", metadata.len());
        }
        Err(e) => println!("Failed to get metadata: {}", e),
    }
}
