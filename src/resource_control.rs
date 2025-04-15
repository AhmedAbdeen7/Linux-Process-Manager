// resource_control.rs

use std::process::Command;

pub fn create_cgroup(group_name: &str) {
    let output = Command::new("cgcreate")
        .args(["-g", &format!("memory:{}", group_name)])
        .output()
        .expect("Failed to execute cgcreate");

    println!("cgcreate output: {}", String::from_utf8_lossy(&output.stdout));
}

pub fn exec_in_cgroup(group_name: &str, command: &str) {
    let output = Command::new("cgexec")
        .args(["-g", &format!("memory:{}", group_name), command])
        .output()
        .expect("Failed to execute cgexec");

    println!("cgexec output: {}", String::from_utf8_lossy(&output.stdout));
}
