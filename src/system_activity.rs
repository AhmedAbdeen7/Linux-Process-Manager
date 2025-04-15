// system_activity.rs

use sysinfo::{System, SystemExt, ProcessExt};

pub fn system_activity() {
    let sys = System::new_all();

    println!("System uptime: {} seconds", sys.uptime());

    for (pid, process) in sys.processes() {
        println!(
            "PID: {} | Name: {} | CPU: {:.2}% | Memory: {} KB",
            pid,
            process.name(),
            process.cpu_usage(),
            process.memory()
        );
    }
}
