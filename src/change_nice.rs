use std::env;
use std::process;
use std::process::Command;
use libc;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        eprintln!("Usage: change_nice <pid> <nice_value>");
        process::exit(1);
    }
    
    let pid = match args[1].parse::<u32>() {
        Ok(pid) => pid,
        Err(_) => {
            eprintln!("Invalid PID: {}", args[1]);
            process::exit(1);
        }
    };
    
    let nice_value = match args[2].parse::<i32>() {
        Ok(nice) => nice,
        Err(_) => {
            eprintln!("Invalid nice value: {}", args[2]);
            process::exit(1);
        }
    };
    
    println!("Attempting to change PID {} to nice value {}", pid, nice_value);
    println!("Running as UID={}, EUID={}", unsafe { libc::getuid() }, unsafe { libc::geteuid() });
    
    let direct_result = unsafe {
        libc::setpriority(
            libc::PRIO_PROCESS,
            pid as libc::id_t,
            nice_value
        )
    };
    
    if direct_result == 0 {
        println!("Successfully changed nice value of PID {} to {} using setpriority", pid, nice_value);
        process::exit(0);
    } else {
        let error = std::io::Error::last_os_error();
        eprintln!("Failed to change nice value using setpriority: {}", error);
    }
    
    println!("Trying renice command...");
    match Command::new("renice")
        .arg(format!("{}", nice_value))
        .arg("-p")
        .arg(format!("{}", pid))
        .output() 
    {
        Ok(output) => {
            if output.status.success() {
                println!("Successfully changed nice value of PID {} to {} using renice", pid, nice_value);
                process::exit(0);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("Renice command failed: {}", stderr);
            }
        },
        Err(e) => {
            eprintln!("Failed to execute renice: {}", e);
        }
    }
    
    #[cfg(target_os = "linux")]
    {
        println!("Trying ptrace method...");
        match unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid as libc::pid_t, 0, 0) } {
            0 => {
                std::thread::sleep(std::time::Duration::from_millis(100));
                
                let result = unsafe { 
                    libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice_value) 
                };
                
                unsafe { libc::ptrace(libc::PTRACE_DETACH, pid as libc::pid_t, 0, 0) };
                
                if result == 0 {
                    println!("Successfully changed nice value using ptrace method");
                    process::exit(0);
                } else {
                    eprintln!("Failed via ptrace: {}", std::io::Error::last_os_error());
                }
            },
            _ => {
                eprintln!("Failed to attach with ptrace: {}", std::io::Error::last_os_error());
            }
        }
    }
    
    eprintln!("All methods to change nice value failed");
    process::exit(1);
} 