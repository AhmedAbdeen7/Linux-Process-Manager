// use std::ffi::OsStr;
use std::io::{self, Write, stdout};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use std::collections::HashMap;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System};

// Internal modules
mod app;
mod display;
mod hierarchy;
mod process;

fn main() -> io::Result<()> {
    loop {
        // println!("\n===== SysTool Menu =====");
        // println!("top (Live Process Viewer)");
        // println!("ps (Process Snapshot)");
        // println!("kill (Terminate a Process)");
        // println!("pstree (Process Tree Viewer)");
        // println!("free (Memory Usage)");
        // println!("q. Quit");

        // print!("Enter your choice: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "top" => launch_top()?,
            "ps" => run_ps()?,
            "kill" => run_kill()?,
            "pstree" => display_process_tree(),
            "free" => display_memory_info(),
            // "vmstat" => display_cpu_usage(),
            "q" => {
                println!("Exiting. Goodbye!");
                break;
            }
            _ => println!("Invalid choice, please try again."),
        }
    }

    Ok(())
}

fn launch_top() -> io::Result<()> {
    let mut stdout = stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen)?;

    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();
    let mut app = app::AppState::new();

    loop {
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') => app.set_sort_field(process::SortField::Cpu),
                    KeyCode::Char('m') => app.set_sort_field(process::SortField::Memory),
                    KeyCode::Char('p') => app.set_sort_field(process::SortField::Pid),
                    KeyCode::Char('n') => app.set_sort_field(process::SortField::Name),
                    // KeyCode::Char('t') => app.toggle_tree_view(),
                    _ => {}
                }
            }
        }

        sys.refresh_memory();
        sys.refresh_cpu_all();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );

        let processes = process::get_processes(&sys, &app);
        let hierarchy = hierarchy::build_hierarchy(&processes);
        display::draw_ui(&sys, &processes, &hierarchy, &app)?;
    }

    execute!(stdout, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

fn run_ps() -> io::Result<()> {
    let mut sys = System::new_all();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything(),
    );
    let mut processes: Vec<_> = sys
        .processes()
        .values()
        .filter(|p| p.exe().is_some() && !p.cmd().is_empty())
        .collect();

    processes.sort_by_key(|p| p.pid());

    // Removed TTY from headers and output
    println!("{:<8} {:<12} {}", "PID", "TIME", "CMD");

    for proc in processes.iter().take(20) {
        let cmd_name = proc
            .exe()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("?");

        println!("{:<8} {:<12} {}", proc.pid(), "00:00:00", cmd_name);
    }

    Ok(())
}

fn run_kill() -> io::Result<()> {
    let mut input = String::new();
    // print!("Enter PID to kill: ");
    io::stdout().flush()?; // Ensure prompt is displayed
    io::stdin().read_line(&mut input)?;
    let pid_input = input.trim();

    // Parse the input into a PID
    let pid: sysinfo::Pid = match pid_input.parse::<usize>() {
        Ok(num) => sysinfo::Pid::from(num),
        Err(_) => {
            println!("Invalid PID entered.");
            return Ok(());
        }
    };

    // Initialize the system and refresh process information
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything(),
    );
    // Attempt to find and kill the process
    if let Some(process) = sys.process(pid) {
        match process.kill_with(Signal::Term) {
            Some(true) => println!("Successfully sent SIGTERM to process {}", pid),
            Some(false) => println!("Failed to send SIGTERM to process {}", pid),
            None => println!("Signal not supported on this platform."),
        }
    } else {
        println!("Process with PID {} not found.", pid);
    }

    Ok(())
}

fn display_process_tree() {
    let mut system = System::new_all();
    system.refresh_all();

    let processes = system.processes();

    // Map each process to its parent
    let mut parent_map: HashMap<Pid, Vec<Pid>> = HashMap::new();
    for (&pid, process) in processes {
        if let Some(parent_pid) = process.parent() {
            parent_map.entry(parent_pid).or_default().push(pid);
        }
    }

    // Recursive function to display the tree
    fn print_tree(
        pid: Pid,
        processes: &HashMap<Pid, &sysinfo::Process>,
        parent_map: &HashMap<Pid, Vec<Pid>>,
        indent: usize,
    ) {
        if let Some(process) = processes.get(&pid) {
            println!("{}{:?} ({})", "  ".repeat(indent), process.name(), pid);
            if let Some(children) = parent_map.get(&pid) {
                for &child_pid in children {
                    print_tree(child_pid, processes, parent_map, indent + 1);
                }
            }
        }
    }

    // Find root processes (those without a parent)
    let root_pids: Vec<Pid> = processes
        .iter()
        .filter_map(|(&pid, process)| {
            if process.parent().is_none() {
                Some(pid)
            } else {
                None
            }
        })
        .collect();

    // Build a map for quick process lookup
    let process_map: HashMap<Pid, &sysinfo::Process> =
        processes.iter().map(|(&pid, proc)| (pid, proc)).collect();

    // Display the process tree starting from root processes
    for pid in root_pids {
        print_tree(pid, &process_map, &parent_map, 0);
    }
}

fn display_memory_info() {
    let mut sys = System::new_all();
    sys.refresh_memory();

    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let free_memory = sys.free_memory();
    let available_memory = sys.available_memory();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();
    let free_swap = sys.free_swap();

    println!("Memory Information:");
    println!("Total: {} KB", total_memory);
    println!("Used: {} KB", used_memory);
    println!("Free: {} KB", free_memory);
    println!("Available: {} KB", available_memory);

    println!("Total: {} KB", total_memory);
    println!("Used: {} KB", used_memory);
    println!("Free: {} KB", free_memory);
    println!("Available: {} KB", available_memory);
    println!("Swap:");
    println!("Total: {} KB", total_swap);
    println!("Used: {} KB", used_swap);
    println!("Free: {} KB", free_swap);
}

// use std::{thread, time};

// use sysinfo::CpuRefreshKind;
// fn display_cpu_usage() {
//     let mut sys = System::new_with_specifics(
//         sysinfo::RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()),
//     );

//     // Initial refresh to gather data
//     sys.refresh_cpu_all();

//     // Wait for a short period to allow for accurate calculations
//     thread::sleep(time::Duration::from_millis(200));

//     // Refresh again to compute CPU usage
//     sys.refresh_cpu_all();

//     // Retrieve and display CPU usage for each processor
//     for (i, cpu) in sys.cpus().iter().enumerate() {
//         println!("CPU {}: {:>6.2}%", i, cpu.cpu_usage());
//     }
// }
