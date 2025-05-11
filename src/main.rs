// main.rs
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, Write, stdout};
use std::time::{Duration, Instant};
use sysinfo::{System, SystemExt, PidExt, ProcessExt, ProcessRefreshKind};
use sysinfo::CpuExt;
use tui::Terminal;
use tui::backend::CrosstermBackend;
use nix::sys::signal;
use nix::unistd;
use tui::widgets::{Block};
use tui::layout::{Layout, Constraint, Direction};
use tui::widgets::Paragraph;
use tui::layout::Rect;
use tui::style::{Style, Color};
use tui::widgets::Borders;
use eframe;
use egui;

mod app;
mod display;
mod process;
mod gui;

use crate::process::{get_processes, build_process_tree, ProcessInfo};
use crate::process::ProcessNode;

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum FilterType {
    None,
    Command,
    User,
    State,
    Pid,
    Cpu,
    Memory,
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub enum SortField {
    Command,
    Pid,
    Ppid,
    User,
    State,
    Cpu,
    Memory,
    Nice,
    StartTime,
}

impl SortField {
    fn get_header(&self) -> &str {
        match self {
            SortField::Command => "Command",
            SortField::Pid => "PID",
            SortField::Ppid => "PPID",
            SortField::User => "USER",
            SortField::State => "STATE",
            SortField::Cpu => "CPU%",
            SortField::Memory => "MEM%",
            SortField::Nice => "NI",
            SortField::StartTime => "STARTED",
        }
    }
}

impl FilterType {
    fn get_prompt(&self) -> &str {
        match self {
            FilterType::None => "",
            FilterType::Command => "Filter by command: ",
            FilterType::User => "Filter by user: ",
            FilterType::State => "Filter by state: ",
            FilterType::Pid => "Filter by PID: ",
            FilterType::Cpu => "Filter by CPU % (>X): ",
            FilterType::Memory => "Filter by Memory % (>X): ",
        }
    }
}

fn display_statistics(sys: &System) {
    println!("\n=== System Statistics ===");
    
    println!("\nCPU Information:");
    println!("  Total CPU Usage: {:.1}%", sys.global_cpu_info().cpu_usage());
    println!("  Number of CPUs: {}", sys.cpus().len());
    
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let free_mem = sys.free_memory();
    let available_mem = sys.available_memory();
    
    println!("\nMemory Statistics:");
    println!("  Total Memory:     {:.2} GB", total_mem as f64 / 1_073_741_824.0);
    println!("  Used Memory:      {:.2} GB", used_mem as f64 / 1_073_741_824.0);
    println!("  Free Memory:      {:.2} GB", free_mem as f64 / 1_073_741_824.0);
    println!("  Available Memory: {:.2} GB", available_mem as f64 / 1_073_741_824.0);
    println!("  Memory Usage:     {:.1}%", (used_mem as f64 / total_mem as f64) * 100.0);
    
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();
    let free_swap = sys.free_swap();
    
    println!("\nSwap Statistics:");
    println!("  Total Swap:  {:.2} GB", total_swap as f64 / 1_073_741_824.0);
    println!("  Used Swap:   {:.2} GB", used_swap as f64 / 1_073_741_824.0);
    println!("  Free Swap:   {:.2} GB", free_swap as f64 / 1_073_741_824.0);
    println!("  Swap Usage:  {:.1}%", (used_swap as f64 / total_swap as f64) * 100.0);
    
    let processes = sys.processes();
    let total_processes = processes.len();
    let running_processes = processes.values()
        .filter(|p| p.status() == sysinfo::ProcessStatus::Run)
        .count();
    
    println!("\nProcess Statistics:");
    println!("  Total Processes:    {}", total_processes);
    println!("  Running Processes:  {}", running_processes);
    println!("  Sleeping Processes: {}", total_processes - running_processes);
    
    println!("\nTop 5 CPU-consuming Processes:");
    let mut top_cpu: Vec<_> = processes.values().collect();
    top_cpu.sort_by(|a, b| b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap());
    for (i, proc) in top_cpu.iter().take(5).enumerate() {
        println!("  {}. {:?} (PID: {}) - CPU: {:.1}%",
            i + 1,
            proc.name().to_string(),
            proc.pid(),
            proc.cpu_usage()
        );
    }
    
    println!("\nTop 5 Memory-consuming Processes:");
    let mut top_mem: Vec<_> = processes.values().collect();
    top_mem.sort_by(|a, b| b.memory().partial_cmp(&a.memory()).unwrap());
    for (i, proc) in top_mem.iter().take(5).enumerate() {
        println!("  {}. {:?} (PID: {}) - Memory: {:.2} MB",
            i + 1,
            proc.name().to_string(),
            proc.pid(),
            proc.memory() as f64 / 1_048_576.0
        );
    }
}

fn display_process_tree(processes: &Vec<ProcessInfo>, parent_pid: Option<u32>, indent: &str) {
    for process in processes {
        let parent_pid_sysinfo = parent_pid.map(|pid| sysinfo::Pid::from(pid as usize));
        
        if process.ppid == Some(parent_pid_sysinfo.unwrap_or(sysinfo::Pid::from(0))) {
            println!("{}- {} (PID: {})", indent, process.command, process.pid);
            display_process_tree(processes, Some(process.pid.as_u32()), &format!("{}  ", indent));
        }
    }
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 && args[1] == "--gui" {
        let options = eframe::NativeOptions {
            initial_window_size: Some(egui::vec2(1024.0, 768.0)),
            ..Default::default()
        };
        
        eframe::run_native(
            "Linux Process Manager",
            options,
            Box::new(|cc| Box::new(gui::ProcessManagerApp::new(cc))),
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("GUI error: {}", e)))?;
        
        Ok(())
    } else {
        launch_top()
    }
}

fn launch_top() -> io::Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut sys = System::new_all();
    sys.refresh_all();
    let tick_rate = Duration::from_secs(1);
    let mut last_tick = Instant::now();
    let mut selected: usize = 0;
    let mut scroll_offset: usize = 0;
    let mut show_kill_prompt = false;
    let mut filter = String::new();
    let mut filter_type = FilterType::None;
    let mut show_tree = false;
    let mut sort_field = SortField::Cpu;
    let mut sort_descending = true;
    let mut kill_target_pid: Option<sysinfo::Pid> = None;
    let mut kill_target_name: Option<String> = None;
    let mut tree_scroll_offset: usize = 0;

    let mut processes = get_processes(&sys);
    let mut tree = build_process_tree(&processes);

    let mut output_buffer: Vec<String> = Vec::new();
    let mut current_view_start: usize = 0;
    const MAX_VISIBLE_LINES: usize = 20; // Adjust based on your terminal size

    // Define the niceness values
    let niceness_values = vec![-20, -10, 0, 10, 19];
    let mut selected_nice_index = 0; // Index for the selected niceness value

    loop {
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => match key.code {
                    KeyCode::Down => {
                        if show_tree {
                            tree_scroll_offset += 1;
                        } else if filter_type == FilterType::None {
                            let mut flat = Vec::new();
                            display::flatten_tree(&tree, &mut flat);
                            if selected + 1 < flat.len() {
                                selected += 1;
                                let terminal_height = terminal.size()?.height as usize;
                                let visible_rows = terminal_height.saturating_sub(4);
                                if selected >= scroll_offset + visible_rows {
                                    scroll_offset = selected.saturating_sub(visible_rows - 1);
                                }
                            }
                        }
                    }
                    KeyCode::Up => {
                        if show_tree {
                            if tree_scroll_offset > 0 {
                                tree_scroll_offset -= 1;
                            }
                        } else if filter_type == FilterType::None {
                            let mut flat = Vec::new();
                            display::flatten_tree(&tree, &mut flat);
                            if selected > 0 {
                                selected -= 1;
                                if selected < scroll_offset {
                                    scroll_offset = selected;
                                }
                            }
                        }
                    }
                    KeyCode::Char('q') => break,
                    KeyCode::Char('k') => {
                        if filter_type == FilterType::None && !show_kill_prompt {
                            let mut flat = Vec::new();
                            display::flatten_tree(&tree, &mut flat);
                            // Apply the same filtering and sorting as in draw_ui
                            let mut filtered_rows: Vec<&ProcessNode> = flat.iter().cloned().collect();
                            if !filter.is_empty() {
                                filtered_rows = filtered_rows.into_iter().filter(|node| {
                                    match filter_type {
                                        FilterType::None => true,
                                        FilterType::Command => node.info.command.to_lowercase().contains(&filter.to_lowercase()) || node.info.cmd.join(" ").to_lowercase().contains(&filter.to_lowercase()),
                                        FilterType::User => node.info.user.to_lowercase().contains(&filter.to_lowercase()),
                                        FilterType::State => node.info.state.to_lowercase().contains(&filter.to_lowercase()),
                                        FilterType::Pid => node.info.pid.to_string().contains(&filter),
                                        FilterType::Cpu => filter.parse::<f32>().map_or(false, |th| node.info.cpu_percent >= th),
                                        FilterType::Memory => filter.parse::<f32>().map_or(false, |th| node.info.mem_percent >= th),
                                    }
                                }).collect();
                            }
                            filtered_rows.sort_by(|a, b| {
                                let cmp = match sort_field {
                                    SortField::Command => a.info.command.cmp(&b.info.command),
                                    SortField::Pid => a.info.pid.cmp(&b.info.pid),
                                    SortField::Ppid => a.info.ppid.cmp(&b.info.ppid),
                                    SortField::User => a.info.user.cmp(&b.info.user),
                                    SortField::State => a.info.state.cmp(&b.info.state),
                                    SortField::Cpu => a.info.cpu_percent.partial_cmp(&b.info.cpu_percent).unwrap_or(std::cmp::Ordering::Equal),
                                    SortField::Memory => a.info.mem_percent.partial_cmp(&b.info.mem_percent).unwrap_or(std::cmp::Ordering::Equal),
                                    SortField::Nice => a.info.nice.cmp(&b.info.nice),
                                    SortField::StartTime => a.info.start_time.cmp(&b.info.start_time),
                                };
                                if sort_descending { cmp.reverse() } else { cmp }
                            });
                            if let Some(node) = filtered_rows.get(selected) {
                                kill_target_pid = Some(node.info.pid);
                                kill_target_name = Some(node.info.command.clone());
                                show_kill_prompt = true;
                            }
                        }
                    }
                    KeyCode::Char('y') => {
                        if show_kill_prompt {
                            if let (Some(pid), Some(name)) = (kill_target_pid, &kill_target_name) {
                                // Try to kill the process
                                let result = unsafe {
                                    libc::kill(pid.as_u32() as libc::pid_t, libc::SIGKILL)
                                };
                                if result == 0 {
                                    // Success
                                    terminal.draw(|f| {
                                        let size = f.size();
                                        let block = Block::default().title("Process Killed").borders(Borders::ALL);
                                        f.render_widget(block, size);
                                        let text = format!("Successfully killed {} (PID {})", name, pid);
                                        let paragraph = Paragraph::new(text).style(Style::default().fg(Color::Green));
                                        let area = Rect::new(2, 1, size.width - 4, 1);
                                        f.render_widget(paragraph, area);
                                    })?;
                                    std::thread::sleep(Duration::from_millis(1000));
                                    sys.refresh_processes();
                                    processes = get_processes(&sys);
                                    tree = build_process_tree(&processes);
                                } else {
                                    // Error
                                    terminal.draw(|f| {
                                        let size = f.size();
                                        let block = Block::default().title("Error").borders(Borders::ALL);
                                        f.render_widget(block, size);
                                        let text = format!("Failed to kill {} (PID {}). Error: {}", name, pid, std::io::Error::last_os_error());
                                        let paragraph = Paragraph::new(text).style(Style::default().fg(Color::Red));
                                        let area = Rect::new(2, 1, size.width - 4, 1);
                                        f.render_widget(paragraph, area);
                                    })?;
                                    std::thread::sleep(Duration::from_millis(2000));
                                }
                            }
                            show_kill_prompt = false;
                            kill_target_pid = None;
                            kill_target_name = None;
                        }
                    }
                    KeyCode::Char('c') => {
                        if filter_type == FilterType::None {
                            filter_type = FilterType::Command;
                            filter.clear();
                        }
                    }
                    KeyCode::Char('u') => {
                        if filter_type == FilterType::None {
                            filter_type = FilterType::User;
                            filter.clear();
                        }
                    }
                    KeyCode::Char('s') => {
                        if filter_type == FilterType::None {
                            filter_type = FilterType::State;
                            filter.clear();
                        }
                    }
                    KeyCode::Char('p') => {
                        if filter_type == FilterType::None {
                            filter_type = FilterType::Pid;
                            filter.clear();
                        }
                    }
                    KeyCode::Char('C') => {
                        if filter_type == FilterType::None {
                            filter_type = FilterType::Cpu;
                            filter.clear();
                        }
                    }
                    KeyCode::Char('m') => {
                        if filter_type == FilterType::None {
                            filter_type = FilterType::Memory;
                            filter.clear();
                        }
                    }
                    KeyCode::Char('n') => {
                        if filter_type == FilterType::None {
                            let mut flat = Vec::new();
                            display::flatten_tree(&tree, &mut flat);
                            // Apply the same filtering and sorting as in draw_ui
                            let mut filtered_rows: Vec<&ProcessNode> = flat.iter().cloned().collect();
                            // (Apply filter if any)
                            if !filter.is_empty() {
                                filtered_rows = filtered_rows.into_iter().filter(|node| {
                                    match filter_type {
                                        FilterType::None => true,
                                        FilterType::Command => node.info.command.to_lowercase().contains(&filter.to_lowercase()) || node.info.cmd.join(" ").to_lowercase().contains(&filter.to_lowercase()),
                                        FilterType::User => node.info.user.to_lowercase().contains(&filter.to_lowercase()),
                                        FilterType::State => node.info.state.to_lowercase().contains(&filter.to_lowercase()),
                                        FilterType::Pid => node.info.pid.to_string().contains(&filter),
                                        FilterType::Cpu => filter.parse::<f32>().map_or(false, |th| node.info.cpu_percent >= th),
                                        FilterType::Memory => filter.parse::<f32>().map_or(false, |th| node.info.mem_percent >= th),
                                    }
                                }).collect();
                            }
                            // (Apply sorting)
                            filtered_rows.sort_by(|a, b| {
                                let cmp = match sort_field {
                                    SortField::Command => a.info.command.cmp(&b.info.command),
                                    SortField::Pid => a.info.pid.cmp(&b.info.pid),
                                    SortField::Ppid => a.info.ppid.cmp(&b.info.ppid),
                                    SortField::User => a.info.user.cmp(&b.info.user),
                                    SortField::State => a.info.state.cmp(&b.info.state),
                                    SortField::Cpu => a.info.cpu_percent.partial_cmp(&b.info.cpu_percent).unwrap_or(std::cmp::Ordering::Equal),
                                    SortField::Memory => a.info.mem_percent.partial_cmp(&b.info.mem_percent).unwrap_or(std::cmp::Ordering::Equal),
                                    SortField::Nice => a.info.nice.cmp(&b.info.nice),
                                    SortField::StartTime => a.info.start_time.cmp(&b.info.start_time),
                                };
                                if sort_descending { cmp.reverse() } else { cmp }
                            });
                            if let Some(node) = filtered_rows.get(selected) {
                                let pid = node.info.pid;
                                let current_nice = node.info.nice;
                                
                                // Show nice value selection prompt
                                let nice_values: Vec<i32> = (-20..=19).collect();
                                let mut selected_nice_index = nice_values.iter()
                                    .position(|&x| x == current_nice)
                                    .unwrap_or(20); // Default to 0 if current nice not found

                                loop {
                                    terminal.draw(|f| {
                                        let size = f.size();
                                        let block = Block::default()
                                            .title(format!("Change Nice Value for PID {} (Current: {})", pid, current_nice))
                                            .borders(Borders::ALL);
                                        f.render_widget(block, size);

                                        // Render the list of nice values
                                        let max_visible = (size.height as usize).saturating_sub(2);
                                        let start = if selected_nice_index >= max_visible {
                                            selected_nice_index + 1 - max_visible
                                        } else {
                                            0
                                        };
                                        let end = std::cmp::min(start + max_visible, nice_values.len());
                                        for (i, &value) in nice_values[start..end].iter().enumerate() {
                                            let idx = start + i;
                                            let is_selected = idx == selected_nice_index;
                                            let style = if is_selected {
                                                Style::default().bg(Color::Yellow).fg(Color::Black)
                                            } else {
                                                Style::default()
                                            };
                                            let text = format!("{}{}", value, if value == current_nice { " (current)" } else { "" });
                                            let paragraph = Paragraph::new(text).style(style);
                                            let area = Rect::new(2, (i as u16) + 1, size.width - 4, 1);
                                            f.render_widget(paragraph, area);
                                        }
                                    })?;

                                    if event::poll(Duration::from_millis(100))? {
                                        if let Event::Key(key) = event::read()? {
                                            match key.code {
                                                KeyCode::Down => {
                                                    selected_nice_index = (selected_nice_index + 1) % nice_values.len();
                                                }
                                                KeyCode::Up => {
                                                    selected_nice_index = (selected_nice_index + nice_values.len() - 1) % nice_values.len();
                                                }
                                                KeyCode::Enter => {
                                                    let new_nice = nice_values[selected_nice_index];
                                                    if new_nice != current_nice {
                                                        unsafe {
                                                            let result = libc::setpriority(
                                                                libc::PRIO_PROCESS,
                                                                pid.as_u32() as libc::id_t,
                                                                new_nice
                                                            );
                                                            if result == 0 {
                                                                // Successfully changed nice value
                                                                // Refresh system information
                                                                sys.refresh_processes();
                                                                processes = get_processes(&sys);
                                                                tree = build_process_tree(&processes);
                                                                
                                                                // Show success message
                                                                terminal.draw(|f| {
                                                                    let size = f.size();
                                                                    let block = Block::default()
                                                                        .title("Success")
                                                                        .borders(Borders::ALL);
                                                                    f.render_widget(block, size);
                                                                    let text = format!("Successfully changed nice value to {} for PID {}", new_nice, pid);
                                                                    let paragraph = Paragraph::new(text)
                                                                        .style(Style::default().fg(Color::Green));
                                                                    let area = Rect::new(2, 1, size.width - 4, 1);
                                                                    f.render_widget(paragraph, area);
                                                                })?;
                                                                
                                                                // Wait a moment to show the message
                                                                std::thread::sleep(Duration::from_millis(1000));
                                                                break;
                                                            } else {
                                                                // Show error message
                                                                terminal.draw(|f| {
                                                                    let size = f.size();
                                                                    let block = Block::default()
                                                                        .title("Error")
                                                                        .borders(Borders::ALL);
                                                                    f.render_widget(block, size);
                                                                    let text = format!("Failed to change nice value for PID {}. Error: {}", pid, std::io::Error::last_os_error());
                                                                    let paragraph = Paragraph::new(text)
                                                                        .style(Style::default().fg(Color::Red));
                                                                    let area = Rect::new(2, 1, size.width - 4, 1);
                                                                    f.render_widget(paragraph, area);
                                                                })?;
                                                                
                                                                // Wait a moment to show the error
                                                                std::thread::sleep(Duration::from_millis(2000));
                                                            }
                                                        }
                                                    } else {
                                                        break;
                                                    }
                                                }
                                                KeyCode::Esc => break,
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char(c) => {
                        if filter_type != FilterType::None {
                            filter.push(c);
                        } else if c == 't' {
                            show_tree = !show_tree;
                            if show_tree {
                                println!("Process Tree:");
                                let processes_vec: Vec<ProcessInfo> = processes.values().cloned().collect();
                                display_process_tree(&processes_vec, None, "");
                            }
                        } else if c.is_ascii_digit() {
                            match c {
                                '1' => {
                                    sort_field = SortField::Command;
                                    sort_descending = !sort_descending;
                                }
                                '2' => {
                                    sort_field = SortField::Pid;
                                    sort_descending = !sort_descending;
                                }
                                '3' => {
                                    sort_field = SortField::Ppid;
                                    sort_descending = !sort_descending;
                                }
                                '4' => {
                                    sort_field = SortField::User;
                                    sort_descending = !sort_descending;
                                }
                                '5' => {
                                    sort_field = SortField::State;
                                    sort_descending = !sort_descending;
                                }
                                '6' => {
                                    sort_field = SortField::Cpu;
                                    sort_descending = !sort_descending;
                                }
                                '7' => {
                                    sort_field = SortField::Memory;
                                    sort_descending = !sort_descending;
                                }
                                '8' => {
                                    sort_field = SortField::Nice;
                                    sort_descending = !sort_descending;
                                }
                                '9' => {
                                    sort_field = SortField::StartTime;
                                    sort_descending = !sort_descending;
                                }
                                _ => {}
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        if filter_type != FilterType::None {
                            filter.pop();
                        }
                    }
                    KeyCode::Esc => {
                        if show_kill_prompt {
                            show_kill_prompt = false;
                        } else if filter_type != FilterType::None {
                            filter_type = FilterType::None;
                            filter.clear();
                        }
                    }
                    KeyCode::Up => {
                        if current_view_start > 0 {
                            current_view_start -= 1; // Scroll up
                        }
                    }
                    KeyCode::Down => {
                        if current_view_start + MAX_VISIBLE_LINES < output_buffer.len() {
                            current_view_start += 1; // Scroll down
                        }
                    }
                    KeyCode::Char('t') => {
                        show_tree = !show_tree; // Toggle tree display
                        if show_tree {
                            println!("Process Tree:");
                            let processes_vec: Vec<ProcessInfo> = processes.values().cloned().collect();
                            display_process_tree(&processes_vec, None, "");
                        }
                    }
                    _ => {}
                },
                Event::Resize(_, _) => {
                    terminal.clear()?;
                }
                _ => {}

            }
            let mut flat = Vec::new();
            display::flatten_tree(&tree, &mut flat);
            display::draw_ui(
                &mut terminal,
                &sys,
                &tree,
                &mut selected,
                scroll_offset,
                show_kill_prompt,
                &filter,
                filter_type,
                show_tree,
                sort_field,
                sort_descending,
                kill_target_pid,
                kill_target_name.clone(),
                tree_scroll_offset,
            )?;
        }

        if last_tick.elapsed() >= tick_rate {
            sys.refresh_memory();
            sys.refresh_cpu();
            sys.refresh_processes();
            processes = get_processes(&sys);
            tree = build_process_tree(&processes);
            let mut flat = Vec::new();
            display::flatten_tree(&tree, &mut flat);
            if selected >= flat.len() && !flat.is_empty() {
                selected = flat.len() - 1;
            }
            display::draw_ui(
                &mut terminal,
                &sys,
                &tree,
                &mut selected,
                scroll_offset,
                show_kill_prompt,
                &filter,
                filter_type,
                show_tree,
                sort_field,
                sort_descending,
                kill_target_pid,
                kill_target_name.clone(),
                tree_scroll_offset,
            )?;
            last_tick = Instant::now();
        }

        // Add logic to display the tree if show_tree is true
        if show_tree {
            let processes_vec: Vec<ProcessInfo> = processes.values().cloned().collect();
            display_process_tree(&processes_vec, None, "");
        }
    }
    execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    disable_raw_mode()?;
    Ok(())
}

fn run_ps() -> io::Result<()> {
    use std::fs;
    let mut sys = System::new_all();
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());
    sys.refresh_all();
    let uptime = sys.uptime();

    let mut procs: Vec<_> = sys.processes().values().collect();
    procs.sort_by_key(|p| p.pid());

    // Print header with better alignment
    println!("\n  PID TTY          TIME CMD");

    for p in procs {
        let pid = p.pid();

        // Get TTY information
        let tty = fs::read_link(format!("/proc/{}/fd/0", pid))
            .ok()
            .and_then(|path| {
                path.file_name()
                    .and_then(|os_str| os_str.to_str().map(String::from))
            })
            .unwrap_or_else(|| "?".to_string());

        // Calculate CPU time
        let elapsed = uptime.saturating_sub(p.start_time());
        let hours = elapsed / 3600;
        let mins = (elapsed % 3600) / 60;
        let secs = elapsed % 60;
        let time = format!("{:02}:{:02}:{:02}", hours, mins, secs);

        // Get command with arguments
        let cmd = if p.cmd().is_empty() {
            p.name().to_string()
        } else {
            p.cmd()
                .iter()
                .map(|arg| arg.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        };

        // Print process information with better alignment
        println!("{:5} {:<12} {} {}",
            pid,
            tty,
            time,
            cmd
        );
    }
    println!();
    Ok(())
}

fn run_kill() -> io::Result<()> {
    let mut input = String::new();
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;
    let pid_input = input.trim();

    let pid: sysinfo::Pid = match pid_input.parse::<usize>() {
        Ok(num) => sysinfo::Pid::from(num),
        Err(_) => {
            println!("Invalid PID entered.");
            return Ok(());
        }
    };

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::everything());

    // Check if process exists
    if !sys.processes().contains_key(&pid) {
        println!("Process with PID {} not found.", pid);
        return Ok(());
    }

    // Attempt to kill the process
    match signal::kill(
        unistd::Pid::from_raw(pid.as_u32() as i32),
        signal::Signal::SIGTERM,
    ) {
        Ok(_) => println!("Successfully sent SIGTERM to process {}", pid),
        Err(e) => {
            println!("Failed to kill process {}: {}", pid, e);
            // Try SIGKILL if SIGTERM fails
            if let Err(e) = signal::kill(
                unistd::Pid::from_raw(pid.as_u32() as i32),
                signal::Signal::SIGKILL,
            ) {
                println!("Failed to send SIGKILL to process {}: {}", pid, e);
            } else {
                println!("Successfully sent SIGKILL to process {}", pid);
            }
        }
    }
    Ok(())
}

fn display_memory_info() {
    let mut sys = System::new_all();
    sys.refresh_memory();

    // Convert to KB for display (like the free command)
    let to_kb = |bytes: u64| -> u64 { bytes / 1024 };

    let total = to_kb(sys.total_memory());
    let used = to_kb(sys.used_memory());
    let free = to_kb(sys.free_memory());
    let available = to_kb(sys.available_memory());
    
    // Calculate shared and buff/cache
    let shared = 3912; // This is a typical value, as sysinfo doesn't provide this directly
    let buff_cache = total.saturating_sub(used + free + shared);

    let swap_total = to_kb(sys.total_swap());
    let swap_used = to_kb(sys.used_swap());
    let swap_free = to_kb(sys.free_swap());

    println!("\n               total        used        free      shared  buff/cache   available");
    println!("Mem:          {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        total, used, free, shared, buff_cache, available);
    println!("Swap:         {:>10} {:>10} {:>10}",
        swap_total, swap_used, swap_free);
    println!();
}

pub fn draw_ui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    _sys: &System,
    _tree: &[ProcessNode],
    _selected: &mut usize,
    _scroll_offset: usize,
    _show_kill_prompt: bool,
    _filter: &str,
    _filter_type: FilterType,
    show_tree: bool,
    sort_field: SortField,
    sort_descending: bool,
    kill_target_pid: Option<sysinfo::Pid>,
    kill_target_name: String,
    tree_scroll_offset: usize,
) -> io::Result<()> {
    terminal.draw(|f| {
        let size = f.size();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // CPU/Memory summary
                Constraint::Min(0),    // Process list
                Constraint::Length(3), // Footer
            ])
            .margin(0)
            .split(size);

        // Draw CPU and Memory summary
        // ... existing summary drawing code ...

        // Process List
        // ... existing process list drawing code ...

        // Footer with toggle option
        let footer_message = if show_tree {
            "Press 't' to hide process tree"
        } else {
            "Press 't' to show process tree"
        };
        let footer = Paragraph::new(footer_message)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)));
        f.render_widget(footer, chunks[2]);
    })?;
    Ok(())
}




