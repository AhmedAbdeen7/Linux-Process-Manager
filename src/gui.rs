use crate::process::{ProcessInfo, ProcessNode};
use crate::{FilterType, SortField};
use egui::{Color32, RichText, ScrollArea, Ui, Key, KeyboardShortcut, Modifiers, Style};
use eframe::egui;
use egui_plot::{Plot, PlotPoints, Line, Legend, Corner};
use sysinfo::{System, SystemExt, CpuExt, ProcessExt, PidExt};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use chrono::{DateTime, Local};
use libc;
use std::collections::{VecDeque, HashMap};

pub struct ProcessManagerApp {
    system: Arc<Mutex<System>>,
    processes: Arc<Mutex<Vec<ProcessNode>>>,
    selected_pid: Option<sysinfo::Pid>,
    filter: String,
    filter_type: FilterType,
    show_tree: bool,
    sort_field: SortField,
    sort_descending: bool,
    show_kill_prompt: bool,
    kill_target_pid: Option<sysinfo::Pid>,
    kill_target_name: Option<String>,
    nice_dialog_state: Option<NiceDialogState>,
    kill_result: Option<KillResult>,
    nice_result: Option<NiceResult>,
    cpu_history: VecDeque<f32>,
    memory_history: VecDeque<f32>,
    history_max_len: usize,
    top_processes_history: HashMap<sysinfo::Pid, (String, VecDeque<f32>)>,
    process_colors: Vec<Color32>,
    show_statistics: bool,
}

impl ProcessManagerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let system = Arc::new(Mutex::new(System::new_all()));
        let processes = Arc::new(Mutex::new(Vec::new()));
        
        let system_clone = Arc::clone(&system);
        let processes_clone = Arc::clone(&processes);
        thread::spawn(move || {
            loop {
                {
                    let mut sys = system_clone.lock().unwrap();
                    sys.refresh_all();
                    
                    let mut process_info_map = std::collections::HashMap::new();
                    for (pid, process) in sys.processes() {
                        let nice = unsafe {
                            libc::getpriority(libc::PRIO_PROCESS, pid.as_u32() as libc::id_t)
                        } as i32;
                        
                        let virt = process.virtual_memory();
                        let res = process.memory() * 1024; 
                        let shr = 0; 
                        let state = format!("{:?}", process.status());
                        let cpu_percent = process.cpu_usage();
                        let mem_percent = (process.memory() as f32 / sys.total_memory() as f32) * 100.0;
                        let time = {
                            let t = process.start_time() as i64;
                            DateTime::from_timestamp(t, 0)
                                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
                                .with_timezone(&Local)
                                .format("%H:%M:%S")
                                .to_string()
                        };
                        let start_time = {
                            let t = process.start_time() as i64;
                            DateTime::from_timestamp(t, 0)
                                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
                                .with_timezone(&Local)
                                .format("%H:%M:%S")
                                .to_string()
                        };
                        
                        let info = ProcessInfo {
                            pid: *pid,
                            ppid: process.parent(),
                            user: process.user_id()
                                .map(|id| id.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            command: process.name().to_string(),
                            cmd: process.cmd().iter().map(|s| s.to_string()).collect(),
                            state,
                            cpu_percent,
                            mem_percent,
                            nice,
                            start_time,
                            priority: 0,
                            virt,
                            res,
                            shr,
                            time,
                        };
                        
                        process_info_map.insert(*pid, info);
                    }
                    
                    let mut tree_nodes = Vec::new();
                    let mut children_map = std::collections::HashMap::new();
                    
                    for (&pid, info) in &process_info_map {
                        children_map.entry(info.ppid).or_insert_with(Vec::new).push(pid);
                    }
                    
                    fn build_tree(
                        pid: sysinfo::Pid,
                        process_info_map: &std::collections::HashMap<sysinfo::Pid, ProcessInfo>,
                        children_map: &std::collections::HashMap<Option<sysinfo::Pid>, Vec<sysinfo::Pid>>,
                        depth: usize,
                    ) -> ProcessNode {
                        let info = process_info_map.get(&pid).unwrap().clone();
                        let children = children_map
                            .get(&Some(pid))
                            .map_or(Vec::new(), |child_pids| {
                                child_pids
                                    .iter()
                                    .map(|&child_pid| {
                                        build_tree(
                                            child_pid,
                                            process_info_map,
                                            children_map,
                                            depth + 1,
                                        )
                                    })
                                    .collect()
                            });
                        
                        ProcessNode {
                            info,
                            children,
                            depth,
                        }
                    }
                    
                    let root_pids: Vec<sysinfo::Pid> = process_info_map
                        .iter()
                        .filter(|(_, info)| {
                            info.ppid.is_none() || !process_info_map.contains_key(&info.ppid.unwrap())
                        })
                        .map(|(&pid, _)| pid)
                        .collect();
                    
                    for &root_pid in &root_pids {
                        tree_nodes.push(build_tree(root_pid, &process_info_map, &children_map, 0));
                    }
                    
                    println!("Updated process list: {} processes total", process_info_map.len());
                    println!("Root processes: {}", root_pids.len());
                    println!("Tree nodes: {}", tree_nodes.len());
                    
                    let mut procs = processes_clone.lock().unwrap();
                    *procs = tree_nodes;
                }
                
                thread::sleep(Duration::from_secs(1));
            }
        });
        
        let process_colors = vec![
            Color32::from_rgb(255, 100, 100),
            Color32::from_rgb(100, 200, 100),
            Color32::from_rgb(100, 100, 255),
            Color32::from_rgb(255, 200, 0),
            Color32::from_rgb(200, 100, 200),
        ];
        
        Self {
            system,
            processes,
            selected_pid: None,
            filter: String::new(),
            filter_type: FilterType::None,
            show_tree: false,
            sort_field: SortField::Cpu,
            sort_descending: true,
            show_kill_prompt: false,
            kill_target_pid: None,
            kill_target_name: None,
            nice_dialog_state: None,
            kill_result: None,
            nice_result: None,
            cpu_history: VecDeque::with_capacity(100),
            memory_history: VecDeque::with_capacity(100),
            history_max_len: 60,
            top_processes_history: HashMap::new(),
            process_colors,
            show_statistics: false,
        }
    }
    
    fn flatten_process_tree(tree: &[ProcessNode]) -> Vec<ProcessNode> {
        let mut flattened = Vec::new();
        
        fn flatten_node(node: &ProcessNode, flattened: &mut Vec<ProcessNode>) {
            flattened.push(node.clone());
            for child in &node.children {
                flatten_node(child, flattened);
            }
        }
        
        for node in tree {
            flatten_node(node, &mut flattened);
        }
        
        flattened
    }
    
    fn render_process_table(&mut self, ui: &mut Ui) {
        let processes = self.processes.lock().unwrap().clone();
        
        ui.heading(RichText::new("Process Table").size(18.0).strong());
        
        let flattened_processes = ProcessManagerApp::flatten_process_tree(&processes);
        let process_count = flattened_processes.len();
        ui.label(format!("Displaying {} processes", process_count));
        
        println!("Flattened process list size: {}", process_count);
        
        let mut filtered_processes = if !self.filter.is_empty() {
            flattened_processes.iter().filter(|node| {
                match self.filter_type {
                    FilterType::None => true,
                    FilterType::Command => {
                        node.info.command.to_lowercase().contains(&self.filter.to_lowercase()) ||
                        node.info.cmd.join(" ").to_lowercase().contains(&self.filter.to_lowercase())
                    },
                    FilterType::User => {
                        node.info.user.to_lowercase().contains(&self.filter.to_lowercase())
                    },
                    FilterType::State => {
                        node.info.state.to_lowercase().contains(&self.filter.to_lowercase())
                    },
                    FilterType::Pid => {
                        node.info.pid.to_string().contains(&self.filter)
                    },
                    FilterType::Cpu => {
                        if let Ok(threshold) = self.filter.parse::<f32>() {
                            node.info.cpu_percent >= threshold
                        } else {
                            false
                        }
                    },
                    FilterType::Memory => {
                        if let Ok(threshold) = self.filter.parse::<f32>() {
                            node.info.mem_percent >= threshold
                        } else {
                            false
                        }
                    },
                }
            }).cloned().collect::<Vec<ProcessNode>>()
        } else {
            flattened_processes
        };
        
        filtered_processes.sort_by(|a, b| {
            let cmp = match self.sort_field {
                SortField::Command => a.info.command.cmp(&b.info.command),
                SortField::Pid => a.info.pid.cmp(&b.info.pid),
                SortField::Ppid => match (a.info.ppid, b.info.ppid) {
                    (Some(a_ppid), Some(b_ppid)) => a_ppid.cmp(&b_ppid),
                    (Some(_), None) => std::cmp::Ordering::Greater,
                    (None, Some(_)) => std::cmp::Ordering::Less,
                    (None, None) => std::cmp::Ordering::Equal,
                },
                SortField::User => a.info.user.cmp(&b.info.user),
                SortField::State => a.info.state.cmp(&b.info.state),
                SortField::Cpu => a.info.cpu_percent.partial_cmp(&b.info.cpu_percent).unwrap_or(std::cmp::Ordering::Equal),
                SortField::Memory => a.info.mem_percent.partial_cmp(&b.info.mem_percent).unwrap_or(std::cmp::Ordering::Equal),
                SortField::Nice => a.info.nice.cmp(&b.info.nice),
                SortField::StartTime => a.info.start_time.cmp(&b.info.start_time),
            };
            if self.sort_descending {
                cmp.reverse()
            } else {
                cmp
            }
        });
        
        if !self.filter.is_empty() {
            ui.label(RichText::new(format!("Filter matched {} of {} processes", 
                                          filtered_processes.len(), process_count))
                    .color(Color32::LIGHT_BLUE));
        }
        
        ui.colored_label(
            Color32::LIGHT_GREEN, 
            "Select a process to manage it. Use K to kill."
        );
        
        egui::Frame::group(ui.style())
            .fill(ui.style().visuals.faint_bg_color)
            .show(ui, |ui| {
                let header_height = 28.0;
                let table = egui_extras::TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(egui_extras::Column::auto().at_least(150.0))
                    .column(egui_extras::Column::auto().at_least(50.0))
                    .column(egui_extras::Column::auto().at_least(50.0))
                    .column(egui_extras::Column::auto().at_least(80.0))
                    .column(egui_extras::Column::auto().at_least(60.0))
                    .column(egui_extras::Column::auto().at_least(60.0))
                    .column(egui_extras::Column::auto().at_least(60.0))
                    .column(egui_extras::Column::auto().at_least(40.0))
                    .column(egui_extras::Column::auto().at_least(80.0))
                    .column(egui_extras::Column::remainder().at_least(150.0))
                    .column(egui_extras::Column::auto().at_least(80.0))
                    .header(header_height, |mut header| {
                        let header_text = |text: &str| RichText::new(text)
                            .strong()
                            .color(Color32::WHITE);
                        
                        header.col(|ui| {
                            let sort_indicator = if self.sort_field == SortField::Command {
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" };
                            
                            if ui.selectable_label(
                                self.sort_field == SortField::Command,
                                header_text(&format!("Command{}", sort_indicator))
                            ).clicked() {
                                if self.sort_field == SortField::Command {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::Command;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::Pid, 
                            format!("PID{}", if self.sort_field == SortField::Pid { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::Pid {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::Pid;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::Ppid, 
                            format!("PPID{}", if self.sort_field == SortField::Ppid { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::Ppid {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::Ppid;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::User, 
                            format!("USER{}", if self.sort_field == SortField::User { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::User {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::User;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::State, 
                            format!("STATE{}", if self.sort_field == SortField::State { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::State {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::State;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::Cpu, 
                            format!("CPU%{}", if self.sort_field == SortField::Cpu { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::Cpu {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::Cpu;
                                    self.sort_descending = true;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::Memory, 
                            format!("MEM%{}", if self.sort_field == SortField::Memory { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::Memory {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::Memory;
                                    self.sort_descending = true;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::Nice, 
                            format!("NI{}", if self.sort_field == SortField::Nice { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::Nice {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::Nice;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| {
                            if ui.selectable_label(self.sort_field == SortField::StartTime, 
                            format!("STARTED{}", if self.sort_field == SortField::StartTime { 
                                if self.sort_descending { " ↓" } else { " ↑" }
                            } else { "" })).clicked() {
                                if self.sort_field == SortField::StartTime {
                                    self.sort_descending = !self.sort_descending;
                                } else {
                                    self.sort_field = SortField::StartTime;
                                    self.sort_descending = false;
                                }
                            }
                        });
                        
                        header.col(|ui| { ui.label("CMD"); });
                        header.col(|ui| { ui.label("Actions"); });
                    });
                    
                let row_height = 28.0;
                
                table.body(|mut body| {
                    for (row_idx, process) in filtered_processes.iter().enumerate() {
                        let is_selected = Some(process.info.pid) == self.selected_pid;
                        let row_bg_color = if is_selected {
                            Color32::from_rgb(70, 70, 100)
                        } else if row_idx % 2 == 0 {
                            Color32::from_rgb(30, 30, 46) 
                        } else {
                            Color32::from_rgb(40, 40, 56)
                        };
                        
                        body.row(row_height, |mut row| {
                            row.col(|ui| {
                                let text = if is_selected {
                                    RichText::new(&process.info.command)
                                        .strong()
                                        .color(Color32::WHITE)
                                } else {
                                    RichText::new(&process.info.command)
                                };
                                
                                ui.style_mut().visuals.override_text_color = Some(if is_selected { 
                                    Color32::WHITE 
                                } else { 
                                    Color32::LIGHT_GRAY 
                                });
                                
                                if ui.selectable_label(is_selected, text)
                                    .clicked() {
                                    self.selected_pid = Some(process.info.pid);
                                }
                                
                                ui.style_mut().visuals.override_text_color = None;
                            });
                            
                            row.col(|ui| { ui.label(process.info.pid.to_string()); });
                            
                            row.col(|ui| { ui.label(process.info.ppid.map_or("?".to_string(), |p| p.to_string())); });
                            
                            row.col(|ui| { ui.label(&process.info.user); });
                            
                            row.col(|ui| { ui.label(&process.info.state); });
                            
                            row.col(|ui| { 
                                let cpu_text = format!("{:.1}%", process.info.cpu_percent);
                                let color = if process.info.cpu_percent > 50.0 {
                                    Color32::RED
                                } else if process.info.cpu_percent > 20.0 {
                                    Color32::YELLOW
                                } else {
                                    Color32::GREEN
                                };
                                ui.label(RichText::new(cpu_text).color(color));
                            });
                            
                            row.col(|ui| { 
                                let mem_text = format!("{:.1}%", process.info.mem_percent);
                                let color = if process.info.mem_percent > 10.0 {
                                    Color32::RED
                                } else if process.info.mem_percent > 5.0 {
                                    Color32::YELLOW
                                } else {
                                    Color32::GREEN
                                };
                                ui.label(RichText::new(mem_text).color(color));
                            });
                            
                            row.col(|ui| { 
                                let nice_text = format!("{}", process.info.nice);
                                let color = if process.info.nice < 0 {
                                    Color32::LIGHT_BLUE
                                } else if process.info.nice > 0 {
                                    Color32::LIGHT_RED
                                } else {
                                    Color32::WHITE
                                };
                                ui.label(RichText::new(nice_text).color(color));
                            });
                            
                            row.col(|ui| { ui.label(&process.info.start_time); });
                            
                            row.col(|ui| { ui.label(process.info.cmd.join(" ")); });
                            
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    if ui.button("Kill").clicked() {
                                        self.show_kill_prompt = true;
                                        self.kill_target_pid = Some(process.info.pid);
                                        self.kill_target_name = Some(process.info.command.clone());
                                    }
                                    
                                    if ui.button("Nice").clicked() {
                                        self.show_nice_dialog(process.info.pid, process.info.nice);
                                    }
                                });
                            });
                        });
                    }
                });
            });
        
        ui.horizontal(|ui| {
            let now = chrono::Local::now();
            let time_str = now.format("%H:%M:%S").to_string();
            ui.label(RichText::new(format!("Last updated: {} | Total processes: {}", time_str, process_count))
                    .italics()
                    .color(Color32::LIGHT_GRAY));
            
            let system = self.system.lock().unwrap();
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(format!("CPU: {:.1}% | MEM: {:.1}%", 
                                             system.global_cpu_info().cpu_usage(),
                                             system.used_memory() as f32 / system.total_memory() as f32 * 100.0))
                       .color(Color32::LIGHT_BLUE));
            });
        });
    }
    
    fn show_nice_dialog(&mut self, pid: sysinfo::Pid, current_nice: i32) {
        let nice_values: Vec<i32> = (-20..=19).collect();
        let selected_nice_index = nice_values.iter()
            .position(|&x| x == current_nice)
            .unwrap_or(20);
        
        println!("Note: Changing nice values typically requires elevated privileges (sudo/root)");
        
        self.nice_dialog_state = Some(NiceDialogState {
            pid,
            current_nice,
            nice_values,
            selected_nice_index,
        });
    }
    
    fn kill_process(&mut self, pid: sysinfo::Pid) {
        let result = unsafe {
            libc::kill(pid.as_u32() as libc::pid_t, libc::SIGKILL)
        };
        
        if result == 0 {
            self.kill_result = Some(KillResult::Success(pid));
        } else {
            self.kill_result = Some(KillResult::Failed(pid, std::io::Error::last_os_error().to_string()));
        }
        
        self.show_kill_prompt = false;
        self.kill_target_pid = None;
        self.kill_target_name = None;
    }
    
    fn change_nice_value(&mut self, pid: sysinfo::Pid, new_nice: i32) {
        println!("Attempting to change nice value of PID {} to {}", pid, new_nice);
        
        let direct_result = unsafe {
            libc::setpriority(
                libc::PRIO_PROCESS,
                pid.as_u32() as libc::id_t,
                new_nice
            )
        };
        
        if direct_result == 0 {
            println!("Successfully changed nice value using direct system call");
            self.nice_result = Some(NiceResult::Success(pid, new_nice));
            self.nice_dialog_state = None;
            
            let system_clone = Arc::clone(&self.system);
            let mut system = system_clone.lock().unwrap();
            system.refresh_processes();
            return;
        } else {
            println!("Direct system call failed: {}", std::io::Error::last_os_error());
        }
        
        println!("Direct system call failed, trying helper binary...");
        
        let compile_output = std::process::Command::new("cargo")
            .args(["build", "--bin", "change_nice"])
            .output();
        
        if compile_output.is_err() {
            println!("Failed to compile helper binary: {:?}", compile_output.err());
        }
        
        let helper_paths = [
            "./target/debug/change_nice",
            "target/debug/change_nice",
            "/mnt/d/OS-2-main/target/debug/change_nice",
            "/mnt/d/OS-2-main/target/release/change_nice",
            "./change_nice",
        ];
        
        println!("Attempting to change nice value with helper binary, current directory: {:?}", std::env::current_dir());
        
        for helper_path in &helper_paths {
            println!("Trying helper at: {}", helper_path);
            let result = std::process::Command::new(helper_path)
                .arg(pid.as_u32().to_string())
                .arg(new_nice.to_string())
                .output();
                
            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("Helper output: {}", stdout);
                    if !stderr.is_empty() {
                        println!("Helper error: {}", stderr);
                    }
                    
                    if output.status.success() {
                        println!("Successfully changed nice value using helper binary");
                        self.nice_result = Some(NiceResult::Success(pid, new_nice));
                        self.nice_dialog_state = None;
                        
                        let system_clone = Arc::clone(&self.system);
                        let mut system = system_clone.lock().unwrap();
                        system.refresh_processes();
                        return;
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("Helper binary failed: {}", stderr);
                    }
                },
                Err(e) => {
                    println!("Failed to execute helper binary {}: {}", helper_path, e);
                }
            }
        }
        
        for helper_path in &helper_paths {
            println!("Trying pkexec with helper at: {}", helper_path);
            let result = std::process::Command::new("pkexec")
                .arg(helper_path)
                .arg(pid.as_u32().to_string())
                .arg(new_nice.to_string())
                .output();
                
            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("pkexec output: {}", stdout);
                    if !stderr.is_empty() {
                        println!("pkexec error: {}", stderr);
                    }
                    
                    if output.status.success() {
                        println!("Successfully changed nice value using pkexec");
                        self.nice_result = Some(NiceResult::Success(pid, new_nice));
                        self.nice_dialog_state = None;
                        
                        let system_clone = Arc::clone(&self.system);
                        let mut system = system_clone.lock().unwrap();
                        system.refresh_processes();
                        return;
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("pkexec method failed: {}", stderr);
                    }
                },
                Err(e) => {
                    println!("Failed to execute pkexec: {}", e);
                }
            }
        }
        
        for helper_path in &helper_paths {
            println!("Trying sudo with helper at: {}", helper_path);
            let result = std::process::Command::new("sudo")
                .arg(helper_path)
                .arg(pid.as_u32().to_string())
                .arg(new_nice.to_string())
                .output();
                
            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("sudo output: {}", stdout);
                    if !stderr.is_empty() {
                        println!("sudo error: {}", stderr);
                    }
                    
                    if output.status.success() {
                        println!("Successfully changed nice value using sudo");
                        self.nice_result = Some(NiceResult::Success(pid, new_nice));
                        self.nice_dialog_state = None;
                        
                        let system_clone = Arc::clone(&self.system);
                        let mut system = system_clone.lock().unwrap();
                        system.refresh_processes();
                        return;
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("sudo method failed: {}", stderr);
                    }
                },
                Err(e) => {
                    println!("Failed to execute sudo: {}", e);
                }
            }
        }
        
        println!("Trying renice command...");
        let renice_result = std::process::Command::new("renice")
            .arg(format!("{}", new_nice))
            .arg("-p")
            .arg(format!("{}", pid.as_u32()))
            .output();
            
        match renice_result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("renice output: {}", stdout);
                if !stderr.is_empty() {
                    println!("renice error: {}", stderr);
                }
                
                if output.status.success() {
                    println!("Successfully changed nice value using renice");
                    self.nice_result = Some(NiceResult::Success(pid, new_nice));
                    self.nice_dialog_state = None;
                    
                    let system_clone = Arc::clone(&self.system);
                    let mut system = system_clone.lock().unwrap();
                    system.refresh_processes();
                    return;
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("renice method failed: {}", stderr);
                }
            },
            Err(e) => {
                println!("Failed to execute renice: {}", e);
            }
        }
        
        self.nice_result = Some(NiceResult::Failed(pid, 
            format!("All methods to change nice value failed.\n\n\
                   This is likely due to permission restrictions.\n\n\
                   Please try one of the following:\n\
                   1. Run the entire application with sudo:\n\
                   sudo cargo run --bin process-governor\n\n\
                   2. In Windows WSL environment, you might need admin privileges.")
        ));
        
        self.nice_dialog_state = None;
    }
    
    fn render_tree_view(&mut self, ui: &mut Ui) {
        let processes = self.processes.lock().unwrap().clone();
        
        ui.heading(RichText::new("Process Tree View").size(18.0).strong());
        ui.label(RichText::new("Shows parent-child relationships between processes").italics());
        
        let mut pids_to_kill: Vec<(sysinfo::Pid, String)> = Vec::new();
        let mut pids_to_nice: Vec<(sysinfo::Pid, i32)> = Vec::new();
        
        egui::Frame::group(ui.style())
            .fill(ui.style().visuals.faint_bg_color)
            .show(ui, |ui| {
                ScrollArea::vertical().show(ui, |ui| {
                    fn render_node(ui: &mut Ui, node: &ProcessNode, indent: usize, is_last: bool, 
                                  pids_to_kill: &mut Vec<(sysinfo::Pid, String)>,
                                  pids_to_nice: &mut Vec<(sysinfo::Pid, i32)>) {
                        let indent_text = if indent > 0 {
                            let prefix = if is_last { "└── " } else { "├── " };
                            format!("{}{}", " ".repeat(4 * (indent - 1)), prefix)
                        } else {
                            "".to_string()
                        };
                        
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("{}{}", indent_text, node.info.command))
                                .strong());
                            
                            ui.label(format!("({})", node.info.pid));
                            
                            ui.add_space(10.0);
                            
                            let cpu_color = if node.info.cpu_percent > 50.0 {
                                Color32::RED
                            } else if node.info.cpu_percent > 20.0 {
                                Color32::YELLOW
                            } else {
                                Color32::GREEN
                            };
                            
                            ui.label(RichText::new(format!("CPU: {:.1}%", node.info.cpu_percent))
                                .color(cpu_color));
                            
                            ui.add_space(10.0);
                            
                            let mem_color = if node.info.mem_percent > 10.0 {
                                Color32::RED
                            } else if node.info.mem_percent > 5.0 {
                                Color32::YELLOW
                            } else {
                                Color32::GREEN
                            };
                            
                            ui.label(RichText::new(format!("MEM: {:.1}%", node.info.mem_percent))
                                .color(mem_color));
                            
                            ui.add_space(10.0);
                            ui.label(format!("State: {}", node.info.state));
                            
                            ui.add_space(10.0);
                            let nice_color = if node.info.nice < 0 {
                                Color32::LIGHT_BLUE
                            } else if node.info.nice > 0 {
                                Color32::LIGHT_RED
                            } else {
                                Color32::WHITE
                            };
                            ui.label(RichText::new(format!("Nice: {}", node.info.nice))
                                .color(nice_color));
                            
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("Kill").clicked() {
                                    pids_to_kill.push((node.info.pid, node.info.command.clone()));
                                }
                                
                                if ui.button("Nice").clicked() {
                                    pids_to_nice.push((node.info.pid, node.info.nice));
                                }
                            });
                        });
                        
                        let children = &node.children;
                        
                        for (i, child) in children.iter().enumerate() {
                            let is_last_child = i == children.len() - 1;
                            render_node(ui, child, indent + 1, is_last_child, pids_to_kill, pids_to_nice);
                        }
                    }
                    
                    for (i, process) in processes.iter().enumerate() {
                        render_node(ui, process, 0, i == processes.len() - 1, &mut pids_to_kill, &mut pids_to_nice);
                    }
                });
            });
        
        if !pids_to_kill.is_empty() {
            if let Some((pid, name)) = pids_to_kill.first() {
                self.show_kill_prompt = true;
                self.kill_target_pid = Some(*pid);
                self.kill_target_name = Some(name.clone());
            }
        }
        
        if !pids_to_nice.is_empty() {
            if let Some((pid, current_nice)) = pids_to_nice.first() {
                self.show_nice_dialog(*pid, *current_nice);
            }
        }
    }
    
    fn handle_kill_prompt(&mut self, ui: &egui::Context) {
        if self.show_kill_prompt {
            egui::Window::new("Kill Process")
                .collapsible(false)
                .resizable(false)
                .show(ui, |ui| {
                    if let (Some(pid), Some(name)) = (self.kill_target_pid, &self.kill_target_name) {
                        ui.label(format!("Kill process {} (PID {})?", name, pid));
                        
                        ui.horizontal(|ui| {
                            if ui.button("Yes").clicked() {
                                self.kill_process(pid);
                            }
                            
                            if ui.button("No").clicked() {
                                self.show_kill_prompt = false;
                                self.kill_target_pid = None;
                                self.kill_target_name = None;
                            }
                        });
                    }
                });
        }
    }
    
    fn handle_nice_dialog(&mut self, ui: &egui::Context) {
        if let Some(dialog_state) = &self.nice_dialog_state {
            let mut selected_index = dialog_state.selected_nice_index;
            let mut dialog_closed = false;
            let mut nice_changed = false;
            let mut new_nice = dialog_state.current_nice;
            
            egui::Window::new(format!("Change Nice Value for PID {} (Current: {})", 
                          dialog_state.pid, dialog_state.current_nice))
                .collapsible(false)
                .resizable(false)
                .show(ui, |ui| {
                    ScrollArea::vertical().show(ui, |ui| {
                        for (i, &value) in dialog_state.nice_values.iter().enumerate() {
                            let is_selected = i == selected_index;
                            if ui.selectable_label(is_selected, 
                               format!("{}{}", value, if value == dialog_state.current_nice { " (current)" } else { "" }))
                               .clicked() {
                                selected_index = i;
                                new_nice = value;
                            }
                        }
                    });
                    
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        if ui.button("Apply").clicked() {
                            if new_nice != dialog_state.current_nice {
                                nice_changed = true;
                            } else {
                                dialog_closed = true;
                            }
                        }
                        
                        if ui.button("Cancel").clicked() {
                            dialog_closed = true;
                        }
                    });
                });
            
            if dialog_closed {
                self.nice_dialog_state = None;
            } else if nice_changed {
                self.change_nice_value(dialog_state.pid, new_nice);
            } else if selected_index != dialog_state.selected_nice_index {
                self.nice_dialog_state = Some(NiceDialogState {
                    pid: dialog_state.pid,
                    current_nice: dialog_state.current_nice,
                    nice_values: dialog_state.nice_values.clone(),
                    selected_nice_index: selected_index,
                });
            }
        }
    }
    
    fn handle_result_popups(&mut self, ui: &egui::Context) {
        if let Some(result) = &self.kill_result {
            let (title, message, color) = match result {
                KillResult::Success(pid) => (
                    "Success", 
                    format!("Successfully killed process (PID {})", pid),
                    Color32::GREEN
                ),
                KillResult::Failed(pid, error) => (
                    "Error", 
                    format!("Failed to kill process (PID {}): {}", pid, error),
                    Color32::RED
                ),
            };
            
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.colored_label(color, message);
                    if ui.button("Close").clicked() {
                        self.kill_result = None;
                    }
                });
        }
        
        if let Some(result) = &self.nice_result {
            let (title, message, color, is_permission_error) = match result {
                NiceResult::Success(pid, new_nice) => (
                    "Success", 
                    format!("Successfully changed nice value to {} for PID {}", new_nice, pid),
                    Color32::GREEN,
                    false
                ),
                NiceResult::Failed(pid, error) => (
                    "Error", 
                    format!("Failed to change nice value for PID {}: {}", pid, error),
                    Color32::RED,
                    error.contains("Permission denied")
                ),
            };
            
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .show(ui, |ui| {
                    ui.colored_label(color, message);
                    
                    if is_permission_error {
                        ui.add_space(10.0);
                        ui.colored_label(Color32::LIGHT_YELLOW, 
                            "Note: Changing process priorities requires root privileges.");
                        ui.label("Run this application with 'sudo' to enable this feature.");
                    }
                    
                    if ui.button("Close").clicked() {
                        self.nice_result = None;
                    }
                });
        }
    }
    
    fn update_usage_history(&mut self) {
        let system = self.system.lock().unwrap();
        
        let cpu_usage = system.global_cpu_info().cpu_usage();
        self.cpu_history.push_back(cpu_usage);
        
        let total_mem = system.total_memory() as f32;
        let used_mem = system.used_memory() as f32;
        let mem_percent = (used_mem / total_mem) * 100.0;
        self.memory_history.push_back(mem_percent);
        
        let mut top_processes: Vec<(sysinfo::Pid, String, f32)> = system.processes()
            .iter()
            .map(|(&pid, proc)| (pid, proc.name().to_string(), proc.cpu_usage()))
            .collect();
        
        top_processes.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        
        let top_5 = top_processes.into_iter().take(5);
        
        for (pid, name, cpu_usage) in top_5 {
            if let Some(history) = self.top_processes_history.get_mut(&pid) {
                history.1.push_back(cpu_usage);
                while history.1.len() > self.history_max_len {
                    history.1.pop_front();
                }
            } else {
                let mut history = VecDeque::with_capacity(self.history_max_len);
                for _ in 0..self.history_max_len - 1 {
                    history.push_back(0.0);
                }
                history.push_back(cpu_usage);
                self.top_processes_history.insert(pid, (name, history));
            }
        }
        
        self.top_processes_history.retain(|&pid, history| {
            system.process(pid).is_some() && history.1.back().map_or(false, |&usage| usage > 0.1)
        });
        
        while self.cpu_history.len() > self.history_max_len {
            self.cpu_history.pop_front();
        }
        
        while self.memory_history.len() > self.history_max_len {
            self.memory_history.pop_front();
        }
    }
    
    fn render_top_processes_graph(&mut self, ui: &mut Ui) {
        ui.add_space(12.0);
        ui.heading("Top Processes (CPU)");
        
        let mut top_procs: Vec<(&sysinfo::Pid, &(String, VecDeque<f32>))> = 
            self.top_processes_history.iter().collect();
        
        top_procs.sort_by(|a, b| {
            let a_usage = a.1.1.back().unwrap_or(&0.0);
            let b_usage = b.1.1.back().unwrap_or(&0.0);
            b_usage.partial_cmp(a_usage).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        let top_5 = top_procs.into_iter().take(5).collect::<Vec<_>>();
        
        if top_5.is_empty() {
            ui.label("No process data available yet...");
            return;
        }
        
        Plot::new("top_processes_plot")
            .height(150.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .show_x(false)
            .include_y(0.0)
            .legend(Legend::default().position(Corner::LeftTop))
            .show(ui, |plot_ui| {
                for (i, (&pid, (name, history))) in top_5.iter().enumerate() {
                    if history.is_empty() {
                        continue;
                    }
                    
                    let color = self.process_colors[i % self.process_colors.len()];
                    
                    let points: PlotPoints = history
                        .iter()
                        .enumerate()
                        .map(|(i, &value)| [i as f64, value as f64])
                        .collect();
                    
                    let line = Line::new(points)
                        .color(color)
                        .name(format!("{} ({:.1}%)", name, history.back().unwrap_or(&0.0)));
                    
                    plot_ui.line(line);
                }
            });
        
        ui.horizontal(|ui| {
            ui.label("Processes:");
            for (i, (&pid, (name, history))) in top_5.iter().enumerate().take(5) {
                let color = self.process_colors[i % self.process_colors.len()];
                let current_usage = history.back().unwrap_or(&0.0);
                ui.label(
                    RichText::new(format!("{}: {:.1}%", name, current_usage))
                        .color(color)
                );
            }
        });
    }
    
    fn render_usage_graphs(&mut self, ui: &mut Ui) {
        ui.add_space(8.0);
        ui.heading("Resource Usage Graphs");
        
        self.update_usage_history();
        
        ui.label("CPU Usage");
        
        let cpu_points: PlotPoints = self.cpu_history
            .iter()
            .enumerate()
            .map(|(i, &value)| [i as f64, value as f64])
            .collect();
        
        let cpu_line = Line::new(cpu_points)
            .color(Color32::from_rgb(100, 200, 100))
            .fill(0.1);
        
        Plot::new("cpu_usage_plot")
            .height(100.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .show_x(false)
            .include_y(0.0)
            .include_y(100.0)
            .y_axis_formatter(|y, _range, _precision| {
                if y == 0.0 || y == 100.0 {
                    format!("{:.0}%", y)
                } else {
                    "".to_string()
                }
            })
            .show(ui, |plot_ui| {
                plot_ui.line(cpu_line);
            });
        
        ui.add_space(8.0);
        ui.label("Memory Usage");
        
        let mem_points: PlotPoints = self.memory_history
            .iter()
            .enumerate()
            .map(|(i, &value)| [i as f64, value as f64])
            .collect();
        
        let mem_line = Line::new(mem_points)
            .color(Color32::from_rgb(100, 150, 230))
            .fill(0.1);
        
        Plot::new("memory_usage_plot")
            .height(100.0)
            .allow_drag(false)
            .allow_zoom(false)
            .allow_scroll(false)
            .show_x(false)
            .include_y(0.0)
            .include_y(100.0)
            .y_axis_formatter(|y, _range, _precision| {
                if y == 0.0 || y == 100.0 {
                    format!("{:.0}%", y)
                } else {
                    "".to_string()
                }
            })
            .show(ui, |plot_ui| {
                plot_ui.line(mem_line);
            });
        
        self.render_top_processes_graph(ui);
    }
    
    fn system_stats_panel(&mut self, ui: &mut Ui) {
        let cpu_usage;
        let used_mem;
        let total_mem;
        let used_swap;
        let total_swap;
        let total_processes;
        let running_processes;
        
        {
            let system = self.system.lock().unwrap();
            cpu_usage = system.global_cpu_info().cpu_usage();
            used_mem = system.used_memory() as f64;
            total_mem = system.total_memory() as f64;
            used_swap = system.used_swap() as f64;
            total_swap = system.total_swap() as f64;
            total_processes = system.processes().len();
            running_processes = system.processes().values()
                .filter(|p| p.status() == sysinfo::ProcessStatus::Run)
                .count();
        }
        
        let mem_percent = (used_mem / total_mem) * 100.0;
        let swap_percent = if total_swap > 0.0 { 
            (used_swap / total_swap) * 100.0 
        } else { 
            0.0 
        };
        let sleeping_processes = total_processes - running_processes;
        
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label("CPU Usage");
                ui.add(egui::ProgressBar::new(cpu_usage / 100.0)
                    .text(format!("{:.1}%", cpu_usage)));
            });
            
            ui.separator();
            
            ui.vertical(|ui| {
                ui.label("Memory Usage");
                ui.add(egui::ProgressBar::new((mem_percent as f32) / 100.0)
                    .text(format!("{:.1}% ({:.1}/{:.1} GB)", 
                        mem_percent, 
                        used_mem / 1_000_000_000.0, 
                        total_mem / 1_000_000_000.0)));
            });
        });
        
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label("Swap Usage");
                ui.add(egui::ProgressBar::new((swap_percent as f32) / 100.0)
                    .text(format!("{:.1}% ({:.1}/{:.1} GB)", 
                        swap_percent, 
                        used_swap / 1_000_000_000.0, 
                        total_swap / 1_000_000_000.0)));
            });
            
            ui.separator();
            
            ui.vertical(|ui| {
                ui.label("Process Statistics");
                ui.label(format!("Total: {}", total_processes));
                ui.label(format!("Running: {} | Sleeping: {}", running_processes, sleeping_processes));
            });
        });
        
        self.render_usage_graphs(ui);
    }
    
    fn handle_keyboard_shortcuts(&mut self, ctx: &egui::Context) {
        let toggle_tree_view = KeyboardShortcut::new(Modifiers::NONE, Key::T);
        if ctx.input_mut(|i| i.consume_shortcut(&toggle_tree_view)) {
            self.show_tree = !self.show_tree;
        }
        
        let sort_by_cpu = KeyboardShortcut::new(Modifiers::NONE, Key::C);
        if ctx.input_mut(|i| i.consume_shortcut(&sort_by_cpu)) {
            if self.sort_field == SortField::Cpu {
                self.sort_descending = !self.sort_descending;
            } else {
                self.sort_field = SortField::Cpu;
                self.sort_descending = true;
            }
        }
        
        let sort_by_mem = KeyboardShortcut::new(Modifiers::NONE, Key::M);
        if ctx.input_mut(|i| i.consume_shortcut(&sort_by_mem)) {
            if self.sort_field == SortField::Memory {
                self.sort_descending = !self.sort_descending;
            } else {
                self.sort_field = SortField::Memory;
                self.sort_descending = true;
            }
        }
        
        let toggle_stats = KeyboardShortcut::new(Modifiers::NONE, Key::G);
        if ctx.input_mut(|i| i.consume_shortcut(&toggle_stats)) {
            self.show_statistics = !self.show_statistics;
        }
        
        let sort_by_pid = KeyboardShortcut::new(Modifiers::NONE, Key::P);
        if ctx.input_mut(|i| i.consume_shortcut(&sort_by_pid)) {
            if self.sort_field == SortField::Pid {
                self.sort_descending = !self.sort_descending;
            } else {
                self.sort_field = SortField::Pid;
                self.sort_descending = false;
            }
        }
        
        let sort_by_name = KeyboardShortcut::new(Modifiers::NONE, Key::N);
        if ctx.input_mut(|i| i.consume_shortcut(&sort_by_name)) {
            if self.sort_field == SortField::Command {
                self.sort_descending = !self.sort_descending;
            } else {
                self.sort_field = SortField::Command;
                self.sort_descending = false;
            }
        }
        
        let focus_filter = KeyboardShortcut::new(Modifiers::NONE, Key::F);
        if ctx.input_mut(|i| i.consume_shortcut(&focus_filter)) {
            ctx.memory_mut(|mem| mem.request_focus(egui::Id::new("filter_text_edit")));
        }
        
        let clear_filter = KeyboardShortcut::new(Modifiers::NONE, Key::Escape);
        if ctx.input_mut(|i| i.consume_shortcut(&clear_filter)) {
            self.filter.clear();
        }
        
        let refresh_processes = KeyboardShortcut::new(Modifiers::NONE, Key::R);
        if ctx.input_mut(|i| i.consume_shortcut(&refresh_processes)) {
            self.refresh_processes();
        }
        
        if let Some(pid) = self.selected_pid {
            let kill_process = KeyboardShortcut::new(Modifiers::NONE, Key::K);
            if ctx.input_mut(|i| i.consume_shortcut(&kill_process)) {
                let process_name = self.processes.lock().unwrap().iter()
                    .flat_map(|node| Self::flatten_process_tree(&[node.clone()]))
                    .find(|node| node.info.pid == pid)
                    .map(|node| node.info.command.clone());
                
                if let Some(name) = process_name {
                    self.show_kill_prompt = true;
                    self.kill_target_pid = Some(pid);
                    self.kill_target_name = Some(name);
                }
            }
            
            let change_nice = KeyboardShortcut::new(Modifiers::CTRL, Key::N);
            if ctx.input_mut(|i| i.consume_shortcut(&change_nice)) {
                let current_nice = self.processes.lock().unwrap().iter()
                    .flat_map(|node| Self::flatten_process_tree(&[node.clone()]))
                    .find(|node| node.info.pid == pid)
                    .map(|node| node.info.nice)
                    .unwrap_or(0);
                
                self.show_nice_dialog(pid, current_nice);
            }
        }
    }
    
    fn refresh_processes(&mut self) {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_all();
        
        println!("Process list refreshed manually");
    }
}

#[derive(Clone)]
struct NiceDialogState {
    pid: sysinfo::Pid,
    current_nice: i32,
    nice_values: Vec<i32>,
    selected_nice_index: usize,
}

enum KillResult {
    Success(sysinfo::Pid),
    Failed(sysinfo::Pid, String),
}

enum NiceResult {
    Success(sysinfo::Pid, i32),
    Failed(sysinfo::Pid, String),
}

impl eframe::App for ProcessManagerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut style = (*ctx.style()).clone();
        style.visuals.dark_mode = true;
        style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(28, 28, 35);
        style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(35, 35, 45);
        style.visuals.widgets.active.bg_fill = Color32::from_rgb(45, 45, 60);
        style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(55, 55, 70);
        style.visuals.panel_fill = Color32::from_rgb(22, 22, 30);
        ctx.set_style(style);
        
        self.handle_keyboard_shortcuts(ctx);
        
        if self.show_statistics {
            egui::SidePanel::right("statistics_panel")
                .resizable(true)
                .default_width(280.0)
                .width_range(250.0..=500.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .show(ui, |ui| {
                            ui.heading("System Statistics");
                            ui.label("Press 'G' to toggle statistics view");
                            ui.add_space(8.0);
                            
                            let cpu_usage;
                            let used_mem;
                            let total_mem;
                            let used_swap;
                            let total_swap;
                            let total_processes;
                            let running_processes;
                            
                            {
                                let system = self.system.lock().unwrap();
                                cpu_usage = system.global_cpu_info().cpu_usage();
                                used_mem = system.used_memory() as f64;
                                total_mem = system.total_memory() as f64;
                                used_swap = system.used_swap() as f64;
                                total_swap = system.total_swap() as f64;
                                total_processes = system.processes().len();
                                running_processes = system.processes().values()
                                    .filter(|p| p.status() == sysinfo::ProcessStatus::Run)
                                    .count();
                            }
                            
                            let mem_percent = (used_mem / total_mem) * 100.0;
                            let swap_percent = if total_swap > 0.0 { 
                                (used_swap / total_swap) * 100.0 
                            } else { 
                                0.0 
                            };
                            let sleeping_processes = total_processes - running_processes;
                            
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label("CPU Usage");
                                    ui.add(egui::ProgressBar::new(cpu_usage / 100.0)
                                        .text(format!("{:.1}%", cpu_usage)));
                                });
                                
                                ui.separator();
                                
                                ui.vertical(|ui| {
                                    ui.label("Memory Usage");
                                    ui.add(egui::ProgressBar::new((mem_percent as f32) / 100.0)
                                        .text(format!("{:.1}% ({:.1}/{:.1} GB)", 
                                            mem_percent, 
                                            used_mem / 1_000_000_000.0, 
                                            total_mem / 1_000_000_000.0)));
                                });
                            });
                            
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label("Swap Usage");
                                    ui.add(egui::ProgressBar::new((swap_percent as f32) / 100.0)
                                        .text(format!("{:.1}% ({:.1}/{:.1} GB)", 
                                            swap_percent, 
                                            used_swap / 1_000_000_000.0, 
                                            total_swap / 1_000_000_000.0)));
                                });
                                
                                ui.separator();
                                
                                ui.vertical(|ui| {
                                    ui.label("Process Statistics");
                                    ui.label(format!("Total: {}", total_processes));
                                    ui.label(format!("Running: {} | Sleeping: {}", running_processes, sleeping_processes));
                                });
                            });
                            
                            self.render_usage_graphs(ui);
                            
                            ui.add_space(8.0);
                            ui.collapsing("Keyboard Shortcuts", |ui| {
                                ui.label("Process Navigation:");
                                ui.label("T: Toggle Tree View");
                                ui.label("F: Focus on Filter Box");
                                ui.label("ESC: Clear Filter");
                                ui.label("G: Toggle Statistics View");
                                ui.separator();
                                
                                ui.label("Sorting:");
                                ui.label("C: Sort by CPU Usage");
                                ui.label("M: Sort by Memory Usage");
                                ui.label("P: Sort by PID");
                                ui.label("N: Sort by Process Name");
                                ui.separator();
                                
                                ui.label("Process Management:");
                                ui.label("K: Kill Selected Process");
                                ui.label("R: Refresh Process List");
                            });
                        });
                });
        }
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Linux Process Manager");
            });
            
            ui.horizontal(|ui| {
                if ui.button("Refresh (R)").clicked() {
                    self.refresh_processes();
                }
                
                ui.checkbox(&mut self.show_tree, "Show Tree View (T)");
                
                if ui.button(if self.show_statistics { "Hide Stats (G)" } else { "Show Stats (G)" }).clicked() {
                    self.show_statistics = !self.show_statistics;
                }
                
                ui.add_space(10.0);
                
                ui.label("Filter:");
                let filter_text_edit = ui.text_edit_singleline(&mut self.filter);
                ctx.memory_mut(|mem| {
                    if mem.focus().is_none() && filter_text_edit.clicked() {
                        mem.request_focus(filter_text_edit.id);
                    }
                });
                
                egui::ComboBox::from_label("Filter Type")
                    .selected_text(format!("{:?}", self.filter_type))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.filter_type, FilterType::None, "None");
                        ui.selectable_value(&mut self.filter_type, FilterType::Command, "Command");
                        ui.selectable_value(&mut self.filter_type, FilterType::User, "User");
                        ui.selectable_value(&mut self.filter_type, FilterType::Pid, "PID");
                        ui.selectable_value(&mut self.filter_type, FilterType::Cpu, "CPU");
                        ui.selectable_value(&mut self.filter_type, FilterType::Memory, "Memory");
                        ui.selectable_value(&mut self.filter_type, FilterType::State, "State");
                    });
            });
            
            ui.separator();
            
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                ui.set_min_height(500.0);
                
                egui::Frame::group(ui.style())
                    .stroke(egui::Stroke::new(1.0, Color32::from_gray(150)))
                    .show(ui, |ui| {
                        if self.show_tree {
                            self.render_tree_view(ui);
                        } else {
                            self.render_process_table(ui);
                        }
                    });
            });
            
            self.handle_kill_prompt(ctx);
            self.handle_nice_dialog(ctx);
            self.handle_result_popups(ctx);
            
            ctx.request_repaint_after(Duration::from_millis(500));
        });
    }
} 