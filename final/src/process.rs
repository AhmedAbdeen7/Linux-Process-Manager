use std::ffi::OsStr;
use sysinfo::{Pid, Process, System};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortField {
    Pid,
    Name,
    Cpu,
    Memory,
}

pub struct ProcessInfo {
    pub pid: Pid,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub parent_pid: Option<Pid>,
}

pub fn get_processes(sys: &System, app: &crate::app::AppState) -> Vec<ProcessInfo> {
    let mut processes: Vec<ProcessInfo> = sys
        .processes()
        .iter()
        .map(|(&pid, proc)| ProcessInfo {
            pid,
            name: proc.name().to_string_lossy().into_owned(),
            cpu_usage: proc.cpu_usage(),
            memory_usage: proc.memory(),
            parent_pid: proc.parent(),
        })
        .collect();

    match app.sort_field {
        SortField::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
        SortField::Name => processes.sort_by(|a, b| a.name.cmp(&b.name)),
        SortField::Cpu => processes.sort_by(|a, b| a.cpu_usage.partial_cmp(&b.cpu_usage).unwrap()),
        SortField::Memory => processes.sort_by(|a, b| a.memory_usage.cmp(&b.memory_usage)),
    }

    if app.sort_descending {
        processes.reverse();
    }

    processes
}
