use sysinfo::{Pid, ProcessExt, System, SystemExt, UserExt, PidExt};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use libc;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub pid: Pid,
    pub ppid: Option<Pid>,
    pub user: String,
    pub priority: i32,
    pub nice: i32,
    pub virt: u64,
    pub res: u64,
    pub shr: u64,
    pub state: String,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub time: String,
    pub command: String,
    pub start_time: String,
    pub cmd: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub info: ProcessInfo,
    pub children: Vec<ProcessNode>,
    pub depth: usize,
}

pub fn get_processes(sys: &System) -> HashMap<Pid, ProcessInfo> {
    let total_mem = sys.total_memory();
    let mut map = HashMap::new();
    for (&pid, proc) in sys.processes() {
        let ppid = proc.parent();
        let user = proc.user_id().and_then(|uid| sys.get_user_by_id(uid)).map(|u| u.name().to_string()).unwrap_or_else(|| "?".to_string());
        let priority = 0;
        
        let nice = unsafe {
            libc::getpriority(libc::PRIO_PROCESS, pid.as_u32() as libc::id_t)
        } as i32;
        
        let virt = proc.virtual_memory();
        let res = proc.memory() * 1024;
        let shr = 0;
        let state = format!("{:?}", proc.status());
        let cpu_percent = proc.cpu_usage();
        let mem_percent = (proc.memory() as f32 / total_mem as f32) * 100.0;
        let time = {
            let t = proc.start_time() as i64;
            DateTime::from_timestamp(t, 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
                .with_timezone(&Local)
                .format("%H:%M:%S")
                .to_string()
        };
        let command = if proc.cmd().is_empty() {
            proc.name().to_string()
        } else {
            proc.cmd().join(" ")
        };
        let start_time = {
            let t = proc.start_time() as i64;
            DateTime::from_timestamp(t, 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
                .with_timezone(&Local)
                .format("%H:%M:%S")
                .to_string()
        };
        let cmd = proc.cmd().iter().map(|s| s.to_string()).collect();
        map.insert(pid, ProcessInfo {
            pid,
            ppid,
            user,
            priority,
            nice,
            virt,
            res,
            shr,
            state,
            cpu_percent,
            mem_percent,
            time,
            command,
            start_time,
            cmd,
        });
    }
    map
}

pub fn build_process_tree(processes: &HashMap<Pid, ProcessInfo>) -> Vec<ProcessNode> {
    let mut tree: Vec<ProcessNode> = Vec::new();
    let mut children_map: HashMap<Option<Pid>, Vec<Pid>> = HashMap::new();
    for (&pid, info) in processes {
        children_map.entry(info.ppid).or_default().push(pid);
    }
    fn build(pid: Pid, processes: &HashMap<Pid, ProcessInfo>, children_map: &HashMap<Option<Pid>, Vec<Pid>>, depth: usize) -> ProcessNode {
        let info = processes.get(&pid).unwrap().clone();
        let children = children_map.get(&Some(pid)).map_or(vec![], |kids| {
            kids.iter().map(|&child_pid| build(child_pid, processes, children_map, depth + 1)).collect()
        });
        ProcessNode { info, children, depth }
    }
    let roots: Vec<Pid> = processes.iter().filter(|(_, info)| {
        info.ppid.is_none() || !processes.contains_key(&info.ppid.unwrap())
    }).map(|(&pid, _)| pid).collect();
    for root in roots {
        tree.push(build(root, processes, &children_map, 0));
    }
    tree
}

// use std::ffi::OsStr;
// use sysinfo::{Pid, Process, System};

// #[derive(Debug, Clone, Copy, PartialEq)]
// pub enum SortField {
//     Pid,
//     Name,
//     Cpu,
//     Memory,
// }

// pub struct ProcessInfo {
//     pub pid: Pid,
//     pub name: String,
//     pub cpu_usage: f32,
//     pub memory_usage: u64,
//     pub parent_pid: Option<Pid>,
// }

// pub fn get_processes(sys: &System, app: &crate::app::AppState) -> Vec<ProcessInfo> {
//     let mut processes: Vec<ProcessInfo> = sys
//         .processes()
//         .iter()
//         .map(|(&pid, proc)| ProcessInfo {
//             pid,
//             name: proc.name().to_string_lossy().into_owned(),
//             cpu_usage: proc.cpu_usage(),
//             memory_usage: proc.memory(),
//             parent_pid: proc.parent(),
//         })
//         .collect();

//     match app.sort_field {
//         SortField::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
//         SortField::Name => processes.sort_by(|a, b| a.name.cmp(&b.name)),
//         SortField::Cpu => processes.sort_by(|a, b| a.cpu_usage.partial_cmp(&b.cpu_usage).unwrap()),
//         SortField::Memory => processes.sort_by(|a, b| a.memory_usage.cmp(&b.memory_usage)),
//     }

//     if app.sort_descending {
//         processes.reverse();
//     }

//     processes
// }
