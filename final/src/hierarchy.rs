use std::collections::HashMap;
use sysinfo::Pid;

pub struct ProcessNode {
    pub pid: Pid,
    pub children: Vec<ProcessNode>,
}

pub fn build_hierarchy(processes: &[crate::process::ProcessInfo]) -> Vec<ProcessNode> {
    let mut parent_child_map: HashMap<Option<Pid>, Vec<Pid>> = HashMap::new();

    for process in processes {
        parent_child_map
            .entry(process.parent_pid)
            .or_default()
            .push(process.pid);
    }

    fn build_subtree(
        pid: Pid,
        parent_child_map: &HashMap<Option<Pid>, Vec<Pid>>,
        processes: &[crate::process::ProcessInfo],
    ) -> Option<ProcessNode> {
        let children = parent_child_map
            .get(&Some(pid))
            .map(|child_pids| {
                child_pids
                    .iter()
                    .filter_map(|&child_pid| build_subtree(child_pid, parent_child_map, processes))
                    .collect()
            })
            .unwrap_or_default();

        Some(ProcessNode { pid, children })
    }

    parent_child_map
        .get(&None)
        .map(|root_pids| {
            root_pids
                .iter()
                .filter_map(|&pid| build_subtree(pid, &parent_child_map, processes))
                .collect()
        })
        .unwrap_or_default()
}
