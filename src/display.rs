use crate::process::{ProcessNode};
use crate::{FilterType, SortField};
use std::io;
use sysinfo::{System, SystemExt, CpuExt, PidExt};
use tui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Gauge},
};

fn summary_bar(sys: &System) -> Vec<Paragraph<'static>> {
    let mut bars = Vec::new();
    for (i, cpu) in sys.cpus().iter().enumerate() {
        let gauge = Gauge::default()
            .block(Block::default().title(format!("CPU{}", i)).borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Green).bg(Color::Black).add_modifier(Modifier::BOLD))
            .percent(cpu.cpu_usage() as u16);
        bars.push(Paragraph::new(Spans::from(vec![Span::styled(
            format!("CPU{}: {:>5.1}%", i, cpu.cpu_usage()),
            Style::default().fg(Color::Green),
        )]))
        .block(Block::default().borders(Borders::NONE)));
        bars.push(Paragraph::new(Spans::from(vec![Span::raw("")]))); 
    }
    let mem_used = sys.used_memory() as f64 / 1024.0 / 1024.0;
    let mem_total = sys.total_memory() as f64 / 1024.0 / 1024.0;
    let mem_pct = (mem_used / mem_total * 100.0).round();
    let _mem_gauge = Gauge::default()
        .block(Block::default().title("Memory").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Blue).bg(Color::Black).add_modifier(Modifier::BOLD))
        .percent(mem_pct as u16);
    bars.push(Paragraph::new(Spans::from(vec![Span::styled(
        format!("Mem: {:.1}/{:.1} MiB ({:.0}%)", mem_used, mem_total, mem_pct),
        Style::default().fg(Color::Blue),
    )]))
    .block(Block::default().borders(Borders::NONE)));
    bars.push(Paragraph::new(Spans::from(vec![Span::raw("")])));
    let swap_used = sys.used_swap() as f64 / 1024.0 / 1024.0;
    let swap_total = sys.total_swap() as f64 / 1024.0 / 1024.0;
    let swap_pct = if swap_total > 0.0 { (swap_used / swap_total * 100.0).round() } else { 0.0 };
    let _swap_gauge = Gauge::default()
        .block(Block::default().title("Swap").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Magenta).bg(Color::Black).add_modifier(Modifier::BOLD))
        .percent(swap_pct as u16);
    bars.push(Paragraph::new(Spans::from(vec![Span::styled(
        format!("Swap: {:.1}/{:.1} MiB ({:.0}%)", swap_used, swap_total, swap_pct),
        Style::default().fg(Color::Magenta),
    )]))
    .block(Block::default().borders(Borders::NONE)));
    bars
}

pub fn flatten_tree<'a>(nodes: &'a [ProcessNode], out: &mut Vec<&'a ProcessNode>) {
    for node in nodes {
        out.push(node);
        flatten_tree(&node.children, out);
    }
}

pub fn draw_ui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    sys: &System,
    tree: &[ProcessNode],
    selected: &mut usize,
    scroll_offset: usize,
    show_kill_prompt: bool,
    filter: &str,
    filter_type: FilterType,
    show_tree: bool,
    sort_field: SortField,
    sort_descending: bool,
    kill_target_pid: Option<sysinfo::Pid>,
    kill_target_name: Option<String>,
    tree_scroll_offset: usize,
) -> io::Result<()> {
    terminal.draw(|f| {
        let size = f.size();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ])
            .margin(0)
            .split(size);

        let summary_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ])
            .split(chunks[0]);

        let cpu_text = format!(
            "CPU: {:.1}%",
            sys.global_cpu_info().cpu_usage()
        );
        let cpu_paragraph = Paragraph::new(cpu_text)
            .block(Block::default().title("CPU").borders(Borders::ALL))
            .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)));
        f.render_widget(cpu_paragraph, summary_chunks[0]);

        let mem_text = format!(
            "Memory: {:.1}%",
            sys.used_memory() as f32 / sys.total_memory() as f32 * 100.0
        );
        let mem_paragraph = Paragraph::new(mem_text)
            .block(Block::default().title("Memory").borders(Borders::ALL))
            .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)));
        f.render_widget(mem_paragraph, summary_chunks[1]);

        if show_tree {
            let mut lines = Vec::new();
            fn render_node(node: &ProcessNode, prefix: &str, is_last: bool, lines: &mut Vec<String>) {
                let connector = if prefix.is_empty() {
                    ""
                } else if is_last {
                    "└── "
                } else {
                    "├── "
                };
                lines.push(format!("{}{}{}", prefix, connector, node.info.command));
                
                let child_count = node.children.len();
                for (i, child) in node.children.iter().enumerate() {
                    let new_prefix = if prefix.is_empty() {
                        if is_last {
                            String::from("    ")
                        } else {
                            String::from("│   ")
                        }
                    } else {
                        if is_last {
                            format!("{}    ", prefix)
                        } else {
                            format!("{}│   ", prefix)
                        }
                    };
                    render_node(child, &new_prefix, i == child_count - 1, lines);
                }
            }
            
            for (i, node) in tree.iter().enumerate() {
                render_node(node, "", i == tree.len() - 1, &mut lines);
            }
            
            let max_visible = chunks[1].height as usize;
            let start = tree_scroll_offset.min(lines.len().saturating_sub(max_visible));
            let end = (start + max_visible).min(lines.len());
            let visible_lines = &lines[start..end];
            let tree_text = visible_lines.join("\n");
            let tree_paragraph = Paragraph::new(tree_text)
                .block(Block::default().title("Process Tree").borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)));
            f.render_widget(tree_paragraph, chunks[1]);
        } else {
            let mut flat = Vec::new();
            flatten_tree(tree, &mut flat);

            let mut filtered_rows: Vec<&ProcessNode> = if !filter.is_empty() {
                flat.iter()
                    .filter(|node| {
                        match filter_type {
                            FilterType::None => true,
                            FilterType::Command => {
                                node.info.command.to_lowercase().contains(&filter.to_lowercase()) ||
                                node.info.cmd.join(" ").to_lowercase().contains(&filter.to_lowercase())
                            },
                            FilterType::User => {
                                node.info.user.to_lowercase().contains(&filter.to_lowercase())
                            },
                            FilterType::State => {
                                node.info.state.to_lowercase().contains(&filter.to_lowercase())
                            },
                            FilterType::Pid => {
                                node.info.pid.to_string().contains(filter)
                            },
                            FilterType::Cpu => {
                                if let Ok(threshold) = filter.parse::<f32>() {
                                    node.info.cpu_percent >= threshold
                                } else {
                                    false
                                }
                            },
                            FilterType::Memory => {
                                if let Ok(threshold) = filter.parse::<f32>() {
                                    node.info.mem_percent >= threshold
                                } else {
                                    false
                                }
                            },
                        }
                    })
                    .cloned()
                    .collect()
            } else {
                flat
            };

            filtered_rows.sort_by(|a, b| {
                let cmp = match sort_field {
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
                if sort_descending {
                    cmp.reverse()
                } else {
                    cmp
                }
            });

            let rows: Vec<Row> = filtered_rows
                .iter()
                .skip(scroll_offset)
                .take(chunks[1].height as usize)
                .enumerate()
                .map(|(i, node)| {
                    let base_style = if i + scroll_offset == *selected {
                        Style::default().bg(Color::Rgb(68, 71, 90))
                    } else {
                        Style::default().bg(Color::Rgb(18, 18, 29))
                    };
                    Row::new(vec![
                        Cell::from(node.info.command.clone()).style(base_style),
                        Cell::from(node.info.pid.to_string()).style(base_style),
                        Cell::from(node.info.ppid.map_or("?".to_string(), |p| p.to_string())).style(base_style),
                        Cell::from(node.info.user.clone()).style(base_style),
                        Cell::from(node.info.state.clone()).style(base_style),
                        Cell::from(format!("{:.1}%", node.info.cpu_percent)).style(base_style),
                        Cell::from(format!("{:.1}%", node.info.mem_percent)).style(base_style),
                        Cell::from(format!("{:>3}", node.info.nice)).style(base_style),
                        Cell::from(node.info.start_time.clone()).style(base_style),
                        Cell::from(node.info.cmd.join(" ")).style(base_style),
                    ])
                })
                .collect();

            let table = Table::new(rows)
                .header(Row::new(vec![
                    Cell::from(format!("Command{}", if sort_field == SortField::Command { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("PID{}", if sort_field == SortField::Pid { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from("PPID").style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("USER{}", if sort_field == SortField::User { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("STATE{}", if sort_field == SortField::State { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("CPU%{}", if sort_field == SortField::Cpu { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("MEM%{}", if sort_field == SortField::Memory { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("NI{}", if sort_field == SortField::Nice { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from(format!("STARTED{}", if sort_field == SortField::StartTime { if sort_descending { " ↓" } else { " ↑" } } else { "" })).style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                    Cell::from("CMD").style(Style::default().fg(Color::Rgb(255, 121, 198)).bg(Color::Rgb(18, 18, 29))),
                ]))
                .block(Block::default()
                    .title(format!("Processes{}", 
                        if filter_type != FilterType::None { 
                            format!(" ({}: {})", filter_type.get_prompt().trim_end_matches(": "), filter) 
                        } else { 
                            String::new() 
                        }
                    ))
                    .borders(Borders::ALL)
                    .border_type(tui::widgets::BorderType::Plain))
                .widths(&[
                    Constraint::Percentage(15),
                    Constraint::Length(6),
                    Constraint::Length(6),
                    Constraint::Length(8),
                    Constraint::Length(6),
                    Constraint::Length(6),
                    Constraint::Length(6),
                    Constraint::Length(3),
                    Constraint::Length(8),
                    Constraint::Percentage(35),
                ])
                .column_spacing(1)
                .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .highlight_symbol(">> ");

            f.render_widget(table, chunks[1]);
        }

        if show_kill_prompt {
            let kill_text = if let (Some(pid), Some(name)) = (kill_target_pid, &kill_target_name) {
                format!("Kill process {} (PID {})? (y/n)", name, pid)
            } else {
                "Kill process? (y/n)".to_string()
            };
            let kill_prompt = Paragraph::new(kill_text)
                .block(Block::default().title("Kill Process").borders(Borders::ALL))
                .style(Style::default().fg(Color::Rgb(255, 85, 85)).bg(Color::Rgb(18, 18, 29)));
            f.render_widget(kill_prompt, chunks[2]);
        } else if filter_type != FilterType::None {
            let filter_text = format!("{}{}", filter_type.get_prompt(), filter);
            let filter_prompt = Paragraph::new(filter_text)
                .block(Block::default().borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)));
            f.render_widget(filter_prompt, chunks[2]);
        } else {
            let help_text = "Press 'q' to quit, 'k' to kill | Filters: 'c' command, 'u' user, 's' state, 'p' PID, 'C' CPU%, 'm' memory% | Sort: 1-8 (toggle direction)";
            let help_width = help_text.len() as u16;
            let footer_width = chunks[2].width;
            
            let scroll_pos = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() % 2) as u16;
            
            let scroll_offset = if help_width > footer_width {
                (scroll_pos * (help_width - footer_width) / 2) % (help_width - footer_width)
            } else {
                0
            };

            let footer = Paragraph::new(help_text)
                .block(Block::default().borders(Borders::ALL))
                .style(Style::default().fg(Color::White).bg(Color::Rgb(18, 18, 29)))
                .scroll((0, scroll_offset));
            f.render_widget(footer, chunks[2]);
        }
    })?;
    Ok(())
}
