use std::io;
use sysinfo::System;
use tui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::{app::AppState, hierarchy::ProcessNode, process::ProcessInfo};

pub fn draw_ui(
    sys: &System,
    processes: &[ProcessInfo],
    hierarchy: &[ProcessNode],
    app: &AppState,
) -> io::Result<()> {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    terminal.draw(|f| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(f.size());

        // Header
        let header = Paragraph::new(Spans::from(vec![
            Span::styled("htop-rs", Style::default().fg(Color::LightCyan)),
            Span::raw("  [C]CPU [M]Memory [P]PID [N]Name [T]Tree [Q]Quit"),
        ]))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(header, chunks[0]);

        // System info - using correct sysinfo 0.29 methods
        let cpu_usage = sys.global_cpu_usage();
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let system_info = Paragraph::new(format!(
            "CPU: {:.1}% | Memory: {}/{} MB ({}%)",
            cpu_usage,
            used_memory / 1024 / 1024,
            total_memory / 1024 / 1024,
            (used_memory as f32 / total_memory as f32 * 100.0).round()
        ))
        .block(Block::default().borders(Borders::ALL));
        f.render_widget(system_info, chunks[1]);

        // Process list
        let rows = processes.iter().map(|p| {
            let memory_mb = p.memory_usage / 1024;
            Row::new(vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.name.as_str()),
                Cell::from(format!("{:.1}%", p.cpu_usage)),
                Cell::from(format!("{} MB", memory_mb)),
            ])
        });

        let table = Table::new(rows)
            .header(
                Row::new(vec!["PID", "Name", "CPU %", "Memory"])
                    .style(Style::default().add_modifier(Modifier::BOLD))
                    .bottom_margin(1),
            )
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(Style::default().fg(Color::Yellow))
            .widths(&[
                Constraint::Length(8),
                Constraint::Percentage(40),
                Constraint::Length(8),
                Constraint::Length(12),
            ]);

        f.render_widget(table, chunks[2]);
    })?;

    Ok(())
}
