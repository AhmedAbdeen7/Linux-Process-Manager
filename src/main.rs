mod app;
mod display;
mod hierarchy;
mod process;

use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use std::io::{self, stdout};
use std::time::Duration;
use sysinfo::{CpuRefreshKind, ProcessRefreshKind, ProcessesToUpdate, System};

fn main() -> io::Result<()> {
    // Initialize terminal
    let mut stdout = stdout();
    enable_raw_mode()?;
    crossterm::execute!(stdout, EnterAlternateScreen)?;

    // System monitoring setup
    let mut sys = System::new();
    sys.refresh_memory();
    sys.refresh_cpu_all();
    let mut app = app::AppState::new();

    // Main loop
    loop {
        // Handle input
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') => app.set_sort_field(process::SortField::Cpu),
                    KeyCode::Char('m') => app.set_sort_field(process::SortField::Memory),
                    KeyCode::Char('p') => app.set_sort_field(process::SortField::Pid),
                    KeyCode::Char('n') => app.set_sort_field(process::SortField::Name),
                    KeyCode::Char('t') => app.toggle_tree_view(),
                    _ => {}
                }
            }
        }

        // System refreshes
        sys.refresh_memory();
        sys.refresh_cpu_all();
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true, // Remove dead processes
            ProcessRefreshKind::everything(),
        );

        // Process data handling
        let processes = process::get_processes(&sys, &app);
        let hierarchy = hierarchy::build_hierarchy(&processes);

        // Render UI
        display::draw_ui(&sys, &processes, &hierarchy, &app)?;
    }

    // Cleanup terminal
    crossterm::execute!(stdout, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}
