# Linux Process Manager

A feature-rich process manager for Linux systems with both terminal and graphical user interfaces.

## Features

- View detailed system information (CPU, memory, swap usage)
- Monitor all running processes with information like CPU usage, memory usage, PID, etc.
- Process tree view to visualize parent-child relationships
- Sort processes by various fields (PID, name, CPU usage, memory usage, etc.)
- Filter processes by command, user, state, or resource usage
- Change process priority (nice values)
- Kill processes

## Screenshots



## Usage

### Terminal UI

Run the application without any arguments to launch the terminal interface:

```
cargo run
```

Terminal UI controls:
- Arrow keys: Navigate the process list
- 't': Toggle tree view
- 'k': Kill selected process
- '1-8': Sort by different columns (PID, CPU, etc.)
- 'c', 'u', 's', 'p', 'C', 'm': Filter by command, user, state, PID, CPU usage, memory usage
- 'q': Quit

### Graphical UI

Run the application with the `--gui` flag to launch the graphical interface:

```
cargo run -- --gui
```

The GUI provides the same functionality with an intuitive point-and-click interface.

## Building from Source

Make sure you have Rust and Cargo installed, then:

```bash
cd linux_process_manager
cargo build --release
```

The compiled binary will be available in `target/release/linux_process_manager`.

## Dependencies

- sysinfo: For system and process information
- crossterm + tui: For the terminal interface
- egui + eframe: For the graphical interface
- nix: For Linux-specific functionality

## License

[MIT License](LICENSE)
