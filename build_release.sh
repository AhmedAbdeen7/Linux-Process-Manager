#!/bin/bash

echo "Building release versions of Linux Process Manager..."

# Build release version of TUI application
echo "Building TUI version..."
cargo build --release

# Build release version of GUI application
echo "Building GUI version..."
cargo build --release --features gui

echo "Done! Release binaries are available in target/release/"
echo "- Run the TUI version: ./target/release/linux_process_manager"
echo "- Run the GUI version: ./target/release/linux_process_manager --gui" 