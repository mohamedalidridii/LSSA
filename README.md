# LSSA - Local Source Storage Assistant

Intelligent backup system with real-time file monitoring and git integration.

## Features

- Real-time file monitoring with inotify
- Smart deduplication (skip unchanged files)
- Git integration with automatic cleanup
- Merge conflict detection
- File activity heatmap
- Debouncing to prevent backup spam


# Install system-wide
Debian and Arch Linux.

# Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/lssa
cd LSSA
```

# Step 2: Run the Automated Installer

```bash
chmod +x setup-lssa.sh
./setup-lssa.sh
```

## Usage & Commands
You can run lssa from the root of any project directory.
Command	        Action
lssa	        Monitor Mode: Starts the background process to watch and backup files.
lssa stats, -s	Analytics: Displays the File Activity Heatmap and modification stats.
lssa -c	        Conflict Scan: Deep-scans all Git branches for divergent files.
lssa -h	Help:   Displays usage information and flags.


## License
MIT License

Developed by mohamedalidridii AKA medaly.dridi
