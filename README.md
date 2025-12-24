# LSSA - Live Source Sync Assistant

Intelligent backup system with real-time file monitoring and git integration.

## Features

- Real-time file monitoring with inotify
- Smart deduplication (skip unchanged files)
- Git integration with automatic cleanup
- Merge conflict detection
- File activity heatmap
- Debouncing to prevent backup spam

## Quick Start

```bash
# Build
make

# Install system-wide
sudo make install

# Run
lssa

# View statistics
lssa stats
```

## Installation

### From Source (All Systems)
```bash
git clone https://github.com/yourusername/lssa
cd lssa
make
sudo make install
```

### Arch Linux
```bash
yay -S lssa
```

### Debian/Ubuntu
```bash
sudo dpkg -i lssa_1.0.0_amd64.deb
```

## Usage

```bash
# Start monitoring current directory
lssa

# Monitor specific directory
lssa /path/to/project

# View file activity heatmap
lssa stats
```

## Uninstall

```bash
sudo make uninstall
```

## License

MIT License
