#!/bin/bash

echo "Installing LSSA..."

# 1. Install dependencies
if [ -f /etc/debian_version ]; then
    sudo apt update && sudo apt install -y build-essential libssl-dev
elif [ -f /etc/arch-release ]; then
    sudo pacman -S --needed base-devel openssl
fi

# 2. Compile and Install
make
if [ $? -eq 0 ]; then
    sudo make install
    echo "✅ Installation successful!"
    echo "💡 Try running: lssa -h"
else
    echo "❌ Installation failed. Please check the errors above."
    exit 1
fi
