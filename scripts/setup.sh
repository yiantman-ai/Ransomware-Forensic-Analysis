#!/bin/bash
#
# Setup Script for Ransomware Forensic Analysis
# Installs all dependencies and prepares environment
#

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Ransomware Forensic Analysis - Setup Script             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "[+] Detected Linux OS"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[+] Detected macOS"
else
    echo "[!] Unsupported OS: $OSTYPE"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "[+] Python version: $PYTHON_VERSION"

# Create virtual environment (optional)
read -p "Create virtual environment? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "[+] Virtual environment activated"
fi

# Install dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# Install Volatility 3
echo ""
echo "[*] Installing Volatility 3..."
if [ ! -d "$HOME/volatility3" ]; then
    git clone https://github.com/volatilityfoundation/volatility3.git "$HOME/volatility3"
    cd "$HOME/volatility3"
    pip3 install -r requirements.txt
    cd -
    echo "[+] Volatility 3 installed"
else
    echo "[+] Volatility 3 already installed"
fi

# Create symlink
if [ ! -L "/usr/local/bin/vol3" ]; then
    sudo ln -sf "$HOME/volatility3/vol.py" /usr/local/bin/vol3
    echo "[+] Volatility 3 symlink created"
fi

# Install system dependencies (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo ""
    echo "[*] Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y wireshark tshark tcpdump yara
    elif command -v yum &> /dev/null; then
        sudo yum install -y wireshark tshark tcpdump yara
    fi
fi

# Verify installations
echo ""
echo "[*] Verifying installations..."

command -v python3 && echo "  ✅ Python 3"
command -v vol3 && echo "  ✅ Volatility 3"
command -v wireshark && echo "  ✅ Wireshark"
command -v tshark && echo "  ✅ tshark"
command -v yara && echo "  ✅ YARA"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  ✅ Setup Complete!                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Review README.md for project overview"
echo "  2. Check QUICKSTART.md for quick introduction"
echo "  3. Explore tools/ directory for utilities"
echo ""
echo "Happy investigating! 🔍"
