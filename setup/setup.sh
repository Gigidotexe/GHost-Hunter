#!/bin/bash

# Function to check if a command is available on the system
function check_command {
    command -v "$1" &> /dev/null
}

# Update and install system dependencies (if needed)
echo "[+] Starting dependency installation..."

# Check if Python3 is installed
if ! check_command "python3"; then
    echo "[!] Python3 not found. Please make sure Python3 is installed before proceeding."
    exit 1
fi

# Check if pip is installed
if ! check_command "pip3"; then
    echo "[!] pip3 not found. Installing pip..."
    sudo apt-get install python3-pip -y
fi

# Install required Python libraries
echo "[+] Installing required Python libraries..."
pip3 install -r requirements.txt --break-system-packages

# Check if nmap is installed
if ! check_command "nmap"; then
    echo "[!] nmap not found. Installing nmap..."
    sudo apt-get install nmap -y
else
    echo "[+] nmap is already installed."
fi

# Provide instructions or install pyfiglet if not present
if ! python3 -c "import pyfiglet" &> /dev/null; then
    echo "[!] pyfiglet not found. Installing pyfiglet..."
    pip3 install pyfiglet
else
    echo "[+] pyfiglet is already installed."
fi

# Check if colorama is installed
if ! python3 -c "import colorama" &> /dev/null; then
    echo "[!] colorama not found. Installing colorama..."
    pip3 install colorama
else
    echo "[+] colorama is already installed."
fi

echo "[+] Setup completed successfully! You can now run the program."
