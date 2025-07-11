#!/usr/bin/env bash

echo -e "\n\033[1;32m[+] Automatic setup for GHost Hunter\033[0m"

echo "[*] Checking for package updates..."
sudo apt update

echo "[*] Installing python3 and python3-venv if not already present..."
sudo apt install -y python3 python3-venv

echo "[*] Creating virtual environment in the ghostenv directory..."
python3 -m venv ghostenv

echo "[*] Activating virtual environment and installing Python libraries..."
ghostenv/bin/pip install --upgrade pip
ghostenv/bin/pip install colorama pyfiglet scapy

echo -e "\n\033[1;32m[+] Setup completed!\033[0m"
echo -e "To start GHost Hunter, use:\033[1;33m"
echo "source ghostenv/bin/activate"
echo "sudo python3 main.py"
echo -e "\033[0m"
echo "To exit the virtual environment, use: deactivate"
