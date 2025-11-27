#!/bin/bash 

echo "[+] Installing deps"
sudo apt-get install -y wireshark tshark libglib2.0-dev zenity

echo "[+] Installing the requirements for Python"
pip3 install -r requirements

git clone https://github.com/mitshell/CryptoMobile.git
cd CryptoMobile
pip3 install .
