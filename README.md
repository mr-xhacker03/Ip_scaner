# 💀 IP Scanner — MR.XHACKER

A powerful **network scanning tool** written in **Python** with a cool **Termux hacking-style UI** 💻⚡  
Detect active hosts, open ports, and network activity easily — fast, reliable, and fully customizable.

## Features
- 🎯 IP Address Scanner (ping sweep)  
- 🌐 Port Scanner (TCP connect)  
- 📶 Multi-threaded & Fast response  
- 💀 Colored skull banner + MR.XHACKER UI  
- 💾 Save scan results to file

## Requirements
- lolcat
- Python 3  
- No external modules required (uses stdlib). For best results on Termux, ensure `ping` binary is available (`pkg install iputils`).

## Usage
```bash
pkg update && pkg upgrade -y
pkg install git -y
pkg install python3 -y
pkg install ruby -y
gem install lolcat
python3 ip_scaner.py
