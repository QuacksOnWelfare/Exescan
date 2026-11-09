# 🛡️ ExeScan v2.2 — by SilentGhostExe1

[Python](https://img.shields.io/badge/Python-3.11+-blue)
[Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20Windows-green)
[Version](https://img.shields.io/badge/Version-2.2%20Stable-red)
[License](https://img.shields.io/badge/License-MIT-yellow)

> **Advanced .EXE Static Analyzer for Security Research & Education.**
> Scan. Detect. Understand. Never execute blindly.

---

## ⚡ What is ExeScan?

ExeScan is a lightweight Python-based static analyzer built for **security learners, researchers and developers**.

It inspects Windows executable files (`.exe`) **without running them** and extracts critical intelligence to help you decide if a file is safe, suspicious, or malicious.

Built in Termux. Tested on Android. Made to be fast, clean and deadly accurate.

## 🔥 Key Features

- **📁 PE Header Analysis** - Architecture, Machine Type, Entry Point, Sections
- **🔍 String Extraction** - URLs, IPs, File Paths, Registry Keys, Suspicious APIs
- **⚠️ Threat Heuristics** - Detection of packed / obfuscated / suspicious patterns
- **📊 Clean Report** - Colored terminal output, readable in seconds
- **🚀 Zero Dependencies** - Pure Python, works on Termux, Linux & Windows
- **🔒 100% Static** - The file is NEVER executed. Safe by design.

## 📦 Installation

bash
git clone https://github.com/SilentGhostExe1/exescan.git
cd exescan
python3 exescan_v2.2.py


No install. No setup. Just clone and run.

## 🎯 Usage

bash
Scan a file
python3 exescan_v2.2.py /path/to/file.exe

Example
python3 exescan_v2.2.py sample.exe


ExeScan will output:
1. File info & Hashes
2. PE Structure
3. Suspicious Strings
4. Final Verdict: `CLEAN / SUSPICIOUS / HIGH RISK`

## 🧠 Why ExeScan?

> Most people double-click an .exe without knowing what's inside.
> Hackers don't. Hackers scan first.

ExeScan was built with one mindset: **Know your target before you trust it.**

## 📂 Project Structure


exescan/
├── exescan_v2.2.py   # Main Engine - v2.2 Stable
├── README.md         # Documentation
└── LICENSE           # MIT License


## 🛠️ Tech Stack

- **Language:** Python 3
- **Platform:** Termux / Linux / Windows
- **Author:** SilentGhostExe1

## ⚖️ Disclaimer / Legal Use

ExeScan is for **educational purposes, defensive security research and authorized analysis only.**

Do NOT use this tool to analyze files you do not have permission to analyze, or to facilitate malicious activity. The author is not responsible for misuse.

**Use it to learn. Use it to protect. Use it to level up.**

## 🤝 Contribute

Found a bug? Have an idea for v2.3?
Open an Issue or a Pull Request. All contributions are welcome.

## ⭐ Support

If you like ExeScan, leave a **⭐ STAR** on this repo.
It helps a young developer from Dominican Republic keep building.

---
**Built by SilentGhostExe1 | ExeScan v2.2**
**Stay Ghost. Stay Smart. Stay Legal.**
