# 🐺 CEREBRUS
### Python Network Scanner & Reconnaissance Tool

<div align="center">

*Lightweight, fast, and dependency-free network scanning inspired by nmap*

[![Python](https://img.shields.io/badge/Python-3.6%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Networking](https://img.shields.io/badge/Networking-TCP%20Scanner-0A66C2?style=for-the-badge)](#)
[![Threads](https://img.shields.io/badge/Multi--Threaded-Fast%20Scan-success?style=for-the-badge)](#)
[![License](https://img.shields.io/badge/License-MIT-black?style=for-the-badge)](#)

</div>

---

## 🎯 Overview

**Cerebrus** is a **Python-based network analysis tool** designed for fast reconnaissance and enumeration.  
It performs **TCP connect scans**, **host discovery**, and **basic service/version detection** using only Python’s standard library.

> 💡 **Why Cerebrus?**  
Cerebrus is lightweight, portable, and easy to understand — ideal for **cybersecurity students**, **CTF practice**, and **authorized penetration testing labs**.

---

## ✨ Key Features

- 🔍 **TCP Connect Port Scanning**
- 🌐 **Host Discovery (No ICMP required)**
- 🧠 **Service Identification (Common Ports)**
- 🧾 **Basic Service Version Detection (`-sV`)**
- ⚡ **Multi-threaded Scanning Engine**
- 📄 **Save Scan Results to File**
- 🧩 **Flexible Target Support**
  - Single IP
  - Hostname
  - CIDR ranges (`192.168.1.0/24`)
  - IP ranges (`192.168.1.10-50`)

---

## 📦 Requirements

- **Python 3.6+**
- ❌ No external dependencies
- Works on **Windows / Linux / macOS**

---

## 📥 Installation

Clone the repository and move into the project directory:

```bash
git clone https://github.com/Bhavith-fs/Cerebrus-Networkscanner.git
cd Cerebrus-Networkscanner
```

---

## 🚀 Usage

```bash
python cerebrus.py <target> [options]
```

### 🔎 Examples

```bash
# Basic scan
python cerebrus.py 192.168.1.1

# Scan specific ports
python cerebrus.py 192.168.1.1 -p 22,80,443

# Scan port range
python cerebrus.py 192.168.1.1 -p 1-1000

# Host discovery on a subnet
python cerebrus.py 192.168.1.0/24 -d

# Service version detection
python cerebrus.py 192.168.1.1 -sV

# Save output to file
python cerebrus.py 192.168.1.1 -o results.txt
```

---

## 🧰 Command-Line Options

```
target              Target IP, hostname, or CIDR range
-p, --ports         Ports to scan (22,80 or 1-1000)
-d, --discover      Host discovery only
-sV, --version      Detect service versions
--top-ports N       Scan top N common ports
--all-ports         Scan all 65535 ports
-t, --threads       Number of threads (default: 100)
--timeout           Socket timeout in seconds (default: 1.0)
-o, --output        Save results to file
--no-banner         Disable banner display
-v, --verbose       Verbose output
```

---

## 🧠 How It Works

- **Host Discovery**  
  Detects live hosts by attempting TCP connections to common service ports.

- **Port Scanning**  
  Uses multi-threaded TCP connect scans for reliable results.

- **Service Detection**  
  Maps open ports to known services and grabs banners when possible.

- **Version Detection**  
  Performs lightweight protocol-specific checks (HTTP, SSH, FTP).

---

## 🏗️ Project Structure

```
Cerebrus/
├── cerebrus.py        # Main scanner logic
├── README.md          # Documentation
└── results.txt        # Optional scan output
```

---

## ⚠️ Disclaimer

> This tool is intended **for educational purposes and authorized security testing only**.  
> Scanning networks without permission may be illegal.

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 👤 Author

**Bhavith Madhav**  
Cybersecurity & Network Security Enthusiast  

---

🐺 *Cerebrus — See the network before it sees you.*

