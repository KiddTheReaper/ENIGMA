# ENIGMA

![ENIGMA Logo](./assets/logo.png)

## Overview

ENIGMA is a PyQt5-based GUI tool that unifies multiple reconnaissance utilities for active and passive information gathering. It features a simple and intuitive interface with both Light and Dark themes. ENIGMA provides an output viewer to conveniently see scan results all in one place.

## Features

- **Multi-tool integration:** Subfinder, Assetfinder, Subjack, Subzy, Httpx, Katana, Waybackurls, Okadminfinder, SSLScan, Whois, and more.
- **Tabbed Interface:**  
  - **Enumeration**  
  - **Information**  
  - **Crawling**  
  - **Path Finder**  
  - **SSL/TLS**  
  - **Output Viewer**  
  - **Settings** (Theme selection, system info, and other configurations)
- **Light and Dark Themes** for comfortable use.
- **Real-time output viewing** and management.
- Compatible with major Linux distributions.

## Installation

ENIGMA has been tested and works well on:

- **Kali Linux**
- **Arch Linux**

### Dependencies

- Python 3.8+
- PyQt5 (for Arch Linux, PyQt5 version 5.15.11 via pip is recommended)
- Go programming language (for Go-based tools)
- System tools: git, curl, whois, sslscan, etc.

### Installation Script

We provide an installer script that handles installation of dependencies, Go tools, and Python packages, adjusting automatically for Kali (Debian/Ubuntu) and Arch Linux.

```bash
chmod +x install.py
python3 install.py
