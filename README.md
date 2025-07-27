# ENIGMA - Pre-Automatic Reconnaissance Tools

![ENIGMA Logo](./assets/logo.png)

## Overview

**ENIGMA** is a PyQt5-based GUI tool that unifies multiple reconnaissance utilities for active and passive information gathering. It features a simple and intuitive interface with both Light and Dark themes. **ENIGMA** provides a real-time output viewer to conveniently monitor scan results all in one place.

## Features

- **Multi-tool integration:**  
  Subfinder, Assetfinder, Subjack, Subzy, Httpx, Katana, Waybackurls, Okadminfinder, SSLScan, Whois, and more.
- **Tabbed Interface:**  
  - **Enumeration**  
  - **Information**  
  - **Crawling**  
  - **Path Finder**  
  - **SSL/TLS**  
  - **Output Viewer**  
  - **Settings** (Theme selection and Information)
- **Light and Dark Themes for comfortable use.**
- **Real-time output viewing and management.**
- **Customizable Theme**
- **Compatible with major Linux distributions.**

## Theme Customization

**ENIGMA** allows full customization of its appearance by modifying CSS theme files located in the `theme/` directory.

You can tweak:

- **Background colors**
- **Font**
- **Widget padding and spacing**
- **Button and hover styles**
- **And others**

For example:

```dark.css
QWidget {
    background-color: #121212;
    color: #dddddd;
    font-family: "Xolonium";
}
```
Your changes will take effect instantly after switching themes from the Settings tab in the GUI.

## Tested on

- **Kali Linux**
- **Arch Linux**

## Dependencies

- **Python 3.8+**
- **PyQt5**
- **Golang/Go**
- **System tools: git, curl, whois, sslscan, etc.**

## Installation

Select your OS and installs the required dependencies, Go tools, and Python packages.
```
chmod +x install.py
python3 install.py
```
## Documentation

- **Arch (Dark Theme)**
  
![Arch](https://i.imgur.com/Wj62OUu.png)
- **Kali (Light Theme)**
  
![Kali](https://i.imgur.com/J1XxHqG.png)
