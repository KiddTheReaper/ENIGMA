#!/usr/bin/env python3

import os
import subprocess
import sys
from shutil import which
from colorama import init, Fore, Style
init(autoreset=True)


ASCII = r"""
:::::::::: ::::    ::: ::::::::::: ::::::::  ::::    ::::      :::    
:+:        :+:+:   :+:     :+:    :+:    :+: +:+:+: :+:+:+   :+: :+:  
+:+        :+:+:+  +:+     +:+    +:+        +:+ +:+:+ +:+  +:+   +:+ 
+#++:++#   +#+ +:+ +#+     +#+    :#:        +#+  +:+  +#+ +#++:++#++:
+#+        +#+  +#+#+#     +#+    +#+   +#+# +#+       +#+ +#+     +#+
#+#        #+#   #+#+#     #+#    #+#    #+# #+#       #+# #+#     #+#
########## ###    #### ########### ########  ###       ### ###     ###

========[Mapping the Unmapped – Every Path, Every Certificate]========
"""

print(Fore.GREEN + ASCII + Style.RESET_ALL)

SUPPORTED_OS = ["arch", "debian", "ubuntu"]

def ask_distro():
    print("[?] Choose your Linux distro:")
    for i, distro in enumerate(SUPPORTED_OS, 1):
        print(f"  {i}. {distro.title()}")
    choice = input("Enter number (1/2/3): ").strip()
    if choice in {"1", "2", "3"}:
        return SUPPORTED_OS[int(choice) - 1]
    else:
        print("[!] Invalid choice. Exiting.")
        sys.exit(1)

def run(cmd):
    print(f"\n[+] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def install_package(package, os_type):
    if os_type == "arch":
        run(f"sudo pacman -Sy --noconfirm {package}")
    elif os_type in ["debian", "ubuntu"]:
        run(f"sudo apt update && sudo apt install -y {package}")
    else:
        print(f"[!] Unsupported OS: {os_type}")
        sys.exit(1)

def install_pip_package(package, version=None):
    if version:
        pkg = f"{package}=={version}"
    else:
        pkg = package
    print(f"[*] Installing Python package: {pkg}")
    run(f"pip3 install {pkg} --break-system-packages")

def install_go_tool(repo, binary_name=None):
    name = binary_name if binary_name else repo.split("/")[-1]
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    bin_path = os.path.join(gopath, "bin", name)

    if not os.path.exists(bin_path):
        print(f"[*] Installing Go tool: {name}")
        run(f"go install github.com/{repo}@latest")

    if os.path.exists(bin_path):
        print(f"[*] Copying {name} to /usr/local/bin")
        run(f"sudo cp {bin_path} /usr/local/bin/{name}")
        run(f"sudo chmod +x /usr/local/bin/{name}")
    else:
        print(f"[!] {name} binary not found after install.")

def verify_tools():
    print("\n===[ Verifying Installed Tools ]===\n")
    tools = [
        "subfinder", "assetfinder", "subjack", "subzy", "httpx",
        "katana", "waybackurls", "okadminfinder", "sslscan", "whois"
    ]
    failed = []

    for tool in tools:
        if which(tool):
            print(f"[✓] {tool} is installed at: {which(tool)}")
        else:
            print(f"[X] {tool} NOT found.")
            failed.append(tool)

    if not failed:
        print("\n[+] All tools installed successfully!")
    else:
        print("\n[!] Tools not found:\n  - " + "\n  - ".join(failed))

def main():
    os_type = ask_distro()

    if os_type == "arch":
        install_pip_package("PyQt5", version="5.15.11")
    else:
        install_package("python3-pyqt5", os_type)
        install_pip_package("PyQt5")

    for pkg in ["go", "git", "curl", "whois", "sslscan"]:
        install_package(pkg, os_type)

    install_pip_package("okadminfinder")

    install_go_tool("projectdiscovery/subfinder/v2/cmd/subfinder", "subfinder")
    install_go_tool("tomnomnom/assetfinder", "assetfinder")
    install_go_tool("haccer/subjack", "subjack")
    install_go_tool("PentestPad/subzy", "subzy")
    install_go_tool("projectdiscovery/httpx/cmd/httpx", "httpx")
    install_go_tool("projectdiscovery/katana/cmd/katana", "katana")
    install_go_tool("tomnomnom/waybackurls", "waybackurls")

    verify_tools()

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"[!] Installation failed: {e}")
        sys.exit(1)
