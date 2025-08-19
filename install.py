#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
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

SUPPORTED_OS = ["arch", "debian", "ubuntu", "windows"]


# ------------------------------
# Utility functions
# ------------------------------
def run(cmd):
    print(f"\n[+] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def install_package(package, os_type):
    if os_type == "arch":
        run(f"sudo pacman -Sy --noconfirm {package}")
    elif os_type in ["debian", "ubuntu"]:
        run(f"sudo apt update && sudo apt install -y {package}")
    elif os_type == "windows":
        if which("winget"):
            run(f"winget install -e --id {package}")
        elif which("choco"):
            run(f"choco install {package} -y")
        else:
            print(f"[!] No package manager found for Windows. Install {package} manually.")
    else:
        print(f"[!] Unsupported OS: {os_type}")
        sys.exit(1)

def install_pip_package(package, version=None):
    pkg = f"{package}=={version}" if version else package
    print(f"[*] Installing Python package: {pkg}")
    run(f"pip install {pkg}")

def install_go_tool(repo, binary_name=None):
    name = binary_name if binary_name else repo.split("/")[-1]
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    bin_path = os.path.join(gopath, "bin", name + (".exe" if platform.system().lower() == "windows" else ""))

    if not os.path.exists(bin_path):
        print(f"[*] Installing Go tool: {name}")
        run(f"go install github.com/{repo}@latest")

    if os.path.exists(bin_path):
        target = os.path.join("C:\\Windows\\System32" if platform.system().lower() == "windows" else "/usr/local/bin", name)
        print(f"[*] Copying {name} to {target}")
        if platform.system().lower() == "windows":
            run(f"copy {bin_path} {target}")
        else:
            run(f"sudo cp {bin_path} {target}")
            run(f"sudo chmod +x {target}")
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


# ------------------------------
# Main logic
# ------------------------------
def ask_distro():
    system = platform.system().lower()
    if "windows" in system:
        return "windows"
    elif "linux" in system:
        print("[?] Choose your Linux distro:")
        for i, distro in enumerate(SUPPORTED_OS[:-1], 1):
            print(f"  {i}. {distro.title()}")
        choice = input("Enter number (1/2/3): ").strip()
        if choice in {"1", "2", "3"}:
            return SUPPORTED_OS[int(choice) - 1]
        else:
            print("[!] Invalid choice. Exiting.")
            sys.exit(1)
    else:
        print(f"[!] Unsupported OS detected: {system}")
        sys.exit(1)


def main():
    print(Fore.GREEN + ASCII + Style.RESET_ALL)
    os_type = ask_distro()

    # Install PyQt5
    if os_type in ["arch", "debian", "ubuntu"]:
        if os_type == "arch":
            install_pip_package("PyQt5-sip", version="12.9.0")
            install_pip_package("PyQt5", version="5.13.0")
        else:
            install_package("python3-pyqt5", os_type)
            install_pip_package("PyQt5")
    elif os_type == "windows":
        install_pip_package("PyQt5")

    # Base packages
    base_packages = {
        "arch": ["go", "git", "curl", "whois", "sslscan"],
        "debian": ["golang", "git", "curl", "whois", "sslscan"],
        "ubuntu": ["golang", "git", "curl", "whois", "sslscan"],
        "windows": ["GoLang.Go", "Git.Git", "Curl.Curl", "GnuWin32.Whois"]
    }

    for pkg in base_packages[os_type]:
        install_package(pkg, os_type)

    # Python packages
    install_pip_package("okadminfinder")
    install_pip_package("openai")   # ditambahkan
    install_pip_package("psutil")   # ditambahkan

    # Go tools
    install_go_tool("projectdiscovery/subfinder/v2/cmd/subfinder", "subfinder")
    install_go_tool("tomnomnom/assetfinder", "assetfinder")
    install_go_tool("haccer/subjack", "subjack")
    install_go_tool("PentestPad/subzy", "subzy")
    install_go_tool("projectdiscovery/httpx/cmd/httpx", "httpx")
    install_go_tool("projectdiscovery/katana/cmd/katana", "katana")
    install_go_tool("tomnomnom/waybackurls", "waybackurls")

    verify_tools()


# ------------------------------
# Entrypoint
# ------------------------------
if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"[!] Installation failed: {e}")
        sys.exit(1)
