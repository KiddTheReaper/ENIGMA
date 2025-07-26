import sys
import os
import re
import platform
import psutil
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QFileSystemModel, QTreeView, QSplitter, QFileDialog,
    QComboBox, QSizePolicy, QListWidget, QStackedWidget
)
from PyQt5.QtCore import Qt, QProcess, QDateTime, QTimer
from PyQt5.QtGui import QFontDatabase, QFont, QPixmap, QIcon


class EnigmaGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ENIGMA")
        self.setWindowIcon(QIcon("assets/logo.png"))
        self.setFixedSize(1000, 600)
        self.font_family = self.load_regular_font()
        QApplication.setFont(QFont(self.font_family, 12))
    
        self.shared_url = ""
        
        self.logo_label = QLabel()
        self.set_logo("Dark") 
        self.logo_label.setAlignment(Qt.AlignCenter)
        self.logo_label.setStyleSheet("QLabel { margin-bottom: 5px; }")
        
        logo_text = QLabel("Tools List:")
        logo_text.setAlignment(Qt.AlignLeft)

        self.tabs = QListWidget()
        self.tabs.setFixedWidth(150)
        self.tabs.setSpacing(5)
        self.tabs.setStyleSheet("QListWidget::item { margin: 2px; }")
        self.tabs.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        self.stack = QStackedWidget()

        self.subdomain_tab = SubdomainTab(self)
        self.info_tab = InformationTab(self)
        self.crawl_tab = CrawlingTab(self)
        self.admin_tab = AdminFinderTab(self)
        self.sslscan_tab = SSLScanTab(self)
        self.output_tab = OutputTab()
        self.settings_tab = SettingsTab(self)

        self.add_tab("Enumeration", self.subdomain_tab)
        self.add_tab("Information", self.info_tab)
        self.add_tab("Crawling", self.crawl_tab)
        self.add_tab("Path Finder", self.admin_tab)
        self.add_tab("SSL/TLS", self.sslscan_tab)
        self.add_tab("Output Viewer", self.output_tab)
        self.add_tab("Settings", self.settings_tab)

        sidebar_layout = QVBoxLayout()
        sidebar_layout.addWidget(self.logo_label)
        sidebar_layout.addWidget(logo_text)
        sidebar_layout.addWidget(self.tabs)
        sidebar_layout.addStretch()

        main_layout = QHBoxLayout()
        main_layout.addLayout(sidebar_layout)
        main_layout.addWidget(self.stack)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.tabs.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.tabs.setCurrentRow(0)

    def add_tab(self, name, widget):
        self.tabs.addItem(name)
        self.stack.addWidget(widget)

    def load_regular_font(self):
        font_id = QFontDatabase.addApplicationFont("assets/regular.ttf")
        families = QFontDatabase.applicationFontFamilies(font_id)
        if families:
            return families[0]
        return "Sans Serif"

    def get_shared_url(self):
        return self.shared_url

    def set_shared_url(self, url):
        self.shared_url = url
        self.update_tabs_url(url)
        
    def set_logo(self, theme):
        if theme == "Dark":
            pixmap = QPixmap("assets/logo.png")
        else:
            pixmap = QPixmap("assets/logo_black.png")

        pixmap = pixmap.scaledToWidth(120, Qt.SmoothTransformation)
        self.logo_label.setPixmap(pixmap)
        self.logo_label.setAlignment(Qt.AlignCenter)

    def update_tabs_url(self, url):
        for i in range(self.stack.count()):
            widget = self.stack.widget(i)
            if hasattr(widget, "set_url_from_global"):
                widget.set_url_from_global(url)
                
    def apply_theme(self, theme_name):
        self.set_logo(theme_name)


import os
import re
from PyQt5.QtCore import QProcess, QDateTime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QApplication
)

import os
import re
from PyQt5.QtCore import QProcess, QDateTime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QApplication
)

import os
import re
from PyQt5.QtCore import QProcess, QDateTime, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QApplication
)

class SubdomainTab(QWidget):
    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui = parent_gui

        layout = QVBoxLayout()
        self.setFont(QApplication.font())

        h_input = QHBoxLayout()
        h_input.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.textChanged.connect(self.save_url_to_global)
        h_input.addWidget(self.url_input)
        layout.addLayout(h_input)

        btn_layout = QHBoxLayout()
        self.btn_all = QPushButton("Enumerate Target")
        self.btn_all.clicked.connect(self.run_all_enum)
        btn_layout.addWidget(self.btn_all)

        self.btn_check_alive = QPushButton("Check Alive")
        self.btn_check_alive.clicked.connect(self.check_alive)
        btn_layout.addWidget(self.btn_check_alive)

        layout.addLayout(btn_layout)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
        self.setLayout(layout)

        self.console.append("Welcome to the Enumeration Module.\n")
        self.console.append(
            "Enumeration is the first and most critical phase of reconnaissance in any security assessment.\n"
            "In this module, Enigma helps you identify publicly available subdomains belonging to a target domain,\n"
            "using multiple powerful tools like Subfinder and Assetfinder.\n"
        )
        self.console.append(
            "After gathering subdomains, Enigma can check for potentially vulnerable dangling DNS records using\n"
            "Subjack and Subzy, tools commonly used in subdomain takeover detection.\n"
        )
        self.console.append(
            "To streamline your workflow, Enigma automatically merges results from multiple tools\n"
            "and allows you to probe live subdomains with HTTPX to validate which hosts are responsive.\n"
        )
        self.console.append(
            "Usage Tips:\n"
            "- Start with 'Enumerate Target' to run subdomain discovery.\n"
            "- Then click 'Check Alive' to find which subdomains are live and vulnerable.\n"
            "- All outputs are saved under output/enumeration/<target>.\n"
        )

        if self.parent_gui:
            current_url = self.parent_gui.get_shared_url()
            if current_url:
                self.url_input.setText(current_url)

    def save_url_to_global(self):
        if self.parent_gui:
            self.parent_gui.set_shared_url(self.url_input.text().strip())

    def set_url_from_global(self, url):
        self.url_input.setText(url)

    def run_tool(self, tool_name):
        url = self.url_input.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL.")
            return

        base_path = f'output/enumeration/{url}'
        os.makedirs(base_path, exist_ok=True)

        if tool_name == 'subfinder':
            cmd = f"subfinder -d {url} -o {base_path}/subfinder.txt"
        elif tool_name == 'assetfinder':
            cmd = f"assetfinder --subs-only {url} > {base_path}/assetfinder.txt"
        elif tool_name == 'subjack':
            cmd = f"subjack -w {base_path}/alive.txt -o {base_path}/subjack.txt"
        elif tool_name == 'subzy':
            cmd = f"subzy --targets {base_path}/alive.txt > {base_path}/subzy.txt"
        else:
            return

        self._execute(cmd)

    def run_all_enum(self):
        url = self.url_input.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL.")
            return

        self.run_tool('subfinder')
        self.run_tool('assetfinder')
        self.merge_subdomain_files(url)

    def merge_subdomain_files(self, url):
        base_path = f'output/enumeration/{url}'
        subfinder_file = os.path.join(base_path, "subfinder.txt")
        assetfinder_file = os.path.join(base_path, "assetfinder.txt")
        merged_file = os.path.join(base_path, "all_subs.txt")

        all_domains = set()

        for file in [subfinder_file, assetfinder_file]:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("http://") or line.startswith("https://"):
                            line = re.sub(r'^https?://', '', line)
                            line = line.split('/')[0]
                        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                            all_domains.add(line)

        with open(merged_file, 'w') as f:
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")

        self.console.append(f"[+] Merged {len(all_domains)} valid domains into all_subs.txt")

    def check_alive(self):
        url = self.url_input.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL.")
            return

        base_path = f'output/enumeration/{url}'
        infile = os.path.join(base_path, "all_subs.txt")
        outfile = os.path.join(base_path, "alive.txt")

        if not os.path.isfile(infile):
            self.console.append("[!] all_subs.txt not found. Run enumeration first.")
            return

        cmd = f"cat {infile} | httpx -silent -threads 100 -timeout 5 -no-color -o {outfile}"
        self._execute(cmd)

        QTimer.singleShot(1500, lambda: self.run_tool('subjack'))
        QTimer.singleShot(3000, lambda: self.run_tool('subzy'))

    def _execute(self, cmd):
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.console.append(f"[{timestamp}] Running: {cmd}")
        proc = QProcess(self)
        env = proc.processEnvironment()
        env.insert("PATH", os.environ.get("PATH", ""))
        env.insert("HOME", os.environ.get("HOME", os.path.expanduser("~")))
        proc.setProcessEnvironment(env)
        proc.setProcessChannelMode(QProcess.MergedChannels)

        def handle_output():
            data = proc.readAllStandardOutput().data().decode()
            filtered_output = self._filter_urls_only(data)
            if filtered_output:
                self.console.append(filtered_output)

        proc.readyReadStandardOutput.connect(handle_output)
        proc.finished.connect(lambda code, status: None)
        proc.start("/bin/bash", ["-lc", cmd])

    def _filter_urls_only(self, text):
        lines = text.strip().split('\n')
        url_pattern = re.compile(r'^(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')
        return '\n'.join(line for line in lines if url_pattern.match(line)) or ''


class InformationTab(QWidget):
    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui = parent_gui

        layout = QVBoxLayout()
        self.setFont(QApplication.font())

        h_input = QHBoxLayout()
        h_input.addWidget(QLabel("Target URL:"))
        self.input_url = QLineEdit()
        self.input_url.textChanged.connect(self.save_url_to_global)
        h_input.addWidget(self.input_url)
        layout.addLayout(h_input)

        self.btn_whois = QPushButton("Collect Information")
        self.btn_whois.clicked.connect(self.run_whois)
        layout.addWidget(self.btn_whois)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)

        self.setLayout(layout)
        
        self.console.append("Welcome to the Information Module.\n")
        self.console.append(
            "This tab is designed to help you gather essential domain registration\n"
            "and ownership data using WHOIS lookups. It is a critical step in passive\n"
            "reconnaissance, allowing you to retrieve registrar information, creation and\n"
            "expiration dates, name servers, and contact details if available.\n"
        )
        self.console.append(
            "Knowing who owns a domain and when it was registered can help identify\n"
            "potential targets, expired domains, or interesting patterns in the organization's\n"
            "domain infrastructure.\n"
        )
        self.console.append(
            "Usage Tips:\n"
            "- Enter a domain to run a WHOIS query.\n"
            "- Results will be printed here and saved to output/information/<domain>.txt\n"
        )
        if self.parent_gui:
            current_url = self.parent_gui.get_shared_url()
            if current_url:
                self.input_url.setText(current_url)

    def save_url_to_global(self):
        if self.parent_gui:
            self.parent_gui.set_shared_url(self.input_url.text().strip())

    def set_url_from_global(self, url):
        cursor_pos = self.input_url.cursorPosition()
        self.input_url.blockSignals(True)
        self.input_url.setText(url)
        self.input_url.setCursorPosition(min(cursor_pos, len(url)))
        self.input_url.blockSignals(False)

    def run_whois(self):
        url = self.input_url.text().strip()
        if not url:
            self.console.append("[!] Please enter a domain or URL.")
            return
        os.makedirs(f"output/information/{url}", exist_ok=True)
        self.output_file = f"output/information/{url}/information.txt"
        cmd = f"whois {url}"
        self._execute(cmd)

    def _execute(self, cmd):
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.console.append(
            f"[{timestamp}] Collecting target information\n"
            f"[{timestamp}] Please wait until the process is finished.\n"
        )

        self.output_lines = []

        self.proc = QProcess(self)
        env = self.proc.processEnvironment()
        env.insert("PATH", os.environ.get("PATH", ""))
        env.insert("HOME", os.environ.get("HOME", os.path.expanduser("~")))
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)

        def handle_output():
            data = self.proc.readAllStandardOutput().data().decode(errors='ignore')
            if data:
                self.console.moveCursor(self.console.textCursor().End)
                self.console.insertPlainText(data)
                self.output_lines.append(data)

        def save_output():
            try:
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.writelines(self.output_lines)
            except Exception as e:
                self.console.append(f"[!] Failed to save output: {e}")

        self.proc.readyReadStandardOutput.connect(handle_output)
        self.proc.finished.connect(save_output)
        self.proc.start("/bin/bash", ["-lc", cmd])



class CrawlingTab(QWidget):
    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui = parent_gui

        layout = QVBoxLayout()
        self.setFont(QApplication.font())

        h_input = QHBoxLayout()
        h_input.addWidget(QLabel("Target URL:"))
        self.input_url = QLineEdit()
        self.input_url.textChanged.connect(self.save_url_to_global)
        h_input.addWidget(self.input_url)
        layout.addLayout(h_input)

        btn_layout = QHBoxLayout()
        self.btn_live = QPushButton("Live Crawling")
        self.btn_live.clicked.connect(self.run_katana)
        btn_layout.addWidget(self.btn_live)

        self.btn_archive = QPushButton("Archive Crawling")
        self.btn_archive.clicked.connect(self.run_waybackurls)
        btn_layout.addWidget(self.btn_archive)

        layout.addLayout(btn_layout)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)

        self.setLayout(layout)

        self.console.append("Welcome to the Crawling Module.\n")
        self.console.append(
            "This module allows you to discover hidden paths, parameters, endpoints,\n"
            "and archived content from both live and historical sources.\n"
        )
        self.console.append(
            "Live crawling uses 'katana' to scan reachable URLs and endpoints in real-time,\n"
            "while archive crawling leverages 'waybackurls' to gather URLs from the Internet Archive.\n"
        )
        self.console.append(
            "These methods help uncover admin panels, hidden directories, old APIs, or endpoints\n"
            "that are no longer linked but still accessible.\n"
        )
        self.console.append(
            "Usage Tips:\n"
            "- Use Live Crawling to find active endpoints.\n"
            "- Use Archive Crawling to find historical URLs of the domain.\n"
            "- Outputs are saved in output/crawling/<domain>/\n"
        )

        if self.parent_gui:
            current_url = self.parent_gui.get_shared_url()
            if current_url:
                self.input_url.setText(current_url)

    def save_url_to_global(self):
        if self.parent_gui:
            self.parent_gui.set_shared_url(self.input_url.text().strip())

    def set_url_from_global(self, url):
        cursor_pos = self.input_url.cursorPosition()
        self.input_url.blockSignals(True)
        self.input_url.setText(url)
        self.input_url.setCursorPosition(min(cursor_pos, len(url)))
        self.input_url.blockSignals(False)

    def run_katana(self):
        url = self.input_url.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL or domain.")
            return
        os.makedirs(f"output/crawling/{url}/", exist_ok=True)
        outfile = f"output/crawling/{url}/live_crawling.txt"
        cmd = f"echo {url} | katana | tee {outfile}"
        self._execute(cmd)

    def run_waybackurls(self):
        url = self.input_url.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL or domain.")
            return
        os.makedirs(f"output/crawling/{url}/", exist_ok=True)
        outfile = f"output/crawling/{url}/archive_crawling.txt"
        cmd = f"echo {url} | waybackurls | tee {outfile}"
        self._execute(cmd)

    def _execute(self, cmd):
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.console.append(
            f"[{timestamp}] Crawling the target\n"
            f"[{timestamp}] Please wait until the process is finished.\n"
        )

        self.proc = QProcess(self)
        env = self.proc.processEnvironment()
        env.insert("PATH", os.environ.get("PATH", ""))
        env.insert("HOME", os.environ.get("HOME", os.path.expanduser("~")))
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.SeparateChannels)

        def handle_stdout():
            data = self.proc.readAllStandardOutput().data().decode()
            filtered = self._filter_urls_only(data)
            if filtered:
                self.console.append(filtered)

        def handle_stderr():
            data = self.proc.readAllStandardError().data().decode()
            lines = data.strip().split('\n')
            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
            for line in lines:
                clean_line = ansi_escape.sub('', line).strip()
                if not clean_line:
                    continue
                if (
                    'projectdiscovery.io' in clean_line
                    or 'katana version' in clean_line.lower()
                    or 'started' in clean_line.lower()
                    or clean_line.startswith('[')
                    or re.match(r'^[\W_]+$', clean_line)
                ):
                    continue
                self.console.append(f"[stderr] {clean_line}")

        self.proc.readyReadStandardOutput.connect(handle_stdout)
        self.proc.readyReadStandardError.connect(handle_stderr)
        self.proc.start("/bin/bash", ["-lc", cmd])

    def _filter_urls_only(self, text):
        lines = text.strip().split('\n')
        url_pattern = re.compile(r'^https?://[^\s]+$')
        ascii_pattern = re.compile(r'[\u2500-\u25FF\u2580-\u259F\u2600-\u26FF\u2700-\u27BF]')
        return '\n'.join(
            line.strip() for line in lines
            if url_pattern.match(line.strip())
            and 'projectdiscovery.io' not in line
            and not ascii_pattern.search(line)
        ) or ''

class AdminFinderTab(QWidget):
    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui = parent_gui

        layout = QVBoxLayout()
        self.setFont(QApplication.font())

        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target URL:"))
        self.input_url = QLineEdit()
        self.input_url.textChanged.connect(self.save_url_to_global)
        input_layout.addWidget(self.input_url)
        layout.addLayout(input_layout)

        self.btn_run = QPushButton("Find Sensitive Paths")
        self.btn_run.clicked.connect(self.run_admin_finder)
        layout.addWidget(self.btn_run)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)

        self.setLayout(layout)

        self.console.append("Welcome to the Path Finder Module.\n")
        self.console.append(
            "This module helps you identify accessible files, folders, and potential hidden\n"
            "resources within a web server. It uses techniques such as directory brute-forcing\n"
            "to uncover admin panels, configuration files, backups, and other sensitive paths.\n"
        )
        self.console.append(
            "Discovering these hidden endpoints can often lead to privilege escalation,\n"
            "information leakage, or even direct exploitation vectors.\n"
        )
        self.console.append(
            "Usage Tips:\n"
            "- Enter a target domain or URL (e.g., https://target.com)\n"
            "- Output will be saved under output/pathfinder/<target>.\n"
        )

        if self.parent_gui:
            current_url = self.parent_gui.get_shared_url()
            if current_url:
                self.input_url.setText(current_url)

    def save_url_to_global(self):
        if self.parent_gui:
            self.parent_gui.set_shared_url(self.input_url.text().strip())

    def set_url_from_global(self, url):
        cursor_pos = self.input_url.cursorPosition()
        self.input_url.blockSignals(True)
        self.input_url.setText(url)
        self.input_url.setCursorPosition(min(cursor_pos, len(url)))
        self.input_url.blockSignals(False)


    def run_admin_finder(self):
        url = self.input_url.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL.")
            return

        os.makedirs(f"output/pathfinder/{url}", exist_ok=True)
        self.output_file = f"output/pathfinder/{url}/paths.txt"
        cmd = f"okadminfinder -u https://{url}"
        self._execute(cmd)

    def _execute(self, cmd):
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.console.append(
            f"[{timestamp}] Enumerating sensitive paths\n"
            f"[{timestamp}] Please wait until the process is finished.\n"
        )

        self.proc = QProcess(self)
        env = self.proc.processEnvironment()
        env.insert("PATH", os.environ.get("PATH", ""))
        env.insert("HOME", os.environ.get("HOME", os.path.expanduser("~")))
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)

        self.output_lines = []

        def handle_output():
            raw_data = self.proc.readAllStandardOutput().data().decode(errors='ignore')
            self.output_lines.append(raw_data)

            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(raw_data)

            filtered = self._extract_urls_from_ascii_output(raw_data)
            if filtered:
                self.console.append(filtered)

        self.proc.readyReadStandardOutput.connect(handle_output)
        self.proc.start("/bin/bash", ["-lc", cmd])

    def _extract_urls_from_ascii_output(self, text):
        url_pattern = re.compile(r'https?://[a-zA-Z0-9./\-_]+')
        urls = url_pattern.findall(text)
        return '\n'.join(sorted(set(urls)))
            
class SSLScanTab(QWidget):
    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui = parent_gui

        layout = QVBoxLayout()
        self.setFont(QApplication.font())

        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target URL:"))
        self.input_url = QLineEdit()
        self.input_url.textChanged.connect(self.save_url_to_global)
        input_layout.addWidget(self.input_url)
        layout.addLayout(input_layout)

        self.btn_run = QPushButton("Run SSLScan")
        self.btn_run.clicked.connect(self.run_sslscan)
        layout.addWidget(self.btn_run)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)

        self.setLayout(layout)

        self.console.append("Welcome to the SSL/TLS Scanner Module.\n")
        self.console.append(
            "This module scans SSL/TLS configurations of a given host using sslscan.\n"
            "It helps identify insecure protocols, weak ciphers, expired certificates,\n"
            "and other misconfigurations that could compromise secure communications.\n"
        )
        self.console.append(
            "Understanding SSL/TLS posture is critical in securing modern web applications,\n"
            "especially for domains handling sensitive user data or financial transactions.\n"
        )
        self.console.append(
            "Usage Tips:\n"
            "- Input a domain or IP with HTTPS enabled (e.g., tesla.com).\n"
            "- Output is saved to output/ssl/<domain>.txt for future reference.\n"
        )

        if self.parent_gui:
            current_url = self.parent_gui.get_shared_url()
            if current_url:
                self.input_url.setText(current_url)

    def save_url_to_global(self):
        if self.parent_gui:
            self.parent_gui.set_shared_url(self.input_url.text().strip())

    def set_url_from_global(self, url):
        cursor_pos = self.input_url.cursorPosition()
        self.input_url.blockSignals(True)
        self.input_url.setText(url)
        self.input_url.setCursorPosition(min(cursor_pos, len(url)))
        self.input_url.blockSignals(False)


    def run_sslscan(self):
        url = self.input_url.text().strip()
        if not url:
            self.console.append("[!] Please enter a target URL or domain.")
            return

        os.makedirs(f"output/sslscan/{url}", exist_ok=True)
        self.output_file = f"output/sslscan/{url}/sslscan.txt"
        cmd = f"sslscan --no-colour {url}"
        self._execute(cmd)

    def _execute(self, cmd):
        timestamp = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.console.append(f"[{timestamp}] Running SSLScan\n[{timestamp}] Please wait until the process is finished.\n")

        self.proc = QProcess(self)
        env = self.proc.processEnvironment()
        env.insert("PATH", os.environ.get("PATH", ""))
        env.insert("HOME", os.environ.get("HOME", os.path.expanduser("~")))
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)

        self.output_lines = []

        self.proc.readyReadStandardOutput.connect(self.handle_stdout)
        self.proc.readyReadStandardError.connect(self.handle_stderr)
        self.proc.finished.connect(self.save_output)
        self.proc.start("/bin/bash", ["-lc", cmd])

    def handle_stdout(self):
        data = self.proc.readAllStandardOutput().data().decode(errors='ignore')
        self.console.moveCursor(self.console.textCursor().End)
        self.console.insertPlainText(data)
        self.output_lines.append(data)

    def handle_stderr(self):
        data = self.proc.readAllStandardError().data().decode(errors='ignore')
        self.console.moveCursor(self.console.textCursor().End)
        self.console.insertPlainText(data)
        self.output_lines.append(data)

    def save_output(self):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.writelines(self.output_lines)


class OutputTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setFont(QApplication.font())

        layout = QVBoxLayout()

        self.viewer = QTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setPlainText(
            "Welcome to the Output Viewer Module.\n\n"
            "This module allows you to quickly browse and review output files generated\n"
            "by other modules in Enigma. All scans and tools store their results under\n"
            "the organized output/ directory structure.\n\n"
            "Usage Tips:\n"
            "- Use the list on the left to open a scan result.\n"
            "- Output is grouped by module and target domain.\n"
            "- Non-URL results (like whois or sslscan) will be shown in full.\n"
        )

        self.file_list = QTreeView()
        self.model = QFileSystemModel()
        self.model.setRootPath(os.path.abspath('output'))
        self.model.setNameFilters(["*.txt"])
        self.model.setNameFilterDisables(False)

        self.file_list.setModel(self.model)
        self.file_list.setRootIndex(self.model.index(os.path.abspath('output')))
        self.file_list.setHeaderHidden(True)
        self.file_list.setColumnHidden(1, True)
        self.file_list.setColumnHidden(2, True)
        self.file_list.setColumnHidden(3, True)
        self.file_list.clicked.connect(self.on_file_clicked)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.file_list)
        splitter.addWidget(self.viewer)
        splitter.setSizes([300, 600])
        layout.addWidget(splitter)

        self.setLayout(layout)

    def on_file_clicked(self, index):
        path = self.model.filePath(index)

        if os.path.isdir(path):
            self.viewer.clear()
            return

        if os.path.isfile(path):
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    filename = os.path.basename(path).lower()

                    if "information" in filename or "sslscan" in filename:
                        self.viewer.setPlainText(content)
                    else:
                        filtered_content = self._filter_urls_only(content)
                        self.viewer.setPlainText(filtered_content)
            except Exception as e:
                self.viewer.setPlainText(f"Cannot open file: {e}")

    def _filter_urls_only(self, text):
        lines = text.strip().split('\n')
        url_pattern = re.compile(r'^(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$')
        return '\n'.join(
            line.strip() for line in lines
            if url_pattern.match(line.strip()) and 'projectdiscovery.io' not in line
        ) or 'No URLs found in this file'
from PyQt5.QtGui import QPainter


class MarqueeLabel(QLabel):
    def __init__(self, text="", parent=None):
        super().__init__(parent)
        self.original_text = text
        self.setStyleSheet("color: gray; font-size: 17px;")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(20)

        self.offset = 0
        self.scroll_speed = 1
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_offset)
        self.timer.start(30) 

    def update_offset(self):
        self.offset += self.scroll_speed
        text_width = self.fontMetrics().width(self.original_text)
        if self.offset > text_width:
            self.offset = 0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setFont(self.font())
        fm = self.fontMetrics()
        text_width = fm.width(self.original_text)
        height = int(self.height() * 0.75)

        x1 = -self.offset
        x2 = x1 + text_width

        painter.drawText(x1, height, self.original_text)
        painter.drawText(x2, height, self.original_text)

class SettingsTab(QWidget):
    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui = parent_gui

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Theme:"))
        self.theme_selector = QComboBox()
        self.theme_selector.addItems(["Dark", "Light"])
        self.theme_selector.currentTextChanged.connect(self.change_theme)
        layout.addWidget(self.theme_selector)

        layout.addWidget(QLabel("System Information:"))
        self.sysinfo = QTextEdit()
        self.sysinfo.setReadOnly(True)
        self.sysinfo.setMaximumHeight(165) 
        layout.addWidget(self.sysinfo)

        layout.addWidget(QLabel("Real-time Usage:"))
        self.usage_info = QTextEdit()
        self.usage_info.setReadOnly(True)
        self.usage_info.setMaximumHeight(65) 
        layout.addWidget(self.usage_info)

        self.setLayout(layout)

        self.load_static_info()

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_usage_info)
        self.timer.start(2000) 
        
        layout.addWidget(QLabel("Information:"))
        self.app_info = QTextEdit()
        self.app_info.setReadOnly(True)
        self.app_info.setText(self.get_app_info())
        layout.addWidget(self.app_info)
        self.app_info.setMaximumHeight(190) 
        
        layout.addWidget(QLabel("Thanks To:"))

        thanks_text = " ProjectDiscovery - tomnomnom - haccer - PentestPad - CyberFlow - Zilox - 下村 努 - - EdOverflow - 0xsha - TheHackerish - NahamSec - The Cyber Mentor - OWASP Community - All member BlackLine - All member SIBERMUDA.IDN - "
        marquee = MarqueeLabel(thanks_text)
        layout.addWidget(marquee)

    def change_theme(self, theme_name):
        path = f"theme/{theme_name.lower()}.css"
        try:
            with open(path, 'r') as f:
                stylesheet = f.read()
                self.parent_gui.setStyleSheet(stylesheet)
        except FileNotFoundError:
            print(f"[!] Theme file '{path}' not found. Using default.")
            self.parent_gui.setStyleSheet("")

        if hasattr(self.parent_gui, 'set_logo'):
            self.parent_gui.set_logo(theme_name)


    def load_static_info(self):
        info = []
        info.append(f"OS: {platform.system()} {platform.release()}")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"CPU Cores: {psutil.cpu_count(logical=True)}")
        info.append(f"Total RAM: {round(psutil.virtual_memory().total / (1024 ** 3), 2)} GB")
        info.append(f"Hostname: {platform.node()}")
        info.append(f"Kernel: {platform.version()}")
        cpu_name = platform.processor() or "Unknown"
        self.sysinfo.setText("\n".join(info))

    def update_usage_info(self):
        cpu = psutil.cpu_percent(interval=0.5)
        ram = psutil.virtual_memory()
        used_ram = round(ram.used / (1024 ** 3), 2)
        total_ram = round(ram.total / (1024 ** 3), 2)
        usage_text = f"CPU Usage: {cpu}%\nRAM Usage: {used_ram} GB / {total_ram} GB"
        self.usage_info.setText(usage_text)

    def get_app_info(self):
        info = []
        info.append("Developed by @KiddTheReaper")
        info.append("Version: 1.0")
        info.append("Telegram: @KiddTheReaper")
        info.append("TikTok: @justan0therloser")
        info.append("Note: Use this tool at your own risk. The developer is not responsible for any illegal activities.")
        return "\n".join(info)

    def scroll_marquee(self):
        self.display_text = self.display_text[1:] + self.display_text[0]
        self.marquee_label.setText(self.display_text)

def set_logo(self, theme):
    if theme.lower() == "dark":
        logo_path = "assets/logo.png"
    else:
        logo_path = "assets/logo_black.png"

    pixmap = QPixmap(logo_path).scaledToWidth(120, Qt.SmoothTransformation)
    self.logo_label.setPixmap(pixmap)
    self.logo_label.setAlignment(Qt.AlignCenter)
    
    def autoload_theme(gui_instance):
        SettingsTab(gui_instance).change_theme("Dark")

if __name__ == '__main__':
    app = QApplication(sys.argv)

    font_db = QFontDatabase()
    font_id = font_db.addApplicationFont("assets/regular.ttf")
    families = font_db.applicationFontFamilies(font_id)

    if families:
        font_family = families[0]
    else:
        font_family = "Sans Serif" 
    
    window = EnigmaGUI()
    window.settings_tab.change_theme("Dark")
    window.show()
    sys.exit(app.exec_())
