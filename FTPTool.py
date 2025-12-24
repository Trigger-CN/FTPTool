import sys
import os
import json
import socket
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, 
    QHBoxLayout, QPushButton, QLineEdit, QLabel, QFileDialog, 
    QMessageBox, QGridLayout, QTextEdit, QGroupBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTime
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# --- Configuration Constant ---
CONFIG_FILE = "ftp_config.json"

# --- Backend FTP Service Logic (QThread) ---

class FTPService(QThread):
    log_signal = pyqtSignal(str, bool) # Added boolean for error logging

    def __init__(self, directory, username, password, port):
        super().__init__()
        self.directory = directory
        self.username = username
        self.password = password
        self.port = port
        self.ftp_server = None
        self.local_ip = self._get_local_ip()

    def _get_local_ip(self):
        """Get local network IP address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip
    
    def _log(self, message, is_error=False):
        """Send log message to the main thread"""
        self.log_signal.emit(f"[SERVER] {message}", is_error)

    def run(self):
        self._log(f"Attempting to start FTP server...")
        
        try:
            authorizer = DummyAuthorizer()
            authorizer.add_user(
                self.username, self.password, self.directory, perm="elradfmw"
            )
            
            handler = FTPHandler
            handler.authorizer = authorizer
            handler.encoding = "utf-8"
            
            # Custom handler to fix log signature and pipe logs to GUI
            class CustomFTPHandler(handler):
                def log(self, message, logfun=None): 
                    is_error = "error" in message.lower() or "unhandled exception" in message.lower()
                    self.parent_service._log(f"[FTP] {message}", is_error)
                    if logfun:
                        super().log(message, logfun=logfun)
                    else:
                        super().log(message) 

            CustomFTPHandler.parent_service = self
            
            address = (self.local_ip, self.port)
            self.ftp_server = FTPServer(address, CustomFTPHandler)
            self.ftp_server.max_cons = 256
            
            self._log(f"FTP server started successfully! IP: {self.local_ip}:{self.port}, Share Directory: {self.directory}")
            self.ftp_server.serve_forever(timeout=0.1)
            
        except OSError as e:
            self._log(f"Startup failed (port might be in use): {e}", is_error=True)
        except Exception as e:
            self._log(f"Unknown error occurred: {e}", is_error=True)

    def stop(self):
        """Stops the FTP server"""
        if self.ftp_server:
            self._log("Requesting FTP server shutdown...")
            self.ftp_server.close_all()
            self.quit()
            self.wait()
            self.ftp_server = None
            self._log("FTP server closed.")

# --- PyQt5 GUI Interface Logic ---

class FTPManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🚀 LAN FTP Tool (Configuration Saved)")
        self.setGeometry(100, 100, 700, 500)
        self.ftp_service_instance = None
        
        self._init_ui()
        self.apply_styles()
        self.load_config()
        self.update_log("Application Started.")

    # --- Configuration R/W Methods ---
    def load_config(self):
        """Loads configuration from JSON file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                self.dir_lineedit.setText(config.get("directory", os.path.expanduser("~")))
                self.port_lineedit.setText(str(config.get("port", 2121)))
                self.user_lineedit.setText(config.get("username", "ftpuser"))
                self.pass_lineedit.setText(config.get("password", "123456"))
                self.update_log("Configuration loaded.")
            except Exception as e:
                self.update_log(f"Failed to load configuration: {e}", is_error=True)
        else:
            self.update_log("Config file not found, using defaults.")

    def save_config(self):
        """Saves current configuration to JSON file"""
        config = {
            "directory": self.dir_lineedit.text(),
            "port": self.port_lineedit.text(),
            "username": self.user_lineedit.text(),
            "password": self.pass_lineedit.text(),
        }
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4)
            self.update_log("Configuration saved.")
        except Exception as e:
            self.update_log(f"Failed to save configuration: {e}", is_error=True)


    def apply_styles(self):
        """Applies QSS styles and sets Cascadia Code font"""
        # Set Cascadia Code font globally
        self.setStyleSheet("""
            * {
                font-family: "Cascadia Code", monospace;
            }
            QMainWindow { background-color: #f0f0f0; }
            QPushButton { 
                padding: 8px 15px; 
                border-radius: 5px; 
                background-color: #0078d7; 
                color: white; 
                border: none;
            }
            QPushButton:hover { background-color: #005a9e; }
            QPushButton:disabled { background-color: #a0a0a0; }
            QLineEdit, QTextEdit { 
                padding: 5px; 
                border: 1px solid #ccc; 
                border-radius: 4px;
            }
            QLabel#status_label { font-size: 14px; font-weight: bold; }
        """)

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # --- Configuration Input Area ---
        config_box = QGroupBox("⚙️ Configuration")
        config_layout = QGridLayout(config_box)
        
        # Shared Directory
        self.dir_lineedit = QLineEdit(os.path.expanduser("~"))
        btn_select_dir = QPushButton("Select Shared Directory")
        btn_select_dir.clicked.connect(self.select_directory)
        config_layout.addWidget(QLabel("Shared Directory:"), 0, 0)
        config_layout.addWidget(self.dir_lineedit, 0, 1)
        config_layout.addWidget(btn_select_dir, 0, 2)
        
        # Port
        self.port_lineedit = QLineEdit("2121")
        config_layout.addWidget(QLabel("Port:"), 1, 0)
        config_layout.addWidget(self.port_lineedit, 1, 1)
        
        # Username and Password
        self.user_lineedit = QLineEdit("ftpuser")
        self.pass_lineedit = QLineEdit("123456")
        self.pass_lineedit.setEchoMode(QLineEdit.Password)
        config_layout.addWidget(QLabel("Username:"), 2, 0)
        config_layout.addWidget(self.user_lineedit, 2, 1)
        config_layout.addWidget(QLabel("Password:"), 3, 0)
        config_layout.addWidget(self.pass_lineedit, 3, 1)

        main_layout.addWidget(config_box)

        # --- Control and Status Area ---
        control_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶️ Start FTP Service")
        self.btn_start.clicked.connect(self.start_server)
        self.btn_stop = QPushButton("⏹️ Stop FTP Service")
        self.btn_stop.clicked.connect(self.stop_server)
        self.btn_stop.setEnabled(False)
        control_layout.addWidget(self.btn_start)
        control_layout.addWidget(self.btn_stop)
        main_layout.addLayout(control_layout)

        # Access Link (Copyable)
        main_layout.addWidget(QLabel("Access Link (Copyable):"))
        self.access_link_lineedit = QLineEdit("Service Not Running")
        self.access_link_lineedit.setReadOnly(True)
        main_layout.addWidget(self.access_link_lineedit)
        
        # Status Label
        self.status_label = QLabel("Status: 🔴 Not Running")
        self.status_label.setObjectName("status_label")
        main_layout.addWidget(self.status_label)
        
        # --- Log Display Area ---
        main_layout.addWidget(QLabel("\n📜 Server Log:"))
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        self.log_text_edit.setMinimumHeight(150)
        main_layout.addWidget(self.log_text_edit)

    def update_log(self, message, is_error=False):
        """Slot function: Receives and displays log information"""
        timestamp = QTime.currentTime().toString("hh:mm:ss")
        if is_error:
             # Use HTML for red error text in QTextEdit
             self.log_text_edit.append(f"<span style='color:red;'>[{timestamp}] {message}</span>")
        else:
            self.log_text_edit.append(f"[{timestamp}] {message}")

    def select_directory(self):
        """Pops up file dialog to select the shared directory"""
        directory = QFileDialog.getExistingDirectory(self, "Select Shared Directory", self.dir_lineedit.text())
        if directory:
            self.dir_lineedit.setText(directory)

    def start_server(self):
        """Starts the FTP server thread"""
        share_path = self.dir_lineedit.text()
        port_str = self.port_lineedit.text()
        username = self.user_lineedit.text()
        password = self.pass_lineedit.text()
        
        # 1. Input Validation and Path Standardization
        share_path = os.path.abspath(share_path)
        self.dir_lineedit.setText(share_path)

        if not os.path.isdir(share_path):
            QMessageBox.warning(self, "Error", "Shared directory does not exist or is invalid!")
            return
        try:
            port = int(port_str)
            if not 1024 < port < 65535: raise ValueError
        except ValueError:
            QMessageBox.warning(self, "Error", "Port number must be a valid number between 1024 and 65535!")
            return
            
        # 2. Save configuration before startup
        self.save_config()

        # 3. Start Service
        try:
            self.ftp_service_instance = FTPService(
                directory=share_path, username=username, password=password, port=port
            )
            # Connect the service thread's signal to the GUI slot
            self.ftp_service_instance.log_signal.connect(self.update_log)
            self.ftp_service_instance.start()
            
            # 4. Update GUI Status
            access_url = f"ftp://{username}:{password}@{self.ftp_service_instance.local_ip}:{port}"
            self.access_link_lineedit.setText(access_url)
            self.status_label.setText("Status: 🟢 Running")
            self.status_label.setStyleSheet("QLabel { color : green; font-weight: bold; }")
            self.btn_start.setEnabled(False)
            self.btn_stop.setEnabled(True)

        except Exception as e:
            QMessageBox.critical(self, "Startup Failed", f"Failed to start FTP service: {e}")
            self.stop_server()


    def stop_server(self):
        """Stops the FTP server thread"""
        if self.ftp_service_instance:
            self.ftp_service_instance.stop()
            self.ftp_service_instance = None
            
            # Update GUI Status
            self.status_label.setText("Status: 🔴 Not Running")
            self.status_label.setStyleSheet("QLabel { color : red; font-weight: bold; }")
            self.access_link_lineedit.setText("Service Not Running")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.update_log("FTP service fully stopped.")

    def closeEvent(self, event):
        """Overrides window close event to ensure service shutdown and config save"""
        
        # Save config before exiting
        self.save_config()
        
        if self.ftp_service_instance:
            reply = QMessageBox.question(self, 'Confirmation', 
                "FTP service is running. Are you sure you want to close and stop the service?", 
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                self.stop_server()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = FTPManagerWindow()
    window.show()
    sys.exit(app.exec_())