from PyQt6 import QtCore
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, 
    QMainWindow, QToolBar, QFileDialog, QTableWidget, QTableWidgetItem
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QPalette, QColor, QAction
import sys

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Login page
        self.setWindowTitle("Login")
        self.setGeometry(100, 100, 400, 300)

        # Login background color
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#3399ff"))
        self.setPalette(palette)

        # Logo
        self.logo = QLabel(self)
        pixmap = QPixmap("image.png")
        self.logo.setPixmap(pixmap)
        self.logo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Login Interface
        self.label_username = QLabel("Username:")
        self.input_username = QLineEdit()
        self.input_username.setPlaceholderText("Enter your username")
        
        self.label_password = QLabel("Password:")
        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_password.setPlaceholderText("Enter your password")

        # Login button
        self.button_login = QPushButton("Login")
        self.button_login.clicked.connect(self.check_login)

        # CSS
        self.setStyleSheet("""
            QLabel {
                font-size: 14px;
            }
            QLineEdit {
                font-size: 14px;
                padding: 8px;
                color: white;
                background-color: black;
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            QLineEdit:focus {
                border: 1px solid #0078d4;
                background-color: #333333;
            }
            QPushButton {
                font-size: 16px;
                padding: 10px;
                color: white;
                background-color: #0078d4;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #00407a;
            }
        """)

        layout = QVBoxLayout()
        layout.addWidget(self.logo)
        layout.addWidget(self.label_username)
        layout.addWidget(self.input_username)
        layout.addWidget(self.label_password)
        layout.addWidget(self.input_password)
        layout.addWidget(self.button_login)
        
        self.setLayout(layout)

    def check_login(self):
        username = self.input_username.text()
        password = self.input_password.text()

        if username == "admin" and password == "password":
            QMessageBox.information(self, "Login Success", "You have successfully logged in!")
            self.open_main_window()
        else:
            QMessageBox.warning(self, "Login Failed", "Invalid username or password.")

    def open_main_window(self):
        self.hide()
        self.main_window = MainWindow(self)
        self.main_window.show()

class MainWindow(QMainWindow):
    def __init__(self, login_window):
        super().__init__()
        self.login_window = login_window 
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Torrent-Like-App")
        self.setGeometry(150, 150, 800, 600) 

        # Toolbar
        toolbar = self.addToolBar("Toolbar")

        self.open_torrent_action = QAction("Upload Torrent", self)
        self.open_torrent_action.triggered.connect(self.open_torrent_file)
        toolbar.addAction(self.open_torrent_action)

        self.logout_action = QAction("Logout", self)
        self.logout_action.triggered.connect(self.logout)
        toolbar.addAction(self.logout_action)

        # Torrent Table
        self.torrent_table = QTableWidget()
        self.torrent_table.setColumnCount(4)
        self.torrent_table.setHorizontalHeaderLabels(["File Name", "Size", "Progress", "Status"])

        # Set the table as the central widget
        self.setCentralWidget(self.torrent_table)

    def logout(self):
        reply = QMessageBox.question(self, 'Logout', 'Are you sure you want to log out?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            self.close()
            self.login_window.show()

    def open_torrent_file(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFiles)
        file_dialog.setNameFilter("Torrent Files (*.torrent)")
        if file_dialog.exec():
            file_paths = file_dialog.selectedFiles()
            if file_paths:
                self.add_torrent_to_table(file_paths[0])

    def add_torrent_to_table(self, file_path):
        # TODO: Get the exactly file size
        file_name = file_path.split("/")[-1]  # Extract the file name from the path
        file_size = "700 MB"  # Placeholder for actual file size
        progress = "0%"  # Placeholder for download progress
        status = "Waiting"  # Placeholder for status

        # Add a new row in the table with the torrent information
        row_position = self.torrent_table.rowCount()
        self.torrent_table.insertRow(row_position)
        self.torrent_table.setItem(row_position, 0, QTableWidgetItem(file_name))
        self.torrent_table.setItem(row_position, 1, QTableWidgetItem(file_size))
        self.torrent_table.setItem(row_position, 2, QTableWidgetItem(progress))
        self.torrent_table.setItem(row_position, 3, QTableWidgetItem(status))

# Run application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec())
