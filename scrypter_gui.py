import sys
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow,
                             QMessageBox, QFileDialog,
                             QPushButton, QLabel, QScrollArea)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        push_button_style = """ 
                QPushButton {
                    background-color: gray; 
                    color: black; 
                    font-size: 20px; 
                    border: 2px none;
                    border-radius: 5px;
                } 
                """

        self.setWindowTitle("Scrypter")
        self.setGeometry(525, 250, 900, 600)
        self.setStyleSheet(""" QMainWindow {background-color: #151515;} """)

        self.label = QLabel(self)
        self.label.setText("Scrypter")
        self.label.setGeometry(340, 50, 600, 100)
        self.label.setStyleSheet(""" QLabel { color: white; font-size: 50px; font-weight: bold;}""")

        self.create_enc = QPushButton(self)
        self.create_enc.setText("Create Key")
        self.create_enc.setGeometry(95, 200, 150, 45)
        self.create_enc.setStyleSheet(push_button_style)
        self.create_enc.clicked.connect(self.create_key)

        self.button_enc = QPushButton("Encrypt", self)
        self.button_enc.setGeometry(270, 200, 150, 45)
        self.button_enc.setStyleSheet(push_button_style)
        self.button_enc.clicked.connect(self.encrypt)

        self.button_dec = QPushButton("Decrypt", self)
        self.button_dec.setGeometry(445, 200, 150, 45)
        self.button_dec.setStyleSheet(push_button_style)
        self.button_dec.clicked.connect(self.decrypt)

        self.help = QPushButton(self)
        self.help.setText("Show Help")
        self.help.setGeometry(620, 200, 150, 45)
        self.help.setStyleSheet(push_button_style)
        self.help.clicked.connect(self.show_help)

        self.exit_app = QPushButton(self)
        self.exit_app.setText("Exit")
        self.exit_app.setGeometry(360, 270, 150, 45)
        self.exit_app.clicked.connect(self.close)
        self.exit_app.setStyleSheet(""" 
        QPushButton {
            background-color: darkred; 
            color: white; 
            font-size: 20px; 
            border: 2px none;
            border-radius: 5px;
        } 
        """)

    def create_key(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Key File", "", "Key Files (*.key);;")
        if not file_path:
            return

        try:
            with open(file_path, "wb") as f:
                key = Fernet.generate_key()
                f.write(key)
            QMessageBox.information(self, "The Key Was Saved", "Key Saved")
        except Exception as e:
            QMessageBox.critical(self, "Failed to Save Key", f"Failed to save key to {file_path}:\n{str(e)}")

    def encrypt(self):
        try:
            key_path, _ = QFileDialog.getOpenFileName(self, "Open Key File", "", "Key Files (*.key);;")
            if not key_path:
                return

            with open(key_path, "rb") as f:
                key = f.read()
            QMessageBox.information(self, "Key Path Selected", "The Path of the Key was selected")
        except Exception as e:
            QMessageBox.critical(self, "Key Path Selection Error", f"The selection of the key path failed.\n{str(e)}")

        file_path, _ = QFileDialog.getOpenFileName(self, "Open File Path", "", "All Files (*);;")
        QMessageBox.information(self, "File Path Selected", "The File Path was selected")
        if not file_path:
            return

        with open(file_path, "rb") as f:
            data = f.read()

        fernet = Fernet(key)

        encrypted_data = fernet.encrypt(data)

        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        QMessageBox.information(self, "File Encrypted", "The File was Encrypted")

    def decrypt(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Open Key File", "", "Key Files (*.key);;")
        if not key_path:
            return

        with open(key_path, "rb") as f:
            key = f.read()
        QMessageBox.information(self, "Key Path Selected", "The Path of the Key was selected")

        file_path, _ = QFileDialog.getOpenFileName(self, "Open File Path", "", "All Files (*);;")
        QMessageBox.information(self, "File Path Selected", "The File Path was selected")
        if not file_path:
            return

        with open(file_path, "rb") as f:
            data = f.read()

        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(data)

        with open(file_path, "wb") as f:
            f.write(decrypted_data)
        QMessageBox.information(self, "File Decrypted", "The File was Decrypted")

    def show_help(self):
        with open("scrypter_help.txt", "r") as f:
            help_text = f.read()

        help_window = QMainWindow(self)
        help_window.setWindowTitle("Help")
        help_window.resize(400, 300)

        label = QLabel(help_window)
        label.setWindowTitle("Help")
        label.setText(help_text)
        label.setWordWrap(True)
        label.setGeometry(0, 0, 400, 300)
        label.setStyleSheet(
            """
            QLabel {
                background-color: #151515;
                color: white; 
                padding: 10px;
            }
            """
        )

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(label)

        help_window.setCentralWidget(scroll)
        help_window.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())