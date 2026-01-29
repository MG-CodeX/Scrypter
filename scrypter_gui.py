import sys
import os
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow,QMessageBox,
                             QFileDialog, QPushButton, QLabel, QScrollArea)

BUTTON_STYLE = """ 
                QPushButton {
                    background-color: gray; 
                    color: black; 
                    font-size: 20px; 
                    border: 2px none;
                    border-radius: 5px;
                } 
                """

class MainWindow(QMainWindow):
    """
    The main window of the application
    """
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Scrypter")
        self.setGeometry(525, 250, 900, 600)
        self.setStyleSheet(""" 
        QMainWindow {
            background-color: #151515;
        } 
        """)

        self.label = QLabel(self)
        self.label.setText("Scrypter")
        self.label.setGeometry(340, 50, 600, 100)
        self.label.setStyleSheet(""" 
        QLabel { 
            color: white; 
            font-size: 50px; 
            font-weight: bold;
        }
        """)

        self.create_enc = QPushButton(self)
        self.create_enc.setText("Create Key")
        self.create_enc.setGeometry(95, 200, 150, 45)
        self.create_enc.setStyleSheet(BUTTON_STYLE)
        self.create_enc.clicked.connect(self.create_key)

        self.button_enc = QPushButton("Encrypt", self)
        self.button_enc.setGeometry(270, 200, 150, 45)
        self.button_enc.setStyleSheet(BUTTON_STYLE)
        self.button_enc.clicked.connect(self.encrypt)

        self.button_dec = QPushButton("Decrypt", self)
        self.button_dec.setGeometry(445, 200, 150, 45)
        self.button_dec.setStyleSheet(BUTTON_STYLE)
        self.button_dec.clicked.connect(self.decrypt)

        self.help = QPushButton(self)
        self.help.setText("Show Help")
        self.help.setGeometry(620, 200, 150, 45)
        self.help.setStyleSheet(BUTTON_STYLE)
        self.help.clicked.connect(self.show_help)

        self.exit_app = QPushButton(self)
        self.exit_app.setText("Exit")
        self.exit_app.setGeometry(360, 270, 150, 45)
        self.exit_app.clicked.connect(self.close)
        self.exit_app.setStyleSheet(""" 
        QPushButton {
            background-color: red; 
            color: white; 
            font-size: 20px; 
            border: 2px none;
            border-radius: 5px;
        } 
        """)

    def load_key_and_file(self):
        """
        Helper function to load the key and file path
        """
        try:
            key_path, _ = QFileDialog.getOpenFileName(self, "Open Key File",
                                                            "",
                                                            "Key Files (*.key);;")
            if not key_path:
                return None, None, None

            with open(key_path, "rb") as f:
                key = f.read()
        except Exception as e:
            QMessageBox.critical(self,
                                 "Key Path Selection Error",
                                 f"The selection of the key path failed.\n{str(e)}")
            return None, None, None

        try:
            file_path, _ = QFileDialog.getOpenFileName(self,
                                                       "Open File Path",
                                                       "",
                                                       "All Files (*);;")
            if not file_path:
                return None, None, None

            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            QMessageBox.critical(self, "File Path Selection Error",
                                 f"The selection of the file path failed.\n{str(e)}")
            return None, None, None

        return key, file_path, data

    def save_file_with_overwrite(
                                self,
                                file_path,
                                data,
                                title="File Saved",
                                msg="The file has been saved."
                                ):
        """
        Writes data to a file, asking the user for permission if the file already exists.
        Works for encryption or decryption.
        """
        if os.path.exists(file_path):
            reply = QMessageBox.question(
                self,
                f"File already exists '{file_path}'",
                "Do you want to overwrite it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return False  # User chose not to overwrite

        with open(file_path, "wb") as f:
            f.write(data)

        QMessageBox.information(self, title, f"{msg}\n{file_path}")
        return True

    def create_key(self):
        """
        Creates an encryption key
        """
        file_path, _ = QFileDialog.getSaveFileName(self,
                                                   "Save Key File",
                                                   "",
                                                   "Key Files (*.key);;")
        if not file_path:
            return

        try:
            with open(file_path, "wb") as f:
                key = Fernet.generate_key()
                f.write(key)
            QMessageBox.information(self,
                                    "The Key Was Saved",
                                    "Key Saved")
        except Exception as e:
            QMessageBox.critical(self,
                                 "Failed to Save Key",
                                 f"Failed to save key to {file_path}:\n{str(e)}")

    def encrypt(self):
        """
        Encrypts a file with .enc file extension
        """
        key, file_path, data = self.load_key_and_file()
        if key is None:
            return
        try:
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)
            encrypted_file_path = file_path + ".enc"

            self.save_file_with_overwrite(
                encrypted_file_path,
                encrypted_data,
                title="File Encrypted",
                msg="The file was encrypted and saved as:"
            )

        except Exception as e:
            QMessageBox.critical(self,
                                 "Encryption Error",
                                 f"Encryption failed.\n{str(e)}")

    def decrypt(self):
        """
        Decrypts a file without .enc file extension
        """
        key, file_path, data = self.load_key_and_file()
        if key is None:
            return

        try:
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(data)

            decrypted_file_path = file_path
            if file_path.endswith(".enc"):
                decrypted_file_path = file_path[:-4]

            self.save_file_with_overwrite(
                decrypted_file_path,
                decrypted_data,
                title="File Decrypted",
                msg="The file was decrypted and saved as:"
            )

        except Exception as e:
            QMessageBox.critical(self,
                                 "Decryption Error",
                                 f"Decryption failed.\n{str(e)}")

    def show_help(self):
        """
        Shows help text from scrypter_help.txt
        """
        try:
            with open("scrypter_help.txt", "r") as f:
                help_text = f.read()
        except FileNotFoundError:
            QMessageBox.warning(self,
                                "Help File Missing",
                                "The help file 'scrypter_help.txt' was not found.")
            return

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

# Tomorrow ask for an explanation about what save_file_with_overwrite() does