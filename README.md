# Scrypter

Scrypter is a simple desktop application for encrypting and decrypting files using **Fernet symmetric encryption** from the Python `cryptography` library. The app has a clean, dark-themed GUI built with **PyQt5**.

---

## Features

- **Create Key**: Generate a new encryption key and save it as a `.key` file.
- **Encrypt Files**: Encrypt any file using a previously generated key.
- **Decrypt Files**: Decrypt encrypted files using the same key.
- **Help Window**: Provides instructions on how to use the app.
- **Dark Mode GUI**: Easy on the eyes with a simple interface.

---

## Installation

1. Make sure you have **Python 3.10+** installed.
2. Install the required libraries:

```bash
pip install pyqt5 cryptography
